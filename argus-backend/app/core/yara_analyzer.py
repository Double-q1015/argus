from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel
import os
import yara
import hashlib
from datetime import datetime
import tempfile
import threading
from sqlalchemy.orm import Session
from app.models.yara import YaraRule
from app.core.cache import Cache

class YaraMatch(BaseModel):
    """YARA规则匹配结果"""
    rule_name: str
    strings: List[Dict[str, Any]]
    meta: Dict[str, Any]
    tags: List[str]
    description: Optional[str] = None

class YaraAnalysisResult(BaseModel):
    """YARA分析结果"""
    file_path: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    matches: List[YaraMatch]
    error_message: Optional[str] = None

class YaraRuleCache:
    """YARA规则缓存管理器"""
    def __init__(self):
        self._cache = Cache()
        self._lock = threading.Lock()
        self._rules: Dict[str, yara.Rules] = {}
        self._last_update = datetime.min

    def get_rules(self) -> Dict[str, yara.Rules]:
        """获取缓存的规则"""
        with self._lock:
            return self._rules.copy()

    def update_rules(self, rules: Dict[str, yara.Rules]):
        """更新规则缓存"""
        with self._lock:
            self._rules = rules
            self._last_update = datetime.now()

    def clear(self):
        """清除规则缓存"""
        with self._lock:
            self._rules.clear()
            self._last_update = datetime.min

# 全局规则缓存实例
rule_cache = YaraRuleCache()

def compile_rules_from_db(db: Session) -> Tuple[bool, Optional[str], Optional[Dict[str, yara.Rules]]]:
    """
    从数据库编译YARA规则
    
    Args:
        db: 数据库会话
        
    Returns:
        Tuple[bool, Optional[str], Optional[Dict[str, yara.Rules]]]: 
        (是否成功, 错误信息, 编译后的规则)
    """
    try:
        # 从数据库获取规则
        rules = db.query(YaraRule).filter(YaraRule.is_active == True).all()
        if not rules:
            return True, None, {}

        # 创建临时文件来编译规则
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
            for rule in rules:
                # 添加规则名称注释
                tmp.write(f"/* Rule: {rule.name} */\n")
                tmp.write(rule.content)
                tmp.write("\n\n")
            tmp_path = tmp.name

        try:
            # 编译规则
            compiled_rules = yara.compile(filepath=tmp_path)
            
            # 创建规则映射
            rules_dict = {}
            for rule in rules:
                rules_dict[rule.name] = compiled_rules
            
            return True, None, rules_dict
        finally:
            # 清理临时文件
            os.unlink(tmp_path)
    except yara.Error as e:
        return False, str(e), None
    except Exception as e:
        return False, f"编译规则时发生错误: {str(e)}", None

def load_yara_rules(db: Session, force_reload: bool = False) -> Dict[str, yara.Rules]:
    """
    加载YARA规则（优先从缓存加载）
    
    Args:
        db: 数据库会话
        force_reload: 是否强制重新加载
        
    Returns:
        Dict[str, yara.Rules]: 规则名称到规则对象的映射
    """
    # 检查缓存是否需要更新（每小时更新一次）
    now = datetime.now()
    if not force_reload and (now - rule_cache._last_update).total_seconds() < 3600:
        return rule_cache.get_rules()

    # 从数据库编译规则
    success, error, rules = compile_rules_from_db(db)
    if not success:
        print(f"加载YARA规则失败: {error}")
        return rule_cache.get_rules()  # 如果编译失败，返回缓存的规则

    # 更新缓存
    rule_cache.update_rules(rules)
    return rules

async def analyze_yara(file_path: str, db: Session) -> YaraAnalysisResult:
    """
    使用YARA规则分析文件
    
    Args:
        file_path: 要分析的文件路径
        db: 数据库会话
        
    Returns:
        YaraAnalysisResult: YARA分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return YaraAnalysisResult(
                file_path=file_path,
                file_size=0,
                md5="",
                sha1="",
                sha256="",
                matches=[],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        
        # 计算哈希值
        with open(file_path, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()

        # 加载YARA规则
        rules = load_yara_rules(db)
        if not rules:
            return YaraAnalysisResult(
                file_path=file_path,
                file_size=file_size,
                md5=md5,
                sha1=sha1,
                sha256=sha256,
                matches=[],
                error_message="未找到YARA规则"
            )

        # 执行规则匹配
        matches = []
        for rule_name, rule in rules.items():
            try:
                rule_matches = rule.match(file_path)
                if rule_matches:
                    for match in rule_matches:
                        # 提取匹配的字符串
                        strings = []
                        for string_id, offset, matched_data in match.strings:
                            strings.append({
                                "string_id": string_id,
                                "offset": offset,
                                "data": matched_data.hex()
                            })
                        
                        # 创建匹配结果
                        matches.append(YaraMatch(
                            rule_name=rule_name,
                            strings=strings,
                            meta=match.meta,
                            tags=match.tags,
                            description=match.meta.get('description', '')
                        ))
            except Exception as e:
                print(f"规则 {rule_name} 匹配失败: {str(e)}")
                continue

        return YaraAnalysisResult(
            file_path=file_path,
            file_size=file_size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            matches=matches
        )

    except Exception as e:
        return YaraAnalysisResult(
            file_path=file_path,
            file_size=0,
            md5="",
            sha1="",
            sha256="",
            matches=[],
            error_message=str(e)
        )

async def analyze_yara_strings(data: bytes, db: Session) -> YaraAnalysisResult:
    """
    使用YARA规则分析内存数据
    
    Args:
        data: 要分析的数据
        db: 数据库会话
        
    Returns:
        YaraAnalysisResult: YARA分析结果
    """
    try:
        # 加载YARA规则
        rules = load_yara_rules(db)
        if not rules:
            return YaraAnalysisResult(
                file_path="memory",
                file_size=len(data),
                md5=hashlib.md5(data).hexdigest(),
                sha1=hashlib.sha1(data).hexdigest(),
                sha256=hashlib.sha256(data).hexdigest(),
                matches=[],
                error_message="未找到YARA规则"
            )

        # 执行规则匹配
        matches = []
        for rule_name, rule in rules.items():
            try:
                rule_matches = rule.match(data=data)
                if rule_matches:
                    for match in rule_matches:
                        # 提取匹配的字符串
                        strings = []
                        for string_id, offset, matched_data in match.strings:
                            strings.append({
                                "string_id": string_id,
                                "offset": offset,
                                "data": matched_data.hex()
                            })
                        
                        # 创建匹配结果
                        matches.append(YaraMatch(
                            rule_name=rule_name,
                            strings=strings,
                            meta=match.meta,
                            tags=match.tags,
                            description=match.meta.get('description', '')
                        ))
            except Exception as e:
                print(f"规则 {rule_name} 匹配失败: {str(e)}")
                continue

        return YaraAnalysisResult(
            file_path="memory",
            file_size=len(data),
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            matches=matches
        )

    except Exception as e:
        return YaraAnalysisResult(
            file_path="memory",
            file_size=len(data),
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            matches=[],
            error_message=str(e)
        ) 