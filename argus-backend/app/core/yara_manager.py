import yara
from typing import Optional, Tuple
import tempfile
import os

class YaraManager:
    @staticmethod
    async def validate_rule(content: str) -> Tuple[bool, Optional[str]]:
        """
        验证Yara规则的语法是否正确
        
        Args:
            content: Yara规则内容
            
        Returns:
            Tuple[bool, Optional[str]]: (是否有效, 错误信息)
        """
        try:
            # 创建临时文件来编译规则
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            
            try:
                # 尝试编译规则
                yara.compile(filepath=tmp_path)
                return True, None
            finally:
                # 清理临时文件
                os.unlink(tmp_path)
        except yara.Error as e:
            return False, str(e)
        except Exception as e:
            return False, f"验证规则时发生错误: {str(e)}"
    
    @staticmethod
    async def compile_rules(rules: list) -> Tuple[bool, Optional[str], Optional[yara.Rules]]:
        """
        编译多个Yara规则
        
        Args:
            rules: 规则列表，每个规则包含name和content
            
        Returns:
            Tuple[bool, Optional[str], Optional[yara.Rules]]: 
            (是否成功, 错误信息, 编译后的规则)
        """
        try:
            # 创建临时文件来编译规则
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as tmp:
                for rule in rules:
                    # 添加规则名称注释
                    tmp.write(f"/* Rule: {rule['name']} */\n")
                    tmp.write(rule['content'])
                    tmp.write("\n\n")
                tmp_path = tmp.name
            
            try:
                # 编译规则
                compiled_rules = yara.compile(filepath=tmp_path)
                return True, None, compiled_rules
            finally:
                # 清理临时文件
                os.unlink(tmp_path)
        except yara.Error as e:
            return False, str(e), None
        except Exception as e:
            return False, f"编译规则时发生错误: {str(e)}", None
    
    @staticmethod
    async def scan_file(file_path: str, rules: yara.Rules) -> Tuple[bool, list]:
        """
        使用编译好的规则扫描文件
        
        Args:
            file_path: 要扫描的文件路径
            rules: 编译好的Yara规则
            
        Returns:
            Tuple[bool, list]: (是否成功, 匹配结果列表)
        """
        try:
            matches = rules.match(file_path)
            return True, matches
        except Exception as e:
            return False, [str(e)] 