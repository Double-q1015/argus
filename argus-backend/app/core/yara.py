import yara
from typing import List, Dict, Union, Any

class YaraManager:
    def validate_rule(self, rule_content: str) -> bool:
        """
        验证Yara规则的语法是否正确
        
        Args:
            rule_content: Yara规则内容
            
        Returns:
            bool: 规则是否有效
        """
        try:
            yara.compile(source=rule_content)
            return True
        except yara.Error:
            return False
    
    def compile_rules(self, rules: List[str]) -> Any:
        """
        编译多个Yara规则
        
        Args:
            rules: Yara规则内容列表
            
        Returns:
            编译后的规则对象
        """
        try:
            return yara.compile(source=rules[0])  # 简化为只编译第一个规则
        except yara.Error as e:
            raise ValueError(f"编译Yara规则失败: {str(e)}")
    
    def scan_data(self, data: bytes, rules: yara.Rules) -> List[Dict[str, Any]]:
        """使用编译好的规则扫描数据"""
        matches = rules.match(data=data)
        result = []
        for match in matches:
            strings = []
            for found in match.strings:
                strings.append({
                    "identifier": str(found[1]),
                    "string": str(found[2].decode('utf-8', errors='ignore')),
                    "offset": found[0]
                })
            result.append({
                "rule": match.rule,
                "strings": strings,
                "tags": match.tags,
                "meta": match.meta
            })
        return result
    
    def scan_file(self, file_path: str, rules: yara.Rules) -> List[Dict[str, Any]]:
        """使用编译好的规则扫描文件"""
        matches = rules.match(filepath=file_path)
        result = []
        for match in matches:
            strings = []
            for found in match.strings:
                strings.append({
                    "identifier": str(found[1]),
                    "string": str(found[2].decode('utf-8', errors='ignore')),
                    "offset": found[0]
                })
            result.append({
                "rule": match.rule,
                "strings": strings,
                "tags": match.tags,
                "meta": match.meta
            })
        return result 