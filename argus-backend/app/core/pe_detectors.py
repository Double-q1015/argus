from typing import Dict, List, Any, Optional
import yaml
from abc import ABC, abstractmethod
import pefile
from dataclasses import dataclass
import math

@dataclass
class DetectionResult:
    """检测结果类"""
    type: str
    risk_level: str
    description: str
    details: Dict[str, Any]

class PEDetector(ABC):
    """PE特征检测器基类"""
    @abstractmethod
    def detect(self, pe_data: Any) -> List[DetectionResult]:
        """执行检测"""
        pass

class ImportDetector(PEDetector):
    """导入特征检测器"""
    def __init__(self, characteristics: Dict):
        self.suspicious_dlls = {dll["name"].lower(): dll for dll in characteristics["suspicious_dlls"]}
        self.suspicious_functions = {func["name"]: func for func in characteristics["suspicious_functions"]}

    def detect(self, pe_data: pefile.PE) -> List[DetectionResult]:
        results = []
        if not hasattr(pe_data, 'DIRECTORY_ENTRY_IMPORT'):
            return results

        for entry in pe_data.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode().lower()
            if dll_name in self.suspicious_dlls:
                dll_info = self.suspicious_dlls[dll_name]
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        if func_name in self.suspicious_functions:
                            func_info = self.suspicious_functions[func_name]
                            results.append(DetectionResult(
                                type="suspicious_imports",
                                risk_level=func_info["risk_level"],
                                description=func_info["description"],
                                details={
                                    "dll": dll_name,
                                    "function": func_name,
                                    "dll_risk_level": dll_info["risk_level"],
                                    "dll_description": dll_info["description"]
                                }
                            ))
        return results

class SectionDetector(PEDetector):
    """节区特征检测器"""
    def __init__(self, characteristics: Dict):
        self.suspicious_names = {section["name"]: section for section in characteristics["suspicious_sections"]["names"]}
        self.suspicious_characteristics = characteristics["suspicious_sections"]["characteristics"]
        self.entropy_thresholds = characteristics["entropy_thresholds"]

    def detect(self, pe_data: pefile.PE) -> List[DetectionResult]:
        results = []
        for section in pe_data.sections:
            section_name = section.Name.decode().rstrip('\x00')
            
            # 检查节区名称
            if section_name in self.suspicious_names:
                section_info = self.suspicious_names[section_name]
                results.append(DetectionResult(
                    type="suspicious_section_names",
                    risk_level=section_info["risk_level"],
                    description=section_info["description"],
                    details={"section_name": section_name}
                ))

            # 检查节区特征
            section_chars = self._get_section_characteristics(section)
            for char_combo in self.suspicious_characteristics:
                if all(char in section_chars for char in char_combo["combination"]):
                    results.append(DetectionResult(
                        type="suspicious_section_characteristics",
                        risk_level=char_combo["risk_level"],
                        description=char_combo["description"],
                        details={
                            "section_name": section_name,
                            "characteristics": section_chars
                        }
                    ))

            # 检查熵值
            section_data = section.get_data()
            entropy = self._calculate_entropy(section_data)
            if entropy > self.entropy_thresholds["high"]:
                results.append(DetectionResult(
                    type="high_entropy_section",
                    risk_level="high",
                    description="高熵值节区",
                    details={
                        "section_name": section_name,
                        "entropy": entropy
                    }
                ))
            elif entropy > self.entropy_thresholds["medium"]:
                results.append(DetectionResult(
                    type="high_entropy_section",
                    risk_level="medium",
                    description="中等熵值节区",
                    details={
                        "section_name": section_name,
                        "entropy": entropy
                    }
                ))

        return results

    def _get_section_characteristics(self, section: Any) -> List[str]:
        """获取节区特征列表"""
        chars = []
        if section.Characteristics & 0x20:  # IMAGE_SCN_CNT_CODE
            chars.append("CODE")
        if section.Characteristics & 0x40:  # IMAGE_SCN_CNT_INITIALIZED_DATA
            chars.append("INITIALIZED_DATA")
        if section.Characteristics & 0x80:  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
            chars.append("UNINITIALIZED_DATA")
        if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
            chars.append("EXECUTE")
        if section.Characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
            chars.append("READ")
        if section.Characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
            chars.append("WRITE")
        return chars

    def _calculate_entropy(self, data: bytes) -> float:
        """计算数据的熵值"""
        if not data:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        entropy = 0.0
        for count in freq.values():
            probability = count / len(data)
            entropy -= probability * math.log2(probability)
        
        return entropy

class PECharacteristicsManager:
    """PE特征管理器"""
    def __init__(self, config_path: str):
        self.config = self._load_config(config_path)
        self.detectors = self._init_detectors()

    def _load_config(self, config_path: str) -> Dict:
        """加载配置文件"""
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)

    def _init_detectors(self) -> List[PEDetector]:
        """初始化检测器"""
        return [
            ImportDetector(self.config),
            SectionDetector(self.config)
        ]

    def detect_all(self, pe_data: pefile.PE) -> List[DetectionResult]:
        """执行所有检测"""
        results = []
        for detector in self.detectors:
            results.extend(detector.detect(pe_data))
        return results

    def get_vulnerabilities(self, pe_data: pefile.PE) -> List[str]:
        """获取漏洞列表"""
        results = self.detect_all(pe_data)
        vulnerabilities = []
        for result in results:
            if result.type == "suspicious_imports":
                vulnerabilities.append(f"suspicious_imports: {result.details['dll']} -> {result.details['function']}")
            elif result.type == "suspicious_section_names":
                vulnerabilities.append(f"suspicious_section_names: {result.details['section_name']}")
            elif result.type == "suspicious_section_characteristics":
                vulnerabilities.append(f"suspicious_section_characteristics: {result.details['section_name']} 同时具有执行和写入权限")
            elif result.type == "high_entropy_section":
                vulnerabilities.append(f"high_entropy_section: {result.details['section_name']} (entropy: {result.details['entropy']:.2f})")
        return vulnerabilities 