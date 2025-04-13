import asyncio
from datetime import datetime
import subprocess
import json
from typing import Dict, Any, List, Protocol
from fastapi import Depends
from app.core.storage import get_sample
from app.models.sample import Sample

class FileAnalyzer(Protocol):
    """文件分析器接口"""
    async def analyze(self, file_path: str) -> Dict[str, Any]:
        pass

class DieAnalyzer:
    """DIE分析器实现"""
    async def analyze(self, file_path: str) -> Dict[str, Any]:
        try:
            process = await asyncio.create_subprocess_exec(
                'diec',
                file_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {"error": f"die分析失败: {stderr.decode()}"}
                
            output = stdout.decode().strip()
            results = {
                "链接器": "",
                "编译器": "",
                "工具": "",
                "字节序": "",
                "模式": "",
                "程序类型": "",
                "文件类型": "",
                "熵": 0.0,
                "语言": "",
                "操作系统": ""
            }
            
            for line in output.split('\n'):
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    if key in results:
                        results[key] = value
                        
            return results
            
        except Exception as e:
            return {"error": f"die分析失败: {str(e)}"}

class TridAnalyzer:
    """TrID分析器实现"""
    async def analyze(self, file_path: str) -> Dict[str, Any]:
        try:
            process = await asyncio.create_subprocess_exec(
                'trid',
                file_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                return {"error": f"TrID分析失败: {stderr.decode()}"}
                
            output = stdout.decode().strip()
            results = {}
            
            for line in output.split('\n'):
                if '%' in line:
                    percentage, file_type = line.split(')', 1)
                    percentage = percentage.strip('( ')
                    file_type = file_type.strip()
                    results[f"{percentage} (.{file_type.split('.')[-1]})"] = file_type
                    
            return results
            
        except Exception as e:
            return {"error": f"TrID分析失败: {str(e)}"}

class SampleAnalyzer:
    """样本分析器"""
    def __init__(
        self,
        die_analyzer: DieAnalyzer = Depends(),
        trid_analyzer: TridAnalyzer = Depends()
    ):
        self.die_analyzer = die_analyzer
        self.trid_analyzer = trid_analyzer

    async def analyze_sample(self, sample: Sample, config: Dict[str, Any]) -> Dict[str, Any]:
        """分析单个样本"""
        try:
            contents = await get_sample(sample.sha256_digest)
            if not contents:
                return {
                    "status": "error",
                    "error": "Sample file not found in storage"
                }
            
            results = {
                "file_info": {
                    "size": len(contents),
                    "type": sample.file_type,
                    "name": sample.file_name
                },
                "analysis_time": datetime.utcnow().isoformat(),
                "basic_stats": {
                    "entropy": calculate_entropy(contents),
                    "byte_distribution": calculate_byte_distribution(contents)
                }
            }
            
            if config.get("perform_strings_analysis"):
                results["strings_analysis"] = extract_strings(contents)
            
            if config.get("perform_header_analysis"):
                results["header_analysis"] = analyze_file_header(contents)
                
            if config.get("perform_die_analysis"):
                results["die_analysis"] = await self.die_analyzer.analyze(sample.file_path)
                
            if config.get("perform_trid_analysis"):
                results["trid_analysis"] = await self.trid_analyzer.analyze(sample.file_path)
            
            return {
                "status": "success",
                "results": results
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": str(e)
            }

# 依赖注入函数
def get_die_analyzer() -> DieAnalyzer:
    return DieAnalyzer()

def get_trid_analyzer() -> TridAnalyzer:
    return TridAnalyzer()

def get_sample_analyzer(
    die_analyzer: DieAnalyzer = Depends(get_die_analyzer),
    trid_analyzer: TridAnalyzer = Depends(get_trid_analyzer)
) -> SampleAnalyzer:
    return SampleAnalyzer(die_analyzer, trid_analyzer)

# 保留原有的工具函数
def calculate_entropy(data: bytes) -> float:
    """计算数据的熵值"""
    if not data:
        return 0.0
    
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    
    entropy = 0
    for freq in frequencies.values():
        probability = freq / len(data)
        entropy -= probability * math.log2(probability)
        
    return entropy

def calculate_byte_distribution(data: bytes) -> Dict[int, int]:
    """计算字节分布"""
    distribution = {}
    for byte in data:
        distribution[byte] = distribution.get(byte, 0) + 1
    return distribution

def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """提取字符串"""
    import string
    printable = set(string.printable.encode())
    strings = []
    current = []
    
    for byte in data:
        if byte in printable:
            current.append(byte)
        elif current:
            if len(current) >= min_length:
                strings.append(bytes(current).decode(errors='ignore'))
            current = []
    
    if current and len(current) >= min_length:
        strings.append(bytes(current).decode(errors='ignore'))
    
    return strings

def analyze_file_header(data: bytes) -> Dict[str, Any]:
    """分析文件头部"""
    if len(data) < 16:
        return {"format": "unknown", "magic": None}
    
    magic_numbers = {
        b'MZ': 'DOS/PE Executable',
        b'\x7fELF': 'ELF',
        b'PK\x03\x04': 'ZIP',
        b'\x25PDF': 'PDF',
        b'\x89PNG': 'PNG',
        b'GIF8': 'GIF',
        b'\xFF\xD8\xFF': 'JPEG',
    }
    
    for magic, format_name in magic_numbers.items():
        if data.startswith(magic):
            return {
                "format": format_name,
                "magic": data[:len(magic)].hex()
            }
    
    return {
        "format": "unknown",
        "magic": data[:16].hex()
    }

async def analyze_sample(sample: Sample, config: Dict[str, Any]) -> Dict[str, Any]:
    """分析样本"""
    pass