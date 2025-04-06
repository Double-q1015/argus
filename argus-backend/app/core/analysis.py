import asyncio
from datetime import datetime
from typing import Dict, Any, List
from app.core.storage import get_sample
from app.models.sample import Sample

async def analyze_sample(sample: Sample, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    分析单个样本
    """
    try:
        # 从MinIO获取样本文件
        contents = await get_sample(sample.sha256_digest)
        if not contents:
            return {
                "status": "error",
                "error": "Sample file not found in storage"
            }
        
        # 执行基本分析
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
        
        # 根据配置执行额外分析
        if config.get("perform_strings_analysis"):
            results["strings_analysis"] = extract_strings(contents)
        
        if config.get("perform_header_analysis"):
            results["header_analysis"] = analyze_file_header(contents)
        
        return {
            "status": "success",
            "results": results
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)
        }

def calculate_entropy(data: bytes) -> float:
    """
    计算数据的熵值
    """
    if not data:
        return 0.0
    
    # 计算字节频率
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # 计算熵
    import math
    entropy = 0
    for count in freq.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

def calculate_byte_distribution(data: bytes) -> Dict[int, int]:
    """
    计算字节分布
    """
    distribution = {}
    for byte in data:
        distribution[byte] = distribution.get(byte, 0) + 1
    return distribution

def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """
    提取字符串
    """
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
    """
    分析文件头部
    """
    if len(data) < 16:
        return {"format": "unknown", "magic": None}
    
    # 常见文件格式的魔数
    magic_numbers = {
        b'MZ': 'DOS/PE Executable',
        b'\x7fELF': 'ELF',
        b'PK\x03\x04': 'ZIP',
        b'\x25PDF': 'PDF',
        b'\x89PNG': 'PNG',
        b'GIF8': 'GIF',
        b'\xFF\xD8\xFF': 'JPEG',
    }
    
    # 检查文件头
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