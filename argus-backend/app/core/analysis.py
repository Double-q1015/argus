import asyncio
from datetime import datetime
from typing import Dict, Any, List
from app.core.storage import get_sample
from app.models.scale import Scale
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

async def start_scale_analysis(scale: Scale) -> bool:
    """
    启动规模分析
    """
    try:
        # 更新规模状态为运行中
        scale.status = "running"
        scale.updated_at = datetime.utcnow()
        await scale.save()
        
        # 获取样本列表
        samples = []
        for sha256 in scale.samples:
            sample = await Sample.find_one(Sample.sha256_digest == sha256)
            if sample:
                samples.append(sample)
        
        # 分析每个样本
        results = []
        for sample in samples:
            sample_result = await analyze_sample(sample, scale.configuration)
            if sample_result["status"] == "success":
                results.append({
                    "sha256": sample.sha256_digest,
                    "results": sample_result["results"]
                })
                
                # 更新样本的分析状态
                sample.analysis_status = "completed"
                sample.analysis_results = sample_result["results"]
                await sample.save()
            else:
                results.append({
                    "sha256": sample.sha256_digest,
                    "error": sample_result["error"]
                })
                
                # 更新样本的分析状态
                sample.analysis_status = "failed"
                sample.analysis_results = {"error": sample_result["error"]}
                await sample.save()
        
        # 更新规模分析结果
        scale.status = "completed"
        scale.results = {
            "completion_time": datetime.utcnow().isoformat(),
            "sample_results": results
        }
        scale.updated_at = datetime.utcnow()
        await scale.save()
        
        return True
        
    except Exception as e:
        # 更新规模分析状态为失败
        scale.status = "failed"
        scale.error_message = str(e)
        scale.updated_at = datetime.utcnow()
        await scale.save()
        return False

async def stop_scale_analysis(scale: Scale) -> bool:
    """
    停止规模分析
    """
    try:
        if scale.status == "running":
            scale.status = "stopped"
            scale.updated_at = datetime.utcnow()
            await scale.save()
        return True
    except Exception as e:
        print(f"Error stopping scale analysis: {e}")
        return False 