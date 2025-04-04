from typing import Dict, List, Optional, Any, Tuple, Generator, Iterator
from pydantic import BaseModel
import os
import math
import numpy as np
from datetime import datetime
import io
from minio import Minio
from minio.error import S3Error

class EntropyResult(BaseModel):
    """熵值分析结果"""
    data_size: int
    entropy: float
    entropy_per_byte: float
    is_encrypted: bool
    is_compressed: bool
    is_text: bool
    entropy_distribution: Dict[str, float]
    block_entropy: List[Tuple[int, float]]
    error_message: Optional[str] = None

def calculate_entropy(data: bytes, block_size: int = 1024) -> EntropyResult:
    """
    计算数据的熵值
    
    Args:
        data: 要分析的数据
        block_size: 块大小，用于计算块熵值
        
    Returns:
        EntropyResult: 熵值分析结果
    """
    try:
        if not data:
            return EntropyResult(
                data_size=0,
                entropy=0.0,
                entropy_per_byte=0.0,
                is_encrypted=False,
                is_compressed=False,
                is_text=False,
                entropy_distribution={},
                block_entropy=[],
                error_message="空数据"
            )
        
        # 计算数据大小
        data_size = len(data)
        
        # 计算字节频率
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        # 计算熵值
        entropy = 0.0
        for count in freq.values():
            probability = count / data_size
            entropy -= probability * math.log2(probability)
        
        # 计算每字节熵值
        entropy_per_byte = entropy / 8.0
        
        # 计算熵值分布
        entropy_distribution = {}
        for byte, count in freq.items():
            probability = count / data_size
            entropy_distribution[hex(byte)] = probability
        
        # 计算块熵值
        block_entropy = []
        for i in range(0, data_size, block_size):
            block = data[i:i+block_size]
            block_freq = {}
            for byte in block:
                block_freq[byte] = block_freq.get(byte, 0) + 1
            
            block_entropy_value = 0.0
            for count in block_freq.values():
                probability = count / len(block)
                block_entropy_value -= probability * math.log2(probability)
            
            block_entropy.append((i, block_entropy_value))
        
        # 判断数据类型
        is_encrypted = entropy > 7.0  # 高熵值通常表示加密数据
        is_compressed = 6.0 < entropy < 7.0  # 中等熵值通常表示压缩数据
        
        # 判断是否为文本
        text_bytes = sum(1 for byte in data if 32 <= byte <= 126 or byte in [9, 10, 13])
        text_ratio = text_bytes / data_size
        is_text = text_ratio > 0.8  # 如果80%以上的字节是可打印字符，则认为是文本
        
        return EntropyResult(
            data_size=data_size,
            entropy=entropy,
            entropy_per_byte=entropy_per_byte,
            is_encrypted=is_encrypted,
            is_compressed=is_compressed,
            is_text=is_text,
            entropy_distribution=entropy_distribution,
            block_entropy=block_entropy
        )
    
    except Exception as e:
        return EntropyResult(
            data_size=len(data) if data else 0,
            entropy=0.0,
            entropy_per_byte=0.0,
            is_encrypted=False,
            is_compressed=False,
            is_text=False,
            entropy_distribution={},
            block_entropy=[],
            error_message=str(e)
        )

def analyze_file_entropy(file_path: str, block_size: int = 1024) -> EntropyResult:
    """
    分析文件的熵值
    
    Args:
        file_path: 文件路径
        block_size: 块大小，用于计算块熵值
        
    Returns:
        EntropyResult: 熵值分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return EntropyResult(
                data_size=0,
                entropy=0.0,
                entropy_per_byte=0.0,
                is_encrypted=False,
                is_compressed=False,
                is_text=False,
                entropy_distribution={},
                block_entropy=[],
                error_message="文件不存在"
            )
        
        # 获取文件大小
        file_size = os.path.getsize(file_path)
        
        # 如果文件太大，只分析前1MB
        max_size = 1024 * 1024  # 1MB
        if file_size > max_size:
            with open(file_path, 'rb') as f:
                data = f.read(max_size)
        else:
            with open(file_path, 'rb') as f:
                data = f.read()
        
        # 计算熵值
        result = calculate_entropy(data, block_size)
        
        # 添加文件大小信息
        result.data_size = file_size
        
        return result
    
    except Exception as e:
        return EntropyResult(
            data_size=0,
            entropy=0.0,
            entropy_per_byte=0.0,
            is_encrypted=False,
            is_compressed=False,
            is_text=False,
            entropy_distribution={},
            block_entropy=[],
            error_message=str(e)
        )

def analyze_entropy_map(data: bytes, block_size: int = 1024, max_blocks: int = 100) -> Dict[str, Any]:
    """
    生成熵值热图数据
    
    Args:
        data: 要分析的数据
        block_size: 块大小
        max_blocks: 最大块数
        
    Returns:
        Dict[str, Any]: 熵值热图数据
    """
    try:
        if not data:
            return {
                "error": "空数据",
                "map": [],
                "min_entropy": 0.0,
                "max_entropy": 0.0,
                "avg_entropy": 0.0
            }
        
        # 计算块熵值
        block_entropy = []
        data_size = len(data)
        
        # 限制块数
        num_blocks = min(data_size // block_size, max_blocks)
        if num_blocks == 0:
            num_blocks = 1
        
        for i in range(num_blocks):
            start = i * block_size
            end = min(start + block_size, data_size)
            block = data[start:end]
            
            # 计算块熵值
            freq = {}
            for byte in block:
                freq[byte] = freq.get(byte, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                probability = count / len(block)
                entropy -= probability * math.log2(probability)
            
            block_entropy.append((start, entropy))
        
        # 计算统计信息
        entropies = [entropy for _, entropy in block_entropy]
        min_entropy = min(entropies) if entropies else 0.0
        max_entropy = max(entropies) if entropies else 0.0
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        # 生成热图数据
        entropy_map = []
        for offset, entropy in block_entropy:
            # 将熵值映射到0-1范围
            normalized_entropy = (entropy - min_entropy) / (max_entropy - min_entropy) if max_entropy > min_entropy else 0.5
            
            # 根据熵值确定颜色
            if entropy < 4.0:
                color = "green"  # 低熵值，可能是文本或未压缩数据
            elif entropy < 6.0:
                color = "yellow"  # 中等熵值，可能是压缩数据
            else:
                color = "red"  # 高熵值，可能是加密数据
            
            entropy_map.append({
                "offset": offset,
                "entropy": entropy,
                "normalized": normalized_entropy,
                "color": color
            })
        
        return {
            "map": entropy_map,
            "min_entropy": min_entropy,
            "max_entropy": max_entropy,
            "avg_entropy": avg_entropy
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "map": [],
            "min_entropy": 0.0,
            "max_entropy": 0.0,
            "avg_entropy": 0.0
        }

def detect_entropy_anomalies(data: bytes, block_size: int = 1024, threshold: float = 0.2) -> List[Dict[str, Any]]:
    """
    检测熵值异常
    
    Args:
        data: 要分析的数据
        block_size: 块大小
        threshold: 异常阈值
        
    Returns:
        List[Dict[str, Any]]: 异常列表
    """
    try:
        if not data:
            return []
        
        # 计算块熵值
        block_entropy = []
        data_size = len(data)
        
        for i in range(0, data_size, block_size):
            end = min(i + block_size, data_size)
            block = data[i:end]
            
            # 计算块熵值
            freq = {}
            for byte in block:
                freq[byte] = freq.get(byte, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                probability = count / len(block)
                entropy -= probability * math.log2(probability)
            
            block_entropy.append((i, entropy))
        
        # 计算统计信息
        entropies = [entropy for _, entropy in block_entropy]
        mean_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        std_entropy = np.std(entropies) if entropies else 0.0
        
        # 检测异常
        anomalies = []
        for i, (offset, entropy) in enumerate(block_entropy):
            # 计算z-score
            z_score = (entropy - mean_entropy) / std_entropy if std_entropy > 0 else 0
            
            # 如果z-score超过阈值，则认为是异常
            if abs(z_score) > threshold:
                anomaly_type = "high_entropy" if entropy > mean_entropy else "low_entropy"
                anomalies.append({
                    "offset": offset,
                    "entropy": entropy,
                    "z_score": z_score,
                    "type": anomaly_type,
                    "description": f"在偏移量 {offset} 处检测到{'高' if anomaly_type == 'high_entropy' else '低'}熵值异常 (z-score: {z_score:.2f})"
                })
        
        return anomalies
    
    except Exception as e:
        return [{"error": str(e)}]

def analyze_minio_file_entropy(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    block_size: int = 1024,
    max_size: int = 1024 * 1024  # 默认只分析前1MB
) -> EntropyResult:
    """
    直接从MinIO分析文件熵值，无需完全下载
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        block_size: 块大小，用于计算块熵值
        max_size: 最大分析大小，超过此大小将只分析前max_size字节
        
    Returns:
        EntropyResult: 熵值分析结果
    """
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            return EntropyResult(
                data_size=0,
                entropy=0.0,
                entropy_per_byte=0.0,
                is_encrypted=False,
                is_compressed=False,
                is_text=False,
                entropy_distribution={},
                block_entropy=[],
                error_message=f"无法获取MinIO对象信息: {str(e)}"
            )
        
        # 确定要分析的大小
        analyze_size = min(file_size, max_size)
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            return EntropyResult(
                data_size=file_size,
                entropy=0.0,
                entropy_per_byte=0.0,
                is_encrypted=False,
                is_compressed=False,
                is_text=False,
                entropy_distribution={},
                block_entropy=[],
                error_message=f"无法获取MinIO对象流: {str(e)}"
            )
        
        # 读取数据
        data = b""
        bytes_read = 0
        
        for chunk in data_stream.stream(block_size):
            data += chunk
            bytes_read += len(chunk)
            if bytes_read >= analyze_size:
                break
        
        # 计算熵值
        result = calculate_entropy(data, block_size)
        
        # 添加文件大小信息
        result.data_size = file_size
        
        return result
    
    except Exception as e:
        return EntropyResult(
            data_size=0,
            entropy=0.0,
            entropy_per_byte=0.0,
            is_encrypted=False,
            is_compressed=False,
            is_text=False,
            entropy_distribution={},
            block_entropy=[],
            error_message=str(e)
        )

def stream_entropy_analysis(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    block_size: int = 1024,
    max_blocks: int = 100
) -> Dict[str, Any]:
    """
    流式分析MinIO文件的熵值，生成熵值热图
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        block_size: 块大小
        max_blocks: 最大块数
        
    Returns:
        Dict[str, Any]: 熵值热图数据
    """
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            return {
                "error": f"无法获取MinIO对象信息: {str(e)}",
                "map": [],
                "min_entropy": 0.0,
                "max_entropy": 0.0,
                "avg_entropy": 0.0
            }
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            return {
                "error": f"无法获取MinIO对象流: {str(e)}",
                "map": [],
                "min_entropy": 0.0,
                "max_entropy": 0.0,
                "avg_entropy": 0.0
            }
        
        # 计算块熵值
        block_entropy = []
        bytes_processed = 0
        
        # 限制块数
        num_blocks = min(file_size // block_size, max_blocks)
        if num_blocks == 0:
            num_blocks = 1
        
        for i in range(num_blocks):
            # 读取一个块
            block = b""
            bytes_to_read = min(block_size, file_size - bytes_processed)
            
            if bytes_to_read <= 0:
                break
                
            for chunk in data_stream.stream(bytes_to_read):
                block += chunk
                if len(block) >= bytes_to_read:
                    break
            
            bytes_processed += len(block)
            
            # 计算块熵值
            freq = {}
            for byte in block:
                freq[byte] = freq.get(byte, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                probability = count / len(block)
                entropy -= probability * math.log2(probability)
            
            block_entropy.append((bytes_processed - len(block), entropy))
        
        # 计算统计信息
        entropies = [entropy for _, entropy in block_entropy]
        min_entropy = min(entropies) if entropies else 0.0
        max_entropy = max(entropies) if entropies else 0.0
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        
        # 生成热图数据
        entropy_map = []
        for offset, entropy in block_entropy:
            # 将熵值映射到0-1范围
            normalized_entropy = (entropy - min_entropy) / (max_entropy - min_entropy) if max_entropy > min_entropy else 0.5
            
            # 根据熵值确定颜色
            if entropy < 4.0:
                color = "green"  # 低熵值，可能是文本或未压缩数据
            elif entropy < 6.0:
                color = "yellow"  # 中等熵值，可能是压缩数据
            else:
                color = "red"  # 高熵值，可能是加密数据
            
            entropy_map.append({
                "offset": offset,
                "entropy": entropy,
                "normalized": normalized_entropy,
                "color": color
            })
        
        return {
            "map": entropy_map,
            "min_entropy": min_entropy,
            "max_entropy": max_entropy,
            "avg_entropy": avg_entropy
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "map": [],
            "min_entropy": 0.0,
            "max_entropy": 0.0,
            "avg_entropy": 0.0
        }

def stream_detect_entropy_anomalies(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    block_size: int = 1024,
    threshold: float = 0.2,
    max_blocks: int = 100
) -> List[Dict[str, Any]]:
    """
    流式检测MinIO文件的熵值异常
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        block_size: 块大小
        threshold: 异常阈值
        max_blocks: 最大块数
        
    Returns:
        List[Dict[str, Any]]: 异常列表
    """
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            return [{"error": f"无法获取MinIO对象信息: {str(e)}"}]
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            return [{"error": f"无法获取MinIO对象流: {str(e)}"}]
        
        # 计算块熵值
        block_entropy = []
        bytes_processed = 0
        
        # 限制块数
        num_blocks = min(file_size // block_size, max_blocks)
        if num_blocks == 0:
            num_blocks = 1
        
        for i in range(num_blocks):
            # 读取一个块
            block = b""
            bytes_to_read = min(block_size, file_size - bytes_processed)
            
            if bytes_to_read <= 0:
                break
                
            for chunk in data_stream.stream(bytes_to_read):
                block += chunk
                if len(block) >= bytes_to_read:
                    break
            
            bytes_processed += len(block)
            
            # 计算块熵值
            freq = {}
            for byte in block:
                freq[byte] = freq.get(byte, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                probability = count / len(block)
                entropy -= probability * math.log2(probability)
            
            block_entropy.append((bytes_processed - len(block), entropy))
        
        # 计算统计信息
        entropies = [entropy for _, entropy in block_entropy]
        mean_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        std_entropy = np.std(entropies) if entropies else 0.0
        
        # 检测异常
        anomalies = []
        for i, (offset, entropy) in enumerate(block_entropy):
            # 计算z-score
            z_score = (entropy - mean_entropy) / std_entropy if std_entropy > 0 else 0
            
            # 如果z-score超过阈值，则认为是异常
            if abs(z_score) > threshold:
                anomaly_type = "high_entropy" if entropy > mean_entropy else "low_entropy"
                anomalies.append({
                    "offset": offset,
                    "entropy": entropy,
                    "z_score": z_score,
                    "type": anomaly_type,
                    "description": f"在偏移量 {offset} 处检测到{'高' if anomaly_type == 'high_entropy' else '低'}熵值异常 (z-score: {z_score:.2f})"
                })
        
        return anomalies
    
    except Exception as e:
        return [{"error": str(e)}]

def stream_entropy_analysis_generator(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    block_size: int = 1024,
    max_blocks: int = 100
) -> Generator[Dict[str, Any], None, None]:
    """
    流式分析MinIO文件的熵值，生成器版本，实时返回分析结果
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        block_size: 块大小
        max_blocks: 最大块数
        
    Yields:
        Dict[str, Any]: 实时熵值分析结果
    """
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            yield {
                "error": f"无法获取MinIO对象信息: {str(e)}",
                "progress": 0,
                "current_block": 0,
                "total_blocks": 0,
                "entropy": 0.0,
                "is_encrypted": False,
                "is_compressed": False
            }
            return
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            yield {
                "error": f"无法获取MinIO对象流: {str(e)}",
                "progress": 0,
                "current_block": 0,
                "total_blocks": 0,
                "entropy": 0.0,
                "is_encrypted": False,
                "is_compressed": False
            }
            return
        
        # 限制块数
        num_blocks = min(file_size // block_size, max_blocks)
        if num_blocks == 0:
            num_blocks = 1
        
        # 计算块熵值
        bytes_processed = 0
        all_entropies = []
        
        for i in range(num_blocks):
            # 读取一个块
            block = b""
            bytes_to_read = min(block_size, file_size - bytes_processed)
            
            if bytes_to_read <= 0:
                break
                
            for chunk in data_stream.stream(bytes_to_read):
                block += chunk
                if len(block) >= bytes_to_read:
                    break
            
            bytes_processed += len(block)
            
            # 计算块熵值
            freq = {}
            for byte in block:
                freq[byte] = freq.get(byte, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                probability = count / len(block)
                entropy -= probability * math.log2(probability)
            
            all_entropies.append(entropy)
            
            # 计算当前进度
            progress = min(100, (bytes_processed / file_size) * 100)
            
            # 判断数据类型
            is_encrypted = entropy > 7.0
            is_compressed = 6.0 < entropy < 7.0
            
            # 生成实时结果
            yield {
                "progress": progress,
                "current_block": i + 1,
                "total_blocks": num_blocks,
                "offset": bytes_processed - len(block),
                "entropy": entropy,
                "is_encrypted": is_encrypted,
                "is_compressed": is_compressed,
                "block_size": len(block)
            }
        
        # 生成最终结果
        if all_entropies:
            avg_entropy = sum(all_entropies) / len(all_entropies)
            min_entropy = min(all_entropies)
            max_entropy = max(all_entropies)
            
            yield {
                "progress": 100,
                "current_block": num_blocks,
                "total_blocks": num_blocks,
                "final_result": True,
                "avg_entropy": avg_entropy,
                "min_entropy": min_entropy,
                "max_entropy": max_entropy,
                "is_likely_encrypted": avg_entropy > 7.0,
                "is_likely_compressed": 6.0 < avg_entropy < 7.0
            }
    
    except Exception as e:
        yield {
            "error": str(e),
            "progress": 0,
            "current_block": 0,
            "total_blocks": 0,
            "entropy": 0.0,
            "is_encrypted": False,
            "is_compressed": False
        } 