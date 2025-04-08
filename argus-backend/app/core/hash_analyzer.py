from typing import Dict, List, Optional, Any, Tuple, Generator, Iterator, Union
from pydantic import BaseModel
import os
import hashlib
import io
import zlib
import re
import struct
import logging
from datetime import datetime
from minio import Minio
from minio.error import S3Error
import tempfile

# 创建logger对象
logger = logging.getLogger(__name__)

# 尝试导入可选依赖
try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except ImportError:
    SSDEEP_AVAILABLE = False

try:
    import tlsh
    TLSH_AVAILABLE = True
except ImportError:
    TLSH_AVAILABLE = False

class HashResult(BaseModel):
    """哈希分析结果"""
    file_size: int
    md5: str
    sha1: str
    sha256: str
    sha512: str
    crc32: str
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    error_message: Optional[str] = None

def calculate_crc32(data: bytes) -> str:
    """
    计算数据的CRC32哈希值
    
    Args:
        data: 要计算哈希的数据
        
    Returns:
        str: CRC32哈希值（大写十六进制）
    """
    return format(zlib.crc32(data) & 0xFFFFFFFF, '08X')

def calculate_ssdeep(data: bytes) -> Optional[str]:
    """
    计算数据的SSDEEP哈希值
    
    Args:
        data: 要计算哈希的数据
        
    Returns:
        Optional[str]: SSDEEP哈希值，如果ssdeep库不可用则返回None
    """
    if not SSDEEP_AVAILABLE:
        return None
    
    try:
        return ssdeep.hash(data)
    except Exception as e:
        print(f"SSDEEP计算错误: {e}")
        return None

def calculate_tlsh(data: bytes) -> Optional[str]:
    """
    计算数据的TLSH哈希值
    
    Args:
        data: 要计算哈希的数据
        
    Returns:
        Optional[str]: TLSH哈希值，如果tlsh库不可用则返回None
    """
    if not TLSH_AVAILABLE:
        return None
    
    try:
        h3 = tlsh.hash(data)
        return h3
    except Exception as e:
        print(f"TLSH计算错误: {e}")
        return None

def calculate_hashes(data: bytes) -> Dict[str, str]:
    """
    计算数据的多种哈希值
    
    Args:
        data: 要计算哈希的数据
        
    Returns:
        Dict[str, str]: 各种哈希算法的结果
    """
    try:
        if not data:
            return {
                "md5": "",
                "sha1": "",
                "sha256": "",
                "sha512": "",
                "crc32": "",
                "ssdeep": None,
                "tlsh": None
            }
        
        # 计算各种哈希值
        md5_hash = hashlib.md5(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha512_hash = hashlib.sha512(data).hexdigest()
        crc32_hash = calculate_crc32(data)
        ssdeep_hash = calculate_ssdeep(data)
        tlsh_hash = calculate_tlsh(data)
        
        return {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash,
            "sha512": sha512_hash,
            "crc32": crc32_hash,
            "ssdeep": ssdeep_hash,
            "tlsh": tlsh_hash
        }
    
    except Exception as e:
        return {
            "md5": "",
            "sha1": "",
            "sha256": "",
            "sha512": "",
            "crc32": "",
            "ssdeep": None,
            "tlsh": None,
            "error": str(e)
        }

def calculate_file_hashes(file_path: str, max_size: int = 1024 * 1024 * 100) -> HashResult:
    """
    计算文件的多种哈希值
    
    Args:
        file_path: 文件路径
        max_size: 最大计算大小，超过此大小将只计算前max_size字节
        
    Returns:
        HashResult: 哈希分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return HashResult(
                file_size=0,
                md5="",
                sha1="",
                sha256="",
                sha512="",
                crc32="",
                ssdeep=None,
                tlsh=None,
                error_message="文件不存在"
            )
        
        # 获取文件大小
        file_size = os.path.getsize(file_path)
        
        # 确定要计算的大小
        calculate_size = min(file_size, max_size)
        
        # 初始化哈希对象
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        sha256_obj = hashlib.sha256()
        sha512_obj = hashlib.sha512()
        
        # 用于计算CRC32的数据
        crc32_data = bytearray()
        
        # 用于计算SSDEEP和TLSH的数据
        ssdeep_data = bytearray()
        tlsh_data = bytearray()
        
        # 分块读取文件并更新哈希对象
        bytes_read = 0
        with open(file_path, 'rb') as f:
            while bytes_read < calculate_size:
                chunk = f.read(min(8192, calculate_size - bytes_read))
                if not chunk:
                    break
                
                md5_obj.update(chunk)
                sha1_obj.update(chunk)
                sha256_obj.update(chunk)
                sha512_obj.update(chunk)
                
                # 收集数据用于其他哈希计算
                crc32_data.extend(chunk)
                ssdeep_data.extend(chunk)
                tlsh_data.extend(chunk)
                
                bytes_read += len(chunk)
        
        # 计算最终哈希值
        return HashResult(
            file_size=file_size,
            md5=md5_obj.hexdigest(),
            sha1=sha1_obj.hexdigest(),
            sha256=sha256_obj.hexdigest(),
            sha512=sha512_obj.hexdigest(),
            crc32=calculate_crc32(bytes(crc32_data)),
            ssdeep=calculate_ssdeep(bytes(ssdeep_data)),
            tlsh=calculate_tlsh(bytes(tlsh_data))
        )
    
    except Exception as e:
        return HashResult(
            file_size=0,
            md5="",
            sha1="",
            sha256="",
            sha512="",
            crc32="",
            ssdeep=None,
            tlsh=None,
            error_message=str(e)
        )

def calculate_minio_file_hashes(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    max_size: int = 1024 * 1024 * 100  # 默认最大100MB
) -> HashResult:
    """
    直接从MinIO计算文件哈希值，无需完全下载
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        max_size: 最大计算大小，超过此大小将只计算前max_size字节
        
    Returns:
        HashResult: 哈希分析结果
    """
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            return HashResult(
                file_size=0,
                md5="",
                sha1="",
                sha256="",
                sha512="",
                crc32="",
                ssdeep=None,
                tlsh=None,
                error_message=f"无法获取MinIO对象信息: {str(e)}"
            )
        
        # 确定要计算的大小
        calculate_size = min(file_size, max_size)
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            return HashResult(
                file_size=file_size,
                md5="",
                sha1="",
                sha256="",
                sha512="",
                crc32="",
                ssdeep=None,
                tlsh=None,
                error_message=f"无法获取MinIO对象流: {str(e)}"
            )
        
        # 初始化哈希对象
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        sha256_obj = hashlib.sha256()
        sha512_obj = hashlib.sha512()
        
        # 用于计算CRC32的数据
        crc32_data = bytearray()
        
        # 用于计算SSDEEP和TLSH的数据
        ssdeep_data = bytearray()
        tlsh_data = bytearray()
        
        # 分块读取数据并更新哈希对象
        bytes_read = 0
        for chunk in data_stream.stream(8192):
            if bytes_read >= calculate_size:
                break
            
            # 如果最后一个块超出计算大小，则截断
            if bytes_read + len(chunk) > calculate_size:
                chunk = chunk[:calculate_size - bytes_read]
            
            md5_obj.update(chunk)
            sha1_obj.update(chunk)
            sha256_obj.update(chunk)
            sha512_obj.update(chunk)
            
            # 收集数据用于其他哈希计算
            crc32_data.extend(chunk)
            ssdeep_data.extend(chunk)
            tlsh_data.extend(chunk)
            bytes_read += len(chunk)
        
        # 计算最终哈希值
        return HashResult(
            file_size=file_size,
            md5=md5_obj.hexdigest(),
            sha1=sha1_obj.hexdigest(),
            sha256=sha256_obj.hexdigest(),
            sha512=sha512_obj.hexdigest(),
            crc32=calculate_crc32(bytes(crc32_data)),
            ssdeep=calculate_ssdeep(bytes(ssdeep_data)),
            tlsh=calculate_tlsh(bytes(tlsh_data)),
        )
    
    except Exception as e:
        return HashResult(
            file_size=0,
            md5="",
            sha1="",
            sha256="",
            sha512="",
            crc32="",
            ssdeep=None,
            tlsh=None,
            error_message=str(e)
        )

def stream_hash_analysis_generator(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    chunk_size: int = 8192,
    max_size: int = 1024 * 1024 * 100  # 默认最大100MB
) -> Generator[Dict[str, Any], None, None]:
    """
    流式分析MinIO文件的哈希值，生成器版本，实时返回分析结果
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        chunk_size: 块大小
        max_size: 最大计算大小
        
    Yields:
        Dict[str, Any]: 实时哈希分析结果
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
                "bytes_processed": 0,
                "total_bytes": 0,
                "md5": "",
                "sha1": "",
                "sha256": "",
                "crc32": ""
            }
            return
        
        # 确定要计算的大小
        calculate_size = min(file_size, max_size)
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            yield {
                "error": f"无法获取MinIO对象流: {str(e)}",
                "progress": 0,
                "bytes_processed": 0,
                "total_bytes": file_size,
                "md5": "",
                "sha1": "",
                "sha256": "",
                "crc32": ""
            }
            return
        
        # 初始化哈希对象
        md5_obj = hashlib.md5()
        sha1_obj = hashlib.sha1()
        sha256_obj = hashlib.sha256()
        
        # 用于计算CRC32的数据
        crc32_data = bytearray()
        
        # 分块读取数据并更新哈希对象
        bytes_processed = 0
        last_progress = 0
        
        for chunk in data_stream.stream(chunk_size):
            if bytes_processed >= calculate_size:
                break
            
            # 如果最后一个块超出计算大小，则截断
            if bytes_processed + len(chunk) > calculate_size:
                chunk = chunk[:calculate_size - bytes_processed]
            
            md5_obj.update(chunk)
            sha1_obj.update(chunk)
            sha256_obj.update(chunk)
            crc32_data.extend(chunk)
            
            bytes_processed += len(chunk)
            
            # 计算当前进度
            progress = min(100, (bytes_processed / calculate_size) * 100)
            
            # 每处理5%或至少处理了1MB时返回一次进度
            if progress - last_progress >= 5 or bytes_processed % (1024 * 1024) < chunk_size:
                last_progress = progress
                yield {
                    "progress": progress,
                    "bytes_processed": bytes_processed,
                    "total_bytes": calculate_size,
                    "md5": md5_obj.hexdigest(),
                    "sha1": sha1_obj.hexdigest(),
                    "sha256": sha256_obj.hexdigest(),
                    "crc32": calculate_crc32(bytes(crc32_data))
                }
        
        # 生成最终结果
        yield {
            "progress": 100,
            "bytes_processed": bytes_processed,
            "total_bytes": calculate_size,
            "final_result": True,
            "md5": md5_obj.hexdigest(),
            "sha1": sha1_obj.hexdigest(),
            "sha256": sha256_obj.hexdigest(),
            "crc32": calculate_crc32(bytes(crc32_data))
        }
    
    except Exception as e:
        yield {
            "error": str(e),
            "progress": 0,
            "bytes_processed": 0,
            "total_bytes": 0,
            "md5": "",
            "sha1": "",
            "sha256": "",
            "crc32": ""
        }

def verify_file_hash(file_path: str, hash_type: str, expected_hash: str) -> Dict[str, Any]:
    """
    验证文件的哈希值是否匹配预期
    
    Args:
        file_path: 文件路径
        hash_type: 哈希类型 (md5, sha1, sha256, sha512, crc32, ssdeep, tlsh)
        expected_hash: 预期的哈希值
        
    Returns:
        Dict[str, Any]: 验证结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return {
                "verified": False,
                "error": "文件不存在",
                "calculated_hash": "",
                "expected_hash": expected_hash,
                "hash_type": hash_type
            }
        
        # 获取文件大小
        file_size = os.path.getsize(file_path)
        
        # 读取文件数据
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # 计算哈希值
        if hash_type.lower() == "md5":
            calculated_hash = hashlib.md5(data).hexdigest()
        elif hash_type.lower() == "sha1":
            calculated_hash = hashlib.sha1(data).hexdigest()
        elif hash_type.lower() == "sha256":
            calculated_hash = hashlib.sha256(data).hexdigest()
        elif hash_type.lower() == "sha512":
            calculated_hash = hashlib.sha512(data).hexdigest()
        elif hash_type.lower() == "crc32":
            calculated_hash = calculate_crc32(data)
        elif hash_type.lower() == "ssdeep":
            calculated_hash = calculate_ssdeep(data)
            if calculated_hash is None:
                return {
                    "verified": False,
                    "error": "SSDEEP库不可用",
                    "calculated_hash": "",
                    "expected_hash": expected_hash,
                    "hash_type": hash_type
                }
        elif hash_type.lower() == "tlsh":
            calculated_hash = calculate_tlsh(data)
            if calculated_hash is None:
                return {
                    "verified": False,
                    "error": "TLSH库不可用",
                    "calculated_hash": "",
                    "expected_hash": expected_hash,
                    "hash_type": hash_type
                }
        else:
            return {
                "verified": False,
                "error": f"不支持的哈希类型: {hash_type}",
                "calculated_hash": "",
                "expected_hash": expected_hash,
                "hash_type": hash_type
            }
        
        # 验证哈希值
        verified = calculated_hash.lower() == expected_hash.lower()
        
        return {
            "verified": verified,
            "calculated_hash": calculated_hash,
            "expected_hash": expected_hash,
            "hash_type": hash_type,
            "file_size": file_size
        }
    
    except Exception as e:
        return {
            "verified": False,
            "error": str(e),
            "calculated_hash": "",
            "expected_hash": expected_hash,
            "hash_type": hash_type
        }

def verify_minio_file_hash(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    hash_type: str,
    expected_hash: str,
    max_size: int = 1024 * 1024 * 100  # 默认最大100MB
) -> Dict[str, Any]:
    """
    验证MinIO文件的哈希值是否匹配预期
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        hash_type: 哈希类型 (md5, sha1, sha256, sha512, crc32, ssdeep, tlsh)
        expected_hash: 预期的哈希值
        max_size: 最大计算大小，超过此大小将只计算前max_size字节
        
    Returns:
        Dict[str, Any]: 验证结果
    """
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            return {
                "verified": False,
                "error": f"无法获取MinIO对象信息: {str(e)}",
                "calculated_hash": "",
                "expected_hash": expected_hash,
                "hash_type": hash_type
            }
        
        # 确定要计算的大小
        calculate_size = min(file_size, max_size)
        
        # 获取对象流
        try:
            data_stream = minio_client.get_object(bucket_name, object_name)
        except S3Error as e:
            return {
                "verified": False,
                "error": f"无法获取MinIO对象流: {str(e)}",
                "calculated_hash": "",
                "expected_hash": expected_hash,
                "hash_type": hash_type
            }
        
        # 收集数据
        data = bytearray()
        bytes_processed = 0
        
        for chunk in data_stream.stream(8192):
            if bytes_processed >= calculate_size:
                break
            
            # 如果最后一个块超出计算大小，则截断
            if bytes_processed + len(chunk) > calculate_size:
                chunk = chunk[:calculate_size - bytes_processed]
            
            data.extend(chunk)
            bytes_processed += len(chunk)
        
        # 计算哈希值
        if hash_type.lower() == "md5":
            calculated_hash = hashlib.md5(bytes(data)).hexdigest()
        elif hash_type.lower() == "sha1":
            calculated_hash = hashlib.sha1(bytes(data)).hexdigest()
        elif hash_type.lower() == "sha256":
            calculated_hash = hashlib.sha256(bytes(data)).hexdigest()
        elif hash_type.lower() == "sha512":
            calculated_hash = hashlib.sha512(bytes(data)).hexdigest()
        elif hash_type.lower() == "crc32":
            calculated_hash = calculate_crc32(bytes(data))
        elif hash_type.lower() == "ssdeep":
            calculated_hash = calculate_ssdeep(bytes(data))
            if calculated_hash is None:
                return {
                    "verified": False,
                    "error": "SSDEEP库不可用",
                    "calculated_hash": "",
                    "expected_hash": expected_hash,
                    "hash_type": hash_type
                }
        elif hash_type.lower() == "tlsh":
            calculated_hash = calculate_tlsh(bytes(data))
            if calculated_hash is None:
                return {
                    "verified": False,
                    "error": "TLSH库不可用",
                    "calculated_hash": "",
                    "expected_hash": expected_hash,
                    "hash_type": hash_type
                }
        else:
            return {
                "verified": False,
                "error": f"不支持的哈希类型: {hash_type}",
                "calculated_hash": "",
                "expected_hash": expected_hash,
                "hash_type": hash_type
            }
        
        # 验证哈希值
        verified = calculated_hash.lower() == expected_hash.lower()
        
        return {
            "verified": verified,
            "calculated_hash": calculated_hash,
            "expected_hash": expected_hash,
            "hash_type": hash_type,
            "file_size": file_size,
            "bytes_processed": bytes_processed
        }
    
    except Exception as e:
        return {
            "verified": False,
            "error": str(e),
            "calculated_hash": "",
            "expected_hash": expected_hash,
            "hash_type": hash_type
        } 

if __name__ == "__main__":
    # 测试calculate_pehashng
    file_path = "argus-backend/tests/data/samples/malware/004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"
    hash_result = calculate_file_hashes(file_path)
    print(f"peHashNG: {hash_result}")
    
    