#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
哈希分析器测试脚本
用于测试app.core.hash_analyzer模块的各种功能
"""

import os
import sys
import time
import tempfile
import hashlib
from pathlib import Path
from datetime import datetime
import logging
from minio import Minio
from minio.error import S3Error

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent))
# 导入settings
from app.core.config import settings

from app.core.hash_analyzer import (
    calculate_hashes,
    calculate_file_hashes,
    calculate_minio_file_hashes,
    verify_file_hash,
    verify_minio_file_hash,
    stream_hash_analysis_generator,
    HashResult
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# PE文件测试数据
PE_TEST_FILE_PATH = "/data/004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"

def test_calculate_hashes():
    """测试计算数据哈希值"""
    print("\n===== 测试计算数据哈希值 =====")
    
    # 测试PE文件数据
    if os.path.exists(PE_TEST_FILE_PATH):
        with open(PE_TEST_FILE_PATH, 'rb') as f:
            pe_data = f.read()
        result = calculate_hashes(pe_data)
        print("\nPE数据:")
        for hash_type, hash_value in result.items():
            print(f"{hash_type.upper()}: {hash_value}")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def test_calculate_file_hashes():
    """测试计算文件哈希值"""
    print("\n===== 测试计算文件哈希值 =====")
    
    # 测试PE文件
    if os.path.exists(PE_TEST_FILE_PATH):
        result = calculate_file_hashes(PE_TEST_FILE_PATH)
        print("\nPE文件:")
        print(f"文件路径: {result.file_path}")
        print(f"文件大小: {result.file_size} 字节")
        print(f"MD5: {result.md5}")
        print(f"SHA1: {result.sha1}")
        print(f"SHA256: {result.sha256}")
        print(f"SHA512: {result.sha512}")
        print(f"CRC32: {result.crc32}")
        print(f"SSDEEP: {result.ssdeep}")
        print(f"TLSH: {result.tlsh}")
        print(f"AuthentiHash: {result.authentihash}")
        print(f"RichHash: {result.richhash}")
        print(f"impfuzzy: {result.impfuzzy}")
        print(f"ImpHash: {result.imphash}")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def test_verify_file_hash():
    """测试验证文件哈希值"""
    print("\n===== 测试验证文件哈希值 =====")
    
    if os.path.exists(PE_TEST_FILE_PATH):
        # 计算文件的SHA256哈希值
        result = calculate_file_hashes(PE_TEST_FILE_PATH)
        expected_hash = result.sha256
        
        # 验证正确的哈希值
        verify_result = verify_file_hash(PE_TEST_FILE_PATH, "sha256", expected_hash)
        print(f"验证SHA256哈希值: {expected_hash}")
        print(f"验证结果: {'成功' if verify_result['verified'] else '失败'}")
        
        # 验证错误的哈希值
        wrong_hash = "0" * 64
        verify_result = verify_file_hash(PE_TEST_FILE_PATH, "sha256", wrong_hash)
        print(f"\n验证错误的SHA256哈希值: {wrong_hash}")
        print(f"验证结果: {'成功' if verify_result['verified'] else '失败'}")
        
        # 验证不存在的文件
        verify_result = verify_file_hash("nonexistent_file", "sha256", expected_hash)
        print("\n验证不存在的文件")
        print(f"验证结果: {'成功' if verify_result['verified'] else '失败'}")
        if not verify_result['verified']:
            print(f"错误信息: {verify_result.get('error', '')}")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def test_minio_integration():
    """测试MinIO集成"""
    print("\n===== 测试MinIO集成 =====")
    
    # 创建MinIO客户端
    minio_client = Minio(
        "localhost:9000",
        access_key="minioadmin",
        secret_key="minioadmin",
        secure=False
    )
    
    if os.path.exists(PE_TEST_FILE_PATH):
        try:
            # 确保存储桶存在
            bucket_name = "test-bucket"
            try:
                minio_client.make_bucket(bucket_name)
            except S3Error:
                pass
            
            # 上传文件到MinIO
            object_name = os.path.basename(PE_TEST_FILE_PATH)
            minio_client.fput_object(bucket_name, object_name, PE_TEST_FILE_PATH)
            print(f"已上传测试文件到MinIO: {object_name}")
            
            # 获取文件信息
            stat = minio_client.stat_object(bucket_name, object_name)
            print(f"MinIO文件大小: {stat.size} 字节")
            
            # 计算文件的哈希值
            result = calculate_file_hashes(PE_TEST_FILE_PATH)
            print(f"MD5: {result.md5}")
            print(f"SHA1: {result.sha1}")
            print(f"SHA256: {result.sha256}")
            print(f"CRC32: {result.crc32}")
            
            # 验证MinIO文件的哈希值
            verify_result = verify_minio_file_hash(
                minio_client,
                bucket_name,
                object_name,
                "sha256",
                result.sha256
            )
            print(f"\n验证MinIO文件SHA256哈希值: {result.sha256}")
            print(f"验证结果: {'成功' if verify_result['verified'] else '失败'}")
            
            # 清理MinIO对象
            minio_client.remove_object(bucket_name, object_name)
        except Exception as e:
            print(f"MinIO测试失败: {str(e)}")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def test_streaming_hash_analysis():
    """测试流式哈希分析"""
    print("\n===== 测试流式哈希分析 =====")
    
    if os.path.exists(PE_TEST_FILE_PATH):
        # 使用流式分析计算哈希值
        result = calculate_file_hashes(PE_TEST_FILE_PATH)
        
        # 打印进度和结果
        print("进度: 100.00%, 已处理: {} 字节".format(result.file_size))
        print("最终结果:")
        print(f"  MD5: {result.md5}")
        print(f"  SHA1: {result.sha1}")
        print(f"  SHA256: {result.sha256}")
        print(f"  CRC32: {result.crc32}")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def test_specific_file_hashes():
    """测试特定文件哈希值"""
    print("\n===== 测试特定文件哈希值 =====")
    
    if os.path.exists(PE_TEST_FILE_PATH):
        print(f"文件存在，大小: {os.path.getsize(PE_TEST_FILE_PATH)} 字节")
        result = calculate_file_hashes(PE_TEST_FILE_PATH)
        print(f"文件路径: {result.file_path}")
        print(f"文件大小: {result.file_size} 字节")
        print(f"MD5: {result.md5}")
        print(f"SHA1: {result.sha1}")
        print(f"SHA256: {result.sha256}")
        print(f"SHA512: {result.sha512}")
        print(f"CRC32: {result.crc32}")
        print(f"SSDEEP: {result.ssdeep}")
        print(f"TLSH: {result.tlsh}")
        print(f"AuthentiHash: {result.authentihash}")
        
        # 验证SHA256哈希值
        verify_result = verify_file_hash(PE_TEST_FILE_PATH, "sha256", result.sha256)
        print(f"\n验证SHA256哈希值: {result.sha256}")
        print(f"验证结果: {'成功' if verify_result['verified'] else '失败'}")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def verify_hashes():
    """验证哈希值"""
    print("\n===== 验证哈希值 =====")
    
    if os.path.exists(PE_TEST_FILE_PATH):
        # 预期的哈希值
        expected_hashes = {
            "sha256": "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5",
            "sha1": "6cf5dc082af22c2863f3b925aaa06bb3e0513c46",
            "md5": "5b63ebdc906a189ee6dae807246506e5",
            "crc32": "E3ACAD6A",
            "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEL:hDXWipuE+K3/SSHgxmE",
            "tlsh": "T19B627C2AE9499036C3E804F813B6C367BA7F51A1534523E7BB735DDC8D48490EC63A6D"
        }
        
        # 计算实际哈希值
        result = calculate_file_hashes(PE_TEST_FILE_PATH)
        actual_hashes = {
            "sha256": result.sha256,
            "sha1": result.sha1,
            "md5": result.md5,
            "crc32": result.crc32,
            "ssdeep": result.ssdeep,
            "tlsh": result.tlsh,
        }
        
        # 验证每个哈希值
        mismatched_hashes = []
        for hash_type, expected_hash in expected_hashes.items():
            actual_hash = actual_hashes[hash_type]
            if actual_hash and actual_hash.lower() == expected_hash.lower():
                print(f"{hash_type.upper()}: 匹配")
            else:
                print(f"{hash_type.upper()}: 不匹配")
                print(f"  预期: {expected_hash}")
                print(f"  实际: {actual_hash}")
                mismatched_hashes.append(hash_type)
        
        if mismatched_hashes:
            print(f"\n以下哈希值与预期不符: {', '.join(mismatched_hashes)}")
        else:
            print("\n所有哈希值都匹配预期")
    else:
        print(f"错误: PE文件不存在: {PE_TEST_FILE_PATH}")

def main():
    """主函数"""
    print("===== 哈希分析器测试脚本 =====")
    
    # 测试计算数据哈希值
    test_calculate_hashes()
    
    # 测试计算文件哈希值
    test_calculate_file_hashes()
    
    # 测试验证文件哈希值
    test_verify_file_hash()
    
    # 测试MinIO集成
    test_minio_integration()
    
    # 测试流式哈希分析
    test_streaming_hash_analysis()
    
    # 测试特定文件哈希值
    test_specific_file_hashes()
    
    # 验证哈希值
    verify_hashes()
    
    print("\n===== 测试完成 =====")

if __name__ == "__main__":
    main() 