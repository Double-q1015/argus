import os
import sys
import pytest
import tempfile
from pathlib import Path
from minio import Minio
from unittest.mock import patch
from app.core.config import settings

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from app.core.exiftool_analyzer import convert_permissions, perform_exiftool_analysis, _analyze_file, ExifToolMetadata
from app.core.exiftool_analyzer import (
    ExifToolError,
    FileNotFoundError
)

# 测试 convert_permissions 函数
def test_convert_permissions():
    # 测试普通文件
    assert convert_permissions(100644) == "-rw-r--r--"
    assert convert_permissions(100755) == "-rwxr-xr-x"
    
    # 测试目录
    assert convert_permissions(400755) == "drwxr-xr-x"
    
    # 测试设备文件
    assert convert_permissions(200644) == "crw-r--r--"
    assert convert_permissions(600644) == "brw-r--r--"
    
    # 测试未知类型
    assert convert_permissions(300644) == "-rw-r--r--"

# 测试 perform_exiftool_analysis 函数
@pytest.mark.asyncio
async def test_perform_exiftool_analysis_file_not_found():
    non_existent_file = "/path/to/non/existent/file.jpg"
    
    with pytest.raises(FileNotFoundError) as exc_info:
        await perform_exiftool_analysis(non_existent_file)
    assert "File not found" in str(exc_info.value)

@pytest.mark.asyncio
async def test_perform_exiftool_analysis_success():
    """测试成功的 EXIFTool 分析"""
    # 创建临时文件并写入测试数据
    with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_file:
        # 写入一些基本的 JPEG 文件头数据
        temp_file.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xDB\x00C\x00')
        temp_file.flush()
        temp_file_path = temp_file.name

    try:
        # 确保文件存在
        assert os.path.exists(temp_file_path)
        
        # 模拟 ExifTool 的输出
        mock_output = {
            "ExifToolVersion": "12.30",
            "FileSize": 1024,
            "FileModifyDate": "2023:01:01 12:00:00",
            "FileAccessDate": "2023:01:01 12:00:00",
            "FileInodeChangeDate": "2023:01:01 12:00:00",
            "FilePermissions": 100644,
            "FilePermissionsStr": "-rw-r--r--",
            "FileType": "JPEG",
            "FileTypeExtension": "jpg",
            "MIMEType": "image/jpeg",
            "MachineType": "0x14c",
            "MachineTypeDescription": "Intel 386 or later processors and compatible processors",
            "TimeStamp": "2023:01:01 12:00:00",
            "ImageFileCharacteristics": 33,
            "ImageFileCharacteristicsDescription": ["Executable", "32-bit"],
            "PEType": 2,
            "PETypeDescription": "PE32",
            "LinkerVersion": "14",
            "CodeSize": 4096,
            "InitializedDataSize": 1024,
            "UninitializedDataSize": 0,
            "EntryPoint": "0x1000",
            "OSVersion": "6.0",
            "ImageVersion": "6.0",
            "SubsystemVersion": "6.0",
            "Subsystem": 2,
            "SubsystemDescription": "Windows GUI"
        }
        
        with patch('app.core.exiftool_analyzer._analyze_file', return_value=mock_output):
            result = await perform_exiftool_analysis(file_path=temp_file_path)
            
            # 验证结果
            assert result is not None
            assert result.exiftool_version == "12.30"
            assert result.file_size == 1024
            assert result.file_type == "JPEG"
            assert result.file_type_extension == "jpg"
            assert result.mime_type == "image/jpeg"
            assert result.machine_type == "0x14c"
            assert result.entry_point == "0x1000"
            assert result.file_permissions_str == "-rw-r--r--"
            
    finally:
        # 清理临时文件
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

@pytest.mark.asyncio
async def test_perform_exiftool_analysis_error():
    """测试 EXIFTool 分析错误处理"""
    # 创建临时文件并写入无效数据
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as temp_file:
        temp_file.write(b"Invalid file content")
        temp_file.flush()
        temp_file_path = temp_file.name

    try:
        # 确保文件存在
        assert os.path.exists(temp_file_path)
        
        # 模拟 ExifTool 抛出错误
        with patch('app.core.exiftool_analyzer._analyze_file', side_effect=ExifToolError("模拟的 ExifTool 错误")):
            with pytest.raises(ExifToolError) as exc_info:
                await perform_exiftool_analysis(file_path=temp_file_path)
            assert "模拟的 ExifTool 错误" in str(exc_info.value)
            
    finally:
        # 清理临时文件
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)

@pytest.mark.asyncio
async def test_analyze_file_with_real_file():
    """使用真实文件测试 _analyze_file 函数"""
    # 使用真实样本文件
    file_path = "tests/data/004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"
    
    # 确保文件存在
    assert os.path.exists(file_path)
    
    # 直接调用 _analyze_file 函数
    result = await _analyze_file(file_path)
    
    # 验证结果
    assert result is not None
    assert result["ExifToolVersion"] == "13.0"
    assert result["FileSize"] == 14896
    assert result["FilePermissions"] == 100644
    assert result["FilePermissionsStr"] == "-rw-r--r--"
    assert result["FileType"] == "Win32 EXE"
    assert result["FileTypeExtension"] == "EXE"
    assert result["MIMEType"] == "application/octet-stream"
    assert result["MachineType"] == "0x14c"
    assert result["MachineTypeDescription"] == "Intel 386 or later processors and compatible processors"
    assert result["ImageFileCharacteristics"] == 258
    assert result["ImageFileCharacteristicsDescription"] == ["Executable", "32-bit"]
    assert result["PEType"] == 267
    assert result["PETypeDescription"] == "PE32"
    assert result["LinkerVersion"] == "10.0"
    assert result["CodeSize"] == 4096
    assert result["InitializedDataSize"] == 5632
    assert result["UninitializedDataSize"] == 0
    assert result["EntryPoint"] == "0x1a0c"
    assert result["OSVersion"] == "5.1"
    assert result["ImageVersion"] == "0.0"
    assert result["SubsystemVersion"] == "5.1"
    assert result["Subsystem"] == 3
    assert result["SubsystemDescription"] == "Windows command line"

@pytest.mark.asyncio
async def test_perform_exiftool_analysis_with_minio():
    """测试使用 MinIO 的 perform_exiftool_analysis 函数"""
    # 创建 MinIO 客户端
    minio_client = Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    )
    
    # 创建测试桶（如果不存在）
    bucket_name = "test-bucket"
    try:
        if not minio_client.bucket_exists(bucket_name):
            minio_client.make_bucket(bucket_name)
    except Exception as e:
        pytest.skip(f"无法创建测试桶: {str(e)}")
    
    # 使用真实样本文件
    file_path = "tests/data/004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"
    assert os.path.exists(file_path)
    
    try:
        # 上传文件到 MinIO
        object_name = "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"
        minio_client.fput_object(bucket_name, object_name, file_path)
        
        # 使用 MinIO 路径调用分析函数
        exiftoolmetadata_obj = await perform_exiftool_analysis(
            minio_client=minio_client,
            bucket_name=bucket_name,
            object_name=object_name
        )

        assert isinstance(exiftoolmetadata_obj, ExifToolMetadata)
        result = exiftoolmetadata_obj.to_dict()
        
        # 验证结果
        assert result is not None
        assert result["ExifToolVersion"] == "13.0"
        assert result["FileSize"] == 14896
        assert result["FilePermissions"] == 100644
        assert result["FilePermissionsStr"] == "-rw-r--r--"
        assert result["FileType"] == "Win32 EXE"
        assert result["FileTypeExtension"] == "EXE"
        assert result["MIMEType"] == "application/octet-stream"
        assert result["MachineType"] == "0x14c"
        assert result["MachineTypeDescription"] == "Intel 386 or later processors and compatible processors"
        assert result["ImageFileCharacteristics"] == 258
        assert result["ImageFileCharacteristicsDescription"] == ["Executable", "32-bit"]
        assert result["PEType"] == 267
        assert result["PETypeDescription"] == "PE32"
        assert result["LinkerVersion"] == "10.0"
        assert result["CodeSize"] == 4096
        assert result["InitializedDataSize"] == 5632
        assert result["UninitializedDataSize"] == 0
        assert result["EntryPoint"] == "0x1a0c"
        assert result["OSVersion"] == "5.1"
        assert result["ImageVersion"] == "0.0"
        assert result["SubsystemVersion"] == "5.1"
        assert result["Subsystem"] == 3
        assert result["SubsystemDescription"] == "Windows command line"
        
    finally:
        # 清理 MinIO 对象
        try:
            minio_client.remove_object(bucket_name, object_name)
        except Exception:
            pass 