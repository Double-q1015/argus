"""ExifTool 分析器测试"""

import os
import sys
import pytest
from pathlib import Path

from unittest.mock import patch
from app.core.exiftool_analyzer import (
    convert_permissions,
    perform_exiftool_analysis,
    _analyze_file,
    ExifToolMetadata,
    ExifToolError,
    FileNotFoundError
)
from app.core.config import settings
from minio import Minio
from tests.fixtures.sample_fixtures import get_sample_path, get_sample_info

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# 定义样本文件路径
SAMPLE_MALWARE_PATH = get_sample_path("win32_exe")

# 测试 convert_permissions 函数
@pytest.mark.parametrize("permissions,expected", [
    (100644, "-rw-r--r--"),  # 普通文件
    (100755, "-rwxr-xr-x"),  # 可执行文件
    (400755, "drwxr-xr-x"),  # 目录
    (200644, "crw-r--r--"),  # 字符设备
    (600644, "brw-r--r--"),  # 块设备
    (300644, "-rw-r--r--"),  # 未知类型
])
def test_convert_permissions(permissions, expected):
    """测试权限转换函数"""
    assert convert_permissions(permissions) == expected

# 测试文件不存在的情况
@pytest.mark.asyncio
async def test_perform_exiftool_analysis_file_not_found():
    """测试文件不存在的情况"""
    non_existent_file = "/path/to/non/existent/file.jpg"
    with pytest.raises(FileNotFoundError) as exc_info:
        await perform_exiftool_analysis(non_existent_file)
    assert "File not found" in str(exc_info.value)

# 测试成功分析的情况
@pytest.mark.asyncio
async def test_perform_exiftool_analysis_success(temp_file):
    """测试成功的 EXIFTool 分析"""
    # 写入测试数据
    with open(temp_file, 'wb') as f:
        f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xFF\xDB\x00C\x00')
    
    # 创建完整的 mock 数据
    mock_output = {
        "ExifToolVersion": "13.1",
        "FileSize": 1024,
        "FilePermissions": 100644,
        "FilePermissionsStr": "-rw-r--r--",
        "FileType": "JPEG",
        "FileTypeExtension": "JPG",
        "MIMEType": "image/jpeg",
        "MachineType": "0x14c",
        "MachineTypeDescription": "Intel 386 or later processors and compatible processors",
        "ImageFileCharacteristics": 258,
        "ImageFileCharacteristicsDescription": ["Executable", "32-bit"],
        "PEType": 267,
        "PETypeDescription": "PE32",
        "LinkerVersion": "10.0",
        "CodeSize": 4096,
        "InitializedDataSize": 5632,
        "UninitializedDataSize": 0,
        "EntryPoint": "0x1a0c",
        "OSVersion": "5.1",
        "ImageVersion": "0.0",
        "SubsystemVersion": "5.1",
        "Subsystem": 3,
        "SubsystemDescription": "Windows command line"
    }
    
    with patch('app.core.exiftool_analyzer._analyze_file', return_value=mock_output):
        result = await perform_exiftool_analysis(file_path=temp_file)
        
        # 验证结果
        assert result is not None
        assert result.exiftool_version == mock_output["ExifToolVersion"]
        assert result.file_size == mock_output["FileSize"]
        assert result.file_type == mock_output["FileType"]
        assert result.file_type_extension == mock_output["FileTypeExtension"]
        assert result.mime_type == mock_output["MIMEType"]
        assert result.file_permissions_str == mock_output["FilePermissionsStr"]

# 测试错误处理
@pytest.mark.asyncio
async def test_perform_exiftool_analysis_error(temp_file):
    """测试 EXIFTool 分析错误处理"""
    # 写入无效数据
    with open(temp_file, 'wb') as f:
        f.write(b"Invalid file content")
    
    with patch('app.core.exiftool_analyzer._analyze_file', 
              side_effect=ExifToolError("模拟的 ExifTool 错误")):
        with pytest.raises(ExifToolError) as exc_info:
            await perform_exiftool_analysis(file_path=temp_file)
        assert "模拟的 ExifTool 错误" in str(exc_info.value)

# 使用真实测试样本测试 _analyze_file 函数
@pytest.mark.asyncio
async def test_analyze_file_with_real_file():
    """使用真实文件测试 _analyze_file 函数"""
    # 使用真实样本文件
    file_path = SAMPLE_MALWARE_PATH
    
    # 确保文件存在
    assert os.path.exists(file_path)
    
    # 获取样本信息
    sample_info = get_sample_info("win32_exe")
    
    # 直接调用 _analyze_file 函数
    result = await _analyze_file(file_path)
    
    # 验证结果
    assert result is not None
    assert result["ExifToolVersion"] == sample_info["exiftools_info"]["ExifToolVersion"]
    assert result["FileSize"] == sample_info["exiftools_info"]["size"]
    assert result["FilePermissions"] == sample_info["exiftools_info"]["FilePermissions"]
    assert result["FilePermissionsStr"] == sample_info["exiftools_info"]["FilePermissionsStr"]
    assert result["FileType"] == sample_info["exiftools_info"]["type"]
    assert result["FileTypeExtension"] == sample_info["exiftools_info"]["extension"]
    assert result["MIMEType"] == sample_info["exiftools_info"]["mime_type"]
    assert result["MachineType"] == sample_info["exiftools_info"]["machine_type"]
    assert result["MachineTypeDescription"] == sample_info["exiftools_info"]["machine_type_description"]
    assert result["ImageFileCharacteristics"] == sample_info["exiftools_info"]["image_file_characteristics"]
    assert result["ImageFileCharacteristicsDescription"] == sample_info["exiftools_info"]["image_file_characteristics_description"]
    assert result["PEType"] == sample_info["exiftools_info"]["pe_type"]
    assert result["PETypeDescription"] == sample_info["exiftools_info"]["pe_type_description"]
    assert result["LinkerVersion"] == sample_info["exiftools_info"]["linker_version"]
    assert result["CodeSize"] == sample_info["exiftools_info"]["code_size"]
    assert result["InitializedDataSize"] == sample_info["exiftools_info"]["initialized_data_size"]
    assert result["UninitializedDataSize"] == sample_info["exiftools_info"]["uninitialized_data_size"]
    assert result["EntryPoint"] == sample_info["exiftools_info"]["entry_point"]
    assert result["OSVersion"] == sample_info["exiftools_info"]["os_version"]
    assert result["ImageVersion"] == sample_info["exiftools_info"]["image_version"]
    assert result["SubsystemVersion"] == sample_info["exiftools_info"]["subsystem_version"]
    assert result["Subsystem"] == sample_info["exiftools_info"]["subsystem"]
    assert result["SubsystemDescription"] == sample_info["exiftools_info"]["subsystem_description"]

# 测试不同类型文件的分析
@pytest.mark.asyncio
@pytest.mark.parametrize("sample_id", ["win32_exe"])
async def test_analyze_file_with_different_types(sample_id):
    """测试不同类型文件的分析"""
    # 获取样本信息
    sample_info = get_sample_info(sample_id)
    
    # 使用真实样本文件路径
    file_path = sample_info["path"]
    assert os.path.exists(file_path)
    
    # 分析文件
    result = await _analyze_file(file_path)
    
    # 验证基本属性
    assert result is not None
    assert result["FileSize"] == sample_info["exiftools_info"]["size"]
    assert result["FileType"] == sample_info["exiftools_info"]["type"]
    assert result["FileTypeExtension"] == sample_info["exiftools_info"]["extension"]
    assert result["MIMEType"] == sample_info["exiftools_info"]["mime_type"]
    
    # 验证特定类型的属性
    if sample_info["exiftools_info"]["type"] == "Win32 EXE":
        assert result["MachineType"] == sample_info["exiftools_info"]["machine_type"]
        assert result["ImageFileCharacteristics"] == sample_info["exiftools_info"]["image_file_characteristics"]
        assert result["PEType"] == sample_info["exiftools_info"]["pe_type"]
        assert result["EntryPoint"] == sample_info["exiftools_info"]["entry_point"]

# 测试 MinIO 集成
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
    file_path = SAMPLE_MALWARE_PATH
    assert os.path.exists(file_path)
    
    # 获取样本信息
    sample_info = get_sample_info("win32_exe")
    
    try:
        # 上传文件到 MinIO
        object_name = sample_info["name"]
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
        assert result["ExifToolVersion"] == sample_info["exiftools_info"]["ExifToolVersion"]
        assert result["FileSize"] == sample_info["exiftools_info"]["size"]
        assert result["FilePermissions"] == sample_info["exiftools_info"]["FilePermissions"]
        assert result["FilePermissionsStr"] == sample_info["exiftools_info"]["FilePermissionsStr"]
        assert result["FileType"] == sample_info["exiftools_info"]["type"]
        assert result["FileTypeExtension"] == sample_info["exiftools_info"]["extension"]
        assert result["MIMEType"] == sample_info["exiftools_info"]["mime_type"]
        assert result["MachineType"] == sample_info["exiftools_info"]["machine_type"]
        assert result["MachineTypeDescription"] == sample_info["exiftools_info"]["machine_type_description"]
        assert result["ImageFileCharacteristics"] == sample_info["exiftools_info"]["image_file_characteristics"]
        assert result["ImageFileCharacteristicsDescription"] == sample_info["exiftools_info"]["image_file_characteristics_description"]
        assert result["PEType"] == sample_info["exiftools_info"]["pe_type"]
        assert result["PETypeDescription"] == sample_info["exiftools_info"]["pe_type_description"]
        assert result["LinkerVersion"] == sample_info["exiftools_info"]["linker_version"]
        assert result["CodeSize"] == sample_info["exiftools_info"]["code_size"]
        assert result["InitializedDataSize"] == sample_info["exiftools_info"]["initialized_data_size"]
        assert result["UninitializedDataSize"] == sample_info["exiftools_info"]["uninitialized_data_size"]
        assert result["EntryPoint"] == sample_info["exiftools_info"]["entry_point"]
        assert result["OSVersion"] == sample_info["exiftools_info"]["os_version"]
        assert result["ImageVersion"] == sample_info["exiftools_info"]["image_version"]
        assert result["SubsystemVersion"] == sample_info["exiftools_info"]["subsystem_version"]
        assert result["Subsystem"] == sample_info["exiftools_info"]["subsystem"]
        assert result["SubsystemDescription"] == sample_info["exiftools_info"]["subsystem_description"]
        
    finally:
        # 清理 MinIO 对象
        try:
            minio_client.remove_object(bucket_name, object_name)
        except Exception:
            pass 

# 测试 MinIO 集成
@pytest.mark.asyncio
async def test_perform_exiftool_analysis_with_local_file():
    """测试使用本地文件的 perform_exiftool_analysis 函数"""
    # 使用真实样本文件
    file_path = SAMPLE_MALWARE_PATH
    assert os.path.exists(file_path)
    
    # 获取样本信息
    sample_info = get_sample_info("win32_exe")
    
    try:
        exiftoolmetadata_obj = await perform_exiftool_analysis(
            file_path=file_path
        )

        assert isinstance(exiftoolmetadata_obj, ExifToolMetadata)
        result = exiftoolmetadata_obj.to_dict()
        
        # 验证结果
        assert result is not None
        assert result["ExifToolVersion"] == sample_info["exiftools_info"]["ExifToolVersion"]
        assert result["FilePermissions"] == sample_info["exiftools_info"]["FilePermissions"]
        assert result["FilePermissionsStr"] == sample_info["exiftools_info"]["FilePermissionsStr"]
        assert result["FileSize"] == sample_info["exiftools_info"]["size"]
        assert result["FileType"] == sample_info["exiftools_info"]["type"]
        assert result["FileTypeExtension"] == sample_info["exiftools_info"]["extension"]
        assert result["MIMEType"] == sample_info["exiftools_info"]["mime_type"]
        assert result["MachineType"] == sample_info["exiftools_info"]["machine_type"]
        assert result["MachineTypeDescription"] == sample_info["exiftools_info"]["machine_type_description"]
        assert result["ImageFileCharacteristics"] == sample_info["exiftools_info"]["image_file_characteristics"]
        assert result["ImageFileCharacteristicsDescription"] == sample_info["exiftools_info"]["image_file_characteristics_description"]
        assert result["PEType"] == sample_info["exiftools_info"]["pe_type"]
        assert result["PETypeDescription"] == sample_info["exiftools_info"]["pe_type_description"]
        assert result["LinkerVersion"] == sample_info["exiftools_info"]["linker_version"]
        assert result["CodeSize"] == sample_info["exiftools_info"]["code_size"]
        assert result["InitializedDataSize"] == sample_info["exiftools_info"]["initialized_data_size"]
        assert result["UninitializedDataSize"] == sample_info["exiftools_info"]["uninitialized_data_size"]
        assert result["EntryPoint"] == sample_info["exiftools_info"]["entry_point"]
        assert result["OSVersion"] == sample_info["exiftools_info"]["os_version"]
        assert result["ImageVersion"] == sample_info["exiftools_info"]["image_version"]
        assert result["SubsystemVersion"] == sample_info["exiftools_info"]["subsystem_version"]
        assert result["Subsystem"] == sample_info["exiftools_info"]["subsystem"]
        assert result["SubsystemDescription"] == sample_info["exiftools_info"]["subsystem_description"]
        
    finally:
        pass
