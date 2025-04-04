import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from app.core.exiftool_analyzer import convert_permissions, perform_exiftool_analysis

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
    with pytest.raises(FileNotFoundError):
        await perform_exiftool_analysis("non_existent_file.txt")

@pytest.mark.asyncio
async def test_perform_exiftool_analysis_success():
    # 创建临时文件
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"Test content")
        temp_file_path = temp_file.name
    
    try:
        # 模拟 exiftool 返回的数据
        mock_metadata = [{
            "ExifTool:ExifToolVersion": "12.30",
            "File:FileSize": 1024,
            "File:FileModifyDate": "2023:01:01 12:00:00",
            "File:FileAccessDate": "2023:01:01 12:00:00",
            "File:FileInodeChangeDate": "2023:01:01 12:00:00",
            "File:FilePermissions": 100644,
            "File:FileType": "JPEG",
            "File:FileTypeExtension": "jpg",
            "File:MIMEType": "image/jpeg",
            "EXE:MachineType": 332,
            "EXE:TimeStamp": "2023:01:01 12:00:00",
            "EXE:ImageFileCharacteristics": 33,
            "EXE:PEType": 2,
            "EXE:LinkerVersion": 14,
            "EXE:CodeSize": 4096,
            "EXE:InitializedDataSize": 1024,
            "EXE:UninitializedDataSize": 0,
            "EXE:EntryPoint": 4096,
            "EXE:OSVersion": "6.0",
            "EXE:ImageVersion": "6.0",
            "EXE:SubsystemVersion": "6.0",
            "EXE:Subsystem": 2
        }]
        
        with patch("exiftool.ExifToolHelper") as mock_et:
            mock_et.return_value.__enter__.return_value.get_metadata.return_value = mock_metadata
            
            result = await perform_exiftool_analysis(temp_file_path)
            
            # 验证结果
            assert result["ExifToolVersion"] == "12.30"
            assert result["FileSize"] == 1024
            assert result["FileType"] == "JPEG"
            assert result["FileTypeExtension"] == "jpg"
            assert result["MIMEType"] == "image/jpeg"
            assert result["MachineType"] == "0x14c"  # 332 的十六进制表示
            assert result["EntryPoint"] == "0x1000"  # 4096 的十六进制表示
            assert result["FilePermissionsStr"] == "-rw-r--r--"
            
            # 验证 ExifToolHelper 被正确调用
            mock_et.return_value.__enter__.return_value.get_metadata.assert_called_once_with([temp_file_path])
    
    finally:
        # 清理临时文件
        os.unlink(temp_file_path)

@pytest.mark.asyncio
async def test_perform_exiftool_analysis_error():
    # 创建临时文件
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"Test content")
        temp_file_path = temp_file.name
    
    try:
        # 模拟 exiftool 抛出异常
        with patch("exiftool.ExifToolHelper") as mock_et:
            mock_et.return_value.__enter__.return_value.get_metadata.side_effect = Exception("ExifTool error")
            
            with pytest.raises(ValueError) as excinfo:
                await perform_exiftool_analysis(temp_file_path)
            
            assert "Error processing file" in str(excinfo.value)
    
    finally:
        # 清理临时文件
        os.unlink(temp_file_path) 