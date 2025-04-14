"""测试夹具配置"""

import os
import pytest
import tempfile
from pathlib import Path
from minio import Minio
from app.core.config import settings
from .test_config import SAMPLE_FILES, MINIO_TEST_CONFIG

@pytest.fixture
def temp_file():
    """创建临时文件的夹具"""
    with tempfile.NamedTemporaryFile(delete=False) as temp:
        yield temp.name
    # 清理临时文件
    if os.path.exists(temp.name):
        os.unlink(temp.name)

@pytest.fixture
def sample_exe():
    """EXE 样本文件夹具"""
    return SAMPLE_FILES["exe"]

@pytest.fixture
def sample_jpg():
    """JPG 样本文件夹具"""
    return SAMPLE_FILES["jpg"]

@pytest.fixture
def sample_pdf():
    """PDF 样本文件夹具"""
    return SAMPLE_FILES["pdf"]

@pytest.fixture
async def minio_client():
    """MinIO 客户端夹具"""
    client = Minio(
        settings.MINIO_ENDPOINT,
        access_key=settings.MINIO_ACCESS_KEY,
        secret_key=settings.MINIO_SECRET_KEY,
        secure=settings.MINIO_SECURE
    )
    
    # 创建测试桶
    bucket_name = MINIO_TEST_CONFIG["bucket_name"]
    try:
        if not client.bucket_exists(bucket_name):
            client.make_bucket(bucket_name)
    except Exception as e:
        pytest.skip(f"无法创建测试桶: {str(e)}")
    
    yield client
    
    # 清理测试桶
    try:
        objects = client.list_objects(bucket_name)
        for obj in objects:
            client.remove_object(bucket_name, obj.object_name)
        client.remove_bucket(bucket_name)
    except Exception:
        pass

@pytest.fixture
def mock_exiftool_output():
    """模拟 ExifTool 输出的夹具"""
    return {
        "ExifToolVersion": "13.0",
        "FileSize": 1024,
        "FileModifyDate": "2023:01:01 12:00:00",
        "FileAccessDate": "2023:01:01 12:00:00",
        "FileInodeChangeDate": "2023:01:01 12:00:00",
        "FilePermissions": 100644,
        "FilePermissionsStr": "-rw-r--r--",
        "FileType": "JPEG",
        "FileTypeExtension": "jpg",
        "MIMEType": "image/jpeg"
    } 