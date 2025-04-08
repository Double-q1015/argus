"""测试配置文件"""

import os
from pathlib import Path

# 测试数据目录
TEST_DATA_DIR = Path(__file__).parent.parent.parent / "data"

# 样本文件
SAMPLE_FILES = {
    "exe": {
        "path": TEST_DATA_DIR / "samples" / "benign" / "sample.exe",
        "size": 14896,
        "type": "Win32 EXE",
        "extension": "EXE",
        "mime_type": "application/octet-stream",
        "machine_type": "0x14c",
        "characteristics": 258,
        "pe_type": 267,
        "entry_point": "0x1a0c"
    },
    "jpg": {
        "path": TEST_DATA_DIR / "samples" / "benign" / "sample.jpg",
        "size": 1024,
        "type": "JPEG",
        "extension": "jpg",
        "mime_type": "image/jpeg"
    },
    "pdf": {
        "path": TEST_DATA_DIR / "samples" / "benign" / "sample.pdf",
        "size": 2048,
        "type": "PDF",
        "extension": "pdf",
        "mime_type": "application/pdf"
    }
}

# MinIO 测试配置
MINIO_TEST_CONFIG = {
    "bucket_name": "test-bucket",
    "object_prefix": "test/"
}

# ExifTool 测试配置
EXIFTOOL_TEST_CONFIG = {
    "version": "13.0",
    "timeout": 30,
    "max_file_size": 100 * 1024 * 1024  # 100MB
} 