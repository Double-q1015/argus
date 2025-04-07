import os
import pytest
from typing import Dict, Any

# 测试样本的元数据
SAMPLE_METADATA: Dict[str, Dict[str, Any]] = {
    "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5": {
        "name": "test_sample",
        "type": "PE32 executable (console) Intel 80386, for MS Windows",
        "format": "EXEx86",
        "size": 14896,
        "description": "Windows 32位控制台可执行文件",
        "exiftool": {
            "FileType": "Win32 EXE",
            "FileTypeExtension": "exe",
            "MIMEType": "application/octet-stream",
            "MachineType": "Intel 386 or later, and compatibles",
            "TimeStamp": "2012:08:11 00:14:27+08:00",
            "ImageFileCharacteristics": "Executable, 32-bit",
            "PEType": "PE32",
            "LinkerVersion": "10",
            "CodeSize": 4096,
            "InitializedDataSize": 5632,
            "UninitializedDataSize": 0,
            "EntryPoint": "0x1a0c",
            "OSVersion": "5.1",
            "ImageVersion": "0",
            "SubsystemVersion": "5.1",
            "Subsystem": "Windows command line"
        },
        "expected_hashes": {
            "md5": "5b63ebdc906a189ee6dae807246506e5",
            "sha1": "6cf5dc082af22c2863f3b925aaa06bb3e0513c46",
            "sha256": "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5",
            "crc32": "E3ACAD6A",
            "ssdeep": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEL:hDXWipuE+K3/SSHgxmE",
            "tlsh": "T19B627C2AE9499036C3E804F813B6C367BA7F51A1534523E7BB735DDC8D48490EC63A6D",
            "authentihash": "69D14FD09682A3755FA87602F209D560DE2B6707C39D0E8328695FABE6C46A01",
            "pehashng": "5f9a88f0f6969e294313fd8413845b0eef6379c5e2a9ed05a740741bc779f05f",
            "richhash": "410c803093d4c1afcacac1e0055b360f",
            "impfuzzy": "24:kd1BzeLKTUdQr+FzJTGPJ/3M/Tl5F6O58yldfDKb:c1leLtdkiKM/wO5ZldfDKb",
            "imphash": "432c342c05744facf1143abcda5d68c4"
        }
    }
}

@pytest.fixture
def sample_files() -> Dict[str, str]:
    """返回测试样本文件的路径"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, "..", "data")
    
    return {
        sample_id: os.path.join(data_dir, sample_id)
        for sample_id in SAMPLE_METADATA.keys()
    }

@pytest.fixture
def sample_metadata() -> Dict[str, Dict[str, Any]]:
    """返回测试样本的元数据"""
    return SAMPLE_METADATA

