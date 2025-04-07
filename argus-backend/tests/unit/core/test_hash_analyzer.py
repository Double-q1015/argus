import os
import pytest
import sys
from pathlib import Path
from collections import defaultdict

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from app.core.hash_analyzer import (
    calculate_file_hashes,
    calculate_hashes,
    calculate_crc32,
    calculate_ssdeep,
    calculate_tlsh,
    HashResult
)

class TestHashAnalyzer:
    @pytest.fixture
    def sample_file(self, tmp_path):
        """创建测试用的样本文件"""
        file_path = tmp_path / "test_file.txt"
        file_path.write_text("This is a test file for hash analysis")
        return str(file_path)

    @pytest.fixture
    def empty_file(self, tmp_path):
        """创建空文件"""
        file_path = tmp_path / "empty_file.txt"
        file_path.write_text("")
        return str(file_path)

    @pytest.fixture
    def real_sample_file(self, sample_files):
        """使用实际的测试样本文件"""
        return sample_files["004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"]

    def test_calculate_hashes(self):
        """测试基本的哈希计算函数"""
        test_data = b"This is a test file for hash analysis"
        hashes = calculate_hashes(test_data)
        
        assert "md5" in hashes
        assert "sha1" in hashes
        assert "sha256" in hashes
        assert "sha512" in hashes
        assert "blake2b" in hashes
        assert "blake2s" in hashes
        assert "sha3_256" in hashes
        assert "sha3_512" in hashes
        assert "crc32" in hashes

    def test_calculate_file_hashes(self, sample_file):
        """测试文件哈希计算"""
        result = calculate_file_hashes(sample_file)
        
        assert isinstance(result, HashResult)
        assert result.file_path == sample_file
        assert result.file_size > 0
        assert result.md5
        assert result.sha1
        assert result.sha256
        assert result.sha512
        assert result.blake2b
        assert result.blake2s
        assert result.sha3_256
        assert result.sha3_512
        assert result.crc32

    def test_real_sample_file_hash(self, real_sample_file, sample_metadata):
        """测试实际样本文件的哈希计算"""
        result = calculate_file_hashes(real_sample_file)
        expected = sample_metadata["004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"]
        expected_hashes = expected["expected_hashes"]
        expected_exif = expected["exiftool"]
        
        assert isinstance(result, HashResult)
        assert result.file_path == real_sample_file
        assert result.file_size == expected["size"]
        
        # 验证基本哈希值
        assert result.md5 == expected_hashes["md5"]
        assert result.sha1 == expected_hashes["sha1"]
        assert result.sha256 == expected_hashes["sha256"]
        assert result.crc32 == expected_hashes["crc32"]
        
        # 验证可选哈希值（如果可用）
        if result.ssdeep:
            assert result.ssdeep == expected_hashes["ssdeep"]
        if result.tlsh:
            assert result.tlsh == expected_hashes["tlsh"]

        # 验证 exiftool 信息
        assert result.file_type == expected_exif["FileType"]
        assert result.file_type_extension == expected_exif["FileTypeExtension"]
        assert result.mime_type == expected_exif["MIMEType"]
        assert result.machine_type == expected_exif["MachineType"]
        assert result.timestamp == expected_exif["TimeStamp"]
        assert result.image_characteristics == expected_exif["ImageFileCharacteristics"]
        assert result.pe_type == expected_exif["PEType"]
        assert result.linker_version == expected_exif["LinkerVersion"]
        assert result.code_size == expected_exif["CodeSize"]
        assert result.initialized_data_size == expected_exif["InitializedDataSize"]
        assert result.uninitialized_data_size == expected_exif["UninitializedDataSize"]
        assert result.entry_point == expected_exif["EntryPoint"]
        assert result.os_version == expected_exif["OSVersion"]
        assert result.image_version == expected_exif["ImageVersion"]
        assert result.subsystem_version == expected_exif["SubsystemVersion"]
        assert result.subsystem == expected_exif["Subsystem"]

    def test_empty_file_hash(self, empty_file):
        """测试空文件的哈希计算"""
        result = calculate_file_hashes(empty_file)
        
        assert result.file_size == 0
        assert result.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert result.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_nonexistent_file(self):
        """测试不存在的文件"""
        result = calculate_file_hashes("nonexistent_file.txt")
        assert result.error_message == "文件不存在"
        assert result.file_size == 0
        assert result.md5 == ""
        assert result.sha1 == ""
        assert result.sha256 == ""

    def test_file_permission_error(self, tmp_path):
        """测试文件权限错误"""
        file_path = tmp_path / "permission_test.txt"
        file_path.write_text("test")
        # 移除文件权限
        os.chmod(file_path, 0o000)
        
        result = calculate_file_hashes(str(file_path))
        assert "权限不足" in result.error_message.lower()
        assert result.file_size == 0
        assert result.md5 == ""
        assert result.sha1 == ""
        assert result.sha256 == ""

    def test_large_file_hash(self, tmp_path):
        """测试大文件哈希计算"""
        file_path = tmp_path / "large_file.txt"
        # 创建 1MB 的测试文件
        with open(file_path, "wb") as f:
            f.write(b"0" * 1024 * 1024)  # 1MB of zeros
        
        result = calculate_file_hashes(str(file_path))
        assert result.file_size == 1024 * 1024
        assert result.md5
        assert result.sha1
        assert result.sha256

    def test_binary_file_hash(self, tmp_path):
        """测试二进制文件哈希计算"""
        file_path = tmp_path / "binary_file.bin"
        # 创建包含随机二进制数据的文件
        binary_data = bytes([i % 256 for i in range(1000)])
        with open(file_path, "wb") as f:
            f.write(binary_data)
        
        result = calculate_file_hashes(str(file_path))
        assert result.file_size == 1000
        assert result.md5
        assert result.sha1
        assert result.sha256

    def test_crc32_calculation(self):
        """测试 CRC32 计算"""
        test_data = b"test data"
        crc32 = calculate_crc32(test_data)
        assert len(crc32) == 8  # CRC32 是 8 位十六进制
        assert crc32.isupper()  # 应该是大写

    @pytest.mark.skipif(not hasattr(calculate_ssdeep, "__module__"), reason="ssdeep not available")
    def test_ssdeep_calculation(self):
        """测试 SSDEEP 计算（如果可用）"""
        test_data = b"test data" * 100  # SSDEEP 需要足够的数据
        ssdeep_hash = calculate_ssdeep(test_data)
        assert ssdeep_hash is not None
        assert ":" in ssdeep_hash  # SSDEEP 格式包含冒号

    @pytest.mark.skipif(not hasattr(calculate_tlsh, "__module__"), reason="tlsh not available")
    def test_tlsh_calculation(self):
        """测试 TLSH 计算（如果可用）"""
        test_data = b"test data" * 100  # TLSH 需要足够的数据
        tlsh_hash = calculate_tlsh(test_data)
        assert tlsh_hash is not None
        assert len(tlsh_hash) > 0
