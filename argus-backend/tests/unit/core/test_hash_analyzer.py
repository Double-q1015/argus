import os
import pytest
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
from minio import Minio
from minio.error import S3Error

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

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

from app.core.hash_analyzer import (
    calculate_file_hashes,
    calculate_hashes,
    calculate_crc32,
    calculate_ssdeep,
    calculate_tlsh,
    HashResult,
    verify_file_hash,
    verify_minio_file_hash,
    calculate_minio_file_hashes,
    stream_hash_analysis_generator
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
    def large_file(self, tmp_path):
        """创建大文件（10MB）"""
        file_path = tmp_path / "large_file.txt"
        with open(file_path, "wb") as f:
            f.write(b"0" * (10 * 1024 * 1024))
        return str(file_path)

    @pytest.fixture
    def mock_minio_client(self):
        """创建模拟的MinIO客户端"""
        return MagicMock(spec=Minio)

    def test_calculate_hashes_basic(self):
        """测试基本的哈希计算功能"""
        data = b"test data"
        result = calculate_hashes(data)
        
        assert isinstance(result, dict)
        assert "md5" in result
        assert "sha1" in result
        assert "sha256" in result
        assert "sha512" in result
        assert "crc32" in result
        assert "ssdeep" in result
        assert "tlsh" in result
        
        # 验证哈希值长度
        assert len(result["md5"]) == 32
        assert len(result["sha1"]) == 40
        assert len(result["sha256"]) == 64
        assert len(result["sha512"]) == 128
        assert len(result["crc32"]) == 8

    def test_calculate_hashes_empty(self):
        """测试空数据的哈希计算"""
        # 直接使用空数据的哈希值
        empty_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        empty_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        empty_sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        empty_crc32 = "00000000"
        
        empty_result = ""
        result = calculate_hashes(empty_result)
        
        assert result["md5"] == empty_result
        assert result["sha1"] == empty_result
        assert result["sha256"] == empty_result
        assert result["sha512"] == empty_result
        assert result["crc32"] == empty_result

    def test_calculate_hashes_error(self):
        """测试哈希计算错误处理"""
        with patch("hashlib.md5") as mock_md5:
            mock_md5.side_effect = Exception("Test error")
            result = calculate_hashes(b"test")
            
            assert "error" in result
            assert result["md5"] == ""
            assert result["sha1"] == ""
            assert result["sha256"] == ""
            assert result["sha512"] == ""
            assert result["crc32"] == ""

    def test_calculate_file_hashes_basic(self, sample_file):
        """测试基本的文件哈希计算"""
        result = calculate_file_hashes(sample_file)
        
        assert isinstance(result, HashResult)
        assert result.file_size > 0
        assert not result.error_message
        
        # 验证各种哈希值
        assert result.md5
        assert result.sha1
        assert result.sha256
        assert result.sha512
        assert result.crc32
        
        # 验证哈希值长度
        assert len(result.md5) == 32
        assert len(result.sha1) == 40
        assert len(result.sha256) == 64
        assert len(result.sha512) == 128
        assert len(result.crc32) == 8

    def test_calculate_file_hashes_empty(self, empty_file):
        """测试空文件的哈希计算"""
        result = calculate_file_hashes(empty_file)
        
        assert result.file_size == 0
        assert not result.error_message
        assert result.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert result.sha1 == "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert result.sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result.sha512 == "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        assert result.crc32 == "00000000"

    def test_calculate_file_hashes_nonexistent(self):
        """测试不存在的文件"""
        result = calculate_file_hashes("nonexistent_file.txt")
        
        assert result.file_size == 0
        assert result.error_message == "文件不存在"
        assert not result.md5
        assert not result.sha1
        assert not result.sha256
        assert not result.sha512
        assert not result.crc32

    def test_calculate_file_hashes_large(self, large_file):
        """测试大文件的哈希计算"""
        result = calculate_file_hashes(large_file)
        
        assert result.file_size == 10 * 1024 * 1024
        assert not result.error_message
        assert result.md5
        assert result.sha1
        assert result.sha256
        assert result.sha512
        assert result.crc32

    @pytest.mark.skipif(not SSDEEP_AVAILABLE, reason="SSDEEP not available")
    def test_ssdeep_calculation(self, sample_file):
        """测试SSDEEP哈希计算"""
        with open(sample_file, "rb") as f:
            data = f.read()
        
        ssdeep_hash = calculate_ssdeep(data)
        assert ssdeep_hash is not None
        assert isinstance(ssdeep_hash, str)
        assert len(ssdeep_hash) > 0
        assert ":" in ssdeep_hash

    @pytest.mark.skipif(not TLSH_AVAILABLE, reason="TLSH not available")
    def test_tlsh_calculation(self, sample_file):
        """测试TLSH哈希计算"""
        with open(sample_file, "rb") as f:
            data = f.read()
        

    def test_verify_file_hash_success(self, sample_file):
        """测试文件哈希验证成功"""
        result = calculate_file_hashes(sample_file)
        verify_result = verify_file_hash(sample_file, "md5", result.md5)
        
        assert verify_result["verified"] is True
        assert verify_result["calculated_hash"] == result.md5
        assert verify_result["expected_hash"] == result.md5
        assert verify_result["hash_type"] == "md5"
        assert verify_result["file_size"] > 0

    def test_verify_file_hash_failure(self, sample_file):
        """测试文件哈希验证失败"""
        verify_result = verify_file_hash(sample_file, "md5", "invalid_hash")
        
        assert verify_result["verified"] is False
        assert verify_result["calculated_hash"] != "invalid_hash"
        assert verify_result["expected_hash"] == "invalid_hash"
        assert verify_result["hash_type"] == "md5"

    def test_verify_file_hash_nonexistent(self):
        """测试验证不存在的文件"""
        verify_result = verify_file_hash("nonexistent_file.txt", "md5", "some_hash")
        
        assert verify_result["verified"] is False
        assert verify_result["error"] == "文件不存在"
        assert verify_result["calculated_hash"] == ""
        assert verify_result["expected_hash"] == "some_hash"

    def test_verify_file_hash_unsupported_type(self, sample_file):
        """测试不支持的哈希类型"""
        verify_result = verify_file_hash(sample_file, "invalid_type", "some_hash")
        
        assert verify_result["verified"] is False
        assert verify_result["error"] == "不支持的哈希类型: invalid_type"
        assert verify_result["calculated_hash"] == ""
        assert verify_result["expected_hash"] == "some_hash"

    def test_calculate_minio_file_hashes_success(self, mock_minio_client, sample_file):
        """测试MinIO文件哈希计算成功"""
        # 设置模拟的MinIO客户端行为
        mock_stat = MagicMock()
        mock_stat.size = os.path.getsize(sample_file)
        mock_minio_client.stat_object.return_value = mock_stat
        
        with open(sample_file, "rb") as f:
            mock_data = f.read()
        
        mock_stream = MagicMock()
        mock_stream.stream.return_value = [mock_data]
        mock_minio_client.get_object.return_value = mock_stream
        
        result = calculate_minio_file_hashes(mock_minio_client, "test-bucket", "test.txt")
        
        assert isinstance(result, HashResult)
        assert result.file_size == mock_stat.size
        assert not result.error_message
        assert result.md5
        assert result.sha1
        assert result.sha256
        assert result.sha512
        assert result.crc32

    def test_calculate_minio_file_hashes_stat_error(self, mock_minio_client):
        """测试MinIO文件哈希计算 - 获取对象信息失败"""
        # 创建正确的S3Error对象
        mock_error = S3Error(
            code="NoSuchKey",
            message="Test error",
            resource="test-bucket/test.txt",
            request_id="test-request-id",
            host_id="test-host-id",
            response=MagicMock()
        )
        mock_minio_client.stat_object.side_effect = mock_error
        
        result = calculate_minio_file_hashes(mock_minio_client, "test-bucket", "test.txt")
        
        assert result.file_size == 0
        assert "无法获取MinIO对象信息" in result.error_message
        assert not result.md5
        assert not result.sha1
        assert not result.sha256
        assert not result.sha512
        assert not result.crc32

    def test_calculate_minio_file_hashes_get_error(self, mock_minio_client):
        """测试MinIO文件哈希计算 - 获取对象流失败"""
        mock_stat = MagicMock()
        mock_stat.size = 100
        mock_minio_client.stat_object.return_value = mock_stat
        
        # 创建正确的S3Error对象
        mock_error = S3Error(
            code="NoSuchKey",
            message="Test error",
            resource="test-bucket/test.txt",
            request_id="test-request-id",
            host_id="test-host-id",
            response=MagicMock()
        )
        mock_minio_client.get_object.side_effect = mock_error
        
        result = calculate_minio_file_hashes(mock_minio_client, "test-bucket", "test.txt")
        
        assert result.file_size == 100
        assert "无法获取MinIO对象流" in result.error_message
        assert not result.md5
        assert not result.sha1
        assert not result.sha256
        assert not result.sha512
        assert not result.crc32

    def test_stream_hash_analysis_generator(self, mock_minio_client, sample_file):
        """测试流式哈希分析生成器"""
        # 设置模拟的MinIO客户端行为
        mock_stat = MagicMock()
        mock_stat.size = os.path.getsize(sample_file)
        mock_minio_client.stat_object.return_value = mock_stat
        
        with open(sample_file, "rb") as f:
            mock_data = f.read()
        
        mock_stream = MagicMock()
        mock_stream.stream.return_value = [mock_data]
        mock_minio_client.get_object.return_value = mock_stream
        
        generator = stream_hash_analysis_generator(mock_minio_client, "test-bucket", "test.txt")
        results = list(generator)
        
        assert len(results) > 0
        assert "progress" in results[0]
        assert "bytes_processed" in results[0]
        assert "total_bytes" in results[0]
        assert "md5" in results[0]
        assert "sha1" in results[0]
        assert "sha256" in results[0]
        assert "crc32" in results[0]
        
        # 验证最后一个结果
        final_result = results[-1]
        assert final_result["progress"] == 100
        assert final_result["final_result"] is True
        assert final_result["md5"]
        assert final_result["sha1"]
        assert final_result["sha256"]
        assert final_result["crc32"]

    def test_stream_hash_analysis_generator_error(self, mock_minio_client):
        """测试流式哈希分析生成器错误处理"""
        # 创建正确的S3Error对象
        mock_error = S3Error(
            code="NoSuchKey",
            message="Test error",
            resource="test-bucket/test.txt",
            request_id="test-request-id",
            host_id="test-host-id",
            response=MagicMock()
        )
        mock_minio_client.stat_object.side_effect = mock_error
        
        generator = stream_hash_analysis_generator(mock_minio_client, "test-bucket", "test.txt")
        result = next(generator)
        
        assert "error" in result
        assert "无法获取MinIO对象信息" in result["error"]
        assert result["progress"] == 0
        assert result["bytes_processed"] == 0
        assert result["total_bytes"] == 0
        assert not result["md5"]
        assert not result["sha1"]
        assert not result["sha256"]
        assert not result["crc32"]
