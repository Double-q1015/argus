import os
import tempfile
import shutil
from datetime import datetime
from unittest.mock import patch, MagicMock

import pytest
from minio import Minio
from minio.error import S3Error

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from app.core.pe_analyzer import (
    PEMetadata, PEHeaderInfo, PESection, PEImport, PEExport, PEResource, PEAnalysisResult,
    get_platform_name, get_pe_header_info, get_section_characteristics, get_dll_characteristics,
    get_subsystem_name, get_machine_type, get_resource_language, get_resource_sublanguage,
    calculate_entropy, analyze_pe_file, analyze_minio_pe_file
)
from tests.fixtures.sample_fixtures import MALWARE_SAMPLES

@pytest.fixture
def test_pe():
    """创建模拟的PE对象"""
    # 模拟pefile.PE对象
    mock_pe = MagicMock()
    mock_pe.FILE_HEADER.Machine = 0x014c  # x86
    mock_pe.FILE_HEADER.TimeDateStamp = 1344615267  # 2012-08-11 12:34:27
    mock_pe.FILE_HEADER.NumberOfSections = 5
    mock_pe.OPTIONAL_HEADER.Magic = 0x10b  # PE32
    mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
    mock_pe.OPTIONAL_HEADER.ImageBase = 0x400000
    mock_pe.OPTIONAL_HEADER.Subsystem = 2  # Windows GUI
    mock_pe.OPTIONAL_HEADER.DllCharacteristics = 0x4000  # WDM_DRIVER
    mock_pe.OPTIONAL_HEADER.MajorLinkerVersion = 10
    mock_pe.OPTIONAL_HEADER.MinorLinkerVersion = 0
    
    # 模拟节
    mock_section = MagicMock()
    mock_section.Name = b".text\x00\x00\x00"
    mock_section.VirtualAddress = 0x1000
    mock_section.Misc_VirtualSize = 0x500
    mock_section.SizeOfRawData = 0x400
    mock_section.Characteristics = 0x20  # IMAGE_SCN_CNT_CODE
    mock_section.PointerToRawData = 0x200
    mock_section.get_data.return_value = b"test data"
    mock_pe.sections = [mock_section]
    
    # 模拟导入
    mock_import_entry = MagicMock()
    mock_import_entry.dll = b"kernel32.dll"
    mock_import = MagicMock()
    mock_import.name = b"CreateFileA"
    mock_import.address = 0x1234
    mock_import_entry.imports = [mock_import]
    mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_import_entry]
    
    # 模拟导出
    mock_export = MagicMock()
    mock_export.name = b"TestFunction"
    mock_export.ordinal = 1
    mock_export.address = 0x2000
    mock_pe.DIRECTORY_ENTRY_EXPORT = MagicMock()
    mock_pe.DIRECTORY_ENTRY_EXPORT.symbols = [mock_export]
    
    # 模拟资源
    mock_resource_type = MagicMock()
    mock_resource_type.name = b"RT_ICON"
    mock_resource_type.struct.Id = 3
    
    # 创建资源ID目录
    mock_resource_id = MagicMock()
    mock_resource_id.directory = MagicMock()
    
    # 创建资源语言目录
    mock_resource_lang = MagicMock()
    mock_resource_lang.data = MagicMock()
    mock_resource_lang.data.lang = 0x0409  # LANG_ENGLISH
    mock_resource_lang.data.sublang = 0x01  # SUBLANG_ENGLISH_US
    mock_resource_lang.data.struct = MagicMock()
    mock_resource_lang.data.struct.Size = 1024
    mock_resource_lang.data.struct.OffsetToData = 0x3000
    
    # 设置资源目录结构
    mock_resource_id.directory.entries = [mock_resource_lang]
    mock_resource_type.directory = MagicMock()
    mock_resource_type.directory.entries = [mock_resource_id]
    
    # 设置资源目录
    mock_pe.DIRECTORY_ENTRY_RESOURCE = MagicMock()
    mock_pe.DIRECTORY_ENTRY_RESOURCE.entries = [mock_resource_type]
    
    # 模拟TLS信息
    mock_pe.DIRECTORY_ENTRY_TLS = MagicMock()
    mock_pe.DIRECTORY_ENTRY_TLS.struct = MagicMock()
    mock_pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks = 0x1
    mock_pe.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex = 0x1
    mock_pe.DIRECTORY_ENTRY_TLS.struct.Characteristics = 0x1
    mock_pe.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData = 0x1
    mock_pe.DIRECTORY_ENTRY_TLS.struct.SizeOfZeroFill = 0x1
    mock_pe.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData = 0x1
    
    # 模拟安全目录
    mock_pe.DIRECTORY_ENTRY_SECURITY = MagicMock()
    
    return mock_pe

@pytest.fixture
def temp_dir():
    """创建临时目录"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def test_file_path(temp_dir):
    """创建测试文件"""
    test_file_path = os.path.join(temp_dir, "test.exe")
    with open(test_file_path, "wb") as f:
        f.write(b"MZ" + b"\x00" * 100)  # 简单的MZ头
    return test_file_path

def test_get_platform_name():
    """测试获取平台名称函数"""
    assert get_platform_name(0x014c) == "x86"
    assert get_platform_name(0x8664) == "x64"
    assert get_platform_name(0x01c4) == "ARM"
    assert get_platform_name(0xaa64) == "ARM64"
    assert get_platform_name(0x9999) == "UNKNOWN_9999"

def test_get_pe_header_info(test_pe):
    """测试获取PE头信息函数"""
    header_info = get_pe_header_info(test_pe)
    
    assert header_info['platform'] == '0x14c'
    assert header_info['platform_name'] == 'x86'
    assert header_info['time_datestamp'] == 1344615267
    assert header_info['entrypoint'] == '0x1000'
    assert header_info['image_base'] == '0x400000'
    assert header_info['number_of_sections'] == 5
    assert header_info['linkerversion'] == (10, 0)
    # 注意：时间戳转换可能因时区而异，这里我们只验证格式
    assert isinstance(header_info['time_datetime_utc'], str)
    assert len(header_info['time_datetime_utc']) == 19  # YYYY-MM-DD HH:MM:SS

def test_get_section_characteristics():
    """测试获取节特征函数"""
    # 测试代码节
    assert "CODE" in get_section_characteristics(0x20)
    # 测试数据节
    assert "INITIALIZED_DATA" in get_section_characteristics(0x40)
    # 测试可执行节
    assert "EXECUTE" in get_section_characteristics(0x20000000)
    # 测试可读节
    assert "READ" in get_section_characteristics(0x40000000)
    # 测试可写节
    assert "WRITE" in get_section_characteristics(0x80000000)

def test_get_dll_characteristics():
    """测试获取DLL特征函数"""
    # 测试WDM驱动
    assert "WDM_DRIVER" in get_dll_characteristics(0x4000)
    # 测试高熵VA
    assert "HIGH_ENTROPY_VA" in get_dll_characteristics(0x0020)
    # 测试动态基址
    assert "DYNAMIC_BASE" in get_dll_characteristics(0x0100)
    # 测试强制完整性
    assert "FORCE_INTEGRITY" in get_dll_characteristics(0x0200)

def test_get_subsystem_name():
    """测试获取子系统名称函数"""
    assert get_subsystem_name(0) == "UNKNOWN"
    assert get_subsystem_name(1) == "NATIVE"
    assert get_subsystem_name(2) == "WINDOWS_GUI"
    assert get_subsystem_name(3) == "WINDOWS_CONSOLE"
    assert get_subsystem_name(5) == "OS2_CONSOLE"
    assert get_subsystem_name(7) == "POSIX_CONSOLE"
    assert get_subsystem_name(9) == "WINDOWS_CE_GUI"
    assert get_subsystem_name(14) == "XBOX"

def test_get_machine_type():
    """测试获取机器类型函数"""
    assert get_machine_type(0x014c) == "I386"
    assert get_machine_type(0x0200) == "IA64"
    assert get_machine_type(0x8664) == "AMD64"
    assert get_machine_type(0x01c4) == "ARM"
    assert get_machine_type(0xaa64) == "ARM64"
    assert get_machine_type(0x9999) == "UNKNOWN"

def test_calculate_entropy():
    """测试计算熵值函数"""
    # 测试空数据
    assert calculate_entropy(b"") == 0.0
    
    # 测试均匀分布的数据（高熵）
    uniform_data = bytes(range(256))
    assert calculate_entropy(uniform_data) > 7.0
    
    # 测试重复数据（低熵）
    repeated_data = b"A" * 100
    assert calculate_entropy(repeated_data) < 1.0

def test_analyze_real_malware_sample():
    """测试使用真实恶意样本进行分析"""
    # 获取样本信息
    sample_info = MALWARE_SAMPLES["win32_exe"]
    sample_path = sample_info["path"]
    expected_result = sample_info["pe_analysis_result"]
    
    # 确保样本文件存在
    assert os.path.exists(sample_path), f"样本文件不存在: {sample_path}"
    
    # 分析样本
    result = analyze_pe_file(sample_path)
    
    # 验证结果
    assert isinstance(result, PEAnalysisResult)
    assert isinstance(result.metadata, PEMetadata)
    
    # 验证元数据
    assert result.metadata.file_size == expected_result["metadata"]["file_size"]
    assert result.metadata.file_type == expected_result["metadata"]["file_type"]
    assert result.metadata.architecture == expected_result["metadata"]["architecture"]
    assert hex(result.metadata.entry_point) == expected_result["metadata"]["entry_point"]
    assert result.metadata.machine_type == expected_result["metadata"]["machine_type"]
    assert result.metadata.subsystem == expected_result["metadata"]["subsystem"]
    assert result.metadata.dll_characteristics == expected_result["metadata"]["dll_characteristics"]
    assert result.metadata.has_signature == expected_result["metadata"]["has_signature"]
    assert result.metadata.is_packed == expected_result["metadata"]["is_packed"]
    assert result.metadata.is_encrypted == expected_result["metadata"]["is_encrypted"]
    assert result.metadata.has_suspicious_imports == expected_result["metadata"]["has_suspicious_imports"]
    assert result.metadata.has_suspicious_exports == expected_result["metadata"]["has_suspicious_exports"]
    assert result.metadata.has_suspicious_sections == expected_result["metadata"]["has_suspicious_sections"]
    assert result.metadata.pehashng == expected_result["metadata"]["pehashng"]
    assert result.metadata.tls_info == expected_result["metadata"]["tls_info"]
    assert result.metadata.debug_info == expected_result["metadata"]["debug_info"]
    
    # 验证节信息
    assert len(result.sections) == len(expected_result["sections"])
    for actual_section, expected_section in zip(result.sections, expected_result["sections"]):
        assert actual_section.name == expected_section["name"]
        assert hex(actual_section.virtual_address) == expected_section["virtual_address"]
        assert hex(actual_section.virtual_size) == expected_section["virtual_size"]
        assert hex(actual_section.raw_size) == expected_section["raw_size"]
        assert actual_section.characteristics == expected_section["characteristics"]
        assert abs(actual_section.entropy - expected_section["entropy"]) < 0.0001
        assert hex(actual_section.physical_address) == expected_section["physical_address"]
        assert hex(actual_section.physical_size) == expected_section["physical_size"]
        assert actual_section.section_hash == expected_section["section_hash"]
    
    # 验证导入信息
    assert len(result.imports) == len(expected_result["imports"])
    for actual_import, expected_import in zip(result.imports, expected_result["imports"]):
        assert actual_import.dll_name == expected_import["dll_name"]
        assert len(actual_import.functions) == len(expected_import["functions"])
        for actual_func, expected_func in zip(actual_import.functions, expected_import["functions"]):
            assert actual_func["name"] == expected_func["name"]
            assert hex(actual_func["address"]) == expected_func["address"]
        assert actual_import.function_count == expected_import["function_count"]
    
    # 验证导出信息
    assert len(result.exports) == len(expected_result["exports"])
    for actual_export, expected_export in zip(result.exports, expected_result["exports"]):
        assert actual_export.name == expected_export["name"]
        assert hex(actual_export.ordinal) == expected_export["ordinal"]
        assert hex(actual_export.address) == expected_export["address"]
        assert actual_export.function_count == expected_export["function_count"]
    
    # 验证资源信息
    assert len(result.resources) == len(expected_result["resources"])
    for actual_resource, expected_resource in zip(result.resources, expected_result["resources"]):
        assert actual_resource.name == expected_resource["name"]
        assert hex(actual_resource.size) == expected_resource["size"]
        assert hex(actual_resource.offset) == expected_resource["offset"]
        assert actual_resource.language == expected_resource["language"]
        assert actual_resource.sublanguage == expected_resource["sublanguage"]
    
    # 验证可疑特征
    assert result.suspicious_features == expected_result["suspicious_features"]
    assert result.error_message == expected_result.get("error_message")

def test_analyze_minio_pe_file_success():
    """测试从MinIO成功下载并分析PE文件"""
    # 创建模拟的MinIO客户端
    mock_minio = MagicMock(spec=Minio)
    
    # 设置模拟的stat_object返回值
    mock_stat = MagicMock()
    mock_stat.size = 1024
    mock_minio.stat_object.return_value = mock_stat
    
    # 设置模拟的fget_object行为
    def mock_fget_object(bucket, object_name, file_path, length=None):
        # 创建一个简单的PE文件
        with open(file_path, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)  # 简单的MZ头
    mock_minio.fget_object.side_effect = mock_fget_object
    
    # 使用patch来模拟analyze_pe_file的返回值
    expected_result = PEAnalysisResult(
        metadata=PEMetadata(
            file_size=1024,
            file_type="PE32 executable",
            architecture="x86",
            entry_point=0x1000,
            timestamp=datetime.now(),
            machine_type="I386",
            subsystem="WINDOWS_CONSOLE",
            dll_characteristics=[],
            has_signature=False,
            is_packed=False,
            is_encrypted=False,
            has_suspicious_imports=False,
            has_suspicious_exports=False,
            has_suspicious_sections=False,
            pehashng="",
            tls_info={},
            debug_info={},
            pe_header_info=None
        ),
        sections=[],
        imports=[],
        exports=[],
        resources=[],
        suspicious_features=[]
    )
    
    with patch('app.core.pe_analyzer.analyze_pe_file', return_value=expected_result):
        result = analyze_minio_pe_file(mock_minio, "test-bucket", "test.exe")
        
        # 验证结果
        assert result == expected_result
        assert mock_minio.stat_object.called
        assert mock_minio.fget_object.called

def test_analyze_minio_pe_file_stat_error():
    """测试获取MinIO对象信息失败的情况"""
    # 创建模拟的MinIO客户端
    mock_minio = MagicMock(spec=Minio)
    
    # 设置stat_object抛出异常
    mock_minio.stat_object.side_effect = S3Error(
        "NoSuchKey",
        "The specified key does not exist",
        "test-bucket/test.exe",
        "test-request-id",
        "test-host-id",
        "test-response"
    )
    
    result = analyze_minio_pe_file(mock_minio, "test-bucket", "test.exe")
    
    # 验证结果
    expected_error = "无法获取MinIO对象信息: S3 operation failed; code: NoSuchKey, message: The specified key does not exist, resource: test-bucket/test.exe, request_id: test-request-id, host_id: test-host-id"
    assert result.error_message == expected_error
    assert "无法获取MinIO对象信息" in result.suspicious_features
    assert result.metadata.file_size == 0

def test_analyze_minio_pe_file_download_error():
    """测试下载MinIO对象失败的情况"""
    # 创建模拟的MinIO客户端
    mock_minio = MagicMock(spec=Minio)
    
    # 设置stat_object成功但fget_object失败
    mock_stat = MagicMock()
    mock_stat.size = 1024
    mock_minio.stat_object.return_value = mock_stat
    mock_minio.fget_object.side_effect = S3Error(
        "AccessDenied",
        "Access denied",
        "test-bucket/test.exe",
        "test-request-id",
        "test-host-id",
        "test-response"
    )
    
    result = analyze_minio_pe_file(mock_minio, "test-bucket", "test.exe")
    
    # 验证结果
    expected_error = "无法下载MinIO对象: S3 operation failed; code: AccessDenied, message: Access denied, resource: test-bucket/test.exe, request_id: test-request-id, host_id: test-host-id"
    assert result.error_message == expected_error
    assert "无法下载MinIO对象" in result.suspicious_features
    assert result.metadata.file_size == 1024

def test_analyze_minio_pe_file_truncated():
    """测试文件被截断的情况"""
    # 创建模拟的MinIO客户端
    mock_minio = MagicMock(spec=Minio)
    
    # 设置文件大小超过最大限制
    mock_stat = MagicMock()
    mock_stat.size = 1024 * 1024 * 200  # 200MB
    mock_minio.stat_object.return_value = mock_stat
    
    # 设置fget_object行为
    def mock_fget_object(bucket, object_name, file_path, length=None):
        with open(file_path, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)
    mock_minio.fget_object.side_effect = mock_fget_object
    
    # 使用patch来模拟analyze_pe_file的返回值
    expected_result = PEAnalysisResult(
        metadata=PEMetadata(
            file_size=1024 * 1024 * 200,
            file_type="PE32 executable",
            architecture="x86",
            entry_point=0x1000,
            timestamp=datetime.now(),
            machine_type="I386",
            subsystem="WINDOWS_CONSOLE",
            dll_characteristics=[],
            has_signature=False,
            is_packed=False,
            is_encrypted=False,
            has_suspicious_imports=False,
            has_suspicious_exports=False,
            has_suspicious_sections=False,
            pehashng="",
            tls_info={},
            debug_info={},
            pe_header_info=None
        ),
        sections=[],
        imports=[],
        exports=[],
        resources=[],
        suspicious_features=[]
    )
    
    with patch('app.core.pe_analyzer.analyze_pe_file', return_value=expected_result):
        result = analyze_minio_pe_file(mock_minio, "test-bucket", "test.exe")
        
        # 验证结果
        assert any("文件被截断" in feature for feature in result.suspicious_features)
        assert mock_minio.fget_object.called
        # 验证下载大小限制
        call_args = mock_minio.fget_object.call_args[1]
        assert call_args['length'] == 1024 * 1024 * 100  # 默认100MB限制

def test_analyze_minio_pe_file_with_real_sample():
    """使用真实样本测试从MinIO获取分析结果"""
    # 获取样本信息
    sample_info = MALWARE_SAMPLES["win32_exe"]
    sample_path = sample_info["path"]
    expected_result = sample_info["pe_analysis_result"]
    
    # 确保样本文件存在
    assert os.path.exists(sample_path), f"样本文件不存在: {sample_path}"
    
    # 创建临时目录用于测试
    temp_dir = tempfile.mkdtemp()
    try:
        # 创建模拟的MinIO客户端
        mock_minio = MagicMock(spec=Minio)
        
        # 设置stat_object返回值
        mock_stat = MagicMock()
        mock_stat.size = os.path.getsize(sample_path)
        mock_minio.stat_object.return_value = mock_stat
        
        # 设置fget_object行为 - 复制真实样本到临时目录
        def mock_fget_object(bucket, object_name, file_path, length=None):
            shutil.copy2(sample_path, file_path)
        mock_minio.fget_object.side_effect = mock_fget_object
        
        # 分析样本
        result = analyze_minio_pe_file(mock_minio, "test-bucket", "test.exe")
        
        # 验证结果
        assert isinstance(result, PEAnalysisResult)
        assert isinstance(result.metadata, PEMetadata)
        
        # 验证元数据
        assert result.metadata.file_size == expected_result["metadata"]["file_size"]
        assert result.metadata.file_type == expected_result["metadata"]["file_type"]
        assert result.metadata.architecture == expected_result["metadata"]["architecture"]
        assert hex(result.metadata.entry_point) == expected_result["metadata"]["entry_point"]
        assert result.metadata.machine_type == expected_result["metadata"]["machine_type"]
        assert result.metadata.subsystem == expected_result["metadata"]["subsystem"]
        assert result.metadata.dll_characteristics == expected_result["metadata"]["dll_characteristics"]
        assert result.metadata.has_signature == expected_result["metadata"]["has_signature"]
        assert result.metadata.is_packed == expected_result["metadata"]["is_packed"]
        assert result.metadata.is_encrypted == expected_result["metadata"]["is_encrypted"]
        assert result.metadata.has_suspicious_imports == expected_result["metadata"]["has_suspicious_imports"]
        assert result.metadata.has_suspicious_exports == expected_result["metadata"]["has_suspicious_exports"]
        assert result.metadata.has_suspicious_sections == expected_result["metadata"]["has_suspicious_sections"]
        assert result.metadata.pehashng == expected_result["metadata"]["pehashng"]
        assert result.metadata.tls_info == expected_result["metadata"]["tls_info"]
        assert result.metadata.debug_info == expected_result["metadata"]["debug_info"]
        
        # 验证节信息
        assert len(result.sections) == len(expected_result["sections"])
        for actual_section, expected_section in zip(result.sections, expected_result["sections"]):
            assert actual_section.name == expected_section["name"]
            assert hex(actual_section.virtual_address) == expected_section["virtual_address"]
            assert hex(actual_section.virtual_size) == expected_section["virtual_size"]
            assert hex(actual_section.raw_size) == expected_section["raw_size"]
            assert actual_section.characteristics == expected_section["characteristics"]
            assert abs(actual_section.entropy - expected_section["entropy"]) < 0.0001
            assert hex(actual_section.physical_address) == expected_section["physical_address"]
            assert hex(actual_section.physical_size) == expected_section["physical_size"]
            assert actual_section.section_hash == expected_section["section_hash"]
        
        # 验证导入信息
        assert len(result.imports) == len(expected_result["imports"])
        for actual_import, expected_import in zip(result.imports, expected_result["imports"]):
            assert actual_import.dll_name == expected_import["dll_name"]
            assert len(actual_import.functions) == len(expected_import["functions"])
            for actual_func, expected_func in zip(actual_import.functions, expected_import["functions"]):
                assert actual_func["name"] == expected_func["name"]
                assert hex(actual_func["address"]) == expected_func["address"]
            assert actual_import.function_count == expected_import["function_count"]
        
        # 验证导出信息
        assert len(result.exports) == len(expected_result["exports"])
        for actual_export, expected_export in zip(result.exports, expected_result["exports"]):
            assert actual_export.name == expected_export["name"]
            assert hex(actual_export.ordinal) == expected_export["ordinal"]
            assert hex(actual_export.address) == expected_export["address"]
            assert actual_export.function_count == expected_export["function_count"]
        
        # 验证资源信息
        assert len(result.resources) == len(expected_result["resources"])
        for actual_resource, expected_resource in zip(result.resources, expected_result["resources"]):
            assert actual_resource.name == expected_resource["name"]
            assert hex(actual_resource.size) == expected_resource["size"]
            assert hex(actual_resource.offset) == expected_resource["offset"]
            assert actual_resource.language == expected_resource["language"]
            assert actual_resource.sublanguage == expected_resource["sublanguage"]
        
        # 验证可疑特征
        assert result.suspicious_features == expected_result["suspicious_features"]
        assert result.error_message == expected_result.get("error_message")
        
        # 验证MinIO客户端调用
        assert mock_minio.stat_object.called
        assert mock_minio.fget_object.called
        
    finally:
        # 清理临时目录
        shutil.rmtree(temp_dir)

