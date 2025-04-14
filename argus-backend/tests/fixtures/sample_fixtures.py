"""样本文件信息管理

本模块集中管理所有测试样本文件的信息，包括文件路径、类型、大小等元数据。
"""

import os
from pathlib import Path
from typing import Dict, Any

# 定义样本文件根目录
SAMPLES_ROOT = Path(__file__).parent.parent / "data/samples"

# 恶意软件样本
MALWARE_SAMPLES = {
    "win32_exe": {
        "name": "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5",
        "path": str(SAMPLES_ROOT / "malware" / "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"),
        "exiftools_info": {
            "ExifToolVersion": "13.1",
            "FilePermissions": 100644,
            "FilePermissionsStr": "-rw-r--r--",
        "size": 14896,
            "type": "Win32 EXE",
            "extension": "EXE",
            "mime_type": "application/octet-stream",
            "machine_type": "0x14c",
            "machine_type_description": "Intel 386 or later processors and compatible processors",
            "image_file_characteristics": 258,
            "image_file_characteristics_description": ["Executable", "32-bit"],
            "pe_type": 267,
            "pe_type_description": "PE32",
            "linker_version": "10.0",
            "code_size": 4096,
            "initialized_data_size": 5632,
            "uninitialized_data_size": 0,
            "entry_point": "0x1a0c",
            "os_version": "5.1",
            "image_version": "0.0",
            "subsystem_version": "5.1",
            "subsystem": 3,
            "subsystem_description": "Windows command line",
        },
        'pe_analysis_result': {
            "metadata": {
                "file_size": 14896,
                "file_type": "PE32 executable (console) Intel 80386, for MS Windows, 5 sections",
                "architecture": "x86",
                "entry_point": "0x1a0c",
                "timestamp": "2012-08-11T00:14:27",
                "machine_type": "I386",
                "subsystem": "WINDOWS_CONSOLE",
                "dll_characteristics": [
                    "DYNAMIC_BASE",
                    "TERMINAL_SERVER_AWARE"
                ],
                "has_signature": False,
                "is_packed": False,
                "is_encrypted": False,
                "has_suspicious_imports": True,
                "has_suspicious_exports": False,
                "has_suspicious_sections": False,
            "pehashng": "5f9a88f0f6969e294313fd8413845b0eef6379c5e2a9ed05a740741bc779f05f",
                "tls_info": {},
                "debug_info": {
                    "PDB": "C:\\ping_pong\\win_client\\Release\\win_client.pdb",
                    "GUID": "6062C1CC-D667-6948-B547-55A58A833594"
                },
                "pe_header_info": {
                    "platform": "0x14c",
                    "platform_name": "x86",
                    "time_datestamp": "2012-08-10 16:14:27",
                    "entrypoint": "0x1a0c",
                    "image_base": "0x400000",
                    "number_of_sections": 5,
                    "linkerversion": [
                        10,
                        0
                    ],
                    "time_datetime_utc": "2012-08-10 16:14:27"
                }
            },
            "sections": [
                {
                    "name": ".text",
                    "virtual_address": "0x1000",
                    "virtual_size": "0xf5a",
                    "raw_size": "0x1000",
                    "characteristics": [
                        "CODE",
                        "EXECUTE",
                        "READ"
                    ],
                    "entropy": 6.004661832472822,
                    "physical_address": "0x400",
                    "physical_size": "0x1000",
                    "section_hash": "11e71d6b64d3f84fd96375bec2a90941"
                },
                {
                    "name": ".rdata",
                    "virtual_address": "0x2000",
                    "virtual_size": "0xd6c",
                    "raw_size": "0xe00",
                    "characteristics": [
                        "INITIALIZED_DATA",
                        "READ"
                    ],
                    "entropy": 5.0861394628944625,
                    "physical_address": "0x1400",
                    "physical_size": "0xe00",
                    "section_hash": "4e808bd6fbb49b84e2b248c5c9c480a1"
                },
                {
                    "name": ".data",
                    "virtual_address": "0x3000",
                    "virtual_size": "0x394",
                    "raw_size": "0x200",
                    "characteristics": [
                        "INITIALIZED_DATA",
                        "READ",
                        "WRITE"
                    ],
                    "entropy": 0.3840168641038749,
                    "physical_address": "0x2200",
                    "physical_size": "0x200",
                    "section_hash": "09d5436bea5eda2762b499561f060d95"
                },
                {
                    "name": ".rsrc",
                    "virtual_address": "0x4000",
                    "virtual_size": "0x1b4",
                    "raw_size": "0x200",
                    "characteristics": [
                        "INITIALIZED_DATA",
                        "READ"
                    ],
                    "entropy": 5.097979088823027,
                    "physical_address": "0x2400",
                    "physical_size": "0x200",
                    "section_hash": "04e3534c39fb38c8dc21bcd423a64b95"
                },
                {
                    "name": ".reloc",
                    "virtual_address": "0x5000",
                    "virtual_size": "0x2ae",
                    "raw_size": "0x400",
                    "characteristics": [
                        "INITIALIZED_DATA",
                        "READ"
                    ],
                    "entropy": 4.217332307966828,
                    "physical_address": "0x2600",
                    "physical_size": "0x400",
                    "section_hash": "5dd96ab397b2c6a3cf2decf25f08d928"
                }
            ],
            "imports": [
                {
                    "dll_name": "KERNEL32.dll",
                    "functions": [
                        {
                            "name": "Sleep",
                            "address": "0x402000"
                        },
                        {
                            "name": "CreateProcessA",
                            "address": "0x402004"
                        },
                        {
                            "name": "GetTempFileNameA",
                            "address": "0x402008"
                        },
                        {
                            "name": "GetModuleFileNameA",
                            "address": "0x40200c"
                        },
                        {
                            "name": "CloseHandle",
                            "address": "0x402010"
                        },
                        {
                            "name": "GetTempPathA",
                            "address": "0x402014"
                        },
                        {
                            "name": "GetSystemTimeAsFileTime",
                            "address": "0x402018"
                        },
                        {
                            "name": "GetCurrentProcessId",
                            "address": "0x40201c"
                        },
                        {
                            "name": "GetCurrentThreadId",
                            "address": "0x402020"
                        },
                        {
                            "name": "GetTickCount",
                            "address": "0x402024"
                        },
                        {
                            "name": "QueryPerformanceCounter",
                            "address": "0x402028"
                        },
                        {
                            "name": "DecodePointer",
                            "address": "0x40202c"
                        },
                        {
                            "name": "IsDebuggerPresent",
                            "address": "0x402030"
                        },
                        {
                            "name": "SetUnhandledExceptionFilter",
                            "address": "0x402034"
                        },
                        {
                            "name": "UnhandledExceptionFilter",
                            "address": "0x402038"
                        },
                        {
                            "name": "GetCurrentProcess",
                            "address": "0x40203c"
                        },
                        {
                            "name": "TerminateProcess",
                            "address": "0x402040"
                        },
                        {
                            "name": "EncodePointer",
                            "address": "0x402044"
                        },
                        {
                            "name": "InterlockedCompareExchange",
                            "address": "0x402048"
                        },
                        {
                            "name": "InterlockedExchange",
                            "address": "0x40204c"
                        },
                        {
                            "name": "HeapSetInformation",
                            "address": "0x402050"
                        }
                    ],
                    "function_count": 0
                },
                {
                    "dll_name": "SHELL32.dll",
                    "functions": [
                        {
                            "name": "ShellExecuteA",
                            "address": "0x4020f0"
                        }
                    ],
                    "function_count": 0
                },
                {
                    "dll_name": "WS2_32.dll",
                    "functions": [
                        {
                            "name": "inet_addr",
                            "address": "0x4020f8"
                        },
                        {
                            "name": "WSAGetLastError",
                            "address": "0x4020fc"
                        },
                        {
                            "name": "htons",
                            "address": "0x402100"
                        },
                        {
                            "name": "WSAStartup",
                            "address": "0x402104"
                        },
                        {
                            "name": "recv",
                            "address": "0x402108"
                        },
                        {
                            "name": "socket",
                            "address": "0x40210c"
                        },
                        {
                            "name": "send",
                            "address": "0x402110"
                        },
                        {
                            "name": "connect",
                            "address": "0x402114"
                        },
                        {
                            "name": "WSACleanup",
                            "address": "0x402118"
                        }
                    ],
                    "function_count": 0
                },
                {
                    "dll_name": "MSVCR100.dll",
                    "functions": [
                        {
                            "name": "printf",
                            "address": "0x402058"
                        },
                        {
                            "name": "fopen",
                            "address": "0x40205c"
                        },
                        {
                            "name": "fread",
                            "address": "0x402060"
                        },
                        {
                            "name": "rand",
                            "address": "0x402064"
                        },
                        {
                            "name": "srand",
                            "address": "0x402068"
                        },
                        {
                            "name": "fwrite",
                            "address": "0x40206c"
                        },
                        {
                            "name": "ftell",
                            "address": "0x402070"
                        },
                        {
                            "name": "fseek",
                            "address": "0x402074"
                        },
                        {
                            "name": "fclose",
                            "address": "0x402078"
                        },
                        {
                            "name": "_time64",
                            "address": "0x40207c"
                        },
                        {
                            "name": "_snprintf",
                            "address": "0x402080"
                        },
                        {
                            "name": "_amsg_exit",
                            "address": "0x402084"
                        },
                        {
                            "name": "__getmainargs",
                            "address": "0x402088"
                        },
                        {
                            "name": "_cexit",
                            "address": "0x40208c"
                        },
                        {
                            "name": "_exit",
                            "address": "0x402090"
                        },
                        {
                            "name": "_XcptFilter",
                            "address": "0x402094"
                        },
                        {
                            "name": "exit",
                            "address": "0x402098"
                        },
                        {
                            "name": "__initenv",
                            "address": "0x40209c"
                        },
                        {
                            "name": "_initterm",
                            "address": "0x4020a0"
                        },
                        {
                            "name": "_initterm_e",
                            "address": "0x4020a4"
                        },
                        {
                            "name": "_configthreadlocale",
                            "address": "0x4020a8"
                        },
                        {
                            "name": "__setusermatherr",
                            "address": "0x4020ac"
                        },
                        {
                            "name": "_commode",
                            "address": "0x4020b0"
                        },
                        {
                            "name": "_fmode",
                            "address": "0x4020b4"
                        },
                        {
                            "name": "__set_app_type",
                            "address": "0x4020b8"
                        },
                        {
                            "name": "_crt_debugger_hook",
                            "address": "0x4020bc"
                        },
                        {
                            "name": "?terminate@@YAXXZ",
                            "address": "0x4020c0"
                        },
                        {
                            "name": "_unlock",
                            "address": "0x4020c4"
                        },
                        {
                            "name": "__dllonexit",
                            "address": "0x4020c8"
                        },
                        {
                            "name": "_lock",
                            "address": "0x4020cc"
                        },
                        {
                            "name": "_onexit",
                            "address": "0x4020d0"
                        },
                        {
                            "name": "_except_handler4_common",
                            "address": "0x4020d4"
                        },
                        {
                            "name": "_invoke_watson",
                            "address": "0x4020d8"
                        },
                        {
                            "name": "_controlfp_s",
                            "address": "0x4020dc"
                        },
                        {
                            "name": "atoi",
                            "address": "0x4020e0"
                        },
                        {
                            "name": "malloc",
                            "address": "0x4020e4"
                        },
                        {
                            "name": "memset",
                            "address": "0x4020e8"
                        }
                    ],
                    "function_count": 0
                }
            ],
            "exports": [],
            "resources": [
                {
                    "name": "RT_MANIFEST",
                    "size": "0x15a",
                    "offset": "0x4058",
                    "language": "LANG_ENGLISH",
                    "sublanguage": "SUBLANG_ENGLISH_US"
                }
            ],
            "suspicious_features": [
                "suspicious_imports: ws2_32.dll -> socket",
                "suspicious_imports: ws2_32.dll -> connect"
            ],
            "error_message": None
        },
        "description": "Windows可执行文件样本，用于测试ExifTool分析器的文件分析功能",
        "hash": "004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5",
        "is_malware": True,
        "tags": ["windows", "executable", "pe", "malware"]
    }
}

# 图片样本
IMAGE_SAMPLES = {
    "jpeg": {
        "name": "sample.jpg",
        "path": str(SAMPLES_ROOT / "images" / "sample.jpg"),
        "type": "JPEG",
        "extension": "JPG",
        "size": 1024,
        "mime_type": "image/jpeg",
        "description": "JPEG图片样本，用于测试ExifTool分析器的图片分析功能",
        "is_malware": False,
        "tags": ["image", "jpeg", "photo"]
    }
}

# PDF样本
PDF_SAMPLES = {
    "pdf": {
        "name": "sample.pdf",
        "path": str(SAMPLES_ROOT / "documents" / "sample.pdf"),
        "type": "PDF",
        "extension": "PDF",
        "size": 2048,
        "mime_type": "application/pdf",
        "description": "PDF文档样本，用于测试ExifTool分析器的文档分析功能",
        "is_malware": False,
        "tags": ["document", "pdf", "text"]
    }
}

# 合并所有样本
ALL_SAMPLES = {
    **MALWARE_SAMPLES,
    **IMAGE_SAMPLES,
    **PDF_SAMPLES
}

# 获取样本路径
def get_sample_path(sample_id: str) -> str:
    """获取样本文件路径
    
    Args:
        sample_id: 样本ID，如 'win32_exe'
        
    Returns:
        样本文件的完整路径
    """
    if sample_id not in ALL_SAMPLES:
        raise KeyError(f"样本ID '{sample_id}' 不存在")
    
    return ALL_SAMPLES[sample_id]["path"]

# 获取样本信息
def get_sample_info(sample_id: str) -> Dict[str, Any]:
    """获取样本文件的完整信息
    
    Args:
        sample_id: 样本ID，如 'win32_exe'
        
    Returns:
        样本文件的完整信息字典
    """
    if sample_id not in ALL_SAMPLES:
        raise KeyError(f"样本ID '{sample_id}' 不存在")
    
    return ALL_SAMPLES[sample_id]

# 检查样本文件是否存在
def check_sample_exists(sample_id: str) -> bool:
    """检查样本文件是否存在
    
    Args:
        sample_id: 样本ID，如 'win32_exe'
        
    Returns:
        样本文件是否存在
    """
    if sample_id not in ALL_SAMPLES:
        return False
    
    return os.path.exists(ALL_SAMPLES[sample_id]["path"])

# 获取所有恶意软件样本
def get_malware_samples() -> Dict[str, Dict[str, Any]]:
    """获取所有恶意软件样本
    
    Returns:
        恶意软件样本字典
    """
    return MALWARE_SAMPLES

# 获取所有图片样本
def get_image_samples() -> Dict[str, Dict[str, Any]]:
    """获取所有图片样本
    
    Returns:
        图片样本字典
    """
    return IMAGE_SAMPLES

# 获取所有PDF样本
def get_pdf_samples() -> Dict[str, Dict[str, Any]]:
    """获取所有PDF样本
    
    Returns:
        PDF样本字典
    """
    return PDF_SAMPLES

# 兼容性函数，用于支持旧的导入
def sample_files() -> Dict[str, str]:
    """返回测试样本文件的路径（兼容旧代码）
    
    Returns:
        样本文件路径字典
    """
    return {sample_id: sample_info["path"] for sample_id, sample_info in ALL_SAMPLES.items()}

# 兼容性函数，用于支持旧的导入
def sample_metadata() -> Dict[str, Dict[str, Any]]:
    """返回测试样本的元数据（兼容旧代码）
    
    Returns:
        样本元数据字典
    """
    return ALL_SAMPLES

