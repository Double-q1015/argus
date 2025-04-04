from typing import Dict, List, Optional, Any
from pydantic import BaseModel
import os
import pefile
import hashlib
import magic
import yara
import re
import math
from datetime import datetime

class PEMetadata(BaseModel):
    """PE文件元数据"""
    file_path: str
    file_size: int
    md5: str
    sha1: str
    sha256: str
    file_type: str
    architecture: str
    entry_point: int
    timestamp: datetime
    machine_type: str
    subsystem: str
    dll_characteristics: List[str]
    has_signature: bool
    is_packed: bool
    is_encrypted: bool
    has_suspicious_imports: bool
    has_suspicious_exports: bool
    has_suspicious_sections: bool

class PESection(BaseModel):
    """PE文件节信息"""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_data: bytes
    characteristics: List[str]
    entropy: float

class PEImport(BaseModel):
    """PE文件导入信息"""
    dll_name: str
    functions: List[Dict[str, Any]]

class PEExport(BaseModel):
    """PE文件导出信息"""
    name: str
    ordinal: int
    address: int

class PEAnalysisResult(BaseModel):
    """PE文件分析结果"""
    metadata: PEMetadata
    sections: List[PESection]
    imports: List[PEImport]
    exports: List[PEExport]
    strings: List[str]
    yara_matches: List[Dict[str, Any]]
    vulnerabilities: List[str]
    error_message: Optional[str] = None

def calculate_entropy(data: bytes) -> float:
    """计算数据的熵值"""
    if not data:
        return 0.0
    
    # 计算每个字节的频率
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    
    # 计算熵值
    entropy = 0.0
    for count in freq.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    
    return entropy

def get_section_characteristics(characteristics: int) -> List[str]:
    """获取节特征列表"""
    chars = []
    if characteristics & 0x20:  # IMAGE_SCN_CNT_CODE
        chars.append("CODE")
    if characteristics & 0x40:  # IMAGE_SCN_CNT_INITIALIZED_DATA
        chars.append("INITIALIZED_DATA")
    if characteristics & 0x80:  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
        chars.append("UNINITIALIZED_DATA")
    if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        chars.append("EXECUTE")
    if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
        chars.append("READ")
    if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
        chars.append("WRITE")
    return chars

def get_dll_characteristics(characteristics: int) -> List[str]:
    """获取DLL特征列表"""
    chars = []
    if characteristics & 0x0020:  # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
        chars.append("HIGH_ENTROPY_VA")
    if characteristics & 0x0100:  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
        chars.append("DYNAMIC_BASE")
    if characteristics & 0x0200:  # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
        chars.append("FORCE_INTEGRITY")
    if characteristics & 0x0400:  # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
        chars.append("NX_COMPAT")
    if characteristics & 0x0800:  # IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
        chars.append("NO_ISOLATION")
    if characteristics & 0x1000:  # IMAGE_DLLCHARACTERISTICS_NO_SEH
        chars.append("NO_SEH")
    if characteristics & 0x2000:  # IMAGE_DLLCHARACTERISTICS_NO_BIND
        chars.append("NO_BIND")
    if characteristics & 0x4000:  # IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
        chars.append("WDM_DRIVER")
    if characteristics & 0x8000:  # IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
        chars.append("TERMINAL_SERVER_AWARE")
    return chars

def get_subsystem_name(subsystem: int) -> str:
    """获取子系统名称"""
    subsystems = {
        0: "UNKNOWN",
        1: "NATIVE",
        2: "WINDOWS_GUI",
        3: "WINDOWS_CONSOLE",
        5: "OS2_CONSOLE",
        7: "POSIX_CONSOLE",
        9: "WINDOWS_CE_GUI",
        14: "XBOX"
    }
    return subsystems.get(subsystem, "UNKNOWN")

def get_machine_type(machine: int) -> str:
    """获取机器类型"""
    machines = {
        0x014c: "I386",
        0x0200: "IA64",
        0x8664: "AMD64",
        0x01c4: "ARM",
        0xaa64: "ARM64"
    }
    return machines.get(machine, "UNKNOWN")

def extract_strings(data: bytes, min_length: int = 4) -> List[str]:
    """提取可打印字符串"""
    strings = []
    current_string = ""
    
    for byte in data:
        if 32 <= byte <= 126:  # 可打印ASCII字符
            current_string += chr(byte)
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""
    
    if len(current_string) >= min_length:
        strings.append(current_string)
    
    return strings

def analyze_pe_file(file_path: str) -> PEAnalysisResult:
    """
    分析PE文件
    
    Args:
        file_path: PE文件路径
        
    Returns:
        PEAnalysisResult: PE文件分析结果
    """
    try:
        # 检查文件是否存在
        if not os.path.exists(file_path):
            return PEAnalysisResult(
                metadata=PEMetadata(
                    file_path=file_path,
                    file_size=0,
                    md5="",
                    sha1="",
                    sha256="",
                    file_type="unknown",
                    architecture="unknown",
                    entry_point=0,
                    timestamp=datetime.now(),
                    machine_type="unknown",
                    subsystem="unknown",
                    dll_characteristics=[],
                    has_signature=False,
                    is_packed=False,
                    is_encrypted=False,
                    has_suspicious_imports=False,
                    has_suspicious_exports=False,
                    has_suspicious_sections=False
                ),
                sections=[],
                imports=[],
                exports=[],
                strings=[],
                yara_matches=[],
                vulnerabilities=["文件不存在"],
                error_message="文件不存在"
            )

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        
        # 计算哈希值
        with open(file_path, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
        
        # 获取文件类型
        file_type = magic.from_file(file_path)
        
        # 打开PE文件
        pe = pefile.PE(file_path)
        
        # 提取基本信息
        architecture = "x64" if pe.OPTIONAL_HEADER.Magic == 0x20b else "x86"
        entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        timestamp = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
        machine_type = get_machine_type(pe.FILE_HEADER.Machine)
        subsystem = get_subsystem_name(pe.OPTIONAL_HEADER.Subsystem)
        dll_characteristics = get_dll_characteristics(pe.OPTIONAL_HEADER.DllCharacteristics)
        
        # 提取节信息
        sections = []
        for section in pe.sections:
            section_data = section.get_data()
            sections.append(PESection(
                name=section.Name.decode().rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                raw_data=section_data,
                characteristics=get_section_characteristics(section.Characteristics),
                entropy=calculate_entropy(section_data)
            ))
        
        # 提取导入信息
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append({
                            "name": imp.name.decode(),
                            "address": imp.address
                        })
                imports.append(PEImport(
                    dll_name=entry.dll.decode(),
                    functions=functions
                ))
        
        # 提取导出信息
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(PEExport(
                        name=exp.name.decode(),
                        ordinal=exp.ordinal,
                        address=exp.address
                    ))
        
        # 提取字符串
        strings = []
        for section in sections:
            strings.extend(extract_strings(section.raw_data))
        
        # 检查可疑特征
        vulnerabilities = []
        suspicious_imports = False
        suspicious_exports = False
        suspicious_sections = False
        is_packed = False
        is_encrypted = False
        
        # 检查可疑导入
        suspicious_dlls = [
            "kernel32.dll", "advapi32.dll", "ws2_32.dll",
            "wininet.dll", "urlmon.dll", "ole32.dll"
        ]
        suspicious_functions = [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc",
            "socket", "connect", "InternetOpenUrl", "URLDownloadToFile",
            "CoCreateInstance", "ShellExecute"
        ]
        
        for imp in imports:
            if imp.dll_name.lower() in suspicious_dlls:
                for func in imp.functions:
                    if func["name"] in suspicious_functions:
                        suspicious_imports = True
                        vulnerabilities.append(f"可疑导入: {imp.dll_name} -> {func['name']}")
        
        # 检查可疑导出
        suspicious_export_names = [
            "DllMain", "CreateRemoteThread", "WriteProcessMemory",
            "VirtualAlloc", "socket", "connect"
        ]
        
        for exp in exports:
            if exp.name in suspicious_export_names:
                suspicious_exports = True
                vulnerabilities.append(f"可疑导出: {exp.name}")
        
        # 检查可疑节
        for section in sections:
            # 检查节名
            if section.name in ["UPX0", "UPX1", "ASPack"]:
                is_packed = True
                vulnerabilities.append(f"可疑节名: {section.name}")
            
            # 检查节特征
            if "EXECUTE" in section.characteristics and "WRITE" in section.characteristics:
                suspicious_sections = True
                vulnerabilities.append(f"可疑节特征: {section.name} 同时具有执行和写入权限")
            
            # 检查熵值
            if section.entropy > 7.0:  # 高熵值通常表示加密或压缩
                is_encrypted = True
                vulnerabilities.append(f"高熵值节: {section.name} (熵值: {section.entropy:.2f})")
        
        # 创建元数据对象
        metadata = PEMetadata(
            file_path=file_path,
            file_size=file_size,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            file_type=file_type,
            architecture=architecture,
            entry_point=entry_point,
            timestamp=timestamp,
            machine_type=machine_type,
            subsystem=subsystem,
            dll_characteristics=dll_characteristics,
            has_signature=hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'),
            is_packed=is_packed,
            is_encrypted=is_encrypted,
            has_suspicious_imports=suspicious_imports,
            has_suspicious_exports=suspicious_exports,
            has_suspicious_sections=suspicious_sections
        )
        
        # 添加漏洞警告
        if is_packed:
            vulnerabilities.append("文件可能被加壳")
        if is_encrypted:
            vulnerabilities.append("文件可能被加密")
        if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            vulnerabilities.append("文件包含数字签名")
        
        return PEAnalysisResult(
            metadata=metadata,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
            yara_matches=[],  # TODO: 实现YARA规则匹配
            vulnerabilities=vulnerabilities
        )
        
    except pefile.PEFormatError:
        return PEAnalysisResult(
            metadata=PEMetadata(
                file_path=file_path,
                file_size=file_size,
                md5="",
                sha1="",
                sha256="",
                file_type="unknown",
                architecture="unknown",
                entry_point=0,
                timestamp=datetime.now(),
                machine_type="unknown",
                subsystem="unknown",
                dll_characteristics=[],
                has_signature=False,
                is_packed=False,
                is_encrypted=False,
                has_suspicious_imports=False,
                has_suspicious_exports=False,
                has_suspicious_sections=False
            ),
            sections=[],
            imports=[],
            exports=[],
            strings=[],
            yara_matches=[],
            vulnerabilities=["无效的PE文件"],
            error_message="无效的PE文件"
        )
    except Exception as e:
        return PEAnalysisResult(
            metadata=PEMetadata(
                file_path=file_path,
                file_size=file_size,
                md5="",
                sha1="",
                sha256="",
                file_type="unknown",
                architecture="unknown",
                entry_point=0,
                timestamp=datetime.now(),
                machine_type="unknown",
                subsystem="unknown",
                dll_characteristics=[],
                has_signature=False,
                is_packed=False,
                is_encrypted=False,
                has_suspicious_imports=False,
                has_suspicious_exports=False,
                has_suspicious_sections=False
            ),
            sections=[],
            imports=[],
            exports=[],
            strings=[],
            yara_matches=[],
            vulnerabilities=["分析失败"],
            error_message=str(e)
        ) 