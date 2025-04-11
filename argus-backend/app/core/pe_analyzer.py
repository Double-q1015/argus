import os
import sys
import pefile
import hashlib
import magic
import math
import tempfile
import shutil
from bz2 import compress
from struct import pack
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pydantic import BaseModel
from minio import Minio
from minio.error import S3Error
# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from app.core.pe_detectors import PECharacteristicsManager
from app.core.config import LANG_DICT, SUBLANG_DICT, RESOURCE_TYPE_DICT

class PEHeaderInfo(BaseModel):
    """PE文件头信息"""
    platform: str
    platform_name: str
    time_datestamp: int
    entrypoint: str
    image_base: str
    number_of_sections: int
    linkerversion: Tuple[int, int]
    time_datetime_utc: str

    def to_dict(self) -> Dict[str, Any]:
        """
        将PE头信息转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有PE头信息的字典
        """
        return {
            "platform": self.platform,
            "platform_name": self.platform_name,
            "time_datestamp": self.time_datetime_utc,
            "entrypoint": self.entrypoint,
            "image_base": self.image_base,
            "number_of_sections": self.number_of_sections,
            "linkerversion": self.linkerversion,
            "time_datetime_utc": self.time_datetime_utc
        }

class PEMetadata(BaseModel):
    """PE文件元数据"""
    file_size: int
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
    pehashng: str = ""  # 添加 PE 结构属性哈希
    tls_info: Dict[str, str] = {}  # 添加 TLS 信息
    debug_info: Dict[str, str] = {}  # 添加调试信息
    pe_header_info: PEHeaderInfo = None  # 添加PE头信息

    def to_dict(self) -> Dict[str, Any]:
        """
        将元数据转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有元数据的字典
        """
        return {
            "file_size": self.file_size,
            "file_type": self.file_type,
            "architecture": self.architecture,
            "entry_point": hex(self.entry_point),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "machine_type": self.machine_type,
            "subsystem": self.subsystem,
            "dll_characteristics": self.dll_characteristics,
            "has_signature": self.has_signature,
            "is_packed": self.is_packed,
            "is_encrypted": self.is_encrypted,
            "has_suspicious_imports": self.has_suspicious_imports,
            "has_suspicious_exports": self.has_suspicious_exports,
            "has_suspicious_sections": self.has_suspicious_sections,
            "pehashng": self.pehashng,
            "tls_info": self.tls_info,
            "debug_info": self.debug_info,
            "pe_header_info": self.pe_header_info.to_dict() if self.pe_header_info else None
        }

class PESection(BaseModel):
    """PE文件节信息"""
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: List[str]
    entropy: float
    physical_address: int
    physical_size: int
    section_hash: str

    def to_dict(self) -> Dict[str, Any]:
        """
        将节信息转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有节信息的字典
        """
        return {
            "name": self.name,
            "virtual_address": hex(self.virtual_address),
            "virtual_size": hex(self.virtual_size),
            "raw_size": hex(self.raw_size),
            "characteristics": self.characteristics,
            "entropy": self.entropy,
            "physical_address": hex(self.physical_address),
            "physical_size": hex(self.physical_size),
            "section_hash": self.section_hash
        }

class PEImport(BaseModel):
    """PE文件导入信息"""
    dll_name: str
    functions: List[Dict[str, Any]]
    function_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """
        将导入信息转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有导入信息的字典
        """
        return {
            "dll_name": self.dll_name,
            "functions": [{"name": func["name"], "address": hex(func["address"])} for func in self.functions],
            "function_count": self.function_count
        }

class PEExport(BaseModel):
    """PE文件导出信息"""
    name: str
    ordinal: int
    address: int
    function_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """
        将导出信息转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有导出信息的字典
        """
        return {
            "name": self.name,
            "ordinal": hex(self.ordinal),
            "address": hex(self.address),
            "function_count": self.function_count
        }

class PEResource(BaseModel):
    """PE文件资源信息"""
    name: str
    size: int
    offset: int
    language: str
    sublanguage: str

    def to_dict(self) -> Dict[str, Any]:
        """
        将资源信息转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有资源信息的字典
        """
        return {
            "name": self.name,
            "size": hex(self.size),
            "offset": hex(self.offset),
            "language": self.language,
            "sublanguage": self.sublanguage
        }

class PEAnalysisResult(BaseModel):
    """PE文件分析结果"""
    metadata: PEMetadata
    sections: List[PESection]
    imports: List[PEImport]
    exports: List[PEExport]
    resources: List[PEResource]
    suspicious_features: List[str]
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        将分析结果转换为字典格式
        
        Returns:
            Dict[str, Any]: 包含所有分析结果的字典
        """
        return {
            "metadata": self.metadata.to_dict(),
            "sections": [section.to_dict() for section in self.sections],
            "imports": [imp.to_dict() for imp in self.imports],
            "exports": [exp.to_dict() for exp in self.exports],
            "resources": [res.to_dict() for res in self.resources],
            "suspicious_features": self.suspicious_features,
            "error_message": self.error_message
        }

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

def get_resource_language(lang_id: int) -> str:
    """
    获取资源语言名称
    
    Args:
        lang_id: 语言ID
        
    Returns:
        str: 语言名称
    """
    # 主语言ID在低10位
    main_lang_id = lang_id & 0x3FF
    return LANG_DICT.get(main_lang_id, f"LANG_UNKNOWN_{main_lang_id:04x}")

def get_resource_sublanguage(lang_id: int, sublang_id: int) -> str:
    """
    获取资源子语言名称
    
    Args:
        lang_id: 语言ID
        
    Returns:
        str: 子语言名称
    """
    # 根据主语言获取对应的子语言
    if lang_id in LANG_DICT:
        lang = LANG_DICT.get(lang_id, "UNKNOWN").replace("LANG_", "")
        if lang in SUBLANG_DICT:
            return SUBLANG_DICT[lang].get(sublang_id, f"SUBLANG_UNKNOWN_{sublang_id:02x}")
    
    return f"SUBLANG_UNKNOWN_{sublang_id:02x}"

def get_resource_type(type_id: int) -> str:
    """获取资源类型名称"""
    types = RESOURCE_TYPE_DICT
    return types.get(type_id, f"RT_UNKNOWN_{type_id}")

def get_tls_info(pe: pefile.PE) -> dict:
    """
    提取PE文件的TLS（Thread Local Storage）信息。
    
    参数:
    pe - 一个PE对象，用于提取TLS信息。
    
    返回:
    一个字典，包含TLS信息的各种字段和它们对应的值。
    
    异常:
    如果提供的不是一个有效的PE对象，将抛出TypeError。
    如果在提取TLS信息过程中遇到任何错误，将抛出ValueError。
    """
    tls_info = {}
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
            tls_data = pe.DIRECTORY_ENTRY_TLS.struct
            tls_info = {
                'AddressOfCallBacks': hex(tls_data.AddressOfCallBacks),
                'AddressOfIndex': hex(tls_data.AddressOfIndex),
                'Characteristics': hex(tls_data.Characteristics),
                'EndAddressOfRawData': hex(tls_data.EndAddressOfRawData),
                'SizeOfZeroFill': hex(tls_data.SizeOfZeroFill),
                'StartAddressOfRawData': hex(tls_data.StartAddressOfRawData)
            }
    except Exception as e:
        tls_info = {}
        raise ValueError(f"Error getting TLS info: {e}")
    finally:
        return tls_info
    
def get_pehashng(pe) ->str:
    """ Return pehashng for PE file, sha256 of PE structural properties.

    :param pe_file: file name or instance of pefile.PE() class
    :return: SHA256 in hexdigest format, None in case of pefile.PE() error
    :rtype: str
    """
    data_sha256 = ""
    try:
        if isinstance(pe, pefile.PE):
            exe = pe
        else:
            raise TypeError("Error getting pshashng info: Invalid PE object")
        def align_down_p2(number):
            return 1 << (number.bit_length() - 1) if number else 0

        def align_up(number, boundary_p2):
            assert not boundary_p2 & (boundary_p2 - 1), \
                "Boundary '%d' is not a power of 2" % boundary_p2
            boundary_p2 -= 1
            return (number + boundary_p2) & ~ boundary_p2

        def get_dirs_status():
            dirs_status = 0
            for idx in range(min(exe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 16)):
                if exe.OPTIONAL_HEADER.DATA_DIRECTORY[idx].VirtualAddress:
                    dirs_status |= (1 << idx)
            return dirs_status

        def get_complexity():
            complexity = 0
            if section.SizeOfRawData:
                complexity = (len(compress(section.get_data())) *
                            7.0 /
                            section.SizeOfRawData)
                complexity = 8 if complexity > 7 else int(round(complexity))
            return complexity

        characteristics_mask = 0b0111111100100011
        data_directory_mask = 0b0111111001111111

        data = [
            pack('> H', exe.FILE_HEADER.Characteristics & characteristics_mask),
            pack('> H', exe.OPTIONAL_HEADER.Subsystem),
            pack("> I", align_down_p2(exe.OPTIONAL_HEADER.SectionAlignment)),
            pack("> I", align_down_p2(exe.OPTIONAL_HEADER.FileAlignment)),
            pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfStackCommit, 4096)),
            pack("> Q", align_up(exe.OPTIONAL_HEADER.SizeOfHeapCommit, 4096)),
            pack('> H', get_dirs_status() & data_directory_mask)]

        for section in exe.sections:
            data += [
                pack('> I', align_up(section.VirtualAddress, 512)),
                pack('> I', align_up(section.SizeOfRawData, 512)),
                pack('> B', section.Characteristics >> 24),
                pack("> B", get_complexity())]

        if not isinstance(pe, pefile.PE):
            pe.close()
        data_sha256 = hashlib.sha256(b"".join(data)).hexdigest()
    except Exception as e:
        data_sha256 = ""
        raise ValueError(f"Error getting pshashng info: {e}")
    finally:
        return data_sha256

def get_debug_info(pe: pefile.PE) -> dict:
    """
    提取可移植可执行文件（PE）中的调试信息。
    
    如果PE文件包含调试目录且其中包含指向程序数据库（PDB）文件的信息，
    则此函数会提取出PDB文件的路径以及与之相关的全局唯一标识符（GUID）。
    
    参数:
    pe - 一个PE文件对象，通常是由pefile库创建的。
    
    返回:
    一个字典，包含提取到的调试信息，主要是PDB文件路径和GUID。如果没有找到相关信息，则返回一个空字典。
    """
    debug_info = {}
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                # 检查是否为 PDB 调试信息
                if entry.struct.Type == 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    # 获取调试数据
                    debug_data = pe.get_data(entry.struct.AddressOfRawData, entry.struct.SizeOfData)
                    
                    # 检查是否为 PDB 7.0 格式
                    if debug_data.startswith(b'RSDS'):
                        # 提取 GUID
                        guid = debug_data[4:20]
                        guid_str = '-'.join([
                            guid[0:4].hex().upper(),
                            guid[4:6].hex().upper(),
                            guid[6:8].hex().upper(),
                            guid[8:10].hex().upper(),
                            guid[10:16].hex().upper()
                        ])
                        
                        # 提取 PDB 路径
                        pdb_path = debug_data[24:].split(b'\x00')[0].decode('utf-8')
                        
                        debug_info['PDB'] = pdb_path
                        debug_info['GUID'] = guid_str
                        break
                    
                    # 检查是否为 PDB 2.0 格式
                    elif debug_data.startswith(b'NB10'):
                        # 提取 PDB 路径
                        pdb_path = debug_data[16:].split(b'\x00')[0].decode('utf-8')
                        
                        debug_info['PDB'] = pdb_path
                        debug_info['GUID'] = '-'
                        break
    except Exception as e:
        debug_info = {}
        raise ValueError(f"Error getting debug info: {e}")
    finally:
        return debug_info

def get_platform_name(platform_value: int) -> str:
    """
    获取平台名称
    
    Args:
        platform_value: 平台值
        
    Returns:
        str: 平台名称
    """
    platforms = {
        0x014c: "x86",
        0x0200: "IA64",
        0x8664: "x64",
        0x01c4: "ARM",
        0xaa64: "ARM64"
    }
    return platforms.get(platform_value, f"UNKNOWN_{platform_value:04x}")

def get_pe_header_info(pe) -> dict:
    """
    获取PE文件头信息。

    从PE文件中提取头部信息，包括平台类型、时间戳、入口点地址等。

    参数:
    pe (pefile.PE): 一个PE文件对象，用于提取文件头信息。

    返回:
    dict: 包含PE文件头信息的字典，如平台类型、时间戳、入口点地址等。
          如果提取过程中发生错误，返回一个空字典。

    抛出:
    ValueError: 如果提取文件头信息时发生异常，抛出此异常。
    """
    try:
        platform_value = pe.FILE_HEADER.Machine
        pe_header_info = {
            'platform': hex(platform_value),
            'platform_name': get_platform_name(platform_value),
            'time_datestamp': pe.FILE_HEADER.TimeDateStamp,
            'entrypoint': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'number_of_sections': pe.FILE_HEADER.NumberOfSections,
            'linkerversion': (pe.OPTIONAL_HEADER.MajorLinkerVersion, pe.OPTIONAL_HEADER.MinorLinkerVersion)
        }
        # 将 TimeDateStamp 转换为 datetime
        pe_header_info['time_datetime_utc'] = datetime.utcfromtimestamp(pe_header_info['time_datestamp']).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        pe_header_info = {}
        raise ValueError(f"Error getting PE header info: {e}")
    finally:
        return pe_header_info

async def perform_pe_analysis(file_path: str) -> PEAnalysisResult:
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
                    file_size=0,
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
                suspicious_features=["文件不存在"],
                error_message="文件不存在"
            )
        
        

        # 获取文件信息
        file_size = os.path.getsize(file_path)
        
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
        
        # 获取 pehashng
        pehashng = get_pehashng(pe)
        
        # 获取 TLS 信息
        tls_info = get_tls_info(pe)
        
        # 获取调试信息
        debug_info = get_debug_info(pe)
        
        # 获取PE头信息
        pe_header_info_dict = get_pe_header_info(pe)
        pe_header_info = PEHeaderInfo(**pe_header_info_dict) if pe_header_info_dict else None
        
        # 提取节信息
        sections = []
        for section in pe.sections:
            section_data = section.get_data()
            sections.append(PESection(
                name=section.Name.decode().rstrip('\x00'),
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_size=section.SizeOfRawData,
                characteristics=get_section_characteristics(section.Characteristics),
                entropy=calculate_entropy(section_data),
                physical_address=section.PointerToRawData,
                physical_size=section.SizeOfRawData,
                section_hash=hashlib.md5(section_data).hexdigest()
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
        
        # 提取资源信息
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                # 确保 resource_lang 是 ResourceDirEntryData 对象
                                if isinstance(resource_lang, pefile.ResourceDirEntryData):
                                    # 获取资源类型名称
                                    if resource_type.name is not None:
                                        name = resource_type.name.decode('utf-8')
                                    else:
                                        name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, f"RT_UNKNOWN_{resource_type.struct.Id}")
                                    
                                    # 获取语言信息
                                    lang_id = resource_lang.data.lang
                                    sublang_id = resource_lang.data.sublang
                                    language = get_resource_language(lang_id)
                                    sublanguage = get_resource_sublanguage(lang_id, sublang_id)
                                    
                                    # 创建资源对象
                                    resources.append(PEResource(
                                        name=name,
                                        size=resource_lang.data.struct.Size,
                                        offset=resource_lang.data.struct.OffsetToData,
                                        language=language,
                                        sublanguage=sublanguage
                                    ))
        
        # 使用特征检测器进行检测
        pe_characteristics_path = os.path.join(os.path.dirname(__file__), "pe_characteristics.yaml")
        characteristics_manager = PECharacteristicsManager(pe_characteristics_path)
        suspicious_features = characteristics_manager.get_vulnerabilities(pe)
        
        # 检查是否有可疑特征
        has_suspicious_imports = any("suspicious_imports" in v for v in suspicious_features)
        has_suspicious_exports = any("suspicious_export_names" in v for v in suspicious_features)
        has_suspicious_sections = any("suspicious_section" in v for v in suspicious_features)
        is_packed = any("suspicious_section_names" in v and any(name in v for name in ["UPX0", "UPX1", "ASPack"]) for v in suspicious_features)
        is_encrypted = any("high_entropy_section" in v for v in suspicious_features)
        
        # 创建元数据对象
        metadata = PEMetadata(
            file_size=file_size,
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
            has_suspicious_imports=has_suspicious_imports,
            has_suspicious_exports=has_suspicious_exports,
            has_suspicious_sections=has_suspicious_sections,
            pehashng=pehashng,
            tls_info=tls_info,
            debug_info=debug_info,
            pe_header_info=pe_header_info
        )
        
        return PEAnalysisResult(
            metadata=metadata,
            sections=sections,
            imports=imports,
            exports=exports,
            resources=resources,
            suspicious_features=suspicious_features
        )
        
    except pefile.PEFormatError:
        return PEAnalysisResult(
            metadata=PEMetadata(
                file_size=file_size,
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
            suspicious_features=["无效的PE文件"],
            error_message="无效的PE文件"
        )
    except Exception as e:
        return PEAnalysisResult(
            metadata=PEMetadata(
                file_size=file_size,
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
            suspicious_features=["分析失败"],
            error_message=str(e)
        )

def analyze_minio_pe_file(
    minio_client: Minio,
    bucket_name: str,
    object_name: str,
    max_size: int = 1024 * 1024 * 100  # 默认最大100MB
) -> PEAnalysisResult:
    """
    从MinIO下载并分析PE文件
    
    Args:
        minio_client: MinIO客户端
        bucket_name: 存储桶名称
        object_name: 对象名称
        max_size: 最大下载大小，超过此大小将只下载前max_size字节
        
    Returns:
        PEAnalysisResult: PE文件分析结果
    """
    # 创建临时目录
    temp_dir = tempfile.mkdtemp()
    temp_file_path = os.path.join(temp_dir, object_name)
    
    try:
        # 获取对象信息
        try:
            stat = minio_client.stat_object(bucket_name, object_name)
            file_size = stat.size
        except S3Error as e:
            return PEAnalysisResult(
                metadata=PEMetadata(
                    file_size=0,
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
                suspicious_features=["无法获取MinIO对象信息"],
                error_message=f"无法获取MinIO对象信息: {str(e)}"
            )
        
        # 确定要下载的大小
        download_size = min(file_size, max_size)
        
        # 下载文件
        try:
            minio_client.fget_object(
                bucket_name,
                object_name,
                temp_file_path,
                length=download_size
            )
        except S3Error as e:
            return PEAnalysisResult(
                metadata=PEMetadata(
                    file_size=file_size,
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
                suspicious_features=["无法下载MinIO对象"],
                error_message=f"无法下载MinIO对象: {str(e)}"
            )
        
        # 分析PE文件
        result = perform_pe_analysis(temp_file_path)
        
        # 如果下载的文件大小小于实际文件大小，添加警告
        if download_size < file_size:
            result.suspicious_features.append(f"文件被截断（仅分析前 {download_size} 字节）")
        
        return result
        
    except Exception as e:
        return PEAnalysisResult(
            metadata=PEMetadata(
                file_size=0,
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
            suspicious_features=["分析失败"],
            error_message=str(e)
        )
    finally:
        # 清理临时文件
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass  # 忽略清理错误

if __name__ == "__main__":
    # 测试calculate_pehashng
    import json
    file_path = "tests/data/samples/malware/004ad8ce84b9ab95d4c38a9d7b23dce68d134c696c1362625ad38153b48038e5"
    pe_analysis_result = perform_pe_analysis(file_path)
    print(f"PE分析结果: {json.dumps(pe_analysis_result.to_dict(), indent=4)}")