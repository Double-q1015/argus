import exiftool
import os
import tempfile
from typing import Dict, Any, Optional, List
from minio import Minio
from app.core.config import settings
from app.models.exiftool import ExifToolMetadata

# 机器类型映射
MACHINE_TYPE_MAPPING = {
    0x014C: "Intel 386 or later processors and compatible processors",
    0x0162: "MIPS little-endian, 0x160 big-endian",
    0x0166: "MIPS with FPU",
    0x0168: "MIPS16 with FPU",
    0x0169: "MIPS little-endian WCE v2",
    0x0184: "Alpha_AXP",
    0x01A2: "SH3 little-endian",
    0x01A3: "SH3 DSP",
    0x01A4: "SH3E little-endian",
    0x01A6: "SH4 little-endian",
    0x01A8: "SH5",
    0x01C0: "ARM Little-Endian",
    0x01C2: "ARM Thumb/Thumb-2 Little-Endian",
    0x01C4: "ARM Thumb-2 Little-Endian",
    0x01D3: "TAM33BD",
    0x01F0: "IBM PowerPC Little-Endian",
    0x01F1: "POWERPCFP",
    0x0200: "Intel 64",
    0x0266: "MIPS",
    0x0284: "ALPHA64 / AXP64",
    0x0366: "MIPS with FPU",
    0x0466: "MIPS16 with FPU",
    0x0520: "ARM64 Little-Endian",
    0x0CEF: "CEF",
    0x0EBC: "EFI Byte Code",
    0x8664: "AMD64 (K8)",
    0x9041: "M32R little-endian",
    0xAA64: "ARM64 Little-Endian",
    0xC0EE: "CEE"
}

# PE文件特征映射
IMAGE_FILE_CHARACTERISTICS = {
    0x0001: "Relocation info stripped",
    0x0002: "Executable",
    0x0004: "Line numbers stripped",
    0x0008: "Local symbols stripped",
    0x0010: "Aggressive trim working set",
    0x0020: "Large address aware",
    0x0040: "Reserved",
    0x0080: "Bytes reversed lo",
    0x0100: "32-bit",
    0x0200: "Debug stripped",
    0x0400: "Run from swap if copy",
    0x0800: "Net run from swap",
    0x1000: "System file",
    0x2000: "DLL file",
    0x4000: "Uniprocessor only",
    0x8000: "Bytes reversed hi"
}

# PE类型映射
PE_TYPE_MAPPING = {
    267: "PE32",  # 0x10b
    523: "PE32+", # 0x20b
    263: "ROM Image"
}

# 子系统类型映射
SUBSYSTEM_MAPPING = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows command line",
    5: "OS/2 command line",
    7: "POSIX command line",
    8: "Native Win9x driver",
    9: "Windows CE GUI",
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM",
    14: "XBOX",
    16: "Windows boot application"
}

def convert_permissions(octal_permission: int) -> str:
    """
    将octal权限表示法转换为标准Linux文件权限表示法
    :param octal_permission: int, 八进制文件权限，例如 100644
    :return: str, 标准文件权限，例如 -rw-r--r--
    """
    # 权限类型前缀映射
    type_mapping = {
        '1': '-',  # 普通文件
        '2': 'c',  # 字符设备
        '4': 'd',  # 目录
        '6': 'b',  # 块设备
        '10': '-', # 普通文件
    }

    # 拆解 100644
    octal_str = str(octal_permission)
    file_type = type_mapping.get(octal_str[:1], '-')
    permission_bits = octal_str[-3:]

    # 权限位映射
    permission_mapping = {
        '0': '---',
        '1': '--x',
        '2': '-w-',
        '3': '-wx',
        '4': 'r--',
        '5': 'r-x',
        '6': 'rw-',
        '7': 'rwx',
    }

    # 转换每一部分权限
    permissions = ''.join(permission_mapping[digit] for digit in permission_bits)

    return f"{file_type}{permissions}"

def convert_machine_type(hex_value: Any) -> str:
    """
    将机器类型值转换为可读的描述
    :param hex_value: Any, 机器类型值，可能是整数或十六进制字符串
    :return: str, 可读的机器类型描述
    """
    try:
        # 如果已经是整数，直接使用
        if isinstance(hex_value, int):
            value = hex_value
        # 如果是字符串，尝试转换为整数
        elif isinstance(hex_value, str):
            # 移除可能存在的 "0x" 前缀
            hex_str = hex_value.lower().replace("0x", "")
            value = int(hex_str, 16)
        else:
            return f"Invalid machine type value type: {type(hex_value)}"
            
        return MACHINE_TYPE_MAPPING.get(value, f"Unknown machine type: {hex_value}")
    except ValueError:
        return f"Invalid machine type value: {hex_value}"

def convert_characteristics(value: int) -> List[str]:
    """
    将PE文件特征值转换为可读的描述列表
    :param value: int, 特征值
    :return: list[str], 特征描述列表
    """
    characteristics = []
    for bit, description in IMAGE_FILE_CHARACTERISTICS.items():
        if value & bit:
            characteristics.append(description)
    return characteristics if characteristics else ["No characteristics"]

def convert_pe_type(value: int) -> str:
    """
    将PE类型值转换为可读的描述
    :param value: int, PE类型值
    :return: str, PE类型描述
    """
    return PE_TYPE_MAPPING.get(value, f"Unknown PE type: {value}")

def convert_subsystem(value: int) -> str:
    """
    将子系统类型值转换为可读的描述
    :param value: int, 子系统类型值
    :return: str, 子系统类型描述
    """
    return SUBSYSTEM_MAPPING.get(value, f"Unknown subsystem: {value}")

async def perform_exiftool_analysis(minio_client: Optional[Minio] = None, 
                                  bucket_name: Optional[str] = None, object_name: Optional[str] = None, file_path: Optional[str] = None) -> ExifToolMetadata:
    """
    使用 exiftool 分析文件元数据
    :param file_path: str, 本地文件路径
    :param minio_client: Optional[Minio], MinIO 客户端
    :param bucket_name: Optional[str], 存储桶名称
    :param object_name: Optional[str], 对象名称
    :return: ExifToolMetadata, 元数据信息
    """
    # 如果是对象存储
    if minio_client and bucket_name and object_name:
        # 创建临时文件
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
            
            try:
                # 下载对象到临时文件
                minio_client.fget_object(bucket_name, object_name, temp_path)
                
                # 分析临时文件
                result = await _analyze_file(temp_path)
                
                # 添加对象存储的元数据
                try:
                    stat = minio_client.stat_object(bucket_name, object_name)
                    result["ObjectSize"] = stat.size
                    result["ObjectLastModified"] = stat.last_modified
                    result["ObjectETag"] = stat.etag
                except Exception as e:
                    print(f"Warning: Could not get object stats: {e}")
                
                return ExifToolMetadata.from_exiftool_output(result)
            finally:
                # 清理临时文件
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
    # 如果是本地文件
    elif file_path and os.path.exists(file_path):
        result = await _analyze_file(file_path)
        return ExifToolMetadata.from_exiftool_output(result)
    else:
        raise FileNotFoundError(f"File not found: {file_path}")

async def _analyze_file(file_path: str) -> Dict[str, Any]:
    """
    分析本地文件的元数据
    :param file_path: str, 文件路径
    :return: Dict[str, Any], 元数据信息
    """
    metadata_dict = {}
    try:
        with exiftool.ExifToolHelper() as et:
            metadata = et.get_metadata([file_path])
            for d in metadata:
                file_info = {
                    "ExifToolVersion": d.get("ExifTool:ExifToolVersion", "N/A"),
                    "FileSize": d.get("File:FileSize", "N/A"),
                    "FileModifyDate": d.get("File:FileModifyDate", "N/A"),
                    "FileAccessDate": d.get("File:FileAccessDate", "N/A"),
                    "FileInodeChangeDate": d.get("File:FileInodeChangeDate", "N/A"),
                    "FilePermissions": d.get("File:FilePermissions", "N/A"),
                    "FileType": d.get("File:FileType", "N/A"),
                    "FileTypeExtension": d.get("File:FileTypeExtension", "N/A"),
                    "MIMEType": d.get("File:MIMEType", "N/A"),
                    "MachineType": d.get("EXE:MachineType", "N/A"),
                    "TimeStamp": d.get("EXE:TimeStamp", "N/A"),
                    "ImageFileCharacteristics": d.get("EXE:ImageFileCharacteristics", "N/A"),
                    "PEType": d.get("EXE:PEType", "N/A"),
                    "LinkerVersion": d.get("EXE:LinkerVersion", "N/A"),
                    "CodeSize": d.get("EXE:CodeSize", "N/A"),
                    "InitializedDataSize": d.get("EXE:InitializedDataSize", "N/A"),
                    "UninitializedDataSize": d.get("EXE:UninitializedDataSize", "N/A"),
                    "EntryPoint": d.get("EXE:EntryPoint", "N/A"),
                    "OSVersion": d.get("EXE:OSVersion", "N/A"),
                    "ImageVersion": d.get("EXE:ImageVersion", "N/A"),
                    "SubsystemVersion": d.get("EXE:SubsystemVersion", "N/A"),
                    "Subsystem": d.get("EXE:Subsystem", "N/A")
                }
                
                # EntryPoint 转为hex
                if file_info["EntryPoint"] != "N/A":
                    file_info["EntryPoint"] = hex(file_info["EntryPoint"])
                
                # 转换权限
                if file_info["FilePermissions"] != "N/A":
                    file_info["FilePermissionsStr"] = convert_permissions(file_info["FilePermissions"])
                
                # 转换机器类型为可读描述
                if file_info["MachineType"] != "N/A":
                    file_info["MachineTypeDescription"] = convert_machine_type(file_info["MachineType"])
                    # 保持原始的十六进制表示
                    file_info["MachineType"] = hex(file_info["MachineType"])
                
                # 转换PE文件特征为可读描述
                if file_info["ImageFileCharacteristics"] != "N/A":
                    file_info["ImageFileCharacteristicsDescription"] = convert_characteristics(file_info["ImageFileCharacteristics"])
                
                # 转换PE类型为可读描述
                if file_info["PEType"] != "N/A":
                    file_info["PETypeDescription"] = convert_pe_type(file_info["PEType"])
                
                # 转换子系统类型为可读描述
                if file_info["Subsystem"] != "N/A":
                    file_info["SubsystemDescription"] = convert_subsystem(file_info["Subsystem"])
                    
                metadata_dict = file_info
        return metadata_dict
    except Exception as e:
        raise ValueError(f"Error processing file: {e}")