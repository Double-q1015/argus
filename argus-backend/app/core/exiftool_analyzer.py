import exiftool
import os
from typing import Dict, Any

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

async def perform_exiftool_analysis(file_path: str) -> Dict[str, Any]:
    """
    使用 exiftool 分析文件元数据
    :param file_path: str, 文件路径
    :return: Dict[str, Any], 元数据信息
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
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
                
                # MachineType 转为hex
                if file_info["MachineType"] != "N/A":
                    file_info["MachineType"] = hex(file_info["MachineType"])
                    
                metadata_dict = file_info
    except Exception as e:
        metadata_dict = {}
        raise ValueError(f"Error processing file: {e}")
    finally:
        return metadata_dict 