from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel, Field, validator

def parse_exiftool_datetime(value: Any) -> Optional[datetime]:
    """
    解析ExifTool的日期时间格式
    :param value: Any, 输入的日期时间值
    :return: Optional[datetime], 解析后的datetime对象
    """
    if not value or value == "N/A":
        return None
    
    try:
        # 处理带时区的格式，例如：2025:04:04 14:31:33+08:00
        if isinstance(value, str):
            # 将ExifTool的日期格式转换为标准格式
            value = value.replace(":", "-", 2)
            return datetime.fromisoformat(value)
        # 如果已经是datetime对象，直接返回
        elif isinstance(value, datetime):
            return value
        return None
    except (ValueError, TypeError):
        return None

class ExifToolMetadata(BaseModel):
    """ExifTool元数据模型"""
    # 基本文件信息
    exiftool_version: Optional[str] = Field(alias="ExifToolVersion")
    file_size: Optional[int] = Field(alias="FileSize")
    file_modify_date: Optional[datetime] = Field(None, alias="FileModifyDate")
    file_access_date: Optional[datetime] = Field(None, alias="FileAccessDate")
    file_inode_change_date: Optional[datetime] = Field(None, alias="FileInodeChangeDate")
    file_permissions: Optional[int] = Field(alias="FilePermissions")
    file_permissions_str: Optional[str] = Field(alias="FilePermissionsStr")
    file_type: Optional[str] = Field(alias="FileType")
    file_type_extension: Optional[str] = Field(alias="FileTypeExtension")
    mime_type: Optional[str] = Field(alias="MIMEType")

    # PE文件特定信息
    machine_type: Optional[str] = Field(alias="MachineType")
    machine_type_description: Optional[str] = Field(alias="MachineTypeDescription")
    time_stamp: Optional[datetime] = Field(None, alias="TimeStamp")
    image_file_characteristics: Optional[int] = Field(alias="ImageFileCharacteristics")
    image_file_characteristics_description: Optional[List[str]] = Field(alias="ImageFileCharacteristicsDescription")
    pe_type: Optional[int] = Field(alias="PEType")
    pe_type_description: Optional[str] = Field(alias="PETypeDescription")
    linker_version: Optional[str] = Field(alias="LinkerVersion")
    code_size: Optional[int] = Field(alias="CodeSize")
    initialized_data_size: Optional[int] = Field(alias="InitializedDataSize")
    uninitialized_data_size: Optional[int] = Field(alias="UninitializedDataSize")
    entry_point: Optional[str] = Field(alias="EntryPoint")
    os_version: Optional[str] = Field(alias="OSVersion")
    image_version: Optional[str] = Field(alias="ImageVersion")
    subsystem_version: Optional[str] = Field(alias="SubsystemVersion")
    subsystem: Optional[int] = Field(alias="Subsystem")
    subsystem_description: Optional[str] = Field(alias="SubsystemDescription")

    # 验证器
    _parse_file_modify_date = validator("file_modify_date", pre=True, allow_reuse=True)(parse_exiftool_datetime)
    _parse_file_access_date = validator("file_access_date", pre=True, allow_reuse=True)(parse_exiftool_datetime)
    _parse_file_inode_change_date = validator("file_inode_change_date", pre=True, allow_reuse=True)(parse_exiftool_datetime)
    _parse_time_stamp = validator("time_stamp", pre=True, allow_reuse=True)(parse_exiftool_datetime)

    class Config:
        """Pydantic配置类"""
        allow_population_by_field_name = True
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }

    def to_dict(self) -> dict:
        """转换为字典格式"""
        return {k: v for k, v in self.dict(by_alias=True).items() if v is not None}

    @classmethod
    def from_exiftool_output(cls, data: dict) -> "ExifToolMetadata":
        """
        从ExifTool输出创建模型实例
        :param data: ExifTool输出的原始数据
        :return: ExifToolMetadata实例
        """
        # 处理可能缺失的字段
        for field in cls.__fields__:
            if field not in data:
                data[field] = None
        return cls(**data)

    def is_executable(self) -> bool:
        """检查是否为可执行文件"""
        return "Executable" in self.image_file_characteristics_description

    def is_dll(self) -> bool:
        """检查是否为DLL文件"""
        return "DLL file" in self.image_file_characteristics_description

    def is_32bit(self) -> bool:
        """检查是否为32位文件"""
        return "32-bit" in self.image_file_characteristics_description

    def get_architecture(self) -> str:
        """获取文件架构"""
        return self.machine_type_description

    def get_subsystem_type(self) -> str:
        """获取子系统类型"""
        return self.subsystem_description

    def get_compilation_timestamp(self) -> Optional[datetime]:
        """获取编译时间戳"""
        return self.time_stamp 