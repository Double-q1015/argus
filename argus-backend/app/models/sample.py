from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from beanie import Document, Link, Indexed
from pydantic import BaseModel, Field
from app.models.user import User
from app.models.exiftool import ExifToolMetadata
from enum import Enum

class SampleStatusEnum(str, Enum):
    pending = "pending"
    analyzing = "analyzing"
    completed = "completed"
    failed = "failed"

class Sample(Document):
    """
    样本模型
    """
    file_name: str = Field(..., description="文件名")
    description: Optional[str] = Field(None, description="样本描述")
    file_path: str = Field(..., description="文件路径")
    file_size: int = Field(..., description="文件大小")
    file_type: Optional[str] = Field(None, description="文件类型")
    sha256_digest: str = Field(..., description="SHA256哈希值", unique=True, index=True)
    md5_digest: Optional[str] = Field(None, description="MD5哈希值", unique=True, index=True)
    hash_info: Optional[Dict[str, Any]] = Field(None, description="哈希信息")
    exiftool_info: Optional[Dict[str, Any]] = Field(None, description="exiftool信息")
    magic_info: Optional[Dict[str, Any]] = Field(None, description="magic信息")
    pe_info: Optional[Dict[str, Any]] = Field(None, description="pe信息")
    upload_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uploader: Link[User] = Field(..., description="上传者")
    analysis_status: SampleStatusEnum = Field(default=SampleStatusEnum.pending, description="分析状态")
    analysis_results: Optional[Dict[str, Any]] = None
    tags: List[str] = Field(default_factory=list, description="标签")
    notes: Optional[str] = None
    creator: Optional[str] = None
    is_public: bool = Field(default=False)
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")

    class Settings:
        name = "samples"
        indexes = [
            "uploader",
            "analysis_status",
            "upload_time",
            "tags",
            "creator",
            "is_public"
        ]

    class Config:
        arbitrary_types_allowed = True
        json_schema_extra = {
            "example": {
                "file_name": "sample.exe",
                "description": "一个可疑的PE文件",
                "file_path": "/path/to/sample.exe",
                "file_size": 1024,
                "file_type": "application/x-msdownload",
                "sha256_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "analysis_status": "pending"
            }
        }

class SampleCreate(BaseModel):
    """
    创建样本模型
    """
    name: str
    description: Optional[str] = None
    file_type: str
    tags: List[str] = []
    metadata: Dict[str, Any] = {}

class SampleUpdate(BaseModel):
    """
    更新样本模型
    """
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    analysis_result: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class SampleResponse(BaseModel):
    """
    样本响应模型
    """
    id: str
    file_name: str
    description: Optional[str]
    file_path: str
    file_size: int
    file_type: Optional[str]
    sha256_digest: str
    md5_digest: Optional[str]
    upload_time: datetime
    uploader: str
    analysis_status: str
    analysis_results: Optional[Dict[str, Any]]
    tags: List[str]

class SampleFilter(BaseModel):
    """
    样本过滤模型
    """
    name: Optional[str] = None
    uploader: Optional[str] = None
    status: Optional[str] = None
    tags: Optional[List[str]] = None
    upload_after: Optional[datetime] = None
    upload_before: Optional[datetime] = None

class SampleStats(BaseModel):
    """
    样本统计模型
    """
    total_samples: int
    samples_by_status: Dict[str, int]
    samples_by_type: Dict[str, int]
    recent_uploads: List[SampleResponse] 

class SampleBaseInfo(BaseModel):
    """
    'fileName': '26c46fdf058abdf2d4cad1d8bcca0d686c1aa556...dc7ba1.zip',
    'firstSubmit': '2025-04-10',
    'lastSubmit': '2025-04-10',
    'lastAnalysis': '2025-04-10 11:54:22',
    'fileSize': '564.87 KB', 
    'fileType': 'Zip archive data, at least v2.0 to extract',
    'detectionCount': 8,
    'engineCount': 28,
    'threatType': '木马',
    'threatLevel': '恶意',
    'malwareFamily': 'AutoIt',
    'malware_type_severity': 'medium',
    'threatTypeDesc': '木马是一类会执行未经授权操作的恶意程序，如下载其他恶意程序和窃取隐私，会破坏系统的安全性',
    'sha256': '13e69bf725e206a1129ddc5bd069f3298a0b0d3c92fe8fc5647c4471b1164bb2',
    'md5': '23f38b4faf93cd3013007d90a712f4ef',
    'sha1': 'dd9edcf2585d2c843151a8705e695e46a87d18e1'
    "sha512": "",
    "CRC32": "E3ACAD6A",
    "SSDEEP": "384:hdtXWiJCQxsEwvK3RpSSHuGQG2Rqm4YhYEL:hDXWipuE+K3/SSHgxmE",
    "peHashNG": "5f9a88f0f6969e294313fd8413845b0eef6379c5e2a9ed05a740741bc779f05f",}
    """

    fileName: Optional[str]
    firstSubmit: Optional[str]
    lastSubmit: Optional[str]
    lastAnalysis: Optional[str]
    fileSize: Optional[str]
    fileType: Optional[str]
    detectionCount: Optional[int]
    engineCount: Optional[int]
    threatType: Optional[str]
    threatLevel: Optional[str]
    malwareFamily: Optional[str]
    malware_type_severity: Optional[str]
    threatTypeDesc: Optional[str]
    sha256: Optional[str]
    md5: Optional[str]
    sha1: Optional[str]
    sha512: Optional[str]
    crc32: Optional[str]
    ssdeep: Optional[str]
    peHashNG: Optional[str]


class SampleStaticInfo(BaseModel):
    """
    样本静态信息模型
    """
    baseInfo: SampleBaseInfo
    exifTool: Optional[ExifToolMetadata]
    pe: Optional[Dict[str, Any]]
    findCrypt: Optional[List[Dict[str, Any]]]
    diec: Optional[Dict[str, Any]]
    magika: Optional[Dict[str, Any]]
    trid: Optional[Dict[str, Any]]

class peinfo(BaseModel):
    """
    peinfo模型
    """
    pdbMap: Dict[str, Any]
    resourcesMap: List[Dict[str, Any]]
    importsMap: List[Dict[str, Any]]
    exportsMap: List[Dict[str, Any]]
    signcheckMap: List[Dict[str, Any]]
    tlsInfoMap: Dict[str, Any]
    fileMap: Dict[str, Any]
    headMap: Dict[str, Any]
    sectionsMap: List[Dict[str, Any]]