from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from beanie import Document, Link, Indexed
from pydantic import BaseModel, Field
from .user import User

class Sample(Document):
    """
    样本模型
    """
    file_name: str = Field(..., description="文件名")
    description: Optional[str] = Field(None, description="样本描述")
    file_path: str = Field(..., description="文件路径")
    file_size: int = Field(..., description="文件大小")
    file_type: str = Field(..., description="文件类型")
    sha256_digest: str = Field(..., description="SHA256哈希值", unique=True, index=True)
    upload_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uploader: Link[User] = Field(..., description="上传者")
    analysis_status: str = Field(default="pending", description="分析状态")
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
    file_type: str
    sha256_digest: str
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