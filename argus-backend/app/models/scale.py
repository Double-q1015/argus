from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from beanie import Document, Indexed, Link
from .user import User
from .sample import Sample

class Scale(Document):
    """
    评分模型
    """
    name: str = Field(..., description="评分名称")
    description: Optional[str] = Field(None, description="评分描述")
    creator: Link[User] = Field(..., description="创建者")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True, description="是否激活")
    is_public: bool = Field(default=False, description="是否公开")
    rules: List[Dict[str, Any]] = Field(default_factory=list, description="评分规则")
    weights: Dict[str, float] = Field(default_factory=dict, description="权重配置")
    thresholds: Dict[str, float] = Field(default_factory=dict, description="阈值配置")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")

    class Settings:
        name = "scales"
        indexes = [
            "name",
            "creator",
            "is_active",
            "is_public",
            "created_at"
        ]

    class Config:
        arbitrary_types_allowed = True
        json_schema_extra = {
            "example": {
                "name": "恶意软件评分",
                "description": "基于多个特征的恶意软件评分系统",
                "creator": "user123",
                "is_active": True,
                "is_public": False
            }
        }

class ScaleCreate(BaseModel):
    """
    创建评分模型
    """
    name: str
    description: Optional[str] = None
    is_public: bool = False
    rules: List[Dict[str, Any]] = []
    weights: Dict[str, float] = {}
    thresholds: Dict[str, float] = {}
    metadata: Dict[str, Any] = {}

class ScaleUpdate(BaseModel):
    """
    更新评分模型
    """
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    is_public: Optional[bool] = None
    rules: Optional[List[Dict[str, Any]]] = None
    weights: Optional[Dict[str, float]] = None
    thresholds: Optional[Dict[str, float]] = None
    metadata: Optional[Dict[str, Any]] = None

class ScaleResponse(BaseModel):
    """
    评分响应模型
    """
    id: str
    name: str
    description: Optional[str]
    creator: str
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_public: bool
    rules: List[Dict[str, Any]]
    weights: Dict[str, float]
    thresholds: Dict[str, float]
    metadata: Dict[str, Any]

class ScaleFilter(BaseModel):
    """
    评分过滤模型
    """
    name: Optional[str] = None
    creator: Optional[str] = None
    is_active: Optional[bool] = None
    is_public: Optional[bool] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None

class ScaleStats(BaseModel):
    """
    评分统计模型
    """
    total_scales: int
    active_scales: int
    public_scales: int
    average_rules: float
    most_used_weights: List[Dict[str, Any]]
    most_used_thresholds: List[Dict[str, Any]] 