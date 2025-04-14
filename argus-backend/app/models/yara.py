from datetime import datetime
from typing import Optional, List, Dict, Any
from beanie import Document, Indexed, Link
from pydantic import BaseModel, Field
from .user import User

class YaraRule(Document):
    """
    YARA规则模型
    """
    name: str = Field(..., description="规则名称")
    description: Optional[str] = Field(None, description="规则描述")
    content: str = Field(..., description="规则内容")
    creator: Link[User] = Field(..., description="创建者")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = Field(default=True, description="是否激活")
    is_public: bool = Field(default=False, description="是否公开")
    tags: List[str] = Field(default_factory=list, description="标签")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")

    class Settings:
        name = "yara_rules"
        indexes = [
            "name",
            "creator",
            "is_active",
            "is_public",
            "tags",
            "created_at"
        ]

    class Config:
        arbitrary_types_allowed = True
        json_schema_extra = {
            "example": {
                "name": "恶意软件检测规则",
                "description": "检测常见恶意软件特征的YARA规则",
                "content": "rule Malware { strings: $a = \"evil\" nocase }",
                "creator": "user123",
                "is_active": True,
                "is_public": False
            }
        }

class YaraRuleCreate(BaseModel):
    """
    创建YARA规则模型
    """
    name: str
    description: Optional[str] = None
    content: str
    is_public: bool = False
    tags: List[str] = []
    metadata: Dict[str, Any] = {}

class YaraRuleUpdate(BaseModel):
    """
    更新YARA规则模型
    """
    name: Optional[str] = None
    description: Optional[str] = None
    content: Optional[str] = None
    is_active: Optional[bool] = None
    is_public: Optional[bool] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class YaraRuleResponse(BaseModel):
    """
    YARA规则响应模型
    """
    id: str
    name: str
    description: Optional[str]
    content: str
    creator: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    is_active: bool
    is_public: bool
    tags: List[str]
    metadata: Dict[str, Any]

class YaraRuleFilter(BaseModel):
    """
    YARA规则过滤模型
    """
    name: Optional[str] = None
    creator: Optional[str] = None
    is_active: Optional[bool] = None
    is_public: Optional[bool] = None
    tags: Optional[List[str]] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None

class YaraRuleStats(BaseModel):
    """
    YARA规则统计模型
    """
    total_rules: int
    active_rules: int
    public_rules: int
    average_tags: float
    most_used_tags: List[Dict[str, Any]] 