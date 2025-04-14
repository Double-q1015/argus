from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from beanie import Document, Link
from .user import User

class ApiKey(Document):
    """
    API密钥模型
    """
    name: str = Field(..., description="密钥名称")
    description: Optional[str] = Field(None, description="密钥描述")
    permissions: List[str] = Field(default_factory=list, description="权限列表")
    expires_at: Optional[datetime] = Field(None, description="过期时间")
    user: Link[User] = Field(..., description="所属用户")
    key: str = Field(..., description="API密钥")
    key_hash: str = Field(..., description="密钥哈希值")
    is_active: bool = Field(default=True, description="是否激活")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_used_at: Optional[datetime] = Field(None, description="最后使用时间")

    class Settings:
        name = "api_keys"
        indexes = [
            "user",
            "key",
            "is_active",
            "created_at"
        ]

    class Config:
        arbitrary_types_allowed = True

class ApiKeyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None

class ApiKeyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    permissions: List[str]
    expires_at: Optional[datetime] = None
    key: str
    is_active: bool
    created_at: datetime
    last_used_at: Optional[datetime] = None

    class Config:
        from_attributes = True 