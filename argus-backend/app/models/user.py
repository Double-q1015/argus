from datetime import datetime, timezone
from typing import Optional
from beanie import Document
from pydantic import BaseModel, Field, EmailStr

class User(Document):
    """
    用户模型
    """
    username: str = Field(..., description="用户名", unique=True, index=True)
    email: EmailStr = Field(..., description="邮箱", unique=True, index=True)
    hashed_password: str = Field(..., description="加密后的密码")
    is_active: bool = Field(default=True, description="是否激活")
    is_superuser: bool = Field(default=False, description="是否是超级用户")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: Optional[datetime] = Field(default=None, description="最后登录时间")
    login_attempts: int = Field(default=0, description="登录尝试次数")
    last_login_attempt: Optional[datetime] = Field(default=None, description="最后登录尝试时间")

    class Settings:
        name = "users"
        indexes = [
            "is_active",
            "is_superuser",
            "created_at"
        ]

    class Config:
        arbitrary_types_allowed = True
        json_schema_extra = {
            "example": {
                "username": "admin",
                "email": "admin@example.com",
                "is_active": True,
                "is_superuser": True
            }
        }

class UserCreate(BaseModel):
    """
    创建用户模型
    """
    username: str
    email: EmailStr
    password: str

class UserUpdate(BaseModel):
    """
    更新用户模型
    """
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None

class UserResponse(BaseModel):
    """
    用户响应模型
    """
    id: str
    username: str
    email: EmailStr
    is_active: bool
    is_superuser: bool
    created_at: datetime
    last_login: Optional[datetime]
    login_attempts: int
    last_login_attempt: Optional[datetime]

class UserFilter(BaseModel):
    """
    用户过滤模型
    """
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    is_active: Optional[bool] = None
    is_superuser: Optional[bool] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None 