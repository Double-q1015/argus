from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class UserBase(BaseModel):
    """
    用户基础模型
    
    包含用户的基本信息字段
    """
    username: str = Field(..., description="用户名，唯一标识符")
    email: EmailStr = Field(..., description="用户电子邮箱地址")
    is_active: bool = Field(default=True, description="用户账户是否激活")
    is_superuser: bool = Field(default=False, description="是否是超级管理员")

class UserCreate(UserBase):
    """
    用户创建模型
    
    用于创建新用户时的数据模型，继承自UserBase，额外包含密码字段
    """
    password: str = Field(..., description="用户密码，将被哈希存储")

class UserUpdate(BaseModel):
    """
    用户更新模型
    
    用于更新用户信息时的数据模型，所有字段都是可选的
    """
    username: Optional[str] = Field(None, description="新的用户名")
    email: Optional[EmailStr] = Field(None, description="新的电子邮箱地址")
    password: Optional[str] = Field(None, description="新的密码")
    old_password: Optional[str] = Field(None, description="当前密码，修改密码时必须提供")
    is_active: Optional[bool] = Field(None, description="是否激活账户")
    is_superuser: Optional[bool] = Field(None, description="是否设为超级管理员")

    class Config:
        json_schema_extra = {
            "example": {
                "username": "newusername",
                "email": "newemail@example.com",
                "password": "NewPassword123!",
                "old_password": "OldPassword123!"
            }
        }

class UserInDB(UserBase):
    """
    数据库用户模型
    
    用于数据库存储的用户模型，包含所有用户相关字段
    """
    id: int = Field(..., description="用户ID，自动生成")
    hashed_password: str = Field(..., description="经过哈希处理的密码")
    created_at: datetime = Field(..., description="账户创建时间")
    last_login: Optional[datetime] = Field(None, description="最后登录时间")
    login_attempts: int = Field(default=0, description="登录尝试次数")
    last_login_attempt: Optional[datetime] = Field(None, description="最后一次登录尝试时间")

    class Config:
        from_attributes = True

class User(UserBase):
    """
    用户响应模型
    
    用于API响应的用户模型，不包含敏感信息
    """
    id: int = Field(..., description="用户ID")
    created_at: datetime = Field(..., description="账户创建时间")
    last_login: Optional[datetime] = Field(None, description="最后登录时间")

    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    """
    用户信息响应模型
    
    用于向客户端返回用户信息的模型，只包含安全的非敏感信息
    """
    username: str = Field(..., description="用户名")
    email: EmailStr = Field(..., description="电子邮箱地址")
    is_active: bool = Field(..., description="账户是否激活")
    created_at: datetime = Field(..., description="账户创建时间")
    last_login: Optional[datetime] = Field(None, description="最后登录时间")

class Token(BaseModel):
    """
    令牌模型
    
    用于用户认证的令牌模型
    """
    access_token: str = Field(..., description="访问令牌")
    token_type: str = Field(..., description="令牌类型，通常为'bearer'") 