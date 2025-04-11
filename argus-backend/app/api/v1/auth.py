from datetime import timedelta, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from app.core.config import settings
from app.models.user import User
from app.core.security import (
    create_access_token,
    get_current_user,
    authenticate_user,
    validate_password_strength,
    get_password_hash
)
from app.core.captcha import verify_captcha, get_captcha_image

router = APIRouter()

class Token(BaseModel):
    access_token: str
    token_type: str
    user: Optional[dict] = None

class LoginForm(BaseModel):
    username: str
    password: str
    captcha: str
    client_id: str

    class Config:
        from_attributes = True

@router.post("/register")
async def register_user(
    username: str,
    email: str,
    password: str,
    is_active: bool = True,
    is_superuser: bool = False
):
    """
    注册新用户
    """
    # 验证密码强度
    if not validate_password_strength(password):
        raise HTTPException(
            status_code=400,
            detail="密码强度不足，请确保密码包含大小写字母、数字和特殊字符，且长度至少为8位"
        )
    
    # 检查用户名是否已存在
    if await User.find_one({"username": username}):
        raise HTTPException(
            status_code=400,
            detail="用户名已存在"
        )
    
    # 检查邮箱是否已存在
    if await User.find_one({"email": email}):
        raise HTTPException(
            status_code=400,
            detail="邮箱已被注册"
        )
    
    # 创建新用户
    user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        is_active=is_active,
        is_superuser=is_superuser
    )
    
    try:
        await user.insert()
        return {"message": "用户注册成功"}
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"用户注册失败: {str(e)}"
        )

@router.get("/captcha")
async def get_captcha(client_id: str):
    """获取验证码图片"""
    return get_captcha_image(client_id)

@router.post("/login", response_model=Token)
async def login(form_data: LoginForm):
    """
    用户登录（带验证码）
    """
    # 验证验证码
    if not verify_captcha(form_data.client_id, form_data.captcha):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="验证码错误"
        )
    
    # 验证用户
    success, user, error_msg = await authenticate_user(form_data.username, form_data.password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if error_msg == "用户名或密码错误" else status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error_msg
        )
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser
        }
    )

@router.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 密码模式登录（不需要验证码）
    """
    # 验证用户
    success, user, error_msg = await authenticate_user(form_data.username, form_data.password)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED if error_msg == "用户名或密码错误" else status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error_msg
        )
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer"
    )

