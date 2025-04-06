from datetime import datetime, timedelta
from typing import Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from app.core.config import settings
from app.models.user import User
from app.core.auth import (
    verify_password,
    create_access_token,
    get_current_user,
    check_login_attempts,
    update_login_attempts,
    validate_password_strength
)
from app.core.captcha import verify_captcha, get_captcha_image

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class LoginForm(BaseModel):
    username: str
    password: str
    captcha: str
    client_id: str

    class Config:
        from_attributes = True

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

async def get_user(username: str) -> Optional[User]:
    return await User.find_one({"username": username})

async def authenticate_user(username: str, password: str) -> Optional[User]:
    user = await get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的认证凭据",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

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
    hashed_password = get_password_hash(password)
    user = User(
        username=username,
        email=email,
        hashed_password=hashed_password,
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

@router.post("/login")
async def login(form_data: LoginForm):
    """
    用户登录
    """
    # 验证验证码
    if not verify_captcha(form_data.client_id, form_data.captcha):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="验证码错误"
        )
    
    # 检查登录尝试次数
    if not await check_login_attempts(form_data.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="登录尝试次数过多，请稍后再试"
        )
    
    # 验证用户
    user = await User.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user.hashed_password):
        # 更新登录尝试次数
        await update_login_attempts(form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )
    
    # 重置登录尝试次数
    user.login_attempts = 0
    user.last_login = datetime.utcnow()
    await user.save()
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": str(user.id),
            "username": user.username,
            "email": user.email,
            "is_active": user.is_active,
            "is_superuser": user.is_superuser
        }
    }

@router.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    使用 OAuth2 密码模式登录（不需要验证码）
    """
    # 检查登录尝试次数
    if not await check_login_attempts(form_data.username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="登录尝试次数过多，请稍后再试"
        )
    
    # 验证用户
    user = await User.find_one({"username": form_data.username})
    if not user or not verify_password(form_data.password, user.hashed_password):
        # 更新登录尝试次数
        await update_login_attempts(form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )
    
    # 重置登录尝试次数
    user.login_attempts = 0
    user.last_login = datetime.utcnow()
    await user.save()
    
    # 创建访问令牌
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@router.post("/test-token")
async def test_token(current_user: User = Depends(get_current_user)):
    """
    测试令牌
    """
    return current_user

