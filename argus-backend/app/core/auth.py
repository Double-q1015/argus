from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.core.config import settings
from app.models.user import User
import re

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码
    
    使用bcrypt算法验证明文密码是否与存储的哈希密码匹配。
    
    Args:
        plain_password (str): 用户输入的明文密码
        hashed_password (str): 数据库中存储的哈希密码
    
    Returns:
        bool: 如果密码匹配返回True，否则返回False
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    获取密码哈希值
    
    使用bcrypt算法对密码进行哈希处理。
    
    Args:
        password (str): 需要哈希的明文密码
    
    Returns:
        str: 哈希后的密码
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    创建访问令牌
    
    生成JWT访问令牌，包含用户信息和过期时间。
    
    Args:
        data (dict): 要编码到令牌中的数据
        expires_delta (timedelta, optional): 令牌的有效期
    
    Returns:
        str: JWT访问令牌
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """
    获取当前用户
    
    从请求中的JWT令牌获取当前认证用户。
    
    Args:
        token (str): JWT访问令牌
    
    Returns:
        User: 当前认证用户的对象
    
    Raises:
        HTTPException: 当令牌无效或用户不存在时抛出401错误
    """
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
    except JWTError:
        raise credentials_exception
    
    user = await User.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

async def check_login_attempts(username: str) -> bool:
    """
    检查用户登录尝试次数
    
    防止暴力破解，限制用户登录尝试次数。
    连续失败5次后需要等待5分钟才能继续尝试。
    
    Args:
        username (str): 要检查的用户名
    
    Returns:
        bool: 如果允许继续尝试登录返回True，否则返回False
    """
    user = await User.find_one({"username": username})
    if not user:
        return True
    
    if user.login_attempts >= 5:
        last_attempt = user.last_login_attempt or datetime.utcnow()
        if (datetime.utcnow() - last_attempt).total_seconds() < 300:  # 5分钟冷却时间
            return False
        else:
            user.login_attempts = 0
            await user.save()
            return True
    return True

async def update_login_attempts(username: str) -> None:
    """
    更新用户登录尝试次数
    
    记录用户登录尝试，用于实现登录限制功能。
    
    Args:
        username (str): 要更新的用户名
    """
    user = await User.find_one({"username": username})
    if user:
        user.login_attempts += 1
        user.last_login_attempt = datetime.utcnow()
        await user.save()

def validate_password_strength(password: str) -> bool:
    """
    验证密码强度
    
    确保密码符合安全要求。
    
    要求：
    1. 至少8个字符
    2. 至少包含一个大写字母
    3. 至少包含一个小写字母
    4. 至少包含一个数字
    5. 至少包含一个特殊字符
    
    Args:
        password (str): 要验证的密码
    
    Returns:
        bool: 如果密码符合所有要求返回True，否则返回False
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True 