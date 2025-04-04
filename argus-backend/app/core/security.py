from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from app.core.config import settings
from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    获取密码哈希值
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    创建访问令牌
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
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
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
    检查登录尝试次数
    """
    user = await User.find_one({"username": username})
    if not user:
        return True
    
    # 检查是否需要重置登录尝试次数
    if user.last_login_attempt and (datetime.utcnow() - user.last_login_attempt) > timedelta(minutes=30):
        user.login_attempts = 0
        await user.save()
        return True
    
    # 检查是否超过最大尝试次数
    if user.login_attempts >= 5:
        return False
    
    return True

async def update_login_attempts(username: str, success: bool = False) -> None:
    """
    更新登录尝试次数
    """
    user = await User.find_one({"username": username})
    if not user:
        return
    
    if success:
        user.login_attempts = 0
        user.last_login = datetime.utcnow()
    else:
        user.login_attempts += 1
        user.last_login_attempt = datetime.utcnow()
    
    await user.save()

def validate_password_strength(password: str) -> bool:
    """
    验证密码强度：
    1. 至少8个字符
    2. 至少包含一个大写字母
    3. 至少包含一个小写字母
    4. 至少包含一个数字
    5. 至少包含一个特殊字符
    """
    if len(password) < 8:
        return False
    
    if not any(c.isupper() for c in password):
        return False
    
    if not any(c.islower() for c in password):
        return False
    
    if not any(c.isdigit() for c in password):
        return False
    
    if not any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        return False
    
    return True