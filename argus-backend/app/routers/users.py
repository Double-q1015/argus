from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from app.core.security import get_current_user, get_password_hash, verify_password
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse, UserUpdate
from app.core.auth import validate_password_strength
from datetime import datetime
import re

router = APIRouter(
    prefix="/users",
    tags=["users"],
    responses={
        401: {"description": "认证失败"},
        403: {"description": "权限不足"},
        404: {"description": "未找到资源"},
        429: {"description": "请求过于频繁"}
    }
)

@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    获取当前用户信息
    
    返回已认证用户的详细信息。
    
    Returns:
        UserResponse: 包含以下字段的用户信息
            - username (str): 用户名
            - email (str): 电子邮箱
            - is_active (bool): 账户是否激活
            - created_at (datetime): 账户创建时间
            - last_login (datetime | None): 最后登录时间
    
    Raises:
        401: 未提供有效的认证令牌
    """
    return current_user

@router.put("/me", response_model=UserResponse)
async def update_user_me(
    user_in: UserUpdate,
    current_user: User = Depends(get_current_user)
):
    """
    更新当前用户信息
    
    允许用户更新自己的个人信息，包括用户名、邮箱和密码。所有字段都是可选的。
    
    Args:
        user_in (UserUpdate): 要更新的用户信息，可包含以下字段：
            - username (str, optional): 新用户名（3-32字符，只允许字母、数字、下划线和连字符）
            - email (str, optional): 新邮箱地址
            - password (str, optional): 新密码
            - old_password (str, required if password provided): 当前密码
    
    Returns:
        UserResponse: 更新后的用户信息
    
    Raises:
        400: 
            - 无效的邮箱格式
            - 用户名长度必须在3-32个字符之间
            - 用户名只能包含字母、数字、下划线和连字符
            - 用户名已被使用
            - 邮箱已被使用
            - 需要提供旧密码
            - 旧密码错误
            - 新密码不符合安全要求
        401: 未提供有效的认证令牌
    """
    # 验证邮箱格式
    if user_in.email and not re.match(r"[^@]+@[^@]+\.[^@]+", user_in.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="无效的邮箱格式"
        )
    
    # 验证用户名长度和格式
    if user_in.username:
        if len(user_in.username) < 3 or len(user_in.username) > 32:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="用户名长度必须在3-32个字符之间"
            )
        if not re.match(r"^[a-zA-Z0-9_-]+$", user_in.username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="用户名只能包含字母、数字、下划线和连字符"
            )
        
        # 检查用户名是否已被使用
        existing_user = await User.find_one({"username": user_in.username, "_id": {"$ne": current_user.id}})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="用户名已被使用"
            )
    
    # 检查邮箱是否已被使用
    if user_in.email:
        existing_user = await User.find_one({"email": user_in.email, "_id": {"$ne": current_user.id}})
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="邮箱已被使用"
            )
    
    # 如果要修改密码，需要验证旧密码
    if user_in.password:
        if not user_in.old_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="需要提供旧密码"
            )
        if not verify_password(user_in.old_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="旧密码错误"
            )
        # 验证新密码强度
        if not validate_password_strength(user_in.password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="新密码不符合安全要求：至少8个字符，包含大小写字母、数字和特殊字符"
            )
    
    # 更新用户信息
    update_data = user_in.dict(exclude_unset=True)
    if "password" in update_data:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    if "old_password" in update_data:
        update_data.pop("old_password")
    
    # 使用MongoDB更新
    await current_user.update({"$set": update_data})
    
    # 重新获取更新后的用户信息
    updated_user = await User.get(current_user.id)
    return updated_user

@router.get("/", response_model=List[UserResponse])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    """
    获取用户列表（仅管理员）
    
    返回系统中所有用户的列表，支持分页。
    
    Args:
        skip (int, optional): 跳过的记录数，默认为0
        limit (int, optional): 返回的最大记录数，默认为100
    
    Returns:
        List[UserResponse]: 用户列表
    
    Raises:
        401: 未提供有效的认证令牌
        403: 用户不是管理员
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    users = await User.find_all().skip(skip).limit(limit).to_list()
    return users

@router.get("/{user_id}", response_model=UserResponse)
async def read_user(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    获取指定用户信息（仅管理员）
    
    根据用户ID获取特定用户的详细信息。
    
    Args:
        user_id (str): 要查询的用户ID
    
    Returns:
        UserResponse: 用户信息
    
    Raises:
        401: 未提供有效的认证令牌
        403: 用户不是管理员
        404: 未找到指定用户
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_in: UserUpdate,
    current_user: User = Depends(get_current_user)
):
    """
    更新指定用户信息（仅管理员）
    
    允许管理员更新任意用户的信息。
    
    Args:
        user_id (str): 要更新的用户ID
        user_in (UserUpdate): 要更新的用户信息
    
    Returns:
        UserResponse: 更新后的用户信息
    
    Raises:
        400: 密码不符合安全要求
        401: 未提供有效的认证令牌
        403: 用户不是管理员
        404: 未找到指定用户
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 更新用户信息
    update_data = user_in.dict(exclude_unset=True)
    if "password" in update_data:
        if not validate_password_strength(update_data["password"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password does not meet security requirements"
            )
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    
    # 使用MongoDB更新
    await user.update({"$set": update_data})
    
    # 重新获取更新后的用户信息
    updated_user = await User.get(user_id)
    return updated_user

@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    删除指定用户（仅管理员）
    
    永久删除指定用户的账户和所有相关数据。
    
    Args:
        user_id (str): 要删除的用户ID
    
    Returns:
        dict: 包含成功消息的响应
    
    Raises:
        401: 未提供有效的认证令牌
        403: 用户不是管理员
        404: 未找到指定用户
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    user = await User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await user.delete()
    return {"message": "User deleted successfully"} 