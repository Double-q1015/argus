from fastapi import APIRouter, Depends, HTTPException
from typing import List
from app.models.api_key import ApiKeyCreate, ApiKeyResponse
from app.services.api_key_service import ApiKeyService
from app.core.security import get_current_user
from app.models.user import User
import logging

logger = logging.getLogger(__name__)
router = APIRouter()

@router.get("/keys/", response_model=List[ApiKeyResponse])
async def get_api_keys(
    current_user: User = Depends(get_current_user),
    api_key_service: ApiKeyService = Depends()
):
    """获取当前用户的所有API密钥"""
    logger.info(f"Current user: {current_user.dict()}")
    return await api_key_service.get_user_keys(current_user)

@router.post("/keys/", response_model=ApiKeyResponse)
async def create_api_key(
    key_data: ApiKeyCreate,
    current_user: User = Depends(get_current_user),
    api_key_service: ApiKeyService = Depends()
):
    """创建新的API密钥"""
    logger.info(f"Current user: {current_user.dict()}")
    logger.info(f"Key data: {key_data.dict()}")
    return await api_key_service.create_key(current_user, key_data)

@router.post("/keys/{key_id}/revoke")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    api_key_service: ApiKeyService = Depends()
):
    """撤销API密钥"""
    await api_key_service.revoke_key(current_user, key_id)
    return {"message": "API密钥已撤销"}

@router.delete("/keys/{key_id}")
async def delete_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    api_key_service: ApiKeyService = Depends()
):
    """删除API密钥"""
    await api_key_service.delete_key(current_user, key_id)
    return {"message": "API密钥已删除"}
 