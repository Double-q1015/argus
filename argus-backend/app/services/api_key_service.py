from typing import List
from datetime import datetime, timedelta
import secrets
from app.models.api_key import ApiKey, ApiKeyCreate, ApiKeyResponse
from app.models.user import User
from bson import ObjectId
import logging

logger = logging.getLogger(__name__)

class ApiKeyService:
    async def get_user_keys(self, user: User) -> List[ApiKeyResponse]:
        """获取用户的所有API密钥"""
        keys = await ApiKey.find(ApiKey.user.id == user.id).to_list()
        return [ApiKeyResponse(
            id=str(key.id),
            name=key.name,
            description=key.description,
            permissions=key.permissions,
            expires_at=key.expires_at,
            key=key.key,
            is_active=key.is_active,
            created_at=key.created_at,
            last_used_at=key.last_used_at
        ) for key in keys]

    async def create_key(self, user: User, key_data: ApiKeyCreate) -> ApiKeyResponse:
        """创建新的API密钥"""
        # 生成API密钥
        api_key = secrets.token_urlsafe(32)
        
        # 创建密钥文档
        key = ApiKey(
            name=key_data.name,
            description=key_data.description,
            permissions=key_data.permissions,
            expires_at=key_data.expires_at,
            user=user,
            key=api_key,
            key_hash=secrets.token_hex(32),
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        # 保存到数据库
        await key.insert()
        
        return ApiKeyResponse(
            id=str(key.id),
            name=key.name,
            description=key.description,
            permissions=key.permissions,
            expires_at=key.expires_at,
            key=key.key,
            is_active=key.is_active,
            created_at=key.created_at,
            last_used_at=key.last_used_at
        )

    async def revoke_key(self, user: User, key_id: str):
        """撤销API密钥"""
        logger.info(f"Revoking key {key_id} for user {user.id}")
        key = await ApiKey.find_one({"_id": ObjectId(key_id), "user.$id": ObjectId(user.id)})
        if key:
            logger.info(f"Found key: {key.dict()}")
            key.is_active = False
            await key.save()
            logger.info("Key revoked successfully")
        else:
            logger.warning("Key not found")

    async def delete_key(self, user: User, key_id: str):
        """删除API密钥"""
        key = await ApiKey.find_one({"_id": ObjectId(key_id), "user.$id": ObjectId(user.id)})
        if key:
            await key.delete()

    async def verify_key(self, api_key: str) -> ApiKey:
        """验证API密钥"""
        key = await ApiKey.find_one(ApiKey.key == api_key)
        if not key:
            return None
            
        # 检查密钥是否有效
        if not key.is_active:
            return None
            
        # 检查是否过期
        if key.expires_at and datetime.utcnow() > key.expires_at:
            return None
            
        # 更新最后使用时间
        key.last_used_at = datetime.utcnow()
        await key.save()
        
        return key 