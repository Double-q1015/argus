from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.core.config import settings
from typing import AsyncGenerator
from contextlib import asynccontextmanager
from fastapi import Depends
import logging

logger = logging.getLogger(__name__)

class MongoDBManager:
    def __init__(self):
        self._client = None
        self._db = None

    async def connect(self):
        """建立数据库连接"""
        try:
            self._client = AsyncIOMotorClient(settings.MONGODB_URL)
            self._db = self._client[settings.MONGODB_DB]
            # 测试连接
            await self._client.admin.command('ping')
            logger.info("MongoDB connected successfully")
        except Exception as e:
            logger.error(f"MongoDB connection error: {str(e)}")
            raise

    async def close(self):
        """关闭数据库连接"""
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed")

    @property
    def client(self):
        if not self._client:
            raise RuntimeError("MongoDB client not initialized")
        return self._client

    @property
    def db(self):
        if not self._db:
            raise RuntimeError("MongoDB database not initialized")
        return self._db

# 创建全局数据库管理器实例
db_manager = MongoDBManager()

async def get_database() -> AsyncIOMotorDatabase:
    """
    FastAPI 依赖注入函数，用于获取数据库实例
    使用示例:
    @router.get("/items")
    async def get_items(db: AsyncIOMotorDatabase = Depends(get_database)):
        items = await db.items.find().to_list(length=10)
        return items
    """
    try:
        if not db_manager._client:
            await db_manager.connect()
        return db_manager.db
    except Exception as e:
        logger.error(f"Failed to get database: {str(e)}")
        raise

async def get_client() -> AsyncIOMotorClient:
    """
    FastAPI 依赖注入函数，用于获取数据库客户端
    使用示例:
    @router.get("/status")
    async def get_status(client: AsyncIOMotorClient = Depends(get_client)):
        status = await client.admin.command('serverStatus')
        return status
    """
    try:
        if not db_manager._client:
            await db_manager.connect()
        return db_manager.client
    except Exception as e:
        logger.error(f"Failed to get client: {str(e)}")
        raise

@asynccontextmanager
async def get_db() -> AsyncGenerator:
    """
    数据库连接上下文管理器
    使用示例:
    async with get_db() as db:
        result = await db.collection.find_one()
    """
    try:
        if not db_manager._client:
            await db_manager.connect()
        yield db_manager.db
    except Exception as e:
        logger.error(f"Database error: {str(e)}")
        raise
    finally:
        # 注意：这里不关闭连接，因为连接是全局共享的
        pass

async def init_db():
    """初始化数据库连接"""
    await db_manager.connect()

async def close_db():
    """关闭数据库连接"""
    await db_manager.close()