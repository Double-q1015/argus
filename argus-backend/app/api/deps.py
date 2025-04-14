from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.core.config import settings

# MongoDB 客户端
client = AsyncIOMotorClient(settings.MONGODB_URL)
db = client[settings.MONGODB_DB]

async def get_db() -> AsyncIOMotorDatabase:
    """
    获取数据库连接
    """
    try:
        yield db
    finally:
        # Motor 会自动管理连接池
        pass 