from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

# MongoDB配置
async def init_db():
    """初始化MongoDB连接"""
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    return client

async def close_db(client):
    """关闭MongoDB连接"""
    if client:
        client.close()

def get_database():
    """获取MongoDB数据库实例"""
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    return client[settings.MONGODB_DB]