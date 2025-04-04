import asyncio
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from minio import Minio
from app.core.config import settings
from app.models.sample import Sample
from app.models.user import User
from app.models.yara import YaraRule
from app.models.scale import Scale
from app.models.api_key import ApiKey
from beanie import init_beanie

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_mongodb():
    """初始化 MongoDB 数据库和集合"""
    try:
        # 连接 MongoDB
        client = AsyncIOMotorClient(settings.MONGODB_URL)
        db = client[settings.MONGODB_DB]
        
        # 清理现有索引
        collections = ["samples", "users", "yara_rules", "scales", "api_keys"]
        for collection_name in collections:
            collection = db[collection_name]
            await collection.drop_indexes()
        
        # 初始化 Beanie
        await init_beanie(
            database=db,
            document_models=[
                Sample,
                User,
                YaraRule,
                Scale,
                ApiKey
            ],
            allow_index_dropping=True
        )
        
        logger.info("MongoDB 初始化成功")
        return True
    except Exception as e:
        logger.error(f"MongoDB 初始化失败: {str(e)}")
        raise

def init_minio():
    """初始化 MinIO 存储桶"""
    try:
        # 创建 MinIO 客户端
        minio_client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE
        )
        
        # 创建存储桶
        if not minio_client.bucket_exists(settings.MINIO_BUCKET_NAME):
            minio_client.make_bucket(settings.MINIO_BUCKET_NAME)
            logger.info(f"创建存储桶成功: {settings.MINIO_BUCKET_NAME}")
        else:
            logger.info(f"存储桶已存在: {settings.MINIO_BUCKET_NAME}")
        
        return True
    except Exception as e:
        logger.error(f"MinIO 初始化失败: {str(e)}")
        raise

async def main():
    """主函数"""
    try:
        # 初始化 MongoDB
        await init_mongodb()
        
        # 初始化 MinIO
        init_minio()
        
        logger.info("测试环境初始化完成")
    except Exception as e:
        logger.error(f"初始化失败: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 