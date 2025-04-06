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
from app.core.storage import StorageFactory, storage_adapter

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

async def init_storage():
    """初始化存储系统"""
    try:
        # 使用存储适配器初始化存储
        if await storage_adapter.file_exists("test.txt"):
            await storage_adapter.delete_file("test.txt")
        
        # 测试文件上传
        test_content = b"test"
        if await storage_adapter.save_file("test.txt", test_content):
            # 测试文件下载
            downloaded_content = await storage_adapter.get_file("test.txt")
            if downloaded_content == test_content:
                # 测试文件删除
                await storage_adapter.delete_file("test.txt")
                logger.info("Storage initialization successful")
                return True
        
        logger.error("Storage initialization failed")
        return False
    except Exception as e:
        logger.error(f"Error initializing storage: {e}")
        return False

async def main():
    """初始化测试环境"""
    try:
        # 初始化 MongoDB
        await init_mongodb()
        
        # 初始化 MinIO
        init_minio()
        
        # 初始化存储系统
        if not await init_storage():
            logger.error("Failed to initialize storage")
            return
        
        logger.info("Test environment initialization completed")
    except Exception as e:
        logger.error(f"初始化失败: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main()) 