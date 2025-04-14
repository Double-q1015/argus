import os
import sys
from pathlib import Path
import asyncio
import logging
from motor.motor_asyncio import AsyncIOMotorClient
from minio import Minio
from beanie import init_beanie
# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent))
from app.core.config import settings
from app.models.sample import Sample
from app.models.user import User
from app.models.yara import YaraRule
from app.models.api_key import ApiKey
from app.core.storage import storage_adapter

# 导入所有模型
from app.models.analysis import (
    Task,
    TaskCondition,
    TaskStatus,
    SampleAnalysisStatus,
    AnalysisConfig,
    SampleAnalysis,
    AnalysisResult,
    AnalysisSchedule
)
from app.models.migration import MigrationTask, MigrationFileStatus

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_test_environment():
    """初始化测试环境"""
    # 设置环境变量
    os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
    os.environ["MONGODB_DB_NAME"] = "argus_test"
    os.environ["TESTING"] = "true"
    
    # 创建数据库连接
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    
    try:
        # 确保数据库存在
        db = client["argus_test"]
        
        # 删除已存在的数据库（如果存在）
        await client.drop_database("argus_test")
        
        # 创建所有集合
        collections = [
            "samples", "users", "yara_rules", "scales", "api_keys",
            "tasks", "task_conditions", "task_status", "sample_analysis_status",
            "analysis_configs", "sample_analyses", "analysis_results", "analysis_schedules",
            "migration_tasks", "migration_file_status"
        ]
        
        for collection_name in collections:
            await db.create_collection(collection_name)
        
        # 初始化 Beanie
        await init_beanie(
            database=db,
            document_models=[
                Sample,
                User,
                YaraRule,
                ApiKey,
                Task,
                TaskCondition,
                TaskStatus,
                SampleAnalysisStatus,
                AnalysisConfig,
                SampleAnalysis,
                AnalysisResult,
                AnalysisSchedule,
                MigrationTask,
                MigrationFileStatus
            ]
        )
        
        print("测试环境初始化完成！")
        print(f"数据库: argus_test")
        print(f"已创建集合: {', '.join(collections)}")
        
    finally:
        # 关闭数据库连接
        client.close()

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
        # 初始化测试环境
        await init_test_environment()
        
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