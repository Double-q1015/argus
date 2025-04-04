import asyncio
import logging
from app.core.config import settings
from app.models.sample import Sample
from app.core.storage import storage
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_db():
    """初始化数据库连接"""
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    await init_beanie(
        database=client[settings.MONGODB_DB_NAME],
        document_models=[Sample]
    )

async def clean_samples():
    """
    清理样本数据：
    1. 删除没有 file_path 的样本记录
    2. 删除存储中不存在的文件
    3. 修复 file_path 格式
    """
    try:
        # 初始化数据库连接
        await init_db()
        
        # 获取所有样本
        samples = await Sample.find_all().to_list()
        logger.info(f"Found {len(samples)} samples")
        
        # 清理计数器
        deleted_count = 0
        fixed_count = 0
        
        for sample in samples:
            try:
                # 检查 file_path
                if not sample.file_path:
                    logger.warning(f"Sample {sample.sha256_digest} has no file_path, deleting...")
                    await sample.delete()
                    deleted_count += 1
                    continue
                
                # 检查文件是否存在于存储中
                if not await storage.file_exists(sample.file_path):
                    logger.warning(f"File not found in storage: {sample.file_path}, deleting sample...")
                    await sample.delete()
                    deleted_count += 1
                    continue
                
                # 修复 file_path 格式
                if not sample.file_path.startswith("samples/"):
                    new_path = f"samples/{sample.sha256_digest}"
                    logger.info(f"Fixing file path for {sample.sha256_digest}: {sample.file_path} -> {new_path}")
                    sample.file_path = new_path
                    await sample.save()
                    fixed_count += 1
                
            except Exception as e:
                logger.error(f"Error processing sample {sample.sha256_digest}: {e}")
                continue
        
        logger.info(f"Cleanup completed:")
        logger.info(f"- Deleted {deleted_count} invalid samples")
        logger.info(f"- Fixed {fixed_count} file paths")
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(clean_samples()) 