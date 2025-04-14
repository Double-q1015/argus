import asyncio
import sys
import os
import logging
from datetime import datetime, timedelta
from beanie import PydanticObjectId
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# 添加项目根目录到Python路径
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
logger.info(f"Project root: {project_root}")
logger.info(f"Python path: {sys.path}")

from app.models.migration import MigrationTask, MigrationFileStatus
from app.core.config import settings
from app.services.migration_service import MigrationService

async def init_database():
    """初始化数据库连接"""
    logger.info("Initializing database connection...")
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB]
    
    # 初始化 Beanie
    logger.info("Initializing Beanie with document models...")
    await init_beanie(
        database=db,
        document_models=[
            MigrationTask,
            MigrationFileStatus
        ]
    )
    logger.info("Database initialization completed")

async def check_stuck_tasks():
    """检查卡住的任务"""
    try:
        # 初始化数据库连接
        await init_database()
        
        # 创建迁移服务实例
        migration_service = MigrationService()
        
        # 获取所有运行中的任务
        running_tasks = await MigrationTask.find(
            MigrationTask.status == "running"
        ).to_list()
        
        logger.info(f"Found {len(running_tasks)} running tasks")
        
        # 检查每个任务
        for task in running_tasks:
            logger.info(f"\nChecking task {task.id}:")
            logger.info(f"Task name: {task.name}")
            logger.info(f"Created at: {task.created_at}")
            logger.info(f"Last heartbeat: {task.last_heartbeat}")
            
            # 使用迁移服务检查任务
            await MigrationService.check_stale_tasks()
            
            # 显示任务进度
            total_files = await MigrationFileStatus.find(
                MigrationFileStatus.task_id == task.id
            ).count()
            
            completed_files = await MigrationFileStatus.find(
                MigrationFileStatus.task_id == task.id,
                MigrationFileStatus.status == "completed"
            ).count()
            
            failed_files = await MigrationFileStatus.find(
                MigrationFileStatus.task_id == task.id,
                MigrationFileStatus.status == "failed"
            ).count()
            
            logger.info(f"Progress: {completed_files}/{total_files} completed, {failed_files} failed")
            
    except Exception as e:
        logger.error(f"Error checking stuck tasks: {str(e)}", exc_info=True)

if __name__ == '__main__':
    asyncio.run(check_stuck_tasks()) 