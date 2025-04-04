import asyncio
import sys
import os
import logging
from datetime import datetime
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

from app.models.user import User
from app.core.auth import pwd_context
from app.models.analysis import Task, TaskStatus, AnalysisConfig, TaskCondition, SampleAnalysis, AnalysisResult, SampleAnalysisStatus
from app.models.sample import Sample
from app.services.task_service import TaskService
from app.services.analysis_service import AnalysisService
from app.services.analysis_config_service import AnalysisConfigService
from app.services.task_executor import TaskExecutor
from app.core.config import settings

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
            User,
            Sample,
            Task,
            TaskStatus,
            TaskCondition,
            AnalysisConfig,
            SampleAnalysis,
            AnalysisResult,
            SampleAnalysisStatus
        ]
    )
    logger.info("Database initialization completed")

async def test_task_executor():
    """测试任务执行器"""
    # 初始化数据库连接
    await init_database()
    
    try:
        # 获取或创建测试用户
        logger.info("Looking for test user...")
        user = await User.find_one(User.email == 'test_hash@example.com')
        if not user:
            logger.info("Creating new test user...")
            user = User(
                username='test_user_hash',
                email='test_hash@example.com',
                hashed_password=pwd_context.hash('test123'),
                is_active=True,
                is_superuser=True
            )
            await user.insert()
            logger.info("Created test user")
        else:
            logger.info("Using existing test user")
        
        # 创建哈希分析配置
        logger.info("Creating hash analysis config...")
        config = await AnalysisConfigService.create_config(
            name='测试哈希分析',
            analysis_type='hash',
            created_by=user,
            description='测试哈希分析功能',
            auto_analyze=True,
            priority=1
        )
        logger.info(f"Created analysis config with ID: {config.id}")
        
        # 创建分析任务
        logger.info("Creating analysis task...")
        task = await TaskService.create_task(
            name='测试哈希分析任务',
            task_type='hash',
            created_by=user,
            description='测试哈希分析任务',
            priority=1,
            config_id=config.id
        )
        logger.info(f"Created analysis task with ID: {task.id}")
        
        # 检查任务状态
        task_status = await TaskService.get_task_status(task.id)
        logger.info(f"Initial task status: {task_status.dict() if task_status else 'None'}")
        
        # 检查样本数量
        samples = await Sample.find().to_list()
        logger.info(f"Total samples in database before execution: {len(samples)}")
        
        # 直接执行任务
        logger.info("Starting task execution...")
        try:
            result = await TaskExecutor.execute_continuous_analysis_task(task.id)
            logger.info(f"Task execution result: {result}")
        except Exception as e:
            logger.error(f"Task execution failed: {str(e)}")
            logger.error("Traceback:", exc_info=True)
        
        # 检查任务状态
        task_status = await TaskService.get_task_status(task.id)
        logger.info(f"Final task status: {task_status.dict() if task_status else 'None'}")
        
        # 检查失败的样本
        if task_status and task_status.failed_samples:
            logger.error(f"Failed samples: {task_status.failed_samples}")
            # 获取第一个失败样本的详细信息
            if task_status.failed_samples:
                sample_id = task_status.failed_samples[0]
                sample = await Sample.get(sample_id)
                if sample:
                    logger.error(f"Failed sample details: {sample.dict()}")
        
        # 检查样本数量
        samples = await Sample.find().to_list()
        logger.info(f"Total samples in database after execution: {len(samples)}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        logger.error("Traceback:", exc_info=True)

if __name__ == '__main__':
    asyncio.run(test_task_executor()) 