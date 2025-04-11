import os
import logging
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.models.user import User
from app.models.sample import Sample
from app.models.analysis import (
    SampleAnalysis, 
    AnalysisResult, 
    Task, 
    TaskStatus, 
    TaskCondition, 
    SampleAnalysisStatus, 
    AnalysisConfig,
    AnalysisSchedule
)
from app.models.migration import MigrationTask, MigrationFileStatus

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_db() -> None:
    """
    初始化数据库连接
    """
    try:
        # 创建MongoDB客户端
        client = AsyncIOMotorClient(settings.MONGODB_URL)
        
        # 初始化Beanie
        await init_beanie(
            database=client[settings.MONGODB_DB],
            document_models=[
                User,
                Sample,
                SampleAnalysis,
                AnalysisResult,
                Task,
                TaskStatus,
                TaskCondition,
                SampleAnalysisStatus,
                MigrationTask,
                MigrationFileStatus,
                AnalysisConfig,
                AnalysisSchedule
            ]
        )
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise