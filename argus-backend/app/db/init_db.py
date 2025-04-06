import os
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from app.core.config import settings
from app.models.user import User
from app.models.sample import Sample
from app.models.analysis import SampleAnalysis, AnalysisResult, Task, TaskStatus, TaskCondition, SampleAnalysisStatus, AnalysisConfig
from app.models.migration import MigrationTask, MigrationFileStatus

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MySQL数据库连接
SQLALCHEMY_DATABASE_URL = f"mysql+pymysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DB}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

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
                AnalysisConfig
            ]
        )
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise

async def close_db():
    """
    关闭数据库连接
    """
    try:
        engine.dispose()
        logger.info("MySQL database connection closed")
    except Exception as e:
        logger.error(f"Error closing database connection: {str(e)}")
        raise

if __name__ == "__main__":
    init_db() 