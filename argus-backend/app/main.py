import os
import logging
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from minio.error import MinioException
from urllib3.exceptions import MaxRetryError

from app.core.config import settings
from app.core.storage import init_storage
from app.api.v1.api import api_router
from app.models.sample import Sample
from app.models.user import User
from app.models.yara import YaraRule
from app.models.api_key import ApiKey
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
from app.core.scheduler import start_scheduler, stop_scheduler
# 确保日志目录存在
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
log_dir = os.path.join(BASE_DIR, "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# 创建文件处理器
file_handler = logging.FileHandler(os.path.join(log_dir, 'captcha.log'))
file_handler.setLevel(logging.DEBUG)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# 创建格式化器
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 添加处理器到日志记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Argus Backend API",
    version="1.0.0",
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该设置为具体的域名
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 注册路由
app.include_router(api_router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def startup_event():
    """
    应用启动时初始化数据库连接和存储服务
    """
    try:
        # 初始化MongoDB连接
        client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=5000)
        # 测试连接
        await client.server_info()
        db = client[settings.MONGODB_DB]
        
        # 清理现有索引
        collections = [
            "samples", "users", "yara_rules", "scales", "api_keys",
            "tasks", "task_conditions", "task_status", "sample_analysis_status",
            "analysis_configs", "sample_analyses", "analysis_results", "analysis_schedules",
            "migration_tasks", "migration_file_status"
        ]
        for collection_name in collections:
            collection = db[collection_name]
            await collection.drop_indexes()
        
        # 初始化Beanie
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
        logger.info("Successfully connected to MongoDB")
        
        # 初始化存储服务
        try:
            await init_storage()
            logger.info("Successfully initialized storage service")
        except (MinioException, MaxRetryError) as e:
            logger.error(f"Failed to initialize storage service: {str(e)}")
            # 存储服务初始化失败不影响应用启动
            pass
        
        # 启动调度器
        start_scheduler()
        logger.info("Scheduler started successfully")
        
    except Exception as e:
        logger.error(f"Failed to initialize application: {str(e)}")
        # 如果是MongoDB连接失败，返回503错误
        if isinstance(e, Exception):
            raise HTTPException(
                status_code=503,
                detail="Service temporarily unavailable. Database connection failed."
            )

@app.on_event("shutdown")
async def shutdown_event():
    """
    应用关闭时清理资源
    """
    try:
        stop_scheduler()
        logger.info("Scheduler stopped successfully")
    except Exception as e:
        logger.error(f"Error stopping scheduler: {str(e)}")

@app.get("/")
async def root():
    return JSONResponse({
        "message": "Welcome to Snake Skin API",
        "version": settings.VERSION,
        "docs_url": "/api/docs"
    })

@app.get("/health")
async def health_check():
    """
    健康检查端点
    """
    try:
        # 检查MongoDB连接
        client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=5000)
        await client.server_info()
        
        # 检查存储服务
        storage_status = "unknown"
        try:
            await init_storage()
            storage_status = "healthy"
        except Exception:
            storage_status = "unhealthy"
        
        return {
            "status": "healthy",
            "mongodb": "connected",
            "storage": storage_status
        }
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        ) 