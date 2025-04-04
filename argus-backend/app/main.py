from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie

from app.core.config import settings
from app.core.storage import init_storage
from app.api.v1.api import api_router
from app.routers import samples, users, analysis, api_keys
from app.models.sample import Sample
from app.models.user import User
from app.models.yara import YaraRule
from app.models.scale import Scale
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
from app.core.database import init_db
from app.core.scheduler import scheduler
from app.api.v1 import (
    tasks,
    analyses,
    analysis_results,
    analysis_configs
)

app = FastAPI(
    title="Argus Backend",
    description="Argus Backend API",
    version="1.0.0"
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
app.include_router(api_router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1", tags=["users"])
app.include_router(samples.router, prefix="/api/v1/samples", tags=["samples"])
app.include_router(tasks.router, prefix="/api/v1/tasks", tags=["tasks"])
app.include_router(analyses.router, prefix="/api/v1/analyses", tags=["analyses"])
app.include_router(analysis_results.router, prefix="/api/v1/analysis-results", tags=["analysis-results"])
app.include_router(api_keys.router, prefix="/api/v1", tags=["api_keys"])

@app.on_event("startup")
async def startup_event():
    """
    应用启动时初始化数据库连接
    """
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB]
    
    # 清理现有索引
    collections = [
        "samples", "users", "yara_rules", "scales", "api_keys",
        "tasks", "task_conditions", "task_status", "sample_analysis_status",
        "analysis_configs", "sample_analyses", "analysis_results", "analysis_schedules"
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
            Scale,
            ApiKey,
            Task,
            TaskCondition,
            TaskStatus,
            SampleAnalysisStatus,
            AnalysisConfig,
            SampleAnalysis,
            AnalysisResult,
            AnalysisSchedule
        ],
        allow_index_dropping=True
    )
    
    await init_storage()
    # 启动任务调度器
    await scheduler.start()

@app.on_event("shutdown")
async def shutdown_event():
    """
    应用关闭时关闭数据库连接
    """
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    client.close()
    # 停止任务调度器
    await scheduler.stop()

@app.get("/")
async def root():
    return JSONResponse({
        "message": "Welcome to Snake Skin API",
        "version": settings.VERSION,
        "docs_url": "/api/docs"
    })

@app.get("/health")
async def health_check():
    return JSONResponse(
        content={
            "status": "healthy",
            "version": settings.VERSION
        },
        status_code=200
    ) 