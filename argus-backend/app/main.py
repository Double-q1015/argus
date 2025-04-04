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

app = FastAPI(
    title="Snake Skin API",
    description="Snake Skin - 恶意软件分析平台API",
    version="1.0.0",
    openapi_url="/api/v1/openapi.json"
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
app.include_router(samples.router, prefix="/api/v1", tags=["samples"])
app.include_router(analysis.router, prefix="/api/v1", tags=["analysis"])
app.include_router(api_keys.router, prefix="/api/v1", tags=["api_keys"])

@app.on_event("startup")
async def startup_event():
    """
    应用启动时初始化数据库连接
    """
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB]
    
    # 清理现有索引
    collections = ["samples", "users", "yara_rules", "scales", "api_keys"]
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
            ApiKey
        ],
        allow_index_dropping=True
    )
    
    await init_storage()

@app.on_event("shutdown")
async def shutdown_event():
    """
    应用关闭时关闭数据库连接
    """
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    client.close()

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