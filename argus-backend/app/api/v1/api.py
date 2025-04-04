from fastapi import APIRouter
from app.api.v1 import auth, samples, scales, yara, analysis
from app.api.v1.endpoints import home, search

api_router = APIRouter()

# 注册各个模块的路由
api_router.include_router(
    auth.router,
    prefix="/auth",
    tags=["认证"]
)

api_router.include_router(
    samples.router,
    prefix="/samples",
    tags=["样本管理"]
)

api_router.include_router(
    analysis.router,
    prefix="/analysis",
    tags=["文件分析"]
)

api_router.include_router(
    scales.router,
    prefix="/scales",
    tags=["规模分析"]
)

api_router.include_router(
    yara.router,
    prefix="/yara",
    tags=["Yara规则"]
)

api_router.include_router(
    home.router,
    prefix="/home",
    tags=["首页"]
)

api_router.include_router(
    search.router,
    prefix="/search",
    tags=["搜索"]
) 