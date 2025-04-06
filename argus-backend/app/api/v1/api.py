from fastapi import APIRouter
from app.api.v1 import auth, samples, yara, analysis, tasks, users, migration
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
    tags=["分析任务"]
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

api_router.include_router(
    tasks.router,
    prefix="/tasks",
    tags=["任务管理"]
)

api_router.include_router(
    users.router,
    prefix="/users",
    tags=["用户管理"]
)

api_router.include_router(
    migration.router,
    prefix="/migration",
    tags=["数据迁移"]
)