# API v1 包初始化文件 
from fastapi import APIRouter
from app.api.v1 import (
    auth, samples, yara, analysis, scales, exiftool,
    tasks, analyses, analysis_results, analysis_configs
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(samples.router, prefix="/samples", tags=["samples"])
api_router.include_router(yara.router, prefix="/yara", tags=["yara"])
api_router.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
api_router.include_router(scales.router, prefix="/scales", tags=["scales"])
api_router.include_router(exiftool.router, prefix="/exiftool", tags=["exiftool"])
api_router.include_router(tasks.router, prefix="/tasks", tags=["tasks"])
api_router.include_router(analyses.router, prefix="/analyses", tags=["analyses"])
api_router.include_router(analysis_results.router, prefix="/analysis-results", tags=["analysis-results"])
api_router.include_router(analysis_configs.router, prefix="/analysis-configs", tags=["analysis-configs"]) 