from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from app.core.security import get_current_user
from app.models.user import User
from app.schemas.analysis import AnalysisResponse
from app.services.analysis_service import AnalysisService

router = APIRouter()

@router.get("/analysis/{sample_id}", response_model=AnalysisResponse)
async def get_analysis(
    sample_id: str,
    current_user: User = Depends(get_current_user),
    analysis_service: AnalysisService = Depends()
):
    """获取样本分析结果"""
    analysis = await analysis_service.get_analysis(sample_id, current_user.id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return analysis

@router.post("/analysis/{sample_id}/start")
async def start_analysis(
    sample_id: str,
    current_user: User = Depends(get_current_user),
    analysis_service: AnalysisService = Depends()
):
    """开始样本分析"""
    success = await analysis_service.start_analysis(sample_id, current_user.id)
    if not success:
        raise HTTPException(status_code=404, detail="Sample not found")
    return {"message": "Analysis started successfully"}

@router.get("/analysis/", response_model=List[AnalysisResponse])
async def get_analyses(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    analysis_service: AnalysisService = Depends()
):
    """获取分析结果列表"""
    return await analysis_service.get_analyses(current_user.id, skip, limit) 