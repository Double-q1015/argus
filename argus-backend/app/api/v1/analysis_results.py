from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Depends
from datetime import datetime

from app.models.user import User
from app.core.auth import get_current_user
from app.models.analysis_result import AnalysisResult
from app.services.analysis_result_service import AnalysisResultService

router = APIRouter()

@router.get("/", response_model=List[AnalysisResult])
async def list_analysis_results(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    analysis_id: Optional[str] = None
):
    """
    获取分析结果列表
    """
    query = {"creator": current_user.id}
    if analysis_id:
        query["analysis"] = analysis_id
        
    results = await AnalysisResult.find(query).skip(skip).limit(limit).to_list()
    return results

@router.get("/{result_id}", response_model=AnalysisResult)
async def get_analysis_result(
    result_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    获取分析结果详情
    """
    result = await AnalysisResult.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found")
        
    if result.creator != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this result")
        
    return result

@router.get("/analysis/{analysis_id}", response_model=List[AnalysisResult])
async def get_results_by_analysis(analysis_id: str):
    """获取分析的所有结果"""
    return await AnalysisResultService.get_results_by_analysis(analysis_id)

@router.get("/sample/{sample_id}", response_model=List[AnalysisResult])
async def get_results_by_sample(
    sample_id: str,
    analysis_type: Optional[str] = Query(None, description="分析类型")
):
    """获取样本的分析结果"""
    return await AnalysisResultService.get_results_by_sample(
        sample_id,
        analysis_type
    )

@router.get("/sample/{sample_id}/latest", response_model=AnalysisResult)
async def get_latest_result(
    sample_id: str,
    analysis_type: str = Query(..., description="分析类型")
):
    """获取最新的分析结果"""
    result = await AnalysisResultService.get_latest_result(
        sample_id,
        analysis_type
    )
    if not result:
        raise HTTPException(status_code=404, detail="分析结果不存在")
    return result

@router.get("/statistics", response_model=dict)
async def get_result_statistics(
    sample_id: Optional[str] = Query(None, description="样本ID"),
    analysis_type: Optional[str] = Query(None, description="分析类型")
):
    """获取分析结果统计信息"""
    return await AnalysisResultService.get_result_statistics(
        sample_id,
        analysis_type
    )

@router.delete("/{result_id}")
async def delete_analysis_result(
    result_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    删除分析结果
    """
    result = await AnalysisResult.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found")
        
    if result.creator != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this result")
        
    await result.delete()
    return {"message": "Analysis result deleted successfully"} 