from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime

from app.models.user import User
from app.core.security import get_current_user
from app.models.analysis import SampleAnalysis

router = APIRouter()

@router.get("/", response_model=List[SampleAnalysis])
async def list_analyses(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None
):
    """
    获取分析列表
    """
    query = {"creator": current_user.id}
    if status:
        query["status"] = status
        
    analyses = await SampleAnalysis.find(query).skip(skip).limit(limit).to_list()
    return analyses

@router.post("/", response_model=SampleAnalysis)
async def create_analysis(
    analysis: SampleAnalysis,
    current_user: User = Depends(get_current_user)
):
    """
    创建新分析
    """
    analysis.creator = current_user.id
    analysis.created_at = datetime.utcnow()
    analysis.status = "pending"
    
    await analysis.save()
    return analysis

@router.get("/{analysis_id}", response_model=SampleAnalysis)
async def get_analysis(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    获取分析详情
    """
    analysis = await SampleAnalysis.get(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    if analysis.creator != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this analysis")
        
    return analysis

@router.delete("/{analysis_id}")
async def delete_analysis(
    analysis_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    删除分析
    """
    analysis = await SampleAnalysis.get(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis not found")
        
    if analysis.creator != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this analysis")
        
    await analysis.delete()
    return {"message": "Analysis deleted successfully"} 