from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime

from app.models.user import User
from app.core.auth import get_current_user
from app.models.analysis import AnalysisConfig

router = APIRouter()

@router.get("/", response_model=List[AnalysisConfig])
async def list_analysis_configs(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100
):
    """
    获取分析配置列表
    """
    configs = await AnalysisConfig.find({"created_by": current_user.id}).skip(skip).limit(limit).to_list()
    return configs

@router.post("/", response_model=AnalysisConfig)
async def create_analysis_config(
    config: AnalysisConfig,
    current_user: User = Depends(get_current_user)
):
    """
    创建新分析配置
    """
    config.created_by = current_user.id
    config.created_at = datetime.utcnow()
    
    await config.save()
    return config

@router.get("/{config_id}", response_model=AnalysisConfig)
async def get_analysis_config(
    config_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    获取分析配置详情
    """
    config = await AnalysisConfig.get(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Analysis config not found")
        
    if config.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this config")
        
    return config

@router.put("/{config_id}", response_model=AnalysisConfig)
async def update_analysis_config(
    config_id: str,
    config_update: AnalysisConfig,
    current_user: User = Depends(get_current_user)
):
    """
    更新分析配置
    """
    config = await AnalysisConfig.get(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Analysis config not found")
        
    if config.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this config")
        
    config_update_dict = config_update.dict(exclude_unset=True)
    await config.update({"$set": config_update_dict})
    
    return await AnalysisConfig.get(config_id)

@router.delete("/{config_id}")
async def delete_analysis_config(
    config_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    删除分析配置
    """
    config = await AnalysisConfig.get(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Analysis config not found")
        
    if config.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this config")
        
    await config.delete()
    return {"message": "Analysis config deleted successfully"} 