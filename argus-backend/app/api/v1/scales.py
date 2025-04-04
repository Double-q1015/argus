from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pymongo import DESCENDING

from app.models.user import User
from app.models.sample import Sample
from app.models.scale import Scale, ScaleCreate, ScaleUpdate, ScaleResponse, ScaleFilter, ScaleStats
from app.api.v1.auth import get_current_user
from app.core.analysis import start_scale_analysis, stop_scale_analysis

router = APIRouter()

@router.post("", response_model=ScaleResponse)
async def create_scale(
    scale_data: ScaleCreate,
    current_user: User = Depends(get_current_user)
):
    # 验证样本是否存在
    samples = []
    for sample_id in scale_data.sample_ids:
        sample = await Sample.find_one(Sample.sha256_digest == sample_id)
        if not sample:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Sample with SHA256 {sample_id} not found"
            )
        samples.append(sample)
    
    # 创建规模分析
    scale = Scale(
        name=scale_data.name,
        description=scale_data.description,
        creator=current_user,
        configuration=scale_data.configuration,
        samples=samples
    )
    await scale.insert()
    
    return ScaleResponse(
        id=str(scale.id),
        name=scale.name,
        description=scale.description,
        creator=scale.creator.username,
        created_at=scale.created_at,
        updated_at=scale.updated_at,
        status=scale.status,
        sample_count=len(scale.samples),
        configuration=scale.configuration,
        results=scale.results,
        error_message=scale.error_message
    )

@router.get("", response_model=List[ScaleResponse])
async def list_scales(
    skip: int = 0,
    limit: int = 10,
    creator: Optional[str] = None,
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(get_current_user)
):
    # 构建查询条件
    query = {}
    if creator:
        creator_user = await User.find_one(User.username == creator)
        if creator_user:
            query["creator"] = creator_user.id
    if status:
        query["status"] = status
    if start_date:
        query["created_at"] = {"$gte": start_date}
    if end_date:
        if "created_at" in query:
            query["created_at"]["$lte"] = end_date
        else:
            query["created_at"] = {"$lte": end_date}
    
    # 获取规模分析列表
    scales = await Scale.find(query).skip(skip).limit(limit).to_list()
    
    return [
        ScaleResponse(
            id=str(scale.id),
            name=scale.name,
            description=scale.description,
            creator=scale.creator.username,
            created_at=scale.created_at,
            updated_at=scale.updated_at,
            status=scale.status,
            sample_count=len(scale.samples),
            configuration=scale.configuration,
            results=scale.results,
            error_message=scale.error_message
        )
        for scale in scales
    ]

@router.get("/stats", response_model=ScaleStats)
async def get_scale_stats(current_user: User = Depends(get_current_user)):
    # 获取总规模分析数
    total_scales = await Scale.count()
    
    # 获取各状态的规模分析数量
    pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}}
    ]
    status_stats = await Scale.aggregate(pipeline).to_list()
    scales_by_status = {stat["_id"]: stat["count"] for stat in status_stats}
    
    # 获取最近的规模分析
    recent_scales = await Scale.find().sort("created_at", DESCENDING).limit(5).to_list()
    recent_scales_response = [
        ScaleResponse(
            id=str(scale.id),
            name=scale.name,
            description=scale.description,
            creator=scale.creator.username,
            created_at=scale.created_at,
            updated_at=scale.updated_at,
            status=scale.status,
            sample_count=len(scale.samples),
            configuration=scale.configuration,
            results=scale.results,
            error_message=scale.error_message
        )
        for scale in recent_scales
    ]
    
    return ScaleStats(
        total_scales=total_scales,
        scales_by_status=scales_by_status,
        recent_scales=recent_scales_response
    )

@router.get("/{scale_id}", response_model=ScaleResponse)
async def get_scale(
    scale_id: str,
    current_user: User = Depends(get_current_user)
):
    scale = await Scale.get(scale_id)
    if not scale:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scale analysis not found"
        )
    
    return ScaleResponse(
        id=str(scale.id),
        name=scale.name,
        description=scale.description,
        creator=scale.creator.username,
        created_at=scale.created_at,
        updated_at=scale.updated_at,
        status=scale.status,
        sample_count=len(scale.samples),
        configuration=scale.configuration,
        results=scale.results,
        error_message=scale.error_message
    )

@router.put("/{scale_id}", response_model=ScaleResponse)
async def update_scale(
    scale_id: str,
    scale_update: ScaleUpdate,
    current_user: User = Depends(get_current_user)
):
    scale = await Scale.get(scale_id)
    if not scale:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scale analysis not found"
        )
    
    # 检查权限（只有创建者或管理员可以更新）
    if scale.creator.id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to update this scale analysis"
        )
    
    # 更新规模分析信息
    update_data = scale_update.dict(exclude_unset=True)
    if update_data:
        update_data["updated_at"] = datetime.utcnow()
        await scale.update({"$set": update_data})
    
    return ScaleResponse(
        id=str(scale.id),
        name=scale.name,
        description=scale.description,
        creator=scale.creator.username,
        created_at=scale.created_at,
        updated_at=scale.updated_at,
        status=scale.status,
        sample_count=len(scale.samples),
        configuration=scale.configuration,
        results=scale.results,
        error_message=scale.error_message
    )

@router.post("/{scale_id}/start")
async def start_scale(
    scale_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    scale = await Scale.get(scale_id)
    if not scale:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scale analysis not found"
        )
    
    # 检查权限（只有创建者或管理员可以启动）
    if scale.creator.id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to start this scale analysis"
        )
    
    # 检查状态
    if scale.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scale analysis is already running"
        )
    
    # 更新状态并启动分析
    await scale.update({"$set": {"status": "running", "updated_at": datetime.utcnow()}})
    background_tasks.add_task(start_scale_analysis, scale)
    
    return {"status": "success", "message": "Scale analysis started"}

@router.post("/{scale_id}/stop")
async def stop_scale(
    scale_id: str,
    current_user: User = Depends(get_current_user)
):
    scale = await Scale.get(scale_id)
    if not scale:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scale analysis not found"
        )
    
    # 检查权限（只有创建者或管理员可以停止）
    if scale.creator.id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to stop this scale analysis"
        )
    
    # 检查状态
    if scale.status != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scale analysis is not running"
        )
    
    # 停止分析
    await stop_scale_analysis(scale)
    await scale.update({"$set": {"status": "stopped", "updated_at": datetime.utcnow()}})
    
    return {"status": "success", "message": "Scale analysis stopped"}

@router.delete("/{scale_id}")
async def delete_scale(
    scale_id: str,
    current_user: User = Depends(get_current_user)
):
    scale = await Scale.get(scale_id)
    if not scale:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scale analysis not found"
        )
    
    # 检查权限（只有创建者或管理员可以删除）
    if scale.creator.id != current_user.id and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to delete this scale analysis"
        )
    
    # 检查状态
    if scale.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running scale analysis"
        )
    
    # 删除规模分析
    await scale.delete()
    
    return {"status": "success", "message": "Scale analysis deleted successfully"} 