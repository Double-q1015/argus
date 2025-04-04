from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from beanie import PydanticObjectId
from app.api.deps import get_current_user
from app.models.user import User
from app.schemas.analysis import (
    TaskCreate,
    TaskResponse,
    TaskStatusResponse,
    AnalysisConfigCreate,
    AnalysisConfigResponse,
    AnalysisScheduleCreate,
    AnalysisScheduleResponse,
    SampleAnalysisResponse,
    AnalysisResultResponse
)
from app.services.task_service import TaskService
from app.services.analysis_service import AnalysisService
from app.services.analysis_config_service import AnalysisConfigService

router = APIRouter()

# 任务管理API
@router.post("/tasks", response_model=TaskResponse)
async def create_task(
    task: TaskCreate,
    current_user: User = Depends(get_current_user)
):
    """创建新任务"""
    return await TaskService.create_task(
        name=task.name,
        task_type=task.type,
        created_by=current_user,
        description=task.description,
        priority=task.priority,
        schedule=task.schedule,
        conditions=task.conditions
    )

@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: PydanticObjectId,
    current_user: User = Depends(get_current_user)
):
    """获取任务详情"""
    task = await TaskService.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task

@router.get("/tasks/{task_id}/status", response_model=TaskStatusResponse)
async def get_task_status(
    task_id: PydanticObjectId,
    current_user: User = Depends(get_current_user)
):
    """获取任务状态"""
    status = await TaskService.get_task_status(task_id)
    if not status:
        raise HTTPException(status_code=404, detail="Task status not found")
    return status

@router.get("/tasks", response_model=List[TaskResponse])
async def get_user_tasks(
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_user)
):
    """获取用户的任务列表"""
    return await TaskService.get_user_tasks(current_user.id, skip, limit)

@router.post("/tasks/{task_id}/deactivate")
async def deactivate_task(
    task_id: PydanticObjectId,
    current_user: User = Depends(get_current_user)
):
    """停用任务"""
    task = await TaskService.deactivate_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deactivated successfully"}

# 分析配置API
@router.post("/configs", response_model=AnalysisConfigResponse)
async def create_analysis_config(
    config: AnalysisConfigCreate,
    current_user: User = Depends(get_current_user)
):
    """创建分析配置"""
    return await AnalysisConfigService.create_config(
        name=config.name,
        analysis_type=config.analysis_type,
        created_by=current_user,
        description=config.description,
        auto_analyze=config.auto_analyze,
        priority=config.priority,
        resource_limits=config.resource_limits
    )

@router.get("/configs/{config_id}", response_model=AnalysisConfigResponse)
async def get_analysis_config(
    config_id: PydanticObjectId,
    current_user: User = Depends(get_current_user)
):
    """获取分析配置"""
    config = await AnalysisConfigService.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Analysis config not found")
    return config

@router.get("/configs", response_model=List[AnalysisConfigResponse])
async def get_analysis_configs(
    analysis_type: Optional[str] = None,
    is_active: Optional[bool] = True,
    skip: int = Query(0, ge=0),
    limit: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_user)
):
    """获取分析配置列表"""
    return await AnalysisConfigService.get_configs(
        analysis_type=analysis_type,
        is_active=is_active,
        skip=skip,
        limit=limit
    )

# 分析计划API
@router.post("/schedules", response_model=AnalysisScheduleResponse)
async def create_analysis_schedule(
    schedule: AnalysisScheduleCreate,
    current_user: User = Depends(get_current_user)
):
    """创建分析计划"""
    return await AnalysisConfigService.create_schedule(
        config_id=schedule.config_id,
        schedule_type=schedule.schedule_type,
        schedule_value=schedule.schedule_value
    )

@router.get("/schedules/{schedule_id}", response_model=AnalysisScheduleResponse)
async def get_analysis_schedule(
    schedule_id: PydanticObjectId,
    current_user: User = Depends(get_current_user)
):
    """获取分析计划"""
    schedule = await AnalysisConfigService.get_schedule(schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Analysis schedule not found")
    return schedule

@router.get("/configs/{config_id}/schedules", response_model=List[AnalysisScheduleResponse])
async def get_config_schedules(
    config_id: PydanticObjectId,
    is_active: Optional[bool] = True,
    current_user: User = Depends(get_current_user)
):
    """获取配置的分析计划"""
    return await AnalysisConfigService.get_config_schedules(config_id, is_active)

# 样本分析API
@router.get("/samples/{sample_id}/analyses", response_model=List[SampleAnalysisResponse])
async def get_sample_analyses(
    sample_id: PydanticObjectId,
    analysis_type: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """获取样本的分析记录"""
    return await AnalysisService.get_sample_analyses(sample_id, analysis_type)

@router.get("/analyses/{analysis_id}/results", response_model=List[AnalysisResultResponse])
async def get_analysis_results(
    analysis_id: PydanticObjectId,
    result_type: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """获取分析结果"""
    return await AnalysisService.get_analysis_results(analysis_id, result_type) 