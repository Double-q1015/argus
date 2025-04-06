from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, Path, Body
from app.models.migration import MigrationTask, MigrationFileStatus, MigrationStatus
from app.services.migration_service import MigrationService
from app.core.config import settings
from app.api.deps import get_current_user
from pydantic import BaseModel, Field

router = APIRouter()


class MigrationTaskCreate(BaseModel):
    """创建迁移任务请求"""
    name: str = Field(..., description="迁移任务名称")
    description: Optional[str] = Field(None, description="迁移任务描述")
    source_storage: str = Field(..., description="源存储类型")
    source_config: Dict[str, Any] = Field(..., description="源存储配置")
    target_storage: str = Field(..., description="目标存储类型")
    target_config: Dict[str, Any] = Field(..., description="目标存储配置")
    file_patterns: Optional[List[str]] = Field(None, description="文件匹配模式，为空则迁移所有文件")


class MigrationTaskUpdate(BaseModel):
    """更新迁移任务请求"""
    name: Optional[str] = Field(None, description="迁移任务名称")
    description: Optional[str] = Field(None, description="迁移任务描述")
    file_patterns: Optional[List[str]] = Field(None, description="文件匹配模式，为空则迁移所有文件")


class MigrationTaskResponse(BaseModel):
    """迁移任务响应"""
    id: str
    name: str
    description: Optional[str]
    source_storage: str
    target_storage: str
    file_patterns: Optional[List[str]]
    status: MigrationStatus
    created_at: str
    updated_at: str
    started_at: Optional[str]
    completed_at: Optional[str]
    error_message: Optional[str]
    total_files: int
    processed_files: int
    failed_files: int
    total_size: int
    processed_size: int

    class Config:
        orm_mode = True


class MigrationFileStatusResponse(BaseModel):
    """迁移文件状态响应"""
    id: str
    task_id: str
    file_path: str
    status: MigrationStatus
    source_size: Optional[int]
    target_size: Optional[int]
    started_at: Optional[str]
    completed_at: Optional[str]
    error_message: Optional[str]

    class Config:
        orm_mode = True


@router.post("/tasks", response_model=MigrationTaskResponse)
async def create_migration_task(
    task: MigrationTaskCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """创建迁移任务"""
    migration_task = await MigrationService.create_migration_task(
        name=task.name,
        description=task.description,
        source_storage=task.source_storage,
        source_config=task.source_config,
        target_storage=task.target_storage,
        target_config=task.target_config,
        file_patterns=task.file_patterns
    )
    return migration_task


@router.get("/tasks", response_model=List[MigrationTaskResponse])
async def get_migration_tasks(
    skip: int = Query(0, description="跳过记录数"),
    limit: int = Query(100, description="返回记录数"),
    status: Optional[MigrationStatus] = Query(None, description="任务状态"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """获取迁移任务列表"""
    tasks = await MigrationService.get_migration_tasks(skip=skip, limit=limit, status=status)
    return tasks


@router.get("/tasks/{task_id}", response_model=MigrationTaskResponse)
async def get_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """获取迁移任务详情"""
    task = await MigrationService.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    return task


@router.put("/tasks/{task_id}", response_model=MigrationTaskResponse)
async def update_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    task_update: MigrationTaskUpdate = Body(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """更新迁移任务"""
    # 获取当前任务
    task = await MigrationService.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    # 只能更新等待中的任务
    if task.status != MigrationStatus.PENDING:
        raise HTTPException(status_code=400, detail="Only pending tasks can be updated")
    
    # 更新任务
    update_data = task_update.dict(exclude_unset=True)
    updated_task = await MigrationService.update_migration_task(task_id, update_data)
    if not updated_task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    return updated_task


@router.delete("/tasks/{task_id}")
async def delete_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """删除迁移任务"""
    # 获取当前任务
    task = await MigrationService.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    # 只能删除已完成、失败或已取消的任务
    if task.status not in [MigrationStatus.COMPLETED, MigrationStatus.FAILED, MigrationStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Only completed, failed, or cancelled tasks can be deleted")
    
    # 删除任务
    success = await MigrationService.delete_migration_task(task_id)
    if not success:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    return {"message": "Migration task deleted successfully"}


@router.post("/tasks/{task_id}/execute")
async def execute_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """执行迁移任务"""
    # 获取当前任务
    task = await MigrationService.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    # 只能执行等待中的任务
    if task.status != MigrationStatus.PENDING:
        raise HTTPException(status_code=400, detail="Only pending tasks can be executed")
    
    # 执行任务
    success = await MigrationService.execute_migration_task(task_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to execute migration task")
    
    return {"message": "Migration task execution started"}


@router.post("/tasks/{task_id}/cancel")
async def cancel_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """取消迁移任务"""
    # 获取当前任务
    task = await MigrationService.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    # 只能取消等待中或运行中的任务
    if task.status not in [MigrationStatus.PENDING, MigrationStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Only pending or running tasks can be cancelled")
    
    # 取消任务
    success = await MigrationService.cancel_migration_task(task_id)
    if not success:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    return {"message": "Migration task cancelled successfully"}


@router.get("/tasks/{task_id}/files", response_model=List[MigrationFileStatusResponse])
async def get_migration_file_statuses(
    task_id: str = Path(..., description="迁移任务ID"),
    skip: int = Query(0, description="跳过记录数"),
    limit: int = Query(100, description="返回记录数"),
    status: Optional[MigrationStatus] = Query(None, description="文件状态"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """获取迁移文件状态列表"""
    # 获取当前任务
    task = await MigrationService.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    # 获取文件状态
    file_statuses = await MigrationService.get_migration_file_statuses(
        task_id=task_id,
        skip=skip,
        limit=limit,
        status=status
    )
    
    return file_statuses 