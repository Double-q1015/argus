from typing import List, Optional, Dict, Any, Union
from fastapi import APIRouter, Depends, HTTPException, Query, Path, Body
from sqlalchemy.orm import Session
from app.services.migration_service import MigrationService
from app.models.migration import MigrationTask, MigrationFileStatus, MigrationStatus
from app.api.v1.auth import get_current_user
from app.models.user import User
from pydantic import BaseModel, Field, HttpUrl, validator
import re

router = APIRouter()
migration_service = MigrationService()

# 存储配置模型
class MinioStorageConfig(BaseModel):
    """MinIO存储配置"""
    endpoint: str = Field(..., description="MinIO服务地址，例如：localhost:9000")
    access_key: str = Field(..., description="访问密钥")
    secret_key: str = Field(..., description="密钥")
    bucket_name: str = Field(..., description="存储桶名称")
    prefix: Optional[str] = Field("", description="文件前缀")
    secure: bool = Field(False, description="是否使用HTTPS")

    @validator('endpoint')
    def validate_endpoint(cls, v):
        # 移除http://或https://前缀
        v = re.sub(r'^https?://', '', v)
        # 验证格式：host:port
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*:[0-9]+$', v):
            raise ValueError('endpoint must be in format: host:port')
        return v

class LocalStorageConfig(BaseModel):
    """本地存储配置"""
    base_path: str = Field(..., description="基础路径")
    directory_depth: Optional[int] = Field(2, description="目录深度", ge=0, le=4)

# 存储配置联合类型
StorageConfig = Union[MinioStorageConfig, LocalStorageConfig]

# 请求和响应模型
class MigrationTaskCreate(BaseModel):
    """创建迁移任务请求"""
    name: str = Field(..., description="迁移任务名称")
    description: Optional[str] = Field(None, description="迁移任务描述")
    source_storage: str = Field(..., description="源存储类型")
    source_config: Dict[str, Any] = Field(..., description="源存储配置")
    target_storage: str = Field(..., description="目标存储类型")
    target_config: Dict[str, Any] = Field(..., description="目标存储配置")
    file_patterns: Optional[List[str]] = Field(None, description="文件匹配模式，为空则迁移所有文件")

    @validator('source_storage', 'target_storage')
    def validate_storage_type(cls, v):
        if v not in ['minio', 'local']:
            raise ValueError('storage type must be either minio or local')
        return v

    @validator('source_config')
    def validate_source_config(cls, v, values):
        storage_type = values.get('source_storage')
        if storage_type == 'minio':
            required_fields = ['endpoint', 'access_key', 'secret_key', 'bucket_name']
            for field in required_fields:
                if field not in v:
                    raise ValueError(f'minio storage requires {field}')
        elif storage_type == 'local':
            if 'base_path' not in v:
                raise ValueError('local storage requires base_path')
        return v

    @validator('target_config')
    def validate_target_config(cls, v, values):
        storage_type = values.get('target_storage')
        if storage_type == 'minio':
            required_fields = ['endpoint', 'access_key', 'secret_key', 'bucket_name']
            for field in required_fields:
                if field not in v:
                    raise ValueError(f'minio storage requires {field}')
        elif storage_type == 'local':
            if 'base_path' not in v:
                raise ValueError('local storage requires base_path')
        return v

class MigrationTaskUpdate(BaseModel):
    """更新迁移任务请求"""
    name: Optional[str] = Field(None, description="迁移任务名称")
    description: Optional[str] = Field(None, description="迁移任务描述")
    file_patterns: Optional[List[str]] = Field(None, description="文件匹配模式，为空则迁移所有文件")

# API路由
@router.get("/tasks", response_model=Dict[str, Any])
async def get_migration_tasks(
    skip: int = Query(0, description="跳过记录数"),
    limit: int = Query(10, description="返回记录数"),
    status: Optional[MigrationStatus] = Query(None, description="任务状态"),
    current_user: User = Depends(get_current_user)
):
    """获取迁移任务列表"""
    tasks = await migration_service.get_migration_tasks(skip=skip, limit=limit, status=status)
    total = await migration_service.count_migration_tasks(status=status)
    return {
        "data": tasks,
        "total": total
    }

@router.post("/tasks", response_model=MigrationTask)
async def create_migration_task(
    task: MigrationTaskCreate,
    current_user: User = Depends(get_current_user)
):
    """创建迁移任务"""
    return await migration_service.create_migration_task(
        name=task.name,
        description=task.description,
        source_storage=task.source_storage,
        source_config=task.source_config,
        target_storage=task.target_storage,
        target_config=task.target_config,
        file_patterns=task.file_patterns
    )

@router.get("/tasks/{task_id}", response_model=MigrationTask)
async def get_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: User = Depends(get_current_user)
):
    """获取迁移任务详情"""
    task = await migration_service.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    return task

@router.put("/tasks/{task_id}", response_model=MigrationTask)
async def update_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    task_update: MigrationTaskUpdate = Body(...),
    current_user: User = Depends(get_current_user)
):
    """更新迁移任务"""
    task = await migration_service.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    if task.status != MigrationStatus.PENDING:
        raise HTTPException(status_code=400, detail="Only pending tasks can be updated")
    
    update_data = task_update.dict(exclude_unset=True)
    updated_task = await migration_service.update_migration_task(task_id, update_data)
    if not updated_task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    return updated_task

@router.delete("/tasks/{task_id}")
async def delete_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: User = Depends(get_current_user)
):
    """删除迁移任务"""
    task = await migration_service.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    if task.status not in [MigrationStatus.COMPLETED, MigrationStatus.FAILED, MigrationStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Only completed, failed, or cancelled tasks can be deleted")
    
    success = await migration_service.delete_migration_task(task_id)
    if not success:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    return {"message": "Migration task deleted successfully"}

@router.post("/tasks/{task_id}/execute")
async def execute_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: User = Depends(get_current_user)
):
    """执行迁移任务"""
    task = await migration_service.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    if task.status != MigrationStatus.PENDING:
        raise HTTPException(status_code=400, detail="Only pending tasks can be executed")
    
    success = await migration_service.execute_migration_task(task_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to execute migration task")
    
    return {"message": "Migration task execution started"}

@router.post("/tasks/{task_id}/cancel")
async def cancel_migration_task(
    task_id: str = Path(..., description="迁移任务ID"),
    current_user: User = Depends(get_current_user)
):
    """取消迁移任务"""
    task = await migration_service.get_migration_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Migration task not found")
    
    if task.status not in [MigrationStatus.PENDING, MigrationStatus.RUNNING]:
        raise HTTPException(status_code=400, detail="Only pending or running tasks can be cancelled")
    
    success = await migration_service.interrupt_migration_task(task_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to cancel migration task")
    
    return {"message": "Migration task cancelled successfully"}

@router.get("/tasks/{task_id}/files", response_model=Dict[str, Any])
async def get_migration_file_statuses(
    task_id: str = Path(..., description="迁移任务ID"),
    skip: int = Query(0, description="跳过记录数"),
    limit: int = Query(100, description="返回记录数"),
    status: Optional[MigrationStatus] = Query(None, description="文件状态"),
    current_user: User = Depends(get_current_user)
):
    """获取迁移文件状态列表"""
    file_statuses = await migration_service.get_migration_file_statuses(
        task_id=task_id,
        skip=skip,
        limit=limit,
        status=status
    )
    total = await migration_service.count_migration_file_statuses(
        task_id=task_id,
        status=status
    )
    return {
        "data": file_statuses,
        "total": total
    }

@router.get("/tasks/{task_id}/files/{file_id}", response_model=MigrationFileStatus)
async def get_migration_file_status(
    task_id: str = Path(..., description="迁移任务ID"),
    file_id: str = Path(..., description="文件ID"),
    current_user: User = Depends(get_current_user)
):
    """获取迁移文件状态"""
    file_status = await migration_service.get_migration_file_status(task_id, file_id)
    if not file_status:
        raise HTTPException(status_code=404, detail="Migration file status not found")
    return file_status 