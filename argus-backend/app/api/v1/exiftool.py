from typing import List
from fastapi import APIRouter, HTTPException, Depends, status
from app.models.exiftool_task import ExifToolTask
from app.services.exiftool_service import ExifToolService
from app.core.security import get_current_user
from app.models.user import User
from pydantic import BaseModel

router = APIRouter()
exiftool_service = ExifToolService()

class TaskCreate(BaseModel):
    name: str
    description: str = None

class TaskResponse(BaseModel):
    id: str
    name: str
    description: str = None
    status: str
    task_status: dict
    created_at: str
    updated_at: str
    results: dict

@router.post("/tasks", response_model=TaskResponse)
async def create_task(
    task_data: TaskCreate,
    current_user: User = Depends(get_current_user)
):
    """创建新的ExifTool分析任务"""
    task = await exiftool_service.create_task(
        name=task_data.name,
        description=task_data.description
    )
    return TaskResponse(
        id=str(task.id),
        name=task.name,
        description=task.description,
        status=task.status,
        task_status=task.task_status.dict(),
        created_at=task.created_at.isoformat(),
        updated_at=task.updated_at.isoformat(),
        results=task.results
    )

@router.get("/tasks", response_model=List[TaskResponse])
async def list_tasks(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user)
):
    """获取ExifTool分析任务列表"""
    tasks = await exiftool_service.list_tasks(skip=skip, limit=limit)
    return [
        TaskResponse(
            id=str(task.id),
            name=task.name,
            description=task.description,
            status=task.status,
            task_status=task.task_status.dict(),
            created_at=task.created_at.isoformat(),
            updated_at=task.updated_at.isoformat(),
            results=task.results
        )
        for task in tasks
    ]

@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """获取特定ExifTool分析任务"""
    task = await exiftool_service.get_task(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found"
        )
    return TaskResponse(
        id=str(task.id),
        name=task.name,
        description=task.description,
        status=task.status,
        task_status=task.task_status.dict(),
        created_at=task.created_at.isoformat(),
        updated_at=task.updated_at.isoformat(),
        results=task.results
    )

@router.post("/tasks/{task_id}/start")
async def start_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """启动ExifTool分析任务"""
    success = await exiftool_service.start_task(task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to start task"
        )
    return {"status": "success", "message": "Task started"}

@router.post("/tasks/{task_id}/stop")
async def stop_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """停止ExifTool分析任务"""
    success = await exiftool_service.stop_task(task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to stop task"
        )
    return {"status": "success", "message": "Task stopped"} 