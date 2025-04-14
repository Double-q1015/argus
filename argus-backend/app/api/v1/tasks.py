from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Optional
from datetime import datetime
from beanie import PydanticObjectId, Link

from app.models.user import User
from app.core.security import get_current_user
from app.models.analysis import Task
from app.models.sample import Sample
from app.services.task_service import TaskService
from app.models.tasks import TaskCreate, TaskResponse, TaskStatus
router = APIRouter()

@router.get("/", response_model=List[TaskResponse])
async def list_tasks(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None
):
    """获取任务列表"""
    # 使用$ref操作符查询引用的用户ID
    user = await User.find_one({"username": current_user.username})
    query = {"created_by.$id": user.id}
    if status:
        query["status"] = status
    tasks = await Task.find(query).skip(skip).limit(limit).to_list()
    
    # 转换为响应格式
    response_tasks = []
    for task in tasks:
        response_tasks.append(await task.to_response_dict())
    
    return response_tasks

@router.post("/", response_model=TaskResponse)
async def create_task(
    task_data: TaskCreate,
    current_user: User = Depends(get_current_user)
):
    """创建任务"""
    task = await TaskService.create_task(
        name=task_data.name,
        task_type=task_data.type,
        description=task_data.description,
        priority=task_data.priority,
        created_by=current_user,  # 使用当前用户的用户名
        schedule=task_data.schedule,
        conditions=task_data.conditions,
        config_id=task_data.config_id
    )
    if not task:
        raise HTTPException(status_code=400, detail="创建任务失败")
    
    # 转换为响应格式
    response_task = await task.to_response_dict()
    return response_task

@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """获取任务详情"""
    task = await Task.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # 获取created_by引用的用户对象
    created_by_user = await task.created_by.fetch()
    if not created_by_user or created_by_user.id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this task")
    
    # 转换为响应格式
    response_task = await task.to_response_dict()
    return response_task

@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """删除任务"""
    task = await Task.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    # 获取created_by引用的用户对象
    created_by_user = await task.created_by.fetch()
    if not created_by_user or created_by_user.id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this task")
    
    await task.delete()
    return {"message": "Task deleted successfully"}

@router.post("/{task_id}/start")
async def start_task(task_id: PydanticObjectId):
    """启动任务"""
    task = await TaskService.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    if task.status != TaskStatus.CREATED:
        raise HTTPException(status_code=400, detail="任务状态不正确，只有已创建的任务可以启动")
    
    # 获取样本数量
    samples = await Sample.find().to_list()
    total_samples = len(samples)
    
    # 更新任务状态为 pending
    task.status = TaskStatus.PENDING
    await task.save()
    
    # 创建任务状态记录并初始化样本数量
    # 先检查在不在
    task_status = await TaskService.get_task_status(task_id)
    if not task_status:
        task_status = await TaskService.create_task_status(task_id)
    if task_status:
        await TaskService.update_task_progress(
            task_id=task_id,
            processed_samples=0,
            failed_samples=[],
            total_samples=total_samples
        )
    
    return {"message": "任务已启动"}