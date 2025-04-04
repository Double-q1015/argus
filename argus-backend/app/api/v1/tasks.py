from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import List, Optional
from datetime import datetime

from app.models.user import User
from app.core.auth import get_current_user
from app.models.analysis import Task
from app.models.sample import Sample

router = APIRouter()

@router.get("/", response_model=List[Task])
async def list_tasks(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None
):
    """
    获取任务列表
    """
    query = {"created_by": current_user.id}
    if status:
        query["status"] = status
        
    tasks = await Task.find(query).skip(skip).limit(limit).to_list()
    return tasks

@router.post("/", response_model=Task)
async def create_task(
    task: Task,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    创建新任务
    """
    task.created_by = current_user.id
    task.created_at = datetime.utcnow()
    task.status = "pending"
    
    await task.save()
    
    # TODO: 在后台任务中执行分析
    # background_tasks.add_task(execute_analysis, task.id)
    
    return task

@router.get("/{task_id}", response_model=Task)
async def get_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    获取任务详情
    """
    task = await Task.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    if task.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to access this task")
        
    return task

@router.delete("/{task_id}")
async def delete_task(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    删除任务
    """
    task = await Task.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
        
    if task.created_by != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this task")
        
    await task.delete()
    return {"message": "Task deleted successfully"} 