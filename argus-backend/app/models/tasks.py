from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class TaskStatus(str, Enum):
    """任务状态"""
    CREATED = "created"      # 已创建
    PENDING = "pending"      # 待执行
    RUNNING = "running"      # 执行中
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"        # 执行失败
    STOPPED = "stopped"      # 已停止 

class TaskCreate(BaseModel):
    """任务创建模型"""
    name: str
    type: str
    description: Optional[str] = None
    priority: int = 0
    schedule: Optional[str] = None
    conditions: Optional[List[Dict[str, Any]]] = None
    config_id: Optional[str] = None

class TaskResponse(BaseModel):
    """任务响应模型"""
    id: str
    name: str
    description: Optional[str] = None
    type: str
    status: str
    priority: int
    created_by: str  # 用户ID
    created_at: datetime
    updated_at: datetime
    schedule: Optional[str] = None
    is_active: bool
    config_id: Optional[str] = None

    class Config:
        from_attributes = True 