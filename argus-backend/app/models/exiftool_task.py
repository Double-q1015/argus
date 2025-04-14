from datetime import datetime
from typing import List, Dict, Optional
from beanie import Document
from pydantic import BaseModel, Field

class ExifToolTaskStatus(BaseModel):
    """ExifTool任务状态"""
    total_samples: int = 0
    processed_samples: int = 0
    failed_samples: List[str] = []
    current_sample: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None

class ExifToolTask(Document):
    """ExifTool分析任务"""
    name: str
    description: Optional[str] = None
    status: str = "pending"  # pending, running, completed, failed
    task_status: ExifToolTaskStatus = Field(default_factory=ExifToolTaskStatus)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    results: Dict[str, dict] = {}  # 存储每个样本的分析结果

    class Settings:
        name = "exiftool_tasks"

    async def update_progress(self, processed: int, failed: List[str] = None, current: str = None):
        """更新任务进度"""
        self.task_status.processed_samples = processed
        if failed:
            self.task_status.failed_samples.extend(failed)
        if current:
            self.task_status.current_sample = current
        self.updated_at = datetime.utcnow()
        await self.save()

    async def start(self):
        """开始任务"""
        self.status = "running"
        self.task_status.start_time = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        await self.save()

    async def complete(self):
        """完成任务"""
        self.status = "completed"
        self.task_status.end_time = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        await self.save()

    async def fail(self, error: str):
        """任务失败"""
        self.status = "failed"
        self.task_status.error_message = error
        self.task_status.end_time = datetime.utcnow()
        self.updated_at = datetime.utcnow()
        await self.save() 