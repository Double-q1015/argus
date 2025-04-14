from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from beanie import Document, Link
from pydantic import BaseModel, Field
from enum import Enum


class MigrationStatus(str, Enum):
    """迁移任务状态"""
    PENDING = "pending"  # 等待执行
    RUNNING = "running"  # 执行中
    COMPLETED = "completed"  # 已完成
    FAILED = "failed"  # 失败
    CANCELLED = "cancelled"  # 已取消


class MigrationTask(Document):
    """迁移任务模型"""
    name: str = Field(..., description="迁移任务名称")
    description: Optional[str] = Field(None, description="迁移任务描述")
    source_storage: str = Field(..., description="源存储类型")
    source_config: Dict[str, Any] = Field(..., description="源存储配置")
    target_storage: str = Field(..., description="目标存储类型")
    target_config: Dict[str, Any] = Field(..., description="目标存储配置")
    file_patterns: Optional[List[str]] = Field(None, description="文件匹配模式，为空则迁移所有文件")
    status: MigrationStatus = Field(default=MigrationStatus.PENDING, description="迁移任务状态")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="创建时间")
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="更新时间")
    started_at: Optional[datetime] = Field(None, description="开始时间")
    completed_at: Optional[datetime] = Field(None, description="完成时间")
    error_message: Optional[str] = Field(None, description="错误信息")
    total_files: int = Field(default=0, description="总文件数")
    processed_files: int = Field(default=0, description="已处理文件数")
    failed_files: int = Field(default=0, description="失败文件数")
    total_size: int = Field(default=0, description="总文件大小(字节)")
    processed_size: int = Field(default=0, description="已处理文件大小(字节)")
    last_processed_file: Optional[str] = Field(None, description="上次处理到的文件路径")
    resume_count: int = Field(default=0, description="恢复执行的次数")
    last_resume_at: Optional[datetime] = Field(None, description="上次恢复执行的时间")
    is_interrupted: bool = Field(default=False, description="任务是否被中断")
    last_heartbeat: Optional[datetime] = Field(None, description="最后一次心跳时间")
    # 是否完成列出文件
    list_files_status: MigrationStatus = Field(default=MigrationStatus.PENDING, description="列出文件状态")

    class Settings:
        name = "migration_tasks"

    def to_dict(self) -> dict:
        """转换为字典格式，确保 id 字段被正确序列化"""
        data = self.dict()
        data["id"] = str(self.id)
        return data


class MigrationFileStatus(Document):
    """迁移文件状态模型"""
    task_id: str = Field(..., description="迁移任务ID")
    file_path: str = Field(..., description="文件路径")
    status: MigrationStatus = Field(default=MigrationStatus.PENDING, description="迁移状态")
    source_size: Optional[int] = Field(None, description="源文件大小")
    target_size: Optional[int] = Field(None, description="目标文件大小")
    started_at: Optional[datetime] = Field(None, description="开始时间")
    completed_at: Optional[datetime] = Field(None, description="完成时间")
    error_message: Optional[str] = Field(None, description="错误信息")

    class Settings:
        name = "migration_file_status"
        indexes = [
            [("task_id", 1), ("file_path", 1)],  # 复合索引
            [("task_id", 1), ("status", 1)],  # 用于查询特定任务的文件状态
        ] 