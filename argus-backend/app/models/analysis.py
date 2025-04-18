from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, ForwardRef, Union
from beanie import Document, Link
from app.models.user import User
from app.models.sample import Sample
from pydantic import Field

class Task(Document):
    """任务基础表"""
    name: str
    description: Optional[str] = None
    type: str  # 任务类型：analysis, scan, etc.
    status: str = Field(default="pending")  # pending, running, completed, failed
    priority: int = 0
    created_by: Link[User] = Field(description="创建者", sa_relationship_kwargs={"lazy": "selectin"})
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)
    schedule: Optional[str] = None  # cron表达式
    is_active: bool = True
    config_id: Optional[Union[str, Link["AnalysisConfig"]]] = Field(default=None, description="分析配置ID", sa_relationship_kwargs={"lazy": "selectin"})

    class Settings:
        name = "tasks"
        indexes = [
            [("status", 1), ("type", 1), ("priority", 1)],
            [("created_by.$id", 1), ("created_at", 1)],
            [("schedule", 1), ("is_active", 1)],
            [("config_id", 1)]
        ]

    async def to_response_dict(self) -> dict:
        """转换为响应字典"""
        d = {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "type": self.type,
            "status": self.status,
            "priority": self.priority,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "schedule": self.schedule,
            "is_active": self.is_active
        }

        # 处理created_by字段
        if isinstance(self.created_by, Link):
            user = await self.created_by.fetch()
            d["created_by"] = str(user.id) if user else None
        elif isinstance(self.created_by, User):
            d["created_by"] = str(self.created_by.id)
        else:
            d["created_by"] = str(self.created_by) if self.created_by else None

        # 处理config_id字段
        if isinstance(self.config_id, Link):
            config = await self.config_id.fetch()
            d["config_id"] = str(config.id) if config else None
        else:
            d["config_id"] = str(self.config_id) if self.config_id else None

        return d

class TaskCondition(Document):
    """任务条件表"""
    task_id: Link[Task]
    condition_type: str  # file_type, file_size, hash, etc.
    field: str  # 字段名
    operator: str  # in, not_in, between, gt, lt, etc.
    value: Any  # 条件值
    logic: str  # AND, OR
    parent_id: Optional[Link["TaskCondition"]] = None  # 父条件ID，用于条件组合
    order: int = 0  # 条件顺序

    class Settings:
        name = "task_conditions"
        indexes = [
            [("task_id", 1), ("condition_type", 1)],
            [("parent_id", 1), ("order", 1)]
        ]

# 应该新建一个枚举类来定义任务状态
class TaskStatusEnum():
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class TaskStatus(Document):
    """任务状态表"""
    task_id: Link[Task]
    status: str  # pending, running, completed, failed
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    current_sample: Optional[str] = None  # 当前处理的样本ID
    processed_samples: int = 0  # 已处理的样本数
    failed_samples: List[str] = []  # 处理失败的样本ID列表
    total_samples: int = 0  # 总样本数
    error_message: Optional[str] = None  # 错误信息
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)

    @classmethod
    def created(cls):
        return 'created'

    @classmethod
    def pending(cls):
        return 'pending'

    @classmethod
    def running(cls):
        return 'running'

    @classmethod
    def completed(cls):
        return 'completed'

    @classmethod
    def failed(cls):
        return 'failed'
    class Settings:
        name = "task_status"
        indexes = [
            [("task_id", 1)],
            [("status", 1)],
            [("start_time", 1)],
            [("end_time", 1)]
        ]

class SampleAnalysisStatus(Document):
    """样本分析状态表"""
    sample: Link[Sample]
    task_type: str  # hash, strings, pe_info, exiftool 等
    status: str  # pending, completed, failed
    analysis_time: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)

    class Settings:
        name = "sample_analysis_status"
        indexes = [
            [("sample", 1), ("task_type", 1)],
            [("status", 1)],
            [("analysis_time", 1)]
        ]

class AnalysisConfig(Document):
    """分析配置表"""
    name: str
    description: Optional[str] = None
    analysis_type: str  # hash, strings, pe_info, exiftool 等
    created_by: Link[User]
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)
    auto_analyze: bool = False  # 是否自动分析
    priority: int = 0  # 优先级
    is_active: bool = True  # 是否激活

    class Settings:
        name = "analysis_configs"
        indexes = [
            [("created_by", 1), ("created_at", 1)],
            [("analysis_type", 1), ("is_active", 1)],
            [("priority", 1)]
        ]

class SampleAnalysis(Document):
    """样本分析记录表"""
    sample: Link[Sample]
    analysis_type: str  # hash, strings, pe_info, exiftool 等
    status: str  # pending, completed, failed
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)
    error_message: Optional[str] = None
    auto_analyze: bool = False  # 是否自动分析
    retry_count: int = Field(default=0, description="重试次数")
    next_analysis_time: Optional[datetime] = None
    last_analysis_time: Optional[datetime] = None

    class Settings:
        name = "sample_analyses"
        indexes = [
            [("sample", 1), ("analysis_type", 1)],
            [("status", 1)],
            [("created_at", 1)]
        ]

class AnalysisResult(Document):
    """分析结果表"""
    analysis: Link[SampleAnalysis]
    result_type: str  # hash, strings, pe_info, exiftool 等
    result_data: Dict[str, Any]  # 分析结果数据
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)

    class Settings:
        name = "analysis_results"
        indexes = [
            [("analysis", 1)],
            [("result_type", 1)],
            [("created_at", 1)]
        ]

class AnalysisSchedule(Document):
    """分析计划表"""
    config_id: Link[AnalysisConfig]
    schedule_type: str  # cron, interval, manual
    schedule_value: str  # cron表达式或时间间隔
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    is_active: bool = True

    class Settings:
        name = "analysis_schedules"
        indexes = [
            [("config_id", 1), ("is_active", 1)],
            [("next_run", 1)]
        ] 