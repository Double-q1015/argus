from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, ForwardRef
from beanie import Document, Link
from app.models.user import User
from app.models.sample import Sample

AnalysisConfig = ForwardRef("AnalysisConfig")

class Task(Document):
    """任务基础表"""
    name: str
    description: Optional[str] = None
    type: str  # 任务类型：analysis, scan, etc.
    status: str  # pending, running, completed, failed
    priority: int = 0
    created_by: Link[User]
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)
    schedule: Optional[str] = None  # cron表达式
    is_active: bool = True
    config_id: Optional[Link[AnalysisConfig]] = None  # 分析配置ID

    class Settings:
        name = "tasks"
        indexes = [
            ("status", "type", "priority"),
            ("created_by", "created_at"),
            ("schedule", "is_active"),
            ("config_id",)
        ]

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
            ("task_id", "condition_type"),
            ("parent_id", "order")
        ]

class TaskStatus(Document):
    """任务状态表"""
    task_id: Link[Task]
    status: str = "pending"  # pending, running, completed, failed
    total_samples: int = 0
    processed_samples: int = 0
    failed_samples: List[str] = []
    current_sample: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    last_updated: datetime = datetime.now(timezone.utc)

    class Settings:
        name = "task_statuses"
        indexes = [
            ("task_id", "last_updated"),
            ("status", "last_updated")
        ]

class SampleAnalysis(Document):
    """样本分析记录表"""
    sample_id: Link[Sample]
    analysis_type: str  # exiftool, pe_info, strings, etc.
    status: str  # pending, analyzing, completed, failed
    version: int = 1  # 分析版本号
    retry_count: int = 0
    last_analysis_time: Optional[datetime] = None
    next_analysis_time: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)

    class Settings:
        name = "sample_analyses"
        indexes = [
            ("sample_id", "analysis_type"),
            ("status", "analysis_type"),
            ("next_analysis_time")
        ]

class AnalysisResult(Document):
    """分析结果表"""
    sample_analysis_id: Link[SampleAnalysis]
    result_type: str  # 结果类型
    result_data: Dict[str, Any]  # 结果数据
    created_at: datetime = datetime.now(timezone.utc)
    version: int = 1  # 结果版本号

    class Settings:
        name = "analysis_results"
        indexes = [
            ("sample_analysis_id", "result_type"),
            ("created_at")
        ]

class AnalysisConfig(Document):
    """分析配置表"""
    name: str
    description: Optional[str] = None
    analysis_type: str
    auto_analyze: bool = False
    priority: int = 0
    resource_limits: Dict[str, int] = {}
    created_by: Link[User]
    created_at: datetime = datetime.now(timezone.utc)
    updated_at: datetime = datetime.now(timezone.utc)
    is_active: bool = True

    class Settings:
        name = "analysis_configs"
        indexes = [
            ("analysis_type", "is_active"),
            ("created_by", "created_at")
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
            ("config_id", "is_active"),
            ("next_run")
        ] 