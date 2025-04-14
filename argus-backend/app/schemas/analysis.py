from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from beanie import PydanticObjectId

class AnalysisBase(BaseModel):
    sample_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: Dict[str, Any] = {}

class AnalysisResponse(AnalysisBase):
    id: str
    user_id: int

    class Config:
        from_attributes = True

# 任务相关Schema
class TaskConditionBase(BaseModel):
    type: str
    field: str
    operator: str
    value: Any
    logic: str = "AND"

class TaskCreate(BaseModel):
    name: str
    type: str
    description: Optional[str] = None
    priority: int = 0
    schedule: Optional[str] = None
    conditions: Optional[List[TaskConditionBase]] = None

class TaskResponse(BaseModel):
    id: PydanticObjectId
    name: str
    type: str
    description: Optional[str] = None
    status: str
    priority: int
    created_by: PydanticObjectId
    created_at: datetime
    updated_at: datetime
    schedule: Optional[str] = None
    is_active: bool

    class Config:
        from_attributes = True

class TaskStatusResponse(BaseModel):
    id: PydanticObjectId
    task_id: PydanticObjectId
    total_samples: int
    processed_samples: int
    failed_samples: List[str]
    current_sample: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error_message: Optional[str] = None
    last_updated: datetime

    class Config:
        from_attributes = True

# 分析配置相关Schema
class AnalysisConfigCreate(BaseModel):
    name: str
    analysis_type: str
    description: Optional[str] = None
    auto_analyze: bool = False
    priority: int = 0
    resource_limits: Dict[str, int] = Field(default_factory=dict)

class AnalysisConfigResponse(BaseModel):
    id: PydanticObjectId
    name: str
    analysis_type: str
    description: Optional[str] = None
    auto_analyze: bool
    priority: int
    resource_limits: Dict[str, int]
    created_by: PydanticObjectId
    created_at: datetime
    updated_at: datetime
    is_active: bool

    class Config:
        from_attributes = True

class AnalysisScheduleCreate(BaseModel):
    config_id: PydanticObjectId
    schedule_type: str
    schedule_value: str

class AnalysisScheduleResponse(BaseModel):
    id: PydanticObjectId
    config_id: PydanticObjectId
    schedule_type: str
    schedule_value: str
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    is_active: bool

    class Config:
        from_attributes = True

# 样本分析相关Schema
class SampleAnalysisResponse(BaseModel):
    id: PydanticObjectId
    sample_id: PydanticObjectId
    analysis_type: str
    status: str
    version: int
    retry_count: int
    last_analysis_time: Optional[datetime] = None
    next_analysis_time: Optional[datetime] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class AnalysisResultResponse(BaseModel):
    id: PydanticObjectId
    sample_analysis_id: PydanticObjectId
    result_type: str
    result_data: Dict[str, Any]
    created_at: datetime
    version: int

    class Config:
        from_attributes = True 