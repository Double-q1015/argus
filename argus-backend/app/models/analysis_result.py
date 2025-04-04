from datetime import datetime
from typing import Dict, Any, Optional, List
from beanie import Document, Indexed
from pydantic import BaseModel, Field

class AnalysisResultData(BaseModel):
    """分析结果数据"""
    result_type: str = Field(..., description="结果类型")
    data: Dict[str, Any] = Field(..., description="结果数据")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="元数据")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="创建时间")

class AnalysisResult(Document):
    """分析结果"""
    analysis_id: Indexed(str) = Field(..., description="分析ID")
    sample_id: Indexed(str) = Field(..., description="样本ID")
    analysis_type: Indexed(str) = Field(..., description="分析类型")
    version: str = Field(..., description="分析版本")
    results: List[AnalysisResultData] = Field(default_factory=list, description="分析结果列表")
    status: str = Field(default="pending", description="状态")
    error_message: Optional[str] = Field(None, description="错误信息")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="创建时间")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="更新时间")

    class Settings:
        name = "analysis_results"
        indexes = [
            "analysis_id",
            "sample_id",
            "analysis_type",
            "status",
            "created_at"
        ]

    class Config:
        schema_extra = {
            "example": {
                "analysis_id": "analysis_123",
                "sample_id": "sample_456",
                "analysis_type": "exiftool",
                "version": "1.0.0",
                "results": [
                    {
                        "result_type": "metadata",
                        "data": {
                            "FileType": "PE32",
                            "FileSize": "1.2MB",
                            "CreationDate": "2024-01-01 12:00:00"
                        },
                        "metadata": {
                            "tool_version": "12.0",
                            "execution_time": 1.5
                        },
                        "created_at": "2024-01-01T12:00:00Z"
                    }
                ],
                "status": "completed",
                "error_message": None,
                "created_at": "2024-01-01T12:00:00Z",
                "updated_at": "2024-01-01T12:00:00Z"
            }
        } 