from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime

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