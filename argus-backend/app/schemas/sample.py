from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class SampleBase(BaseModel):
    filename: str
    content_type: str
    size: int
    status: str

class SampleCreate(SampleBase):
    pass

class SampleResponse(SampleBase):
    id: str
    user_id: int
    created_at: datetime
    content: Optional[bytes] = None

    class Config:
        from_attributes = True 