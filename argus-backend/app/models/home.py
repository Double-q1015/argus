from pydantic import BaseModel
from typing import List
from datetime import datetime

class DashboardStats(BaseModel):
    total_samples: int
    today_samples: int
    total_storage: int
    active_users: int

class RecentSample(BaseModel):
    sha256_digest: str
    file_name: str
    upload_time: datetime
    tags: List[str] 