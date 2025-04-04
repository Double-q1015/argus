from typing import List, Optional
from datetime import datetime
from app.core.database import get_database
from app.schemas.analysis import AnalysisResponse
from bson import ObjectId

class AnalysisService:
    def __init__(self, db=None):
        self.db = db or get_database()
        self.collection = self.db.analyses

    async def get_analysis(self, sample_id: str, user_id: int) -> Optional[AnalysisResponse]:
        """获取单个分析结果"""
        analysis = await self.collection.find_one({
            "sample_id": sample_id,
            "user_id": user_id
        })
        if analysis:
            analysis["id"] = str(analysis["_id"])
            return AnalysisResponse(**analysis)
        return None

    async def get_analyses(self, user_id: int, skip: int = 0, limit: int = 100) -> List[AnalysisResponse]:
        """获取分析结果列表"""
        cursor = self.collection.find({"user_id": user_id}).skip(skip).limit(limit)
        analyses = await cursor.to_list(length=None)
        return [AnalysisResponse(**analysis) for analysis in analyses]

    async def start_analysis(self, sample_id: str, user_id: int) -> bool:
        """开始样本分析"""
        # 检查样本是否存在
        sample = await self.db.samples.find_one({
            "_id": ObjectId(sample_id),
            "user_id": user_id
        })
        if not sample:
            return False
        
        # 创建分析记录
        analysis_doc = {
            "sample_id": sample_id,
            "user_id": user_id,
            "status": "running",
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "results": {}
        }
        
        await self.collection.insert_one(analysis_doc)
        return True 