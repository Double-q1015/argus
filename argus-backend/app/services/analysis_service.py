from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from beanie import PydanticObjectId
from app.core.database import get_database
from app.schemas.analysis import AnalysisResponse
from bson import ObjectId
from app.models.analysis import SampleAnalysis, AnalysisResult
from app.models.sample import Sample

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

    @staticmethod
    async def create_analysis(
        sample_id: PydanticObjectId,
        analysis_type: str,
        auto_analyze: bool = False
    ) -> SampleAnalysis:
        """创建样本分析记录"""
        analysis = SampleAnalysis(
            sample=sample_id,
            analysis_type=analysis_type,
            status="pending",
            next_analysis_time=datetime.utcnow() if auto_analyze else None
        )
        await analysis.insert()
        return analysis

    @staticmethod
    async def get_analysis(analysis_id: PydanticObjectId) -> Optional[SampleAnalysis]:
        """获取分析记录"""
        return await SampleAnalysis.get(analysis_id)

    @staticmethod
    async def get_sample_analyses(
        sample_id: PydanticObjectId,
        analysis_type: Optional[str] = None
    ) -> List[SampleAnalysis]:
        """获取样本的分析记录"""
        query = SampleAnalysis.find(SampleAnalysis.sample_id == sample_id)
        if analysis_type:
            query = query.find(SampleAnalysis.analysis_type == analysis_type)
        return await query.to_list()

    @staticmethod
    async def update_analysis_status(
        analysis_id: PydanticObjectId,
        status: str,
        error_message: Optional[str] = None
    ) -> Optional[SampleAnalysis]:
        """更新分析状态"""
        analysis = await SampleAnalysis.get(analysis_id)
        if not analysis:
            return None

        analysis.status = status
        analysis.updated_at = datetime.utcnow()
        
        if status == "analyzing":
            analysis.last_analysis_time = datetime.utcnow()
        elif status == "completed":
            analysis.next_analysis_time = None
        elif status == "failed":
            analysis.error_message = error_message
            analysis.retry_count += 1
            # 设置重试时间（指数退避）
            retry_delay = min(300 * (2 ** analysis.retry_count), 86400)  # 最大24小时
            analysis.next_analysis_time = datetime.utcnow() + timedelta(seconds=retry_delay)

        await analysis.save()
        return analysis

    @staticmethod
    async def save_analysis_result(
        analysis_id: PydanticObjectId,
        result_type: str,
        result_data: Dict[str, Any]
    ) -> AnalysisResult:
        """保存分析结果"""
        result = AnalysisResult(
            analysis=analysis_id,
            result_type=result_type,
            result_data=result_data
        )
        await result.insert()
        return result

    @staticmethod
    async def get_analysis_results(
        analysis_id: PydanticObjectId,
        result_type: Optional[str] = None
    ) -> List[AnalysisResult]:
        """获取分析结果"""
        query = AnalysisResult.find(AnalysisResult.sample_analysis_id == analysis_id)
        if result_type:
            query = query.find(AnalysisResult.result_type == result_type)
        return await query.sort(AnalysisResult.created_at).to_list()

    @staticmethod
    async def get_pending_analyses(
        analysis_type: Optional[str] = None,
        limit: int = 10
    ) -> List[SampleAnalysis]:
        """获取待执行的分析任务"""
        query = SampleAnalysis.find(
            SampleAnalysis.status == "pending",
            SampleAnalysis.next_analysis_time <= datetime.utcnow()
        )
        if analysis_type:
            query = query.find(SampleAnalysis.analysis_type == analysis_type)
        return await query.limit(limit).to_list()

    @staticmethod
    async def schedule_analysis(
        analysis_id: PydanticObjectId,
        next_analysis_time: datetime
    ) -> Optional[SampleAnalysis]:
        """调度分析任务"""
        analysis = await SampleAnalysis.get(analysis_id)
        if not analysis:
            return None

        analysis.next_analysis_time = next_analysis_time
        analysis.updated_at = datetime.utcnow()
        await analysis.save()
        return analysis

    async def analyze_pdf(self, pdf_path: str) -> AnalysisResponse:
        # Implementation of analyze_pdf method
        pass

    async def analyze_office(self, office_path: str) -> AnalysisResponse:
        # Implementation of analyze_office method
        pass

    async def analyze_archive(self, archive_path: str) -> AnalysisResponse:
        # Implementation of analyze_archive method
        pass

    async def analyze_script(self, script_path: str) -> AnalysisResponse:
        # Implementation of analyze_script method
        pass 