from datetime import datetime
from typing import List, Optional, Dict, Any
from app.models.analysis_result import AnalysisResult, AnalysisResultData

class AnalysisResultService:
    """分析结果服务"""
    
    @staticmethod
    async def create_result(
        analysis_id: str,
        sample_id: str,
        analysis_type: str,
        version: str,
        results: List[Dict[str, Any]]
    ) -> AnalysisResult:
        """创建分析结果"""
        result = AnalysisResult(
            analysis_id=analysis_id,
            sample_id=sample_id,
            analysis_type=analysis_type,
            version=version,
            results=[AnalysisResultData(**r) for r in results]
        )
        await result.insert()
        return result
        
    @staticmethod
    async def get_result(result_id: str) -> Optional[AnalysisResult]:
        """获取分析结果"""
        return await AnalysisResult.get(result_id)
        
    @staticmethod
    async def get_results_by_analysis(analysis_id: str) -> List[AnalysisResult]:
        """获取分析的所有结果"""
        return await AnalysisResult.find(
            AnalysisResult.analysis_id == analysis_id
        ).to_list()
        
    @staticmethod
    async def get_results_by_sample(
        sample_id: str,
        analysis_type: Optional[str] = None
    ) -> List[AnalysisResult]:
        """获取样本的分析结果"""
        query = AnalysisResult.find(AnalysisResult.sample_id == sample_id)
        if analysis_type:
            query = query.find(AnalysisResult.analysis_type == analysis_type)
        return await query.to_list()
        
    @staticmethod
    async def update_result(
        result_id: str,
        results: List[Dict[str, Any]],
        status: str = "completed",
        error_message: Optional[str] = None
    ) -> Optional[AnalysisResult]:
        """更新分析结果"""
        result = await AnalysisResult.get(result_id)
        if result:
            result.results = [AnalysisResultData(**r) for r in results]
            result.status = status
            result.error_message = error_message
            result.updated_at = datetime.utcnow()
            await result.save()
        return result
        
    @staticmethod
    async def delete_result(result_id: str) -> bool:
        """删除分析结果"""
        result = await AnalysisResult.get(result_id)
        if result:
            await result.delete()
            return True
        return False
        
    @staticmethod
    async def get_latest_result(
        sample_id: str,
        analysis_type: str
    ) -> Optional[AnalysisResult]:
        """获取最新的分析结果"""
        return await AnalysisResult.find(
            AnalysisResult.sample_id == sample_id,
            AnalysisResult.analysis_type == analysis_type
        ).sort(-AnalysisResult.created_at).first()
        
    @staticmethod
    async def get_result_statistics(
        sample_id: Optional[str] = None,
        analysis_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """获取分析结果统计信息"""
        query = AnalysisResult.find()
        if sample_id:
            query = query.find(AnalysisResult.sample_id == sample_id)
        if analysis_type:
            query = query.find(AnalysisResult.analysis_type == analysis_type)
            
        total = await query.count()
        completed = await query.find(
            AnalysisResult.status == "completed"
        ).count()
        failed = await query.find(
            AnalysisResult.status == "failed"
        ).count()
        pending = await query.find(
            AnalysisResult.status == "pending"
        ).count()
        
        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "pending": pending,
            "success_rate": (completed / total * 100) if total > 0 else 0
        } 