from datetime import datetime
from typing import Optional, List, Dict, Any
from beanie import PydanticObjectId
from app.models.analysis import SampleAnalysis, AnalysisResult
from app.models.sample import Sample
from app.services.analysis_service import AnalysisService
from app.core.exiftool_analyzer import perform_exiftool_analysis
from app.core.pe_analyzer import perform_pe_analysis
from app.core.strings_analyzer import analyze_strings
from app.core.yara_analyzer import analyze_yara
from app.core.hash_analyzer import calculate_hashes
from app.core.entropy_analyzer import calculate_entropy
from app.core.magic_analyzer import perform_magic_analysis

class AnalysisExecutor:
    """分析执行器"""
    
    @staticmethod
    async def execute_analysis(analysis_id: PydanticObjectId) -> bool:
        """执行分析任务"""
        # 获取分析记录
        analysis = await AnalysisService.get_analysis(analysis_id)
        if not analysis:
            return False
            
        try:
            # 更新分析状态为运行中
            await AnalysisService.update_analysis_status(analysis_id, "analyzing")
            
            # 获取样本信息
            sample = await Sample.get(analysis.sample_id)
            if not sample:
                raise ValueError(f"Sample not found: {analysis.sample_id}")
                
            # 执行分析
            result = None
            if analysis.analysis_type == "exiftool":
                result = await perform_exiftool_analysis(str(sample.file_path))
            elif analysis.analysis_type == "pe_info":
                result = await perform_pe_analysis(str(sample.file_path))
            elif analysis.analysis_type == "strings":
                result = await analyze_strings(str(sample.file_path))
            elif analysis.analysis_type == "yara":
                result = await analyze_yara(str(sample.file_path))
            elif analysis.analysis_type == "hash":
                result = await calculate_hashes(str(sample.file_path))
            elif analysis.analysis_type == "entropy":
                result = await calculate_entropy(str(sample.file_path))
            elif analysis.analysis_type == "magic":
                result = await perform_magic_analysis(str(sample.file_path))
            else:
                raise ValueError(f"Unsupported analysis type: {analysis.analysis_type}")
                
            # 保存分析结果
            await AnalysisService.save_analysis_result(
                analysis_id=analysis_id,
                result_type=analysis.analysis_type,
                result_data=result
            )
            
            # 更新分析状态为完成
            await AnalysisService.update_analysis_status(analysis_id, "completed")
            
            return True
            
        except Exception as e:
            # 更新分析状态为失败
            await AnalysisService.update_analysis_status(
                analysis_id=analysis_id,
                status="failed",
                error_message=str(e)
            )
            return False
            
    @staticmethod
    async def execute_batch_analysis(
        sample_ids: List[PydanticObjectId],
        analysis_types: List[str],
        auto_analyze: bool = False
    ) -> Dict[str, List[PydanticObjectId]]:
        """批量执行分析任务"""
        results = {
            "success": [],
            "failed": []
        }
        
        for sample_id in sample_ids:
            for analysis_type in analysis_types:
                try:
                    # 创建分析记录
                    analysis = await AnalysisService.create_analysis(
                        sample_id=sample_id,
                        analysis_type=analysis_type,
                        auto_analyze=auto_analyze
                    )
                    
                    # 执行分析
                    if await AnalysisExecutor.execute_analysis(analysis.id):
                        results["success"].append(analysis.id)
                    else:
                        results["failed"].append(analysis.id)
                        
                except Exception as e:
                    print(f"Error executing analysis for sample {sample_id}: {e}")
                    results["failed"].append(analysis.id)
                    
        return results
        
    @staticmethod
    async def execute_auto_analysis(sample_id: PydanticObjectId) -> Dict[str, List[PydanticObjectId]]:
        """执行自动分析任务"""
        # 获取样本信息
        sample = await Sample.get(sample_id)
        if not sample:
            raise ValueError(f"Sample not found: {sample_id}")
            
        # 获取文件类型
        file_type = await perform_magic_analysis(str(sample.file_path))
        
        # 根据文件类型选择分析类型
        analysis_types = ["hash", "entropy", "magic"]  # 基础分析类型
        
        if file_type.startswith("PE32"):
            analysis_types.extend(["pe_info", "strings", "yara"])
        elif file_type.startswith(("JPEG", "PNG", "GIF", "TIFF")):
            analysis_types.extend(["exiftool"])
        else:
            analysis_types.extend(["strings", "yara"])
            
        # 执行分析
        return await AnalysisExecutor.execute_batch_analysis(
            sample_ids=[sample_id],
            analysis_types=analysis_types,
            auto_analyze=True
        ) 