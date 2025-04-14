import logging
import os
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from beanie import PydanticObjectId
from app.models.analysis import Task, TaskStatus, TaskCondition, SampleAnalysisStatus
from app.models.sample import Sample
from app.services.task_service import TaskService
from app.services.analysis_service import AnalysisService
from app.core.exiftool_analyzer import perform_exiftool_analysis
from app.core.pe_analyzer import perform_pe_analysis
from app.core.strings_analyzer import analyze_strings
from app.core.hash_analyzer import calculate_minio_file_hashes
from app.core.storage import create_minio_client
from app.core.config import settings
import traceback
import croniter


# 确保日志目录存在
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
log_dir = os.path.join(BASE_DIR, "logs")
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# 创建文件处理器
file_handler = logging.FileHandler(os.path.join(log_dir, 'task_executor.log'))
file_handler.setLevel(logging.DEBUG)

# 创建控制台处理器
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# 创建格式化器
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# 添加处理器到日志记录器
logger.addHandler(file_handler)
logger.addHandler(console_handler)


class TaskExecutor:
    """任务执行器"""
    
    @staticmethod
    async def evaluate_conditions(sample: Sample, conditions: List[TaskCondition]) -> bool:
        """评估任务条件"""
        if not conditions:
            return True
            
        result = True
        for condition in conditions:
            field_value = getattr(sample, condition.field, None)
            if field_value is None:
                continue
                
            condition_result = False
            if condition.operator == "in":
                condition_result = field_value in condition.value
            elif condition.operator == "not_in":
                condition_result = field_value not in condition.value
            elif condition.operator == "eq":
                condition_result = field_value == condition.value
            elif condition.operator == "ne":
                condition_result = field_value != condition.value
            elif condition.operator == "gt":
                condition_result = field_value > condition.value
            elif condition.operator == "lt":
                condition_result = field_value < condition.value
            elif condition.operator == "between":
                condition_result = condition.value[0] <= field_value <= condition.value[1]
                
            if condition.logic == "AND":
                result = result and condition_result
            else:  # OR
                result = result or condition_result
                
        return result

    @staticmethod
    async def execute_analysis_task(task_id: PydanticObjectId) -> bool:
        """执行分析任务"""
        # 获取任务信息
        task = await TaskService.get_task(task_id)
        if not task:
            logger.error(f"Task not found: {task_id}")
            return False
        # 更新任务本身的状态
        task.status = 'running'
        task.updated_at = datetime.now(timezone.utc)
        await task.save()
            
        # 获取任务状态，如果不存在则创建
        task_status = await TaskService.get_task_status(task_id)
        if not task_status:
            logger.info(f"Creating new task status for task: {task_id}")
            task_status = await TaskService.create_task_status(task_id)
            if not task_status:
                logger.error(f"Failed to create task status for task: {task_id}")
                return False
            
        # 获取任务条件
        conditions = await TaskService.get_task_conditions(task_id)
        
        try:
            # 更新任务状态为运行中
            await TaskService.update_task_status(task_id, "running")
            
            # 获取待分析的样本
            samples = await Sample.find().to_list()
            total_samples = len(samples)
            processed_samples = 0
            failed_samples = []
            
            logger.info(f"Starting task execution for {total_samples} samples")
            
            # 更新任务状态中的总样本数
            await TaskService.update_task_progress(
                task_id=task_id,
                processed_samples=0,
                failed_samples=[],
                total_samples=total_samples
            )
            
            # 设置开始时间
            task_status.start_time = datetime.now(timezone.utc)
            await task_status.save()
            
            # 创建 MinIO 客户端
            minio_client = create_minio_client()
            logger.info("Created MinIO client")
            
            # 遍历样本
            for sample in samples:
                # 评估条件
                if not await TaskExecutor.evaluate_conditions(sample, conditions):
                    continue
                    
                try:
                    # 更新当前样本
                    await TaskService.update_task_status(
                        task_id,
                        "running",
                        current_sample=str(sample.id)
                    )
                    
                    # 创建分析记录
                    analysis = await AnalysisService.create_analysis(
                        sample_id=sample.id,
                        analysis_type=task.type,
                        auto_analyze=True
                    )
                    
                    # 执行分析
                    if task.type == "exiftool":
                        result = await perform_exiftool_analysis(str(sample.file_path))
                    elif task.type == "pe_info":
                        result = await perform_pe_analysis(str(sample.file_path))
                    elif task.type == "strings":
                        result = await analyze_strings(str(sample.file_path))
                    elif task.type == "hash":
                        bucket_name = settings.MINIO_BUCKET_NAME
                        object_name = str(sample.file_path)
                        result = calculate_minio_file_hashes(
                            minio_client=minio_client,
                            bucket_name=bucket_name,
                            object_name=object_name
                        )
                    else:
                        raise ValueError(f"Unsupported analysis type: {task.type}")
                        
                    # 保存分析结果
                    await AnalysisService.save_analysis_result(
                        analysis_id=analysis.id,
                        result_type=task.type,
                        result_data=result
                    )
                    
                    # 更新分析状态
                    await AnalysisService.update_analysis_status(
                        analysis_id=analysis.id,
                        status="completed"
                    )
                    processed_samples += 1
                    
                except Exception as e:
                    error_msg = f"Error processing sample {sample.id}: {str(e)}\n{traceback.format_exc()}"
                    logger.error(error_msg)
                    # 如果分析记录已经创建，则更新其状态为失败
                    if 'analysis' in locals():
                        await AnalysisService.update_analysis_status(
                            analysis_id=analysis.id,
                            status="failed",
                            error_message=error_msg
                        )
                    failed_samples.append(str(sample.id))
                    
                # 更新任务进度
                await TaskService.update_task_progress(
                    task_id=task_id,
                    processed_samples=processed_samples,
                    failed_samples=failed_samples,
                    total_samples=total_samples
                )
                
            # 更新任务状态为完成
            await TaskService.update_task_status(
                task_id,
                'completed',
                error_message=f"Processed {processed_samples}/{total_samples} samples, {len(failed_samples)} failed"
            )
            
            # 更新任务本身的状态
            task.status = 'completed'
            task.updated_at = datetime.now(timezone.utc)
            await task.save()
            
            return True
            
        except Exception as e:
            error_msg = f"Task execution failed: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            # 更新任务状态为失败
            await TaskService.update_task_status(
                task_id,
                'failed',
                error_message=error_msg
            )
            # 更新任务本身的状态
            task.status = 'failed'
            task.updated_at = datetime.now(timezone.utc)
            logger.info(f"Task {task.id} failed")
            await task.save()
            return False

    @staticmethod
    async def execute_scheduled_tasks():
        """执行定时任务"""
        # 获取待执行的任务
        tasks = await TaskService.get_pending_tasks()
        
        for task in tasks:
            # 检查任务调度时间
            if task.schedule:
                try:
                    cron = croniter.croniter(task.schedule, datetime.now(timezone.utc))
                    next_run = cron.get_prev(datetime)
                    if next_run > datetime.now(timezone.utc):
                        logger.info(f"Task {task.id} scheduled for {next_run}, skipping")
                        continue
                except Exception as e:
                    logger.error(f"Error parsing cron expression for task {task.id}: {e}")
                    continue
                
            # 执行任务
            await TaskExecutor.execute_analysis_task(task.id)

    @staticmethod
    async def execute_continuous_analysis_task(task_id: PydanticObjectId) -> bool:
        """执行持续分析任务（处理所有样本，包括新上传的）"""
        # 获取任务信息
        task = await TaskService.get_task(task_id)
        if not task:
            logger.error(f"Task not found: {task_id}")
            return False
            
        # 获取任务状态
        task_status = await TaskService.get_task_status(task_id)
        if not task_status:
            logger.error(f"Task status not found: {task_id}")
            return False
            
        try:
            # 更新任务状态为运行中
            await TaskService.update_task_status(task_id, "running")
            
            # 创建 MinIO 客户端
            minio_client = create_minio_client()
            logger.info("Created MinIO client")
            
            # 获取所有样本
            samples = await Sample.find().to_list()
            total_samples = len(samples)
            processed_samples = 0
            failed_samples = []
            
            logger.info(f"Starting continuous task execution for {total_samples} samples")
            
            # 更新任务状态中的总样本数
            await TaskService.update_task_progress(
                task_id=task_id,
                processed_samples=0,
                failed_samples=[],
                total_samples=total_samples
            )
            
            # 设置开始时间
            task_status.start_time = datetime.utcnow()
            await task_status.save()
            
            # 遍历样本
            for sample in samples:
                # 检查是否已有该类型的分析状态
                status = await SampleAnalysisStatus.find_one(
                    SampleAnalysisStatus.sample == sample.id,
                    SampleAnalysisStatus.task_type == task.type
                )
                
                # 如果已有成功的分析记录，跳过
                if status and status.status == "completed":
                    continue
                    
                try:
                    # 更新当前样本
                    await TaskService.update_task_status(
                        task_id,
                        "running",
                        current_sample=str(sample.id)
                    )
                    
                    logger.info(f"Processing sample {sample.id} with file path: {sample.file_path}")
                    
                    # 创建或更新分析状态记录
                    if not status:
                        status = SampleAnalysisStatus(
                            sample=sample,
                            task_type=task.type,
                            status="pending"
                        )
                        await status.insert()
                    
                    # 创建分析记录
                    analysis = await AnalysisService.create_analysis(
                        sample_id=sample.id,
                        analysis_type=task.type,
                        auto_analyze=True
                    )
                    
                    # 执行分析
                    if task.type == "exiftool":
                        result = await perform_exiftool_analysis(str(sample.file_path))
                    elif task.type == "pe_info":
                        result = await perform_pe_analysis(str(sample.file_path))
                    elif task.type == "strings":
                        result = await analyze_strings(str(sample.file_path))
                    elif task.type == "hash":
                        # 从文件路径中提取 bucket 和 object 名称
                        path_parts = str(sample.file_path).split('/', 1)
                        if len(path_parts) != 2:
                            raise ValueError(f"Invalid file path format: {sample.file_path}")
                        bucket_name, object_name = path_parts
                        logger.info(f"Calculating hashes for bucket: {bucket_name}, object: {object_name}")
                        result = calculate_minio_file_hashes(
                            minio_client=minio_client,
                            bucket_name=bucket_name,
                            object_name=object_name
                        )
                    else:
                        raise ValueError(f"Unsupported analysis type: {task.type}")
                        
                    # 保存分析结果
                    await AnalysisService.save_analysis_result(
                        analysis_id=analysis.id,
                        result_type=task.type,
                        result_data=result
                    )
                    
                    # 更新分析状态
                    await AnalysisService.update_analysis_status(
                        analysis_id=analysis.id,
                        status="completed"
                    )
                    
                    # 更新样本分析状态
                    status.status = "completed"
                    status.analysis_time = datetime.now(timezone.utc)
                    await status.save()
                    
                    processed_samples += 1
                    logger.info(f"Successfully processed sample {sample.id}")
                    
                except Exception as e:
                    error_msg = f"Error processing sample {sample.id}: {str(e)}\n{traceback.format_exc()}"
                    logger.error(error_msg)
                    # 更新样本分析状态为失败
                    if status:
                        status.status = "failed"
                        status.error_message = error_msg
                        await status.save()
                    # 如果分析记录已经创建，则更新其状态为失败
                    if 'analysis' in locals():
                        await AnalysisService.update_analysis_status(
                            analysis_id=analysis.id,
                            status="failed",
                            error_message=error_msg
                        )
                    failed_samples.append(str(sample.id))
                    
                # 更新任务进度
                await TaskService.update_task_progress(
                    task_id=task_id,
                    processed_samples=processed_samples,
                    failed_samples=failed_samples,
                    total_samples=total_samples
                )
                
            # 更新任务状态为完成
            await TaskService.update_task_status(
                task_id,
                'completed',
                error_message=f"Processed {processed_samples}/{total_samples} samples, {len(failed_samples)} failed"
            )
            
            # 更新任务本身的状态
            task.status = 'completed'
            task.updated_at = datetime.now(timezone.utc)
            logger.info(f"Task {task.id} completed")
            await task.save()
            
            return True
            
        except Exception as e:
            error_msg = f"Task execution failed: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            # 更新任务状态为失败
            await TaskService.update_task_status(
                task_id,
                'failed',
                error_message=error_msg
            )
            # 更新任务本身的状态
            task.status = 'failed'
            task.updated_at = datetime.now(timezone.utc)
            logger.info(f"Task {task.id} failed")
            await task.save()
            return False

