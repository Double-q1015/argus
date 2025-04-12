# 创建一个系统任务，系统任务会按照既定的流程分析上传的样本
# 在样本上传或添加的逻辑中触发任务
from abc import ABC, abstractmethod
from minio import Minio
from fastapi import UploadFile
from datetime import datetime, timedelta, timezone
from typing import Optional, Union, Dict, Any, List
import logging
import asyncio
import os
import tempfile
from pathlib import Path
import sys
# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.core.config import settings
from app.models.sample import Sample, SampleStatusEnum
from app.services.task_service import TaskService
from app.models.analysis import Task, TaskStatus
from app.models.analysis_result import AnalysisResult
from app.services.analysis_service import AnalysisService
from app.services.analysis_config_service import AnalysisConfigService
from app.services.analysis_executor import AnalysisExecutor
from app.models.user import User
from app.core.hash_analyzer import perform_hash_analysis
from app.core.magic_analyzer import perform_magic_analysis
from app.core.pe_analyzer import perform_pe_analysis
from app.core.exiftool_analyzer import perform_exiftool_analysis
from app.core.storage import create_minio_client
from app.db.init_db import init_db

logger = logging.getLogger(__name__)

async def on_sample_added(sha256_digest: str):
    # 创建并启动任务
    system_user = await User.find_one({"username": settings.SYSTEM_USER})
    task = await TaskService.create_task(
        name=f"Analyze sample {sha256_digest}",
        task_type="ANALYSIS",
        description=f"Analyze sample {sha256_digest} for hash, magic, PE info",
        created_by=system_user
    )
    sample = await Sample.find_one({"sha256_digest": sha256_digest})
    sample.analysis_status = SampleStatusEnum.analyzing
    await sample.save()
    await start_analysis_task(task.id, sha256_digest)

# 计算文件属性的任务
async def start_analysis_task(task_id: str, sha256_digest: str):
    # 获取样本文件
    # hash analyzer
    # magic analyzer
    # pe analyzer
    # 获取样本文件 保存到临时文件
    # 下载文件
    # 创建临时目录
    try:
        sample = await Sample.find_one({"sha256_digest": sha256_digest})
        temp_dir = tempfile.mkdtemp()
        temp_file_path = os.path.join(temp_dir, sample.file_name)
        minio_client = create_minio_client()
        try:
            minio_client.fget_object(
                bucket_name=settings.MINIO_BUCKET_NAME,
                object_name=sample.file_path,
                file_path=temp_file_path,
            )
            logger.info(f"Downloaded file from MinIO: {temp_file_path}")
        except Exception as e:
            logger.error(f"Failed to download file from MinIO: {e}")
            raise e
        
        # 计算属性
        hash_result = await perform_hash_analysis(file_path=temp_file_path)
        magic_result = await perform_magic_analysis(file_path=temp_file_path)
        if magic_result.is_pe:
            pe_info = await perform_pe_analysis(file_path=temp_file_path)
            exiftool_result = await perform_exiftool_analysis(file_path=temp_file_path)

        # 更新样本属性
        sample.hash_info = hash_result.to_dict()
        sample.magic_info = magic_result.to_dict()
        if magic_result.is_pe:
            sample.pe_info = pe_info.to_dict()
            sample.exiftool_info = exiftool_result.to_dict()
        sample.analysis_status = SampleStatusEnum.completed
        await sample.save()

        # 更新任务状态
        task = await Task.get(task_id)
        task.status = 'completed'
        await task.save()

        # 更新样本的分析状态
        sample.analysis_status = SampleStatusEnum.completed
        await sample.save()
    except Exception as e:
        logger.error(f"Failed to analyze sample {sha256_digest}: {e}")
        sample.analysis_status = SampleStatusEnum.failed
        await sample.save()
        raise e
    finally:
        # 删除临时文件
        os.remove(temp_file_path)
        os.rmdir(temp_dir)

async def check_pending_samples():
    # 查询新添加的样本并触发分析任务
    await init_db()
    pending_samples = await Sample.find({"analysis_status": SampleStatusEnum.pending}).to_list()
    # pending_samples = pending_samples[:10]
    for sample in pending_samples:
        logger.info(f"Checking sample {sample.sha256_digest}")
        await on_sample_added(sample.sha256_digest)

if __name__ == "__main__":
    # asyncio.run(init_db())
    asyncio.run(check_pending_samples())