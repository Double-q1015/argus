#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import sys
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import settings
from app.services.migration_service import MigrationService
from app.models.migration import MigrationStatus

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

async def migrate_minio_to_local():
    """从MinIO迁移到本地存储"""
    try:
        # 确保本地存储目录存在
        local_storage_path = settings.LOCAL_STORAGE_PATH
        os.makedirs(local_storage_path, exist_ok=True)
        logger.info(f"本地存储目录: {local_storage_path}")
        
        # 创建迁移任务
        task = await MigrationService.create_migration_task(
            name="从MinIO迁移到本地存储",
            description="将MinIO中的所有文件迁移到本地存储",
            source_storage="minio",
            source_config={
                "endpoint": settings.MINIO_ENDPOINT,
                "access_key": settings.MINIO_ACCESS_KEY,
                "secret_key": settings.MINIO_SECRET_KEY,
                "secure": settings.MINIO_SECURE,
                "bucket_name": settings.MINIO_BUCKET_NAME
            },
            target_storage="local",
            target_config={
                "base_path": local_storage_path
            }
        )
        
        logger.info(f"创建迁移任务成功: {task.id}")
        
        # 执行迁移任务
        logger.info("开始执行迁移任务...")
        success = await MigrationService.execute_migration_task(str(task.id))
        
        if success:
            logger.info("迁移任务执行成功")
        else:
            logger.error("迁移任务执行失败")
            
        # 获取迁移任务状态
        task = await MigrationService.get_migration_task(str(task.id))
        if task:
            logger.info(f"迁移任务状态: {task.status}")
            logger.info(f"总文件数: {task.total_files}")
            logger.info(f"已处理文件数: {task.processed_files}")
            logger.info(f"失败文件数: {task.failed_files}")
            logger.info(f"总文件大小: {task.total_size} 字节")
            logger.info(f"已处理文件大小: {task.processed_size} 字节")
            
            if task.error_message:
                logger.error(f"错误信息: {task.error_message}")
                
            # 获取文件状态
            file_statuses = await MigrationService.get_migration_file_statuses(str(task.id))
            logger.info(f"文件状态数量: {len(file_statuses)}")
            
            # 统计各状态的文件数量
            status_counts = {}
            for status in MigrationStatus:
                status_counts[status] = 0
                
            for file_status in file_statuses:
                status_counts[file_status.status] += 1
                
            for status, count in status_counts.items():
                logger.info(f"{status}状态的文件数量: {count}")
                
    except Exception as e:
        logger.error(f"迁移过程中发生错误: {e}")
        return False
        
    return True

if __name__ == "__main__":
    asyncio.run(migrate_minio_to_local()) 