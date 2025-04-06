#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import sys
import traceback
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.config import settings
from app.services.migration_service import MigrationService
from app.db.init_db import init_db

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

async def migrate_minio_to_local_example():
    """从MinIO迁移到本地存储的示例"""
    try:
        # 初始化数据库
        logger.info("初始化数据库...")
        await init_db()
        logger.info("数据库初始化成功")
        
        # 设置存储路径和存储桶名称
        local_storage_path = "/data/argus-samples"
        minio_bucket_name = "samples"
        
        # 确保本地存储目录存在
        os.makedirs(local_storage_path, exist_ok=True)
        logger.info(f"本地存储目录: {local_storage_path}")
        
        # 创建迁移任务
        task = await MigrationService.create_migration_task(
            name="从MinIO迁移到本地存储示例",
            description="将MinIO中的所有文件迁移到本地存储",
            source_storage="minio",
            source_config={
                "endpoint": settings.MINIO_ENDPOINT,
                "access_key": settings.MINIO_ACCESS_KEY,
                "secret_key": settings.MINIO_SECRET_KEY,
                "secure": settings.MINIO_SECURE,
                "bucket_name": minio_bucket_name
            },
            target_storage="local",
            target_config={
                "base_path": local_storage_path,
                "directory_depth": 4
            },
            # 可选：指定文件匹配模式
            file_patterns=None
        )
        
        logger.info(f"创建迁移任务成功: {task.id}")
        
        # 执行迁移任务
        logger.info("开始执行迁移任务...")
        success = await MigrationService.execute_migration_task(str(task.id))
        
        if success:
            logger.info("迁移任务执行成功")
        else:
            logger.error("迁移任务执行失败")
            
    except Exception as e:
        logger.error(f"迁移过程中发生错误: {str(e)}")
        logger.error(f"错误详情: {traceback.format_exc()}")
        return False
        
    return True

if __name__ == "__main__":
    asyncio.run(migrate_minio_to_local_example()) 