#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging
from datetime import datetime
from typing import List, Dict
import sys
import os

# 添加项目根目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from app.core.config import settings
from app.core.storage import MinioStorageAdapter
from app.models.migration import MigrationFileStatus, MigrationStatus

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def fix_minio_paths():
    """修复MinIO中的文件路径问题"""
    try:
        # 初始化MinIO存储适配器
        minio_config = {
            "endpoint": settings.MINIO_ENDPOINT,
            "access_key": settings.MINIO_ACCESS_KEY,
            "secret_key": settings.MINIO_SECRET_KEY,
            "secure": settings.MINIO_SECURE,
            "bucket_name": settings.MINIO_BUCKET_NAME
        }
        
        logger.info(f"MinIO配置: {minio_config}")
        minio_adapter = MinioStorageAdapter(config=minio_config)
        
        # 列出所有文件
        logger.info("正在列出所有文件...")
        files = await minio_adapter.list_files(prefix="samples/", recursive=True)
        
        # 统计需要修复的文件
        files_to_fix = [f for f in files if f["path"].startswith("samples/")]
        logger.info(f"找到 {len(files_to_fix)} 个需要修复的文件")
        
        # 修复文件路径
        fixed_count = 0
        error_count = 0
        
        for file in files_to_fix:
            old_path = file["path"]
            new_path = old_path.replace("samples/", "", 1)
            
            try:
                # 读取原文件内容
                logger.info(f"正在处理文件: {old_path} -> {new_path}")
                content = await minio_adapter.get_file(old_path)
                
                if content is None:
                    logger.error(f"无法读取文件: {old_path}")
                    error_count += 1
                    continue
                
                # 写入新路径
                success = await minio_adapter.save_file(new_path, content)
                if not success:
                    logger.error(f"无法写入文件: {new_path}")
                    error_count += 1
                    continue
                
                # 删除原文件
                success = await minio_adapter.delete_file(old_path)
                if not success:
                    logger.error(f"无法删除文件: {old_path}")
                    error_count += 1
                    continue
                
                fixed_count += 1
                if fixed_count % 100 == 0:
                    logger.info(f"已修复 {fixed_count} 个文件")
                    
            except Exception as e:
                logger.error(f"处理文件 {old_path} 时出错: {str(e)}")
                error_count += 1
        
        logger.info(f"修复完成！成功: {fixed_count}, 失败: {error_count}")
        
    except Exception as e:
        logger.error(f"修复过程中出错: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(fix_minio_paths()) 