#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import argparse
import logging
import os
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

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

async def migrate_storage(
    name: str,
    description: Optional[str],
    source_storage: str,
    source_config: Dict[str, Any],
    target_storage: str,
    target_config: Dict[str, Any],
    file_patterns: Optional[List[str]] = None
):
    """执行存储迁移任务"""
    try:
        # 确保目标存储目录存在（如果是本地存储）
        if target_storage == "local":
            local_storage_path = target_config.get("base_path")
            if local_storage_path:
                os.makedirs(local_storage_path, exist_ok=True)
                logger.info(f"本地存储目录: {local_storage_path}")
        
        # 创建迁移任务
        task = await MigrationService.create_migration_task(
            name=name,
            description=description,
            source_storage=source_storage,
            source_config=source_config,
            target_storage=target_storage,
            target_config=target_config,
            file_patterns=file_patterns
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

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="存储迁移工具")
    
    parser.add_argument("--name", required=True, help="迁移任务名称")
    parser.add_argument("--description", help="迁移任务描述")
    parser.add_argument("--source-storage", required=True, choices=["minio", "s3", "local"], help="源存储类型")
    parser.add_argument("--source-config", required=True, help="源存储配置，JSON格式")
    parser.add_argument("--target-storage", required=True, choices=["minio", "s3", "local"], help="目标存储类型")
    parser.add_argument("--target-config", required=True, help="目标存储配置，JSON格式")
    parser.add_argument("--file-patterns", help="文件匹配模式，逗号分隔的列表，例如：*.exe,*.dll")
    
    return parser.parse_args()

async def main():
    """主函数"""
    args = parse_args()
    
    # 解析源存储配置
    try:
        source_config = json.loads(args.source_config)
    except json.JSONDecodeError:
        logger.error("源存储配置不是有效的JSON格式")
        return False
    
    # 解析目标存储配置
    try:
        target_config = json.loads(args.target_config)
    except json.JSONDecodeError:
        logger.error("目标存储配置不是有效的JSON格式")
        return False
    
    # 解析文件匹配模式
    file_patterns = None
    if args.file_patterns:
        file_patterns = [pattern.strip() for pattern in args.file_patterns.split(",")]
    
    # 执行迁移
    return await migrate_storage(
        name=args.name,
        description=args.description,
        source_storage=args.source_storage,
        source_config=source_config,
        target_storage=args.target_storage,
        target_config=target_config,
        file_patterns=file_patterns
    )

if __name__ == "__main__":
    asyncio.run(main()) 