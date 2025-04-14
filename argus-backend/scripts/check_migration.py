#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging
import os
import sys
from pathlib import Path
from collections import defaultdict

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.init_db import init_db
from app.models.migration import MigrationTask, MigrationFileStatus
from app.core.storage import Storage

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

async def check_migration_files(task_id: str):
    """检查迁移任务中的文件状态"""
    try:
        # 初始化数据库
        logger.info("初始化数据库...")
        await init_db()
        logger.info("数据库初始化成功")
        
        # 获取迁移任务
        task = await MigrationTask.get(task_id)
        if not task:
            logger.error(f"找不到迁移任务: {task_id}")
            return False
            
        logger.info(f"迁移任务: {task.name}")
        logger.info(f"源存储: {task.source_storage}, 目标存储: {task.target_storage}")
        logger.info(f"总文件数: {task.total_files}, 已处理: {task.processed_files}, 失败: {task.failed_files}")
        
        # 获取文件状态
        file_statuses = await MigrationFileStatus.find(
            MigrationFileStatus.task_id == task_id
        ).to_list()
        
        logger.info(f"找到 {len(file_statuses)} 个文件状态记录")
        
        # 统计文件状态
        status_counts = defaultdict(int)
        for status in file_statuses:
            status_counts[status.status] += 1
            
        for status, count in status_counts.items():
            logger.info(f"状态 '{status}': {count} 个文件")
            
        # 检查本地文件
        if task.target_storage == "local":
            local_path = task.target_config.get("base_path")
            if local_path and os.path.exists(local_path):
                local_files = os.listdir(local_path)
                logger.info(f"本地目录 '{local_path}' 中有 {len(local_files)} 个文件")
                
                # 检查文件路径冲突
                path_counts = defaultdict(int)
                for status in file_statuses:
                    if status.status == "completed":
                        path_counts[status.file_path] += 1
                        
                conflicts = {path: count for path, count in path_counts.items() if count > 1}
                if conflicts:
                    logger.warning(f"发现 {len(conflicts)} 个文件路径冲突:")
                    for path, count in list(conflicts.items())[:10]:  # 只显示前10个
                        logger.warning(f"  - {path}: {count} 个文件使用相同路径")
                    if len(conflicts) > 10:
                        logger.warning(f"  - ... 还有 {len(conflicts) - 10} 个冲突未显示")
                
                # 检查文件是否存在于本地
                missing_files = []
                for status in file_statuses:
                    if status.status == "completed":
                        file_path = os.path.join(local_path, os.path.basename(status.file_path))
                        if not os.path.exists(file_path):
                            missing_files.append(status.file_path)
                            
                if missing_files:
                    logger.warning(f"发现 {len(missing_files)} 个标记为完成但本地不存在的文件:")
                    for path in missing_files[:10]:  # 只显示前10个
                        logger.warning(f"  - {path}")
                    if len(missing_files) > 10:
                        logger.warning(f"  - ... 还有 {len(missing_files) - 10} 个文件未显示")
        
        return True
        
    except Exception as e:
        logger.error(f"检查过程中发生错误: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python check_migration.py <task_id>")
        sys.exit(1)
        
    task_id = sys.argv[1]
    asyncio.run(check_migration_files(task_id)) 