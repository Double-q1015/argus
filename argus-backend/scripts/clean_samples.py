#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import logging
import sys
from pathlib import Path
from collections import defaultdict

# 添加项目根目录到Python路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.db.init_db import init_db
from app.models.sample import Sample
from app.core.storage import storage

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

async def clean_duplicate_samples():
    """清理重复的样本记录"""
    try:
        # 初始化数据库
        logger.info("初始化数据库...")
        await init_db()
        logger.info("数据库初始化成功")
        
        # 获取所有样本
        samples = await Sample.find().to_list()
        logger.info(f"找到 {len(samples)} 个样本记录")
        
        # 按SHA256分组
        sha256_groups = defaultdict(list)
        for sample in samples:
            sha256_groups[sample.sha256_digest].append(sample)
        
        # 统计重复记录
        duplicate_count = sum(len(group) - 1 for group in sha256_groups.values() if len(group) > 1)
        logger.info(f"发现 {duplicate_count} 个重复记录")
        
        # 处理重复记录
        deleted_count = 0
        for sha256, group in sha256_groups.items():
            if len(group) > 1:
                # 按创建时间排序
                group.sort(key=lambda x: x.created_at)
                
                # 保留第一条记录，删除其他记录
                keep_sample = group[0]
                for sample in group[1:]:
                    logger.info(f"删除重复记录: {sample.id} (SHA256: {sha256})")
                    await sample.delete()
                    deleted_count += 1
                
                logger.info(f"保留记录: {keep_sample.id} (SHA256: {sha256})")
        
        logger.info(f"清理完成，共删除 {deleted_count} 个重复记录")
        return True
        
    except Exception as e:
        logger.error(f"清理过程中发生错误: {str(e)}")
        return False

if __name__ == "__main__":
    asyncio.run(clean_duplicate_samples()) 