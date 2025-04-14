#!/usr/bin/env python3
import asyncio
import logging
from datetime import datetime
from typing import List, Dict
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.models.sample import Sample
from app.core.config import settings

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def init_db():
    """初始化数据库连接"""
    try:
        client = AsyncIOMotorClient(settings.MONGODB_URL)
        await init_beanie(
            database=client[settings.MONGODB_DB],
            document_models=[Sample]
        )
        logger.info("数据库连接成功")
    except Exception as e:
        logger.error(f"数据库连接失败: {e}")
        raise

async def remove_duplicates():
    """删除所有重复的样本记录"""
    try:
        # 获取所有重复的 SHA256 值
        pipeline = [
            {
                "$group": {
                    "_id": "$sha256_digest",
                    "count": {"$sum": 1}
                }
            },
            {
                "$match": {
                    "count": {"$gt": 1}
                }
            }
        ]
        
        duplicate_hashes = await Sample.aggregate(pipeline).to_list(None)
        
        if not duplicate_hashes:
            logger.info("没有找到重复记录")
            return
        
        total_deleted = 0
        for group in duplicate_hashes:
            sha256 = group["_id"]
            count = group["count"]
            
            # 删除所有具有该 SHA256 的记录
            result = await Sample.find({"sha256_digest": sha256}).delete()
            deleted_count = result.deleted_count
            
            logger.info(f"删除 SHA256: {sha256} 的所有 {deleted_count} 条记录")
            total_deleted += deleted_count
        
        logger.info(f"\n清理完成! 共删除 {total_deleted} 条重复记录")
        
    except Exception as e:
        logger.error(f"处理重复记录时出错: {e}")
        raise

async def main():
    """主函数"""
    try:
        await init_db()
        await remove_duplicates()
    except Exception as e:
        logger.error(f"脚本执行失败: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main()) 