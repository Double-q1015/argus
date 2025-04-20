from typing import List, Dict, Any, TypeVar
from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from app.core.security import get_current_user
from app.models.user import User
from app.models.sample import Sample
from app.models.home import DashboardStats, RecentSample, MimeTypeStat
from datetime import datetime, timedelta, timezone
import logging
from motor.motor_asyncio import AsyncIOMotorDatabase
from motor.motor_asyncio import AsyncIOMotorClient
from app.db.mongodb import get_client, get_database

router = APIRouter()
logger = logging.getLogger(__name__)

MongoClient = TypeVar('MongoClient', bound=AsyncIOMotorClient)
MongoDB = TypeVar('MongoDB', bound=AsyncIOMotorDatabase)

class DashboardStatsResponse(BaseModel):
    total_samples: int
    today_samples: int
    total_storage: int
    active_users: int

class DashboardStatsWrapper(BaseModel):
    data: DashboardStatsResponse

@router.get("/stats", response_model=DashboardStatsWrapper)
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    """
    获取仪表盘统计数据
    """
    # 获取总样本数
    total_samples = await Sample.find().count()
    
    # 获取今日新增样本数
    today = datetime.now(timezone.utc).date()
    today_samples = await Sample.find(
        {"upload_time": {"$gte": datetime.combine(today, datetime.min.time())}}
    ).count()
    
    # 获取总存储量
    pipeline = [
        {"$group": {"_id": None, "total": {"$sum": "$file_size"}}}
    ]
    result = await Sample.aggregate(pipeline).to_list()
    total_storage = result[0]["total"] if result else 0
    
    # 获取活跃用户数（最近7天）
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    active_users = await User.find(
        {"last_login": {"$gte": seven_days_ago}}
    ).count()
    
    # 构建返回数据
    stats = DashboardStatsResponse(
        total_samples=total_samples,
        today_samples=today_samples,
        total_storage=total_storage,
        active_users=active_users
    )

    # 使用 data 包装返回数据
    return DashboardStatsWrapper(data=stats)

@router.get("/recent-samples", response_model=Dict[str, List[RecentSample]])
async def get_recent_samples(
    limit: int = Query(5, ge=1, le=20),
    current_user: User = Depends(get_current_user)
):
    """
    获取最近的样本列表
    """
    try:
        # 获取最近的样本
        samples = await Sample.find(
            {"$or": [
                {"creator": current_user.username},
                {"uploader": current_user.id},
                {"is_public": True}
            ]}
        ).sort("-upload_time").limit(limit).to_list()
        
        # 转换为响应格式
        """
        sha256_digest: str
        file_name: str
        upload_time: datetime
        tags: List[str] 
        """
        return {"data": [
            {
                "sha256_digest": sample.sha256_digest,
                "file_name": sample.file_name,
                "upload_time": sample.upload_time,
                "tags": sample.tags
            }
            for sample in samples
        ]}
    except Exception as e:
        logger.error(f"获取最近样本失败: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="获取最近样本失败"
        ) 
    
# 获取后端数据库的状态
@router.get("/database-status", response_model=Dict[str, Any])
async def get_database_status(
    current_user: User = Depends(get_current_user),
    client: MongoClient = Depends(get_client),
    db: MongoDB = Depends(get_database)
):
    """
    获取后端数据库的状态
    返回包括连接状态、服务器状态、数据库统计信息等
    """
    try:
        # 1. 检查基本连接
        await db.command('ping')
        # 构建状态响应
        status = {
            "status": "ok",
            "message": "Database is reachable",
        }
        
        return {"data": status}
    except Exception as e:
        logger.error(f"Get database status failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Get database status failed: {str(e)}"
        )

@router.get("/mime-type-stats", response_model=Dict[str, List[MimeTypeStat]])
async def get_mime_type_stats(
    current_user: User = Depends(get_current_user),
    client: MongoClient = Depends(get_client),
    db: MongoDB = Depends(get_database)
):
    """
    获取文件类型统计信息（Top 10）
    """
    try:
        # 使用聚合管道获取文件类型统计
        pipeline = [
            {
                "$match": {
                    "magic_info.mime_type": {"$exists": True, "$ne": ""}
                }
            },
            {
                "$group": {
                    "_id": "$magic_info.mime_type",
                    "count": {"$sum": 1}
                }
            },
            {
                "$sort": {"count": -1}
            },
            {
                "$limit": 10
            }
        ]
        
        # 执行聚合查询
        cursor = db.samples.aggregate(pipeline)
        results = await cursor.to_list(length=None)
        
        # 转换为响应格式，去掉 application/ 前缀
        return {"data": [
            {"mime_type": result["_id"].replace("application/", ""), "count": result["count"]}
            for result in results
        ]}
    except Exception as e:
        logger.error(f"获取文件类型统计信息失败: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="获取文件类型统计信息失败"
        )
