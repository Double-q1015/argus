from typing import List
from fastapi import APIRouter, Depends, Query, HTTPException
from app.core.auth import get_current_user
from app.models.user import User
from app.models.sample import Sample
from app.models.home import DashboardStats, RecentSample
from datetime import datetime, timedelta
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(current_user: User = Depends(get_current_user)):
    """
    获取仪表盘统计数据
    """
    # 获取总样本数
    total_samples = await Sample.find().count()
    
    # 获取今日新增样本数
    today = datetime.utcnow().date()
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
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    active_users = await User.find(
        {"last_login": {"$gte": seven_days_ago}}
    ).count()
    
    return DashboardStats(
        total_samples=total_samples,
        today_samples=today_samples,
        total_storage=total_storage,
        active_users=active_users
    )

@router.get("/recent-samples")
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
        return [
            {
                "id": str(sample.id),
                "name": sample.name,
                "md5": sample.md5,
                "sha256": sample.sha256,
                "file_size": sample.file_size,
                "file_type": sample.file_type,
                "file_path": sample.file_path,
                "upload_time": sample.upload_time,
                "status": sample.status,
                "tags": sample.tags,
                "is_public": sample.is_public,
                "creator": sample.creator,
                "uploader": str(sample.uploader.id) if sample.uploader else None
            }
            for sample in samples
        ]
    except Exception as e:
        logger.error(f"获取最近样本失败: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="获取最近样本失败"
        ) 