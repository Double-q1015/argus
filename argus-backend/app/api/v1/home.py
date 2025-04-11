from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException
from app.core.security import get_current_user
from app.models.user import User
from app.models.sample import Sample
from app.models.home import DashboardStats, RecentSample
from datetime import datetime, timedelta, timezone
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/stats", response_model=Dict[str, Any])
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
    stats = {
        "total_samples": total_samples,
        "today_samples": today_samples,
        "total_storage": total_storage,
        "active_users": active_users
    }

    # 使用 data 包装返回数据
    return {"data": stats}

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