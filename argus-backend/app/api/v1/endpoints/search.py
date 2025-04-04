from fastapi import APIRouter, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from typing import Optional

from app.api import deps
from app.services.search_parser import SearchParser
from app.services.search_service import SearchService
from app.schemas.search import SearchResponse

router = APIRouter()

@router.get("", response_model=SearchResponse)
async def search_samples(
    query: str,
    limit: Optional[int] = 1000,
    db = Depends(deps.get_db)
) -> SearchResponse:
    """
    搜索样本
    
    参数:
    - query: 搜索查询字符串，支持以下格式：
      - sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      - filename:test.exe
    - limit: 最大返回结果数量（默认1000）
    
    返回:
    - total: 总结果数量
    - results: 搜索结果列表
    """
    try:
        # 解析搜索条件
        conditions = SearchParser.parse_query(query)
        if not conditions:
            raise HTTPException(status_code=400, detail="无效的搜索条件")
            
        # 执行搜索
        search_service = SearchService(db)
        response = await search_service.search(conditions, limit=limit)
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 