from typing import List
from app.schemas.search import SearchCondition, SearchType, SearchOperator, SearchResult, SearchResponse
import logging

logger = logging.getLogger(__name__)

class SearchService:
    def __init__(self, db):
        self.db = db

    async def search(self, conditions: List[SearchCondition], limit: int = 1000) -> SearchResponse:
        """
        根据搜索条件执行搜索
        """
        # 构建 MongoDB 查询条件
        query = {}
        
        # 处理搜索条件
        for condition in conditions:
            if condition.type == SearchType.SHA256:
                query["sha256_digest"] = condition.value.lower()
            elif condition.type == SearchType.FILENAME:
                query["file_name"] = {"$regex": condition.value, "$options": "i"}
        
        # 打印查询条件
        logger.info(f"Search query: {query}")
        
        # 执行查询
        cursor = self.db.samples.find(query)
        
        # 获取总数
        total = await self.db.samples.count_documents(query)
        logger.info(f"Found {total} documents")
        
        # 按文件名排序并限制结果数量
        cursor = cursor.sort("file_name", 1).limit(limit)
        
        # 获取结果
        results = []
        async for doc in cursor:
            logger.info(f"Found document: {doc}")
            results.append(
                SearchResult(
                    file_name=doc["file_name"],
                    description=doc.get("description"),  # 使用 get 处理可选字段
                    file_path=doc["file_path"],
                    file_size=doc["file_size"],
                    file_type=doc["file_type"],
                    sha256_digest=doc["sha256_digest"],
                    analysis_status=doc["analysis_status"]
                )
            )
        
        return SearchResponse(total=total, results=results) 