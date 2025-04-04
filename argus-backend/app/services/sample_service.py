from typing import List, Optional
from datetime import datetime
from fastapi import UploadFile
from app.core.database import get_database
from app.schemas.sample import SampleCreate, SampleResponse
from bson import ObjectId

class SampleService:
    def __init__(self, db=None):
        self.db = db or get_database()
        self.collection = self.db.samples

    async def create_sample(self, file: UploadFile, user_id: int) -> SampleResponse:
        """创建新的样本"""
        # 读取文件内容
        content = await file.read()
        
        # 创建样本文档
        sample_doc = {
            "user_id": user_id,
            "filename": file.filename,
            "content_type": file.content_type,
            "size": len(content),
            "content": content,
            "created_at": datetime.utcnow(),
            "status": "pending"
        }
        
        # 保存到数据库
        result = await self.collection.insert_one(sample_doc)
        sample_doc["id"] = str(result.inserted_id)
        
        return SampleResponse(**sample_doc)

    async def get_samples(self, user_id: int, skip: int = 0, limit: int = 100) -> List[SampleResponse]:
        """获取用户的样本列表"""
        cursor = self.collection.find({"user_id": user_id}).skip(skip).limit(limit)
        samples = await cursor.to_list(length=None)
        return [SampleResponse(**sample) for sample in samples]

    async def get_sample(self, sample_id: str, user_id: int) -> Optional[SampleResponse]:
        """获取单个样本"""
        sample = await self.collection.find_one({
            "_id": ObjectId(sample_id),
            "user_id": user_id
        })
        if sample:
            sample["id"] = str(sample["_id"])
            return SampleResponse(**sample)
        return None

    async def delete_sample(self, sample_id: str, user_id: int) -> bool:
        """删除样本"""
        result = await self.collection.delete_one({
            "_id": ObjectId(sample_id),
            "user_id": user_id
        })
        return result.deleted_count > 0 