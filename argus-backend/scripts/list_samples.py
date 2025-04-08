import asyncio
import sys
import os

# 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from app.models.sample import Sample
from app.models.user import User
from app.models.yara import YaraRule
from app.models.api_key import ApiKey
from app.core.config import settings

async def main():
    # 初始化数据库连接
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB]
    
    # 初始化 Beanie
    await init_beanie(
        database=db,
        document_models=[
            Sample,
            User,
            YaraRule,
            ApiKey
        ]
    )
    
    # 查询所有样本
    samples = await Sample.find().to_list()
    
    print(f'找到 {len(samples)} 个样本')
    
    # 打印样本信息
    for sample in samples:
        print(f'ID: {sample.id}, 文件名: {sample.file_name}, SHA256: {sample.sha256_digest}')

if __name__ == "__main__":
    asyncio.run(main()) 