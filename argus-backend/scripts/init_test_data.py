#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import asyncio
import bcrypt
from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from minio import Minio
from minio.error import S3Error

# 添加项目根目录到 Python 路径
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings
from app.models.user import User

def get_password_hash(password: str) -> str:
    """生成密码哈希"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

async def test_minio():
    """测试 MinIO 连接和操作"""
    try:
        # 初始化 MinIO 客户端
        minio_client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=False  # 如果使用 HTTPS 则设为 True
        )
        # 获取存储桶信息
        bucket_name = settings.MINIO_BUCKET_NAME
        
        # 列出所有存储桶
        buckets = minio_client.list_buckets()
        print("\nMinIO 存储桶列表:")
        for bucket in buckets:
            print(f"- {bucket.name}")
            
        
        try:
            bucket_info = minio_client.get_bucket_info(bucket_name)
            print(f"\n存储桶 {bucket_name} 信息:")
            print(f"创建时间: {bucket_info.creation_date}")
            print(f"存储桶名称: {bucket_info.name}")
        except S3Error as e:
            print(f"存储桶 {bucket_name} 不存在或无法访问")
            
    except Exception as e:
        print(f"MinIO 测试失败: {str(e)}")

# 创建测试用户
async def create_test_user():
    """初始化测试数据"""
    # 连接数据库
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    
    # 初始化 beanie
    await init_beanie(
        database=client[settings.MONGODB_DB],
        document_models=[User]
    )
    
    # 清空用户集合
    await User.delete_all()
    
    # 创建管理员账户
    admin_user = User(
        username="admin",
        email="admin@example.com",
        hashed_password=get_password_hash("admin123"),
        is_active=True,
        is_superuser=True,
        created_at=datetime.now(timezone.utc)
    )

    # 创建普通用户账户
    normal_user = User(
        username="user",
        email="user@example.com",
        hashed_password=get_password_hash("user123"),
        is_active=True,
        is_superuser=False,
        created_at=datetime.now(timezone.utc)
    )
    
    # 插入用户数据
    await admin_user.insert()
    await normal_user.insert()
    
    print("测试数据初始化完成！")
    print("\n管理员账户:")
    print("用户名: admin")
    print("密码: admin123")
    print("\n普通用户账户:")
    print("用户名: user")
    print("密码: user123")

if __name__ == "__main__":
    asyncio.run(create_test_user())
    asyncio.run(test_minio()) 