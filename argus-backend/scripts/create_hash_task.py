#!/usr/bin/env python3

import asyncio
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from beanie import init_beanie
from app.models.user import User, pwd_context
from app.models.sample import Sample
from app.models.analysis import Task, TaskStatus, AnalysisConfig
from app.services.analysis_config_service import AnalysisConfigService
from app.services.task_service import TaskService
from app.core.config import settings
import traceback

async def init_database():
    """初始化数据库连接"""
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    db = client[settings.MONGODB_DB]
    
    # 初始化 Beanie
    await init_beanie(
        database=db,
        document_models=[
            User,
            Sample,
            Task,
            TaskStatus,
            AnalysisConfig
        ]
    )

async def create_hash_task():
    # 初始化数据库连接
    await init_database()
    
    try:
        # 获取或创建测试用户
        user = await User.find_one(User.email == 'test_hash@example.com')
        if not user:
            user = User(
                username='test_user_hash',
                email='test_hash@example.com',
                hashed_password=pwd_context.hash('test123'),
                is_active=True,
                is_superuser=True
            )
            await user.insert()
            print("Created test user")
        else:
            print("Using existing test user")
        
        # 创建哈希分析配置
        config = await AnalysisConfigService.create_config(
            name='全样本哈希分析',
            analysis_type='hash',
            created_by=user,
            description='对所有样本进行哈希分析',
            auto_analyze=True,
            priority=1
        )
        print(f"Created analysis config with ID: {config.id}")
        
        # 创建分析任务
        task = await TaskService.create_task(
            name='全样本哈希分析任务',
            task_type='hash',
            created_by=user,
            description='对所有样本执行哈希分析',
            priority=1,
            config_id=config.id  # 关联分析配置
        )
        print(f"Created analysis task with ID: {task.id}")
        
        # 手动执行任务
        from app.services.task_executor import TaskExecutor
        await TaskExecutor.execute_analysis_task(task.id)
        print("Task execution started")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        print("Traceback:")
        traceback.print_exc()

if __name__ == '__main__':
    asyncio.run(create_hash_task()) 