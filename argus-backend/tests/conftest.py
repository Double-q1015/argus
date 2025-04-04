import asyncio
import pytest
import motor.motor_asyncio
from beanie import init_beanie
from datetime import datetime
import os
import sys
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# 设置测试环境变量
os.environ["TESTING"] = "true"
os.environ["MONGODB_URL"] = "mongodb://localhost:27017"
os.environ["MONGODB_DB_NAME"] = "snake_skin_test"

# 现在导入应用模块
from app.models.user import User
from app.models.yara import YaraRule
from motor.motor_asyncio import AsyncIOMotorClient

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="function")
async def db():
    """创建测试数据库连接"""
    client = AsyncIOMotorClient("mongodb://localhost:27017")
    db = client["snake_skin_test"]
    
    # 初始化 Beanie
    await init_beanie(
        database=db,
        document_models=[User, YaraRule]
    )
    
    yield db
    
    # 清理数据库
    await db.drop_collection("users")
    await db.drop_collection("yara_rules")
    client.close()

@pytest.fixture(scope="function")
async def test_user(db):
    """创建测试用户"""
    user = User(
        username="test_user",
        email="test@example.com",
        hashed_password="hashed_password",
        is_active=True
    )
    await user.insert()
    return user

@pytest.fixture
def valid_yara_rule():
    return {
        "name": "test_rule",
        "description": "Test Yara rule for testing",
        "content": """
        rule TestRule {
            strings:
                $test_string = "test"
            condition:
                $test_string
        }
        """
    }

@pytest.fixture
def invalid_yara_rule():
    return {
        "name": "invalid_rule",
        "description": "Invalid Yara rule for testing",
        "content": """
        rule InvalidRule {
            strings:
                $test_string = "test
            condition:
                $test_string
        }
        """
    }

@pytest.fixture
def test_data_dir():
    """返回测试数据目录路径"""
    return project_root / "tests" / "data" 