import json
import pytest
from datetime import datetime
from pathlib import Path
from app.models.yara import YaraRule
from app.models.user import User
from app.core.yara_manager import YaraManager

pytestmark = pytest.mark.asyncio

@pytest.fixture
def test_data_dir():
    """返回测试数据目录路径"""
    return Path(__file__).parent / "data"

@pytest.fixture
def valid_yara_rule(test_data_dir):
    """加载有效的YARA规则测试数据"""
    with open(test_data_dir / "valid_yara_rule.json") as f:
        return json.load(f)

@pytest.fixture
def invalid_yara_rule(test_data_dir):
    """加载无效的YARA规则测试数据"""
    with open(test_data_dir / "invalid_yara_rule.json") as f:
        return json.load(f)

@pytest.fixture
async def test_user():
    """创建测试用户"""
    user = User(
        username="test_user",
        email="test@example.com",
        hashed_password="test_password",
        is_active=True,
        is_superuser=False
    )
    await user.insert()
    return user

@pytest.fixture
async def test_rule(test_user):
    """创建测试规则"""
    rule = YaraRule(
        name="test_rule",
        description="Test Description",
        content="rule test { strings: $a = \"test\" condition: $a }",
        creator=test_user,
        is_active=True,
        is_public=False,
        tags=["test"],
        metadata={"test": "value"}
    )
    await rule.insert()
    return rule

@pytest.fixture
async def another_user():
    """创建另一个测试用户"""
    user = User(
        username="another_user",
        email="another@example.com",
        hashed_password="test_password",
        is_active=True,
        is_superuser=False
    )
    await user.insert()
    return user

@pytest.fixture
async def another_rule(another_user):
    """创建另一个用户的测试规则"""
    rule = YaraRule(
        name="another_rule",
        description="Another Description",
        content="rule another { strings: $a = \"another\" condition: $a }",
        creator=another_user,
        is_active=True,
        is_public=False,
        tags=["another"],
        metadata={"another": "value"}
    )
    await rule.insert()
    return rule

async def test_create_yara_rule(test_user):
    """测试创建YARA规则"""
    rule_data = {
        "name": "new_rule",
        "description": "New Description",
        "content": "rule new { strings: $a = \"new\" condition: $a }",
        "is_public": False,
        "tags": ["new"],
        "metadata": {"new": "value"}
    }
    
    # 创建规则
    rule = YaraRule(**rule_data, creator=test_user)
    await rule.insert()
    
    # 验证规则
    assert rule.name == "new_rule"
    assert rule.description == "New Description"
    assert rule.content == "rule new { strings: $a = \"new\" condition: $a }"
    assert rule.creator == test_user
    assert rule.is_active is True
    assert rule.is_public is False
    assert rule.tags == ["new"]
    assert rule.metadata == {"new": "value"}

async def test_create_duplicate_rule(test_rule):
    """测试创建重复名称的规则"""
    with pytest.raises(Exception):
        duplicate_rule = YaraRule(
            name="test_rule",  # 使用已存在的名称
            description="Duplicate Description",
            content="rule duplicate { strings: $a = \"duplicate\" condition: $a }",
            creator=test_rule.creator
        )
        await duplicate_rule.insert()

async def test_list_yara_rules(test_user, test_rule, another_rule):
    """测试获取规则列表（基于用户权限）"""
    # 获取当前用户的规则
    rules = await YaraRule.find(
        {"creator": {"$ref": "users", "$id": test_user.id}}
    ).to_list()
    
    # 验证只返回当前用户的规则
    assert len(rules) == 1
    assert rules[0].id == test_rule.id
    assert rules[0].creator == test_user

async def test_get_yara_rule(test_user, test_rule, another_rule):
    """测试获取单个规则（基于用户权限）"""
    # 获取自己的规则
    rule = await YaraRule.get(test_rule.id)
    creator = await rule.creator.fetch()
    assert str(creator.id) == str(test_user.id)
    
    # 尝试获取他人的规则
    another_rule = await YaraRule.get(another_rule.id)
    creator = await another_rule.creator.fetch()
    assert str(creator.id) != str(test_user.id)

async def test_update_yara_rule(test_user, test_rule):
    """测试更新规则（基于用户权限）"""
    # 更新规则
    test_rule.name = "updated_rule"
    test_rule.description = "Updated Description"
    test_rule.content = "rule updated { strings: $a = \"updated\" condition: $a }"
    await test_rule.save()
    
    # 验证更新
    updated_rule = await YaraRule.get(test_rule.id)
    assert updated_rule.name == "updated_rule"
    assert updated_rule.description == "Updated Description"
    assert updated_rule.content == "rule updated { strings: $a = \"updated\" condition: $a }"

async def test_update_duplicate_rule(test_user, test_rule, another_rule):
    """测试更新规则为重复名称"""
    with pytest.raises(Exception):
        test_rule.name = "another_rule"  # 使用已存在的名称
        await test_rule.save()

async def test_delete_yara_rule(test_user, test_rule):
    """测试删除规则（基于用户权限）"""
    # 删除规则
    await test_rule.delete()
    
    # 验证规则已被删除
    deleted_rule = await YaraRule.get(test_rule.id)
    assert deleted_rule is None

async def test_validate_rule_syntax():
    """测试规则语法验证"""
    # 测试有效规则
    valid_rule = "rule valid { strings: $a = \"valid\" condition: $a }"
    is_valid, error = await YaraManager.validate_rule(valid_rule)
    assert is_valid is True
    assert error is None
    
    # 测试无效规则
    invalid_rule = "rule invalid { strings: $a = \"invalid\" condition: $a"  # 缺少右括号
    is_valid, error = await YaraManager.validate_rule(invalid_rule)
    assert is_valid is False
    assert error is not None

async def test_scan_file_with_yara(valid_yara_rule):
    """测试使用Yara规则扫描文件"""
    # 创建测试文件内容
    test_content = b"This is a test file containing the word 'test'"
    
    # 编译规则并扫描
    yara_manager = YaraManager()
    compiled_rules = yara_manager.compile_rules([valid_yara_rule["content"]])
    matches = yara_manager.scan_data(test_content, compiled_rules)
    
    assert len(matches) > 0
    assert matches[0]["rule"] == "TestRule" 