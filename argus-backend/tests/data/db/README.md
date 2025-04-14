# 数据库测试数据

此目录包含数据库相关的测试数据。

## 目录结构

- `init_data/` - 数据库初始化数据
  - 用户数据
  - 规则数据
  - 样本数据
  - 分析结果数据

- `migrations/` - 数据库迁移文件
  - 架构变更脚本
  - 数据迁移脚本
  - 回滚脚本

## 数据文件格式

1. 初始化数据（JSON 格式）：
```json
{
  "users": [
    {
      "username": "test_admin",
      "email": "admin@test.com",
      "hashed_password": "...",
      "is_active": true,
      "is_superuser": true
    }
  ],
  "rules": [
    {
      "name": "test_rule",
      "content": "...",
      "description": "Test rule",
      "created_by": "test_admin"
    }
  ]
}
```

2. 迁移文件（JavaScript 格式）：
```javascript
db.users.updateMany(
  { is_active: true },
  { $set: { last_login: new Date() } }
);
```

## 使用说明

1. 初始化数据应该：
   - 包含测试所需的最小数据集
   - 使用一致的格式和编码
   - 包含必要的关联数据
   - 避免使用真实敏感信息

2. 迁移文件应该：
   - 有清晰的版本号
   - 包含向前和向后迁移
   - 有详细的注释说明
   - 包含数据验证步骤

3. 数据管理：
   - 使用版本控制管理数据文件
   - 定期更新测试数据
   - 保持数据的一致性
   - 记录数据变更历史 