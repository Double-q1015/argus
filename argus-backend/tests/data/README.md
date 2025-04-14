# 测试数据目录

此目录包含所有测试所需的数据文件。

## 目录结构

- `yara/` - YARA 规则相关测试数据
  - `valid_rules/` - 有效的 YARA 规则
  - `invalid_rules/` - 无效的 YARA 规则
  - `complex_rules/` - 复杂的 YARA 规则测试用例
- `samples/` - 样本文件
  - `malware/` - 恶意软件样本
  - `benign/` - 良性样本
  - `corrupted/` - 损坏的样本
- `configs/` - 配置文件
  - `test_config.yaml` - 测试配置
  - `minio_config.yaml` - MinIO 测试配置
- `db/` - 数据库相关
  - `init_data/` - 数据库初始化数据
  - `migrations/` - 数据库迁移文件

## 使用说明

1. 所有测试数据文件应该尽可能小，但又要能覆盖测试场景
2. 敏感数据（如密钥、密码）应该使用占位符
3. 每个数据文件都应该有对应的说明文档
4. 大型二进制文件应该使用 Git LFS 管理 