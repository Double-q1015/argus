# 测试夹具目录

此目录包含所有测试夹具（fixtures）。

## 目录结构

- `base/` - 基础夹具
  - `db.py` - 数据库连接和会话管理
  - `auth.py` - 认证相关夹具
  - `minio.py` - MinIO 客户端夹具
- `models/` - 模型相关夹具
  - `user.py` - 用户模型夹具
  - `sample.py` - 样本模型夹具
  - `analysis.py` - 分析模型夹具
- `services/` - 服务相关夹具
  - `yara.py` - YARA 服务夹具
  - `storage.py` - 存储服务夹具
  - `analysis.py` - 分析服务夹具
- `api/` - API 相关夹具
  - `client.py` - API 客户端夹具
  - `auth.py` - API 认证夹具

## 使用说明

1. 夹具应该尽可能独立和可重用
2. 使用 pytest 的 fixture 作用域来优化性能
3. 夹具应该包含适当的清理机制
4. 避免夹具之间的循环依赖 