# 测试目录

此目录包含项目的所有测试代码。

## 目录结构

```
tests/
├── conftest.py           # pytest 配置文件
├── data/                 # 测试数据
│   ├── yara/            # YARA 规则测试数据
│   ├── samples/         # 样本文件
│   ├── configs/         # 配置文件
│   └── db/              # 数据库相关数据
├── fixtures/            # 测试夹具
│   ├── base/           # 基础夹具
│   ├── models/         # 模型夹具
│   ├── services/       # 服务夹具
│   └── api/            # API 夹具
├── integration/         # 集成测试
│   ├── api/            # API 集成测试
│   ├── db/             # 数据库集成测试
│   └── services/       # 服务集成测试
└── unit/               # 单元测试
    ├── core/           # 核心功能测试
    ├── models/         # 模型测试
    └── services/       # 服务测试
```

## 测试规范

1. 命名规范
   - 测试文件以 `test_` 开头
   - 测试类以 `Test` 开头
   - 测试函数以 `test_` 开头

2. 测试覆盖
   - 单元测试覆盖率要求 > 80%
   - 关键功能覆盖率要求 > 90%
   - 使用 pytest-cov 进行覆盖率统计

3. 测试原则
   - 每个测试应该只测试一个功能点
   - 测试应该是独立的，不依赖其他测试
   - 使用适当的断言方法
   - 测试数据应该易于理解和维护

4. 性能考虑
   - 使用适当的 fixture 作用域
   - 避免不必要的数据库操作
   - 大型测试数据使用异步加载

## 运行测试

1. 运行所有测试：
```bash
pytest
```

2. 运行特定模块的测试：
```bash
pytest tests/unit/core/
```

3. 运行带覆盖率报告的测试：
```bash
pytest --cov=app tests/
```

4. 运行特定测试：
```bash
pytest tests/unit/core/test_yara_manager.py::test_compile_rules
``` 