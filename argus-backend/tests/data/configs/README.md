# 配置文件测试数据

此目录包含用于测试的配置文件。

## 文件列表

- `test_config.yaml` - 测试环境配置
  - 数据库连接信息
  - API 配置
  - 日志配置
  - 测试特定设置

- `minio_config.yaml` - MinIO 测试配置
  - 存储端点配置
  - 访问凭证
  - 存储桶设置
  - 测试数据路径

## 配置模板

1. test_config.yaml:
```yaml
database:
  url: mongodb://localhost:27017
  name: argus_test
  username: test_user
  password: test_pass

api:
  host: 0.0.0.0
  port: 8000
  debug: true

logging:
  level: DEBUG
  file: test.log

test:
  data_dir: ./data
  timeout: 30
```

2. minio_config.yaml:
```yaml
endpoint: localhost:9000
access_key: test_access_key
secret_key: test_secret_key
secure: false

buckets:
  samples: argus-samples-test
  rules: argus-rules-test
  reports: argus-reports-test

paths:
  samples: samples/
  rules: rules/
  reports: reports/
```

## 使用说明

1. 配置文件应该：
   - 使用占位符代替敏感信息
   - 包含所有必要的配置项
   - 有清晰的注释说明
   - 遵循 YAML 格式规范

2. 安全注意事项：
   - 不要提交真实的凭证
   - 使用环境变量或配置文件覆盖敏感信息
   - 测试配置应该与生产配置分离 