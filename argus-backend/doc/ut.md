## 目录组织结构
argus-backend/tests/
├── conftest.py                 # 已有的配置文件
├── data/                       # 已有的测试数据目录
│   ├── invalid_yara_rule.json
│   └── valid_yara_rule.json
├── unit/                       # 单元测试目录
│   ├── __init__.py
│   ├── core/                   # 对应 app/core 目录的测试
│   │   ├── __init__.py
│   │   ├── test_analysis.py
│   │   ├── test_auth.py
│   │   ├── test_document_analyzer.py
│   │   ├── test_entropy_analyzer.py
│   │   ├── test_exiftool_analyzer.py
│   │   ├── test_hash_analyzer.py
│   │   ├── test_magic_analyzer.py
│   │   ├── test_pe_analyzer.py
│   │   ├── test_strings_analyzer.py
│   │   ├── test_yara_analyzer.py
│   │   └── test_yara_manager.py
│   ├── models/                 # 对应 app/models 目录的测试
│   │   ├── __init__.py
│   │   ├── test_analysis.py
│   │   ├── test_analysis_result.py
│   │   ├── test_api_key.py
│   │   ├── test_sample.py
│   │   ├── test_task.py
│   │   └── test_user.py
│   └── services/              # 对应 app/services 目录的测试
│       ├── __init__.py
│       ├── test_analysis_service.py
│       ├── test_analysis_executor.py
│       ├── test_sample_service.py
│       ├── test_search_service.py
│       └── test_task_service.py
├── integration/               # 集成测试目录
│   ├── __init__.py
│   ├── api/                  # API 集成测试
│   │   ├── __init__.py
│   │   ├── test_analysis.py
│   │   ├── test_auth.py
│   │   └── test_samples.py
│   └── db/                   # 数据库集成测试
│       ├── __init__.py
│       └── test_mongodb.py
└── fixtures/                 # 测试夹具目录
    ├── __init__.py
    ├── analysis_fixtures.py  # 分析相关的测试数据
    ├── sample_fixtures.py    # 样本相关的测试数据
    └── user_fixtures.py      # 用户相关的测试数据
```

# 单元测试文档

## ExifTool 分析器测试

### 测试文件
- 位置：`tests/unit/core/test_exiftool_analyzer.py`
- 测试目标：`app/core/exiftool_analyzer.py`

### 测试用例

#### 1. 权限转换测试
```python
def test_convert_permissions():
    """测试权限转换函数"""
    test_cases = [
        (0o777, "rwxrwxrwx"),  # 完全权限
        (0o755, "rwxr-xr-x"),  # 所有者完全权限，组和其他用户只读和执行
        (0o644, "rw-r--r--"),  # 所有者读写，组和其他用户只读
        (0o600, "rw-------"),  # 只有所有者有读写权限
        (0o000, "---------")   # 无权限
    ]
```
- 目的：验证八进制权限值到标准 Linux 权限字符串的转换
- 测试内容：各种常见权限组合的转换结果

#### 2. 成功分析测试
```python
async def test_perform_exiftool_analysis_success():
    """测试成功的 EXIFTool 分析"""
```
- 目的：验证正常文件分析功能
- 测试内容：
  - 创建临时 JPEG 文件
  - 模拟 ExifTool 输出
  - 验证返回的元数据字段
  - 确保文件清理

#### 3. 文件不存在测试
```python
async def test_perform_exiftool_analysis_file_not_found():
    """测试文件不存在的错误处理"""
```
- 目的：验证文件不存在时的错误处理
- 测试内容：
  - 使用不存在的文件路径
  - 验证抛出 `FileNotFoundError` 异常
  - 检查错误消息

#### 4. 分析错误测试
```python
async def test_perform_exiftool_analysis_error():
    """测试 EXIFTool 分析错误处理"""
```
- 目的：验证 ExifTool 执行错误时的处理
- 测试内容：
  - 创建无效的测试文件
  - 模拟 ExifTool 错误
  - 验证抛出 `ExifToolError` 异常
  - 检查错误消息

#### 5. 真实文件分析测试
```python
async def test_analyze_file_with_real_file():
    """使用真实文件测试 _analyze_file 函数"""
```
- 目的：验证 `_analyze_file` 函数对真实文件的处理能力
- 测试内容：
  - 创建包含实际 JPEG 文件头的临时文件
  - 直接调用 `_analyze_file` 函数
  - 验证返回的元数据字段
  - 确保文件清理
- 特点：
  - 使用真实的文件数据
  - 直接测试底层分析函数
  - 不依赖模拟数据

#### 6. MinIO 集成测试
```python
async def test_perform_exiftool_analysis_with_minio():
    """测试使用 MinIO 的 perform_exiftool_analysis 函数"""
```
- 目的：验证与 MinIO 对象存储的集成
- 测试内容：
  - 创建 MinIO 客户端
  - 创建测试桶
  - 上传测试文件到 MinIO
  - 使用 MinIO 路径调用分析函数
  - 验证分析结果
  - 清理测试资源
- 特点：
  - 测试完整的对象存储集成
  - 验证文件上传和下载功能
  - 确保资源正确清理

### 测试数据模型
测试使用 `ExifToolMetadata` 模型，包含以下主要字段：
- 基本文件信息：
  - `exiftool_version`
  - `file_size`
  - `file_type`
  - `file_type_extension`
  - `mime_type`
  - `file_permissions`
  - `file_permissions_str`
- PE 文件特定信息：
  - `machine_type`
  - `machine_type_description`
  - `time_stamp`
  - `image_file_characteristics`
  - `entry_point`
  - `subsystem`
  - `subsystem_description`

### 测试覆盖
- 基本功能测试
- 错误处理测试
- 边界条件测试
- 数据模型验证
- 真实文件处理
- 对象存储集成

### 注意事项
1. 测试前确保 ExifTool 已正确安装
2. 测试使用临时文件，确保测试后清理
3. 模拟数据需要包含所有必需的元数据字段
4. 正确处理异步操作和异常
5. MinIO 测试需要有效的配置和连接
6. 确保测试环境的网络连接正常