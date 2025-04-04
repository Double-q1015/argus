# Snake-Skin 系统特性分析文档

## 用户管理模块

### 数据模型设计

#### 基础用户模型 (UserBase)
- 用户名（唯一标识符）
- 电子邮箱（唯一）
- 账户状态（是否激活）
- 管理员权限标识

#### 数据库用户模型 (UserInDB)
- 继承基础用户模型
- 用户ID（自动生成）
- 哈希密码
- 创建时间
- 最后登录时间
- 登录尝试计数
- 最后登录尝试时间

#### 用户响应模型 (UserResponse)
- 仅包含非敏感信息
- 过滤掉密码等敏感字段
- 包含基本用户信息和时间戳

### 安全特性

#### 密码安全
1. 密码强度要求：
   - 最小长度：8个字符
   - 必须包含大写字母
   - 必须包含小写字母
   - 必须包含数字
   - 必须包含特殊字符（!@#$%^&*(),.?":{}|<>）

2. 密码存储：
   - 使用bcrypt算法进行哈希
   - 从不存储明文密码
   - 密码修改时验证旧密码

#### 防暴力破解
1. 登录保护：
   - 追踪登录尝试次数
   - 连续失败5次后锁定
   - 锁定时间：5分钟
   - 自动重置尝试计数

#### 访问控制
1. 认证机制：
   - 基于JWT的令牌认证
   - 令牌包含过期时间
   - 请求头中使用Bearer认证

2. 权限控制：
   - 基于角色的访问控制（RBAC）
   - 管理员特权操作
   - 普通用户权限限制

#### 数据验证
1. 用户名验证：
   - 长度限制：3-32个字符
   - 字符限制：字母、数字、下划线、连字符
   - 唯一性检查

2. 邮箱验证：
   - 格式验证
   - 唯一性检查

### API端点

#### 用户信息管理
1. 获取当前用户信息
   ```
   GET /users/me
   ```
   - 需要认证
   - 返回用户非敏感信息

2. 更新用户信息
   ```
   PUT /users/me
   ```
   - 需要认证
   - 支持部分更新
   - 密码更新需要验证

#### 管理员功能
1. 用户列表查询
   ```
   GET /users/
   ```
   - 仅管理员访问
   - 支持分页
   - 默认限制100条

2. 用户信息管理
   ```
   GET /users/{user_id}    # 查询指定用户
   PUT /users/{user_id}    # 更新指定用户
   DELETE /users/{user_id} # 删除指定用户
   ```
   - 仅管理员访问
   - 完整的CRUD操作
   - 防止越权访问

### 错误处理

#### HTTP状态码
- 400：请求参数错误
- 401：未认证
- 403：权限不足
- 404：资源不存在
- 429：请求过于频繁

#### 错误响应
- 统一的错误响应格式
- 详细的错误描述
- 多语言支持（中文）

### 最佳实践

1. 安全性
   - 密码强度验证
   - 防暴力破解
   - 敏感信息过滤
   - 权限精细控制

2. 用户体验
   - 友好的错误提示
   - 合理的访问限制
   - 灵活的更新机制

3. 可维护性
   - 模块化设计
   - 完整的文档
   - 统一的响应格式
   - 清晰的代码结构

## 恶意软件分析功能文档

## 1. 基础分析功能

### 1.1 文件基本信息分析
- 文件大小
- 文件类型
- 创建时间
- 修改时间
- 文件哈希值（MD5, SHA1, SHA256）
- 文件格式识别

### 1.2 代码基础统计
- 代码行数统计
- 函数数量统计
- 基本块数量统计
- 字符串数量统计

## 2. 静态分析功能

### 2.1 导入表分析
- API调用统计
  - 文件操作API
  - 网络操作API
  - 进程操作API
  - 注册表操作API
  - 系统信息API
- 可疑API组合识别
- API调用模式分析

### 2.2 资源分析
- 资源类型统计
  - 字符串资源
  - 图标资源
  - 光标资源
  - 位图资源
  - 菜单资源
  - 对话框资源
  - 版本信息资源
- 加密资源检测
- 资源文件提取

## 3. 动态分析功能

### 3.1 系统调用分析
- 系统调用频率统计
- 系统调用模式识别
- 异常调用序列检测

### 3.2 文件操作分析
- 文件读写操作统计
- 文件创建/删除统计
- 文件路径分析

### 3.3 网络行为分析
- 连接尝试统计
- 数据传输量统计
- 协议使用分析

## 4. 分析结果存储

### 4.1 MongoDB文档结构
```json
{
    "sample_id": "string",
    "basic_info": {
        "file_size": "number",
        "file_type": "string",
        "create_time": "datetime",
        "modify_time": "datetime",
        "hashes": {
            "md5": "string",
            "sha1": "string",
            "sha256": "string"
        }
    },
    "code_stats": {
        "line_count": "number",
        "function_count": "number",
        "basic_block_count": "number",
        "string_count": "number"
    },
    "import_analysis": {
        "api_categories": {
            "file_ops": {
                "count": "number",
                "apis": ["string"]
            },
            "network": {
                "count": "number",
                "apis": ["string"]
            },
            "process": {
                "count": "number",
                "apis": ["string"]
            },
            "registry": {
                "count": "number",
                "apis": ["string"]
            },
            "system": {
                "count": "number",
                "apis": ["string"]
            }
        },
        "suspicious_apis": ["string"]
    },
    "resource_analysis": {
        "resource_types": {
            "string": {
                "count": "number",
                "items": ["object"]
            },
            "icon": {
                "count": "number",
                "items": ["object"]
            },
            "cursor": {
                "count": "number",
                "items": ["object"]
            },
            "bitmap": {
                "count": "number",
                "items": ["object"]
            },
            "menu": {
                "count": "number",
                "items": ["object"]
            },
            "dialog": {
                "count": "number",
                "items": ["object"]
            },
            "version": {
                "count": "number",
                "items": ["object"]
            }
        },
        "encrypted_resources": {
            "count": "number",
            "items": ["object"]
        }
    }
}
```

## 5. API接口

### 5.1 静态分析接口
```python
POST /api/analysis/static/{sample_id}
```

请求参数：
- sample_id: 样本ID

响应数据：
```json
{
    "status": "success",
    "data": {
        "import_analysis": {
            "api_categories": {},
            "suspicious_apis": []
        },
        "resource_analysis": {
            "resource_types": {},
            "encrypted_resources": {}
        },
        "report": "string"
    }
}
```

### 5.2 动态分析接口
```python
POST /api/analysis/dynamic/{sample_id}
```

请求参数：
- sample_id: 样本ID

响应数据：
```json
{
    "status": "success",
    "data": {
        "system_calls": {},
        "file_operations": {},
        "network_behavior": {},
        "report": "string"
    }
}
```

## 6. 待实现功能

### 6.1 高级分析功能
- 机器学习模型集成
- 行为模式识别
- 威胁等级评估
- 家族关系分析

### 6.2 可视化增强
- 交互式分析界面
- 实时分析监控
- 批量分析支持
- 自定义分析规则

### 6.3 报告系统
- 自定义报告模板
- 多格式导出支持
- 报告自动生成
- 报告版本管理

## 7. 文件下载功能

### 7.1 压缩下载
- 支持格式：
  - ZIP格式（默认）
  - 7Z格式
- 安全特性：
  - 所有压缩文件使用密码保护（可配置）
  - 防止主机反病毒引擎误删
  - 使用临时文件处理，自动清理

### 7.2 配置说明
- 配置文件：`backend/app/core/config.py`
- 环境变量：
  ```bash
  # .env 文件
  COMPRESSION_PASSWORD="your_password"  # 压缩文件密码，默认为"infected"
  ```
- 配置项：
  ```python
  # config.py
  class Settings(BaseSettings):
      COMPRESSION_PASSWORD: str = "infected"  # 默认密码，可以通过环境变量覆盖
  ```

### 7.3 接口说明
```python
GET /api/samples/download/{sample_id}?format=zip  # 下载ZIP格式
GET /api/samples/download/{sample_id}?format=7z   # 下载7Z格式
```
- 参数说明：
  - sample_id: 样本ID
  - format: 压缩格式（可选值：zip、7z）
- 响应：
  - Content-Type: application/octet-stream
  - 文件名：原始文件名.zip/7z
  - 文件内容：密码保护的压缩文件

### 7.4 依赖要求
- py7zr==0.20.8：用于7Z格式压缩
- 安装命令：
  ```bash
  pip install py7zr==0.20.8
  ```

### 7.5 实现细节
- 使用临时文件处理，避免内存占用
- 异步处理下载请求
- 自动清理临时文件
- 完整的错误处理
- 保持原始文件名
- 支持单个文件压缩
- 从配置文件读取压缩密码

## 8. API密钥管理

### 8.1 安全特性
- 密钥生成：使用`secrets.token_urlsafe`生成安全的随机密钥
- 密钥存储：使用SHA-256哈希存储密钥，原始密钥只在创建时返回一次
- 密钥验证：支持过期时间和启用状态检查
- 权限控制：支持细粒度的API权限控制
- 使用追踪：记录密钥的最后使用时间
- 密钥撤销：支持临时禁用和永久删除密钥

### 8.2 数据模型
```python
class APIKeyBase:
    name: str                    # API密钥名称
    description: Optional[str]   # API密钥描述
    permissions: list[str]       # 权限列表
    expires_at: Optional[datetime]  # 过期时间
    is_active: bool             # 是否启用

class APIKeyInDB(APIKeyBase):
    id: str                     # 密钥ID
    user_id: str               # 所属用户ID
    key: str                   # 哈希后的密钥
    created_at: datetime       # 创建时间
    last_used_at: Optional[datetime]  # 最后使用时间
```

### 8.3 API接口
```python
# 创建API密钥
POST /api/keys/
请求体：
{
    "name": "string",
    "description": "string",
    "permissions": ["string"],
    "expires_at": "datetime",
    "is_active": true
}

# 获取API密钥列表
GET /api/keys/

# 撤销API密钥
POST /api/keys/{key_id}/revoke

# 删除API密钥
DELETE /api/keys/{key_id}
```

### 8.4 使用说明
1. 创建API密钥：
   - 访问用户管理页面
   - 点击"创建API密钥"
   - 填写密钥信息
   - 保存并记录返回的密钥（仅显示一次）

2. 使用API密钥：
   - 在请求头中添加：`X-API-Key: your_api_key`
   - 密钥权限决定可访问的API范围
   - 密钥过期后需要重新创建

3. 安全建议：
   - 定期轮换API密钥
   - 设置合理的过期时间
   - 仅授予必要的最小权限
   - 及时撤销不再使用的密钥
   - 不要在代码中硬编码API密钥

### 8.5 权限说明
- read: 读取权限
- write: 写入权限
- admin: 管理权限
- analysis: 分析权限
- download: 下载权限

### 8.6 创建和使用示例

#### 8.6.1 创建API密钥
1. 通过Web界面创建：
   - 登录系统
   - 进入"用户管理"页面
   - 点击"创建API密钥"按钮
   - 填写表单：
     ```json
     {
         "name": "自动化分析密钥",
         "description": "用于自动化分析脚本",
         "permissions": ["read", "analysis"],
         "expires_at": "2024-12-31T23:59:59Z"
     }
     ```
   - 点击"创建"按钮
   - 保存显示的API密钥（仅显示一次）

2. 通过API创建：
   ```bash
   curl -X POST "http://your-domain/api/keys/" \
        -H "Authorization: Bearer your_jwt_token" \
        -H "Content-Type: application/json" \
        -d '{
            "name": "自动化分析密钥",
            "description": "用于自动化分析脚本",
            "permissions": ["read", "analysis"],
            "expires_at": "2024-12-31T23:59:59Z"
        }'
   ```

#### 8.6.2 使用API密钥
1. 在请求头中添加API密钥：
   ```bash
   curl -X GET "http://your-domain/api/samples/" \
        -H "X-API-Key: your_api_key"
   ```

2. Python示例：
   ```python
   import requests
   
   # 设置API密钥
   headers = {
       "X-API-Key": "your_api_key"
   }
   
   # 获取样本列表
   response = requests.get(
       "http://your-domain/api/samples/",
       headers=headers
   )
   
   # 上传样本
   files = {
       "file": ("sample.exe", open("sample.exe", "rb"))
   }
   response = requests.post(
       "http://your-domain/api/samples/upload",
       headers=headers,
       files=files
   )
   
   # 获取分析结果
   response = requests.get(
       "http://your-domain/api/analysis/static/sample_id",
       headers=headers
   )
   ```

3. PowerShell示例：
   ```powershell
   # 设置API密钥
   $headers = @{
       "X-API-Key" = "your_api_key"
   }
   
   # 获取样本列表
   Invoke-RestMethod -Uri "http://your-domain/api/samples/" -Headers $headers
   
   # 上传样本
   $file = Get-Item "sample.exe"
   $form = @{
       file = $file
   }
   Invoke-RestMethod -Uri "http://your-domain/api/samples/upload" -Headers $headers -Form $form
   ```

#### 8.6.3 最佳实践
1. 密钥管理：
   - 使用环境变量存储API密钥
   - 不要在代码中硬编码密钥
   - 定期轮换密钥
   - 及时撤销不再使用的密钥

2. 权限控制：
   - 为不同用途创建不同的API密钥
   - 只授予必要的最小权限
   - 设置合理的过期时间
   - 监控密钥使用情况

3. 错误处理：
   ```python
   try:
       response = requests.get(url, headers=headers)
       response.raise_for_status()
   except requests.exceptions.HTTPError as e:
       if e.response.status_code == 401:
           print("API密钥无效或已过期")
       elif e.response.status_code == 403:
           print("权限不足")
       else:
           print(f"请求失败: {e}")
   ```

4. 安全建议：
   - 使用HTTPS传输
   - 不要在日志中记录API密钥
   - 不要在公共场合分享API密钥
   - 定期检查密钥使用记录
   - 发现异常及时撤销密钥

### 8.7 前端实现

#### 8.7.1 组件结构
```typescript
// 组件目录结构
frontend/
  ├── src/
  │   ├── components/
  │   │   └── ApiKeyManager.tsx    // API密钥管理组件
  │   └── pages/
  │       └── Settings.tsx         // 设置页面
```

#### 8.7.2 功能实现
1. API密钥管理组件 (`ApiKeyManager.tsx`)：
   - 密钥列表展示
   - 创建新密钥
   - 撤销/删除密钥
   - 权限管理
   - 过期时间设置
   - 操作反馈

2. 设置页面集成 (`Settings.tsx`)：
   - 页面布局
   - 组件集成
   - 预留扩展空间

#### 8.7.3 界面功能
1. 密钥列表：
   - 显示密钥基本信息
   - 权限标签展示
   - 时间信息展示
   - 状态管理
   - 操作按钮

2. 创建密钥：
   - 名称和描述输入
   - 权限选择
   - 过期时间设置
   - 新密钥展示

3. 密钥管理：
   - 撤销功能
   - 删除功能
   - 状态切换

4. 用户体验：
   - 操作反馈
   - 确认提示
   - 警告信息
   - 响应式布局

#### 8.7.4 数据交互
1. API调用：
   ```typescript
   // 获取密钥列表
   GET /api/keys/
   
   // 创建新密钥
   POST /api/keys/
   {
     name: string;
     description: string;
     permissions: string[];
     expires_at: string | null;
   }
   
   // 撤销密钥
   POST /api/keys/{id}/revoke
   
   // 删除密钥
   DELETE /api/keys/{id}
   ```

2. 状态管理：
   ```typescript
   interface ApiKey {
     id: string;
     name: string;
     description: string;
     permissions: string[];
     created_at: string;
     last_used_at: string | null;
     expires_at: string | null;
     is_active: boolean;
   }
   ```

#### 8.7.5 安全考虑
1. 密钥显示：
   - 新密钥仅显示一次
   - 警告提示保存
   - 只读显示模式

2. 权限控制：
   - 权限标签展示
   - 权限选择控制
   - 默认最小权限

3. 操作安全：
   - 撤销确认
   - 删除确认
   - 状态切换保护

#### 8.7.6 使用说明
1. 访问设置页面：
   - 点击用户头像
   - 选择"设置"选项
   - 进入API密钥管理区域

2. 创建新密钥：
   - 点击"创建新密钥"按钮
   - 填写密钥信息
   - 选择权限范围
   - 设置过期时间
   - 保存并记录密钥

3. 管理密钥：
   - 查看密钥列表
   - 撤销不再使用的密钥
   - 删除已撤销的密钥
   - 监控密钥使用情况

# 分析功能设计文档

## 1. 数据结构设计

### 1.1 任务相关表

#### Task（任务基础表）
```python
class Task(Document):
    """任务基础表"""
    name: str
    description: Optional[str]
    type: str  # 任务类型：analysis, scan, etc.
    status: str  # pending, running, completed, failed
    priority: int
    created_by: User
    created_at: datetime
    updated_at: datetime
    schedule: Optional[str]  # cron表达式
    is_active: bool = True
```

#### TaskCondition（任务条件表）
```python
class TaskCondition(Document):
    """任务条件表"""
    task_id: Task
    condition_type: str  # file_type, file_size, hash, etc.
    field: str  # 字段名
    operator: str  # in, not_in, between, gt, lt, etc.
    value: Any  # 条件值
    logic: str  # AND, OR
    parent_id: Optional[TaskCondition]  # 父条件ID，用于条件组合
    order: int  # 条件顺序
```

#### TaskStatus（任务状态表）
```python
class TaskStatus(Document):
    """任务状态表"""
    task_id: Task
    total_samples: int
    processed_samples: int
    failed_samples: List[str]
    current_sample: Optional[str]
    start_time: Optional[datetime]
    end_time: Optional[datetime]
    error_message: Optional[str]
    last_updated: datetime
```

### 1.2 样本分析相关表

#### SampleAnalysis（样本分析记录表）
```python
class SampleAnalysis(Document):
    """样本分析记录表"""
    sample_id: Sample
    analysis_type: str  # exiftool, pe_info, strings, etc.
    status: str  # pending, analyzing, completed, failed
    version: int  # 分析版本号
    retry_count: int
    last_analysis_time: Optional[datetime]
    next_analysis_time: Optional[datetime]
    error_message: Optional[str]
    created_at: datetime
    updated_at: datetime
```

#### AnalysisResult（分析结果表）
```python
class AnalysisResult(Document):
    """分析结果表"""
    sample_analysis_id: SampleAnalysis
    result_type: str  # 结果类型
    result_data: Dict[str, Any]  # 结果数据
    created_at: datetime
    version: int  # 结果版本号
```

### 1.3 分析配置相关表

#### AnalysisConfig（分析配置表）
```python
class AnalysisConfig(Document):
    """分析配置表"""
    name: str
    description: Optional[str]
    analysis_type: str
    auto_analyze: bool
    priority: int
    resource_limits: Dict[str, int]
    created_by: User
    created_at: datetime
    updated_at: datetime
    is_active: bool = True
```

#### AnalysisSchedule（分析计划表）
```python
class AnalysisSchedule(Document):
    """分析计划表"""
    config_id: AnalysisConfig
    schedule_type: str  # cron, interval, manual
    schedule_value: str  # cron表达式或时间间隔
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    is_active: bool = True
```

## 2. 索引设计

### 2.1 任务相关索引
```python
# Task表索引
Task.Index("status", "type", "priority")
Task.Index("created_by", "created_at")
Task.Index("schedule", "is_active")

# TaskCondition表索引
TaskCondition.Index("task_id", "condition_type")
TaskCondition.Index("parent_id", "order")

# TaskStatus表索引
TaskStatus.Index("task_id", "last_updated")
```

### 2.2 样本分析相关索引
```python
# SampleAnalysis表索引
SampleAnalysis.Index("sample_id", "analysis_type")
SampleAnalysis.Index("status", "analysis_type")
SampleAnalysis.Index("next_analysis_time")

# AnalysisResult表索引
AnalysisResult.Index("sample_analysis_id", "result_type")
AnalysisResult.Index("created_at")
```

### 2.3 分析配置相关索引
```python
# AnalysisConfig表索引
AnalysisConfig.Index("analysis_type", "is_active")
AnalysisConfig.Index("created_by", "created_at")

# AnalysisSchedule表索引
AnalysisSchedule.Index("config_id", "is_active")
AnalysisSchedule.Index("next_run")
```

## 3. 功能特点

### 3.1 任务管理
- 支持多种任务类型（分析、扫描等）
- 支持任务优先级
- 支持任务调度（cron表达式）
- 支持任务状态跟踪
- 支持任务条件组合

### 3.2 样本分析
- 支持多种分析类型（exiftool、pe_info、strings等）
- 支持分析版本控制
- 支持分析重试机制
- 支持分析结果历史记录
- 支持增量分析

### 3.3 分析配置
- 支持自动分析配置
- 支持资源限制配置
- 支持分析计划配置
- 支持分析优先级配置

## 4. 查询示例

### 4.1 任务查询
```python
# 获取待执行的任务
pending_tasks = await Task.find(
    Task.status == "pending",
    Task.is_active == True
).sort(Task.priority).to_list()

# 获取特定用户的任务
user_tasks = await Task.find(
    Task.created_by == user_id
).sort(Task.created_at).to_list()
```

### 4.2 样本分析查询
```python
# 获取需要分析的样本
samples_to_analyze = await SampleAnalysis.find(
    SampleAnalysis.status == "pending",
    SampleAnalysis.next_analysis_time <= datetime.utcnow()
).to_list()

# 获取特定类型的分析结果
pe_results = await AnalysisResult.find(
    AnalysisResult.result_type == "pe_header"
).sort(AnalysisResult.created_at).to_list()
```

### 4.3 分析配置查询
```python
# 获取活动的分析配置
active_configs = await AnalysisConfig.find(
    AnalysisConfig.is_active == True
).to_list()

# 获取待执行的分析计划
pending_schedules = await AnalysisSchedule.find(
    AnalysisSchedule.is_active == True,
    AnalysisSchedule.next_run <= datetime.utcnow()
).to_list()
```

## 5. 设计优点

### 5.1 完整性
- 覆盖任务管理的各个方面
- 支持条件组合
- 支持分析版本控制
- 支持结果历史记录

### 5.2 灵活性
- 支持多种任务类型
- 支持多种分析类型
- 支持多种调度方式
- 支持配置管理

### 5.3 可扩展性
- 易于添加新的任务类型
- 易于添加新的分析类型
- 易于添加新的配置项

### 5.4 性能考虑
- 合理的索引设计
- 支持高效查询
- 支持分页和排序

## YARA 规则管理

### 功能概述
YARA 规则管理模块提供了规则的创建、查询、更新和删除功能，并实现了基于用户的权限控制。

### 主要功能

#### 1. 规则创建
- 支持创建新的 YARA 规则
- 自动验证规则语法
- 检查规则名称唯一性
- 自动关联创建者信息
- 支持设置规则描述、标签和元数据

#### 2. 规则查询
- 支持获取规则列表（分页）
- 支持获取单个规则详情
- 基于用户权限过滤规则
- 支持规则内容、创建时间等信息的查询

#### 3. 规则更新
- 支持更新规则内容
- 自动验证更新后的规则语法
- 检查规则名称唯一性
- 自动更新修改时间
- 基于用户权限控制更新操作

#### 4. 规则删除
- 支持删除规则
- 基于用户权限控制删除操作

### 权限控制
- 用户只能查看自己创建的规则
- 用户只能修改自己创建的规则
- 用户只能删除自己创建的规则

### 数据模型
```python
class YaraRule:
    name: str                    # 规则名称
    description: Optional[str]    # 规则描述
    content: str                 # 规则内容
    creator: Link[User]          # 创建者（关联用户）
    created_at: datetime         # 创建时间
    updated_at: datetime         # 更新时间
    is_active: bool             # 是否激活
    is_public: bool             # 是否公开
    tags: List[str]             # 标签列表
    metadata: Dict[str, Any]    # 元数据
```

### API 接口
1. 创建规则
   ```
   POST /api/v1/yara/rules
   ```

2. 获取规则列表
   ```
   GET /api/v1/yara/rules?skip=0&limit=10
   ```

3. 获取单个规则
   ```
   GET /api/v1/yara/rules/{rule_id}
   ```

4. 更新规则
   ```
   PUT /api/v1/yara/rules/{rule_id}
   ```

5. 删除规则
   ```
   DELETE /api/v1/yara/rules/{rule_id}
   ```

### 错误处理
- 400: 规则名称已存在
- 400: 规则语法错误
- 403: 没有权限操作此规则
- 404: 规则不存在 