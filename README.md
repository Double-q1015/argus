# argus
Argus is a malware analysis platform built with Vue 3 and Python

## 系统依赖
* strings相关
apt-get install binutils

* TLSH相关
apt-get install -y libssl-dev

* magic相关
apt-get install -y libmagic1 python3-magic

* ssdeep相关
apt-get install -y ssdeep

* exiftool相关
apt install libimage-exiftool-perl

* yara相关
apt-get install yara

## API
### 认证模块 (auth.py)

**安全特性：**
* 密码加密：使用 bcrypt 加密
* 登录限制：限制登录尝试次数
* 验证码：防止暴力破解
* JWT令牌：使用 JWT 进行身份验证
* 密码强度验证：确保密码符合安全要求

**路径:**
* /auth

功能: 
* 用户认证
* 登录
* 注册

注册
```bash
curl -X POST "http://localhost:8000/api/v1/auth/register?username=testuser&email=test@example.com&password=Test123!@#&is_active=true&is_superuser=false"
```

获取验证码
```bash
curl -X GET "http://localhost:8000/api/v1/auth/captcha?client_id=test123" -o captcha.png
```

### 样本管理 (samples.py)
路径: /samples
功能: 样本文件的上传、下载、查询等


### 分析任务 (analysis.py, analyses.py, analysis_configs.py, analysis_results.py)
路径: /analysis
功能: 分析任务的创建、配置、结果查询等

### Yara规则 (yara.py)
路径: /yara
功能: Yara规则的创建、更新、查询等

### 首页 (endpoints/home.py)
路径: /home
功能: 首页数据展示

### 搜索 (endpoints/search.py)
路径: /search
功能: 全局搜索功能

### 任务管理 (tasks.py)
路径: /tasks
功能: 后台任务管理

### 用户管理 (users.py)
路径: /users
功能: 用户信息管理

### 数据迁移 (migration.py)
路径: /migration
功能: 数据迁移相关操作

### Exif工具 (exiftool.py)
功能: 处理文件元数据

## PE节区信息
Windows 资源语言和子语言的官方定义可以在以下位置找到：
Windows SDK 头文件：
winnt.h 文件中包含了完整的语言和子语言定义
路径通常在：C:\Program Files (x86)\Windows Kits\10\Include\<version>\um\winnt.h
MSDN 文档：
语言标识符：https://learn.microsoft.com/en-us/windows/win32/intl/language-identifiers
子语言标识符：https://learn.microsoft.com/en-us/windows/win32/intl/sublanguage-identifiers
Windows API 参考：
LANGID 和 SUBLANGID 宏的定义
MAKELANGID 和 MAKESUBLANGID 宏的使用方法