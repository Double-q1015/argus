export default {
  common: {
    welcome: '欢迎',
    login: '登录',
    logout: '退出',
    profile: '个人信息',
    settings: '设置'
  },
  nav: {
    home: '首页',
    search: '搜索',
    samples: '样本管理',
    analysis: '分析',
    yara: 'Yara',
    createYara: '创建Yara规则',
    listYara: '查看Yara规则',
    tasks: '任务管理',
    migration: '数据迁移'
  },
  database: {
    online: '数据库连接正常',
    offline: '数据库连接异常，请联系管理员'
  },
  yara: {
    create: {
      title: '创建Yara规则',
      name: '规则名称',
      namePlaceholder: '请输入规则名称',
      nameRules: {
        required: '请输入规则名称',
        length: '长度在 3 到 50 个字符'
      },
      description: '规则描述',
      descriptionPlaceholder: '请输入规则描述',
      descriptionRules: {
        required: '请输入规则描述'
      },
      content: '规则内容',
      contentPlaceholder: '请输入Yara规则内容',
      contentRules: {
        required: '请输入规则内容'
      },
      submit: '创建规则',
      reset: '重置',
      success: '规则创建成功',
      error: '创建规则失败'
    },
    list: {
      title: 'Yara规则列表',
      createButton: '创建规则',
      table: {
        name: '规则名称',
        description: '描述',
        createTime: '创建时间',
        status: '状态',
        actions: '操作',
        view: '查看',
        edit: '编辑',
        delete: '删除'
      },
      status: {
        active: '启用',
        inactive: '禁用'
      },
      dialog: {
        viewTitle: '查看规则'
      },
      confirm: {
        deleteTitle: '警告',
        deleteMessage: '确定要删除该规则吗？',
        confirmButton: '确定',
        cancelButton: '取消'
      },
      message: {
        deleteSuccess: '删除成功',
        deleteError: '删除规则失败',
        loadError: '加载规则列表失败'
      }
    }
  },
  analysis: {
    title: '文件分析',
    dropZone: {
      title: '拖放文件到此处进行分析',
      description1: '支持Windows PE可执行文件和所有文件类型',
      description2: '最多10个文件，每个文件限制10MB'
    },
    fileList: {
      startAnalysis: '开始分析',
      clearList: '清空列表'
    },
    message: {
      maxFiles: '最多只能上传{count}个文件',
      maxFileSize: '以下文件超过大小限制(10MB)：{files}',
      noFiles: '请先添加文件',
      analysisSuccess: '所有文件分析成功',
      analysisPartial: '分析完成，{success}个成功，{error}个失败',
      analysisError: '分析失败，请重试'
    }
  },
  home: {
    stats: {
      totalSamples: '总样本数',
      todaySamples: '今日新增',
      totalStorage: '总存储量',
      activeUsers: '活跃用户',
      mimeTypeStats: '文件类型统计'
    },
    recentSamples: {
      title: '最近添加的样本',
      viewAll: '查看全部',
      table: {
        sha256: 'SHA256摘要',
        time: '时间',
        name: '名称',
        tags: '标签'
      }
    },
    message: {
      loadError: '获取数据失败'
    }
  },
  login: {
    title: '欢迎登录',
    subtitle: '请登录您的账号',
    username: '用户名',
    password: '密码',
    captcha: '验证码',
    submit: '登录',
    register: '注册账号',
    rules: {
      username: {
        required: '请输入用户名',
        length: '用户名长度应在3-20个字符之间'
      },
      password: {
        required: '请输入密码',
        min: '密码长度至少为8个字符'
      },
      captcha: {
        required: '请输入验证码'
      }
    },
    error: {
      default: '登录失败，请检查用户名和密码'
    },
    success: '登录成功'
  },
  migration: {
    create: {
      title: '创建迁移任务',
      back: '返回',
      success: '创建迁移任务成功',
      error: '创建迁移任务失败'
    },
    detail: {
      title: '迁移任务详情',
      back: '返回',
      labels: {
        name: '任务名称',
        status: '状态',
        sourceStorage: '源存储',
        targetStorage: '目标存储',
        createdAt: '创建时间',
        updatedAt: '更新时间',
        startedAt: '开始时间',
        completedAt: '完成时间',
        description: '描述',
        errorMessage: '错误信息'
      },
      progress: {
        title: '迁移进度',
        processedFiles: '已处理文件',
        processedSize: '已处理大小'
      },
      fileList: {
        title: '文件列表',
        filePath: '文件路径',
        status: '状态',
        sourceSize: '源文件大小',
        targetSize: '目标文件大小',
        errorMessage: '错误信息'
      },
      message: {
        loadTaskError: '加载迁移任务失败',
        loadTaskEmpty: '迁移任务数据为空或格式不正确',
        loadFileStatusError: '加载文件状态失败'
      }
    }
  }
} 