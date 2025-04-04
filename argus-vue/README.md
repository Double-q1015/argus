# Argus Vue

Argus是一个基于Vue 3的恶意软件分析平台前端项目。

## 技术栈

- Vue 3
- TypeScript
- Vite
- Element Plus
- Pinia
- Vue Router
- Axios

## 开发环境要求

- Node.js >= 16.0.0
- npm >= 7.0.0

## 安装依赖

```bash
npm install
```

## 开发服务器

```bash
npm run dev
```

## 构建生产版本

```bash
npm run build
```

## 代码检查

```bash
npm run lint
```

## 代码格式化

```bash
npm run format
```

## 项目结构

```
src/
├── assets/        # 静态资源
├── components/    # 公共组件
├── composables/   # 组合式函数
├── router/        # 路由配置
├── stores/        # 状态管理
├── types/         # TypeScript类型定义
├── utils/         # 工具函数
└── views/         # 页面组件
```

## 环境变量

项目使用以下环境变量：

- `VITE_API_BASE_URL`: API服务器地址
- `VITE_APP_TITLE`: 应用标题

## 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建Pull Request

## 许可证

MIT
