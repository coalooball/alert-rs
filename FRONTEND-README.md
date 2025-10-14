# 前端使用说明

## 项目概览

这是一个基于 Vue 3 + Element Plus 的安全告警监控系统前端，包含三个独立的页面来展示不同类型的告警数据。

## 功能特性

### 三个子页面

1. **网络攻击告警** (`/network-attack`)
   - 展示网络攻击相关的告警信息
   - 包含源IP、目标IP、攻击阶段、CVE编号等信息
   - 支持查看详细的攻击载荷和漏洞描述

2. **恶意样本告警** (`/malicious-sample`)
   - 展示恶意样本检测告警
   - 显示文件哈希值（MD5/SHA1/SHA256/SHA512/SSDEEP）
   - 包含样本家族、APT组织、文件类型等信息

3. **主机行为告警** (`/host-behavior`)
   - 展示主机异常行为告警
   - 显示主机名、用户账号、进程信息
   - 包含注册表操作、文件操作等详细信息

### 功能特性

- ✅ 分页查询，支持自定义每页显示数量
- ✅ 表格展示，关键信息一目了然
- ✅ 详情对话框，查看完整告警信息
- ✅ 实时刷新功能
- ✅ 响应式布局
- ✅ 侧边栏导航

## 技术栈

- **Vue 3** - 渐进式 JavaScript 框架
- **Vue Router 4** - 官方路由管理器
- **Element Plus** - Vue 3 UI 组件库
- **Axios** - HTTP 客户端
- **Vite** - 前端构建工具

## 快速开始

### 1. 启动后端服务

```bash
# 在项目根目录
cargo run --bin server
```

后端将在 `http://localhost:3000` 启动，提供以下 API：

- `GET /api/network-attacks?page=1&page_size=20`
- `GET /api/malicious-samples?page=1&page_size=20`
- `GET /api/host-behaviors?page=1&page_size=20`

### 2. 启动前端开发服务器

```bash
# 进入前端目录
cd frontend

# 启动开发服务器
npm run dev
```

前端将在 `http://localhost:5173` 启动（或其他可用端口）。

### 3. 访问应用

在浏览器中打开 `http://localhost:5173`，即可看到安全告警监控系统。

## 项目结构

```
frontend/
├── src/
│   ├── api/
│   │   └── index.js          # API 接口封装
│   ├── views/
│   │   ├── NetworkAttack.vue  # 网络攻击页面
│   │   ├── MaliciousSample.vue # 恶意样本页面
│   │   └── HostBehavior.vue   # 主机行为页面
│   ├── App.vue               # 主应用组件（包含布局和导航）
│   ├── main.js               # 应用入口
│   └── router.js             # 路由配置
├── index.html
├── package.json
└── vite.config.js
```

## API 数据格式

### 请求参数

```javascript
{
  page: 1,          // 页码，从 1 开始
  page_size: 20     // 每页数量，默认 20
}
```

### 响应格式

```javascript
{
  data: [],         // 数据数组
  total: 0,         // 总记录数
  page: 1,          // 当前页码
  page_size: 20     // 每页数量
}
```

## 构建生产版本

```bash
cd frontend
npm run build
```

构建产物将输出到 `frontend/dist` 目录。

## 开发提示

### 修改 API 地址

如果后端运行在其他地址，请修改 `src/api/index.js` 中的 `API_BASE_URL`：

```javascript
const API_BASE_URL = 'http://your-backend-url/api'
```

### 自定义样式

- 全局样式在 `App.vue` 的 `<style>` 标签中
- 组件样式在各自的 `.vue` 文件中

### 添加新页面

1. 在 `src/views/` 创建新的 `.vue` 组件
2. 在 `src/router.js` 添加路由配置
3. 在 `App.vue` 的侧边栏菜单中添加导航项

## 常见问题

### 1. 数据加载失败

- 检查后端服务是否正常运行
- 检查浏览器控制台的网络请求
- 确认 API 地址配置正确
- 检查 CORS 配置

### 2. 页面空白

- 检查浏览器控制台是否有错误
- 确认路由配置正确
- 尝试清除浏览器缓存

### 3. 样式问题

- 确认 Element Plus 样式已正确导入
- 检查 CSS 冲突

## 后续优化建议

- [ ] 添加数据筛选功能（按时间、严重级别等）
- [ ] 添加数据导出功能（CSV/Excel）
- [ ] 添加图表统计展示
- [ ] 添加实时推送（WebSocket）
- [ ] 添加告警处理流程
- [ ] 添加用户认证和权限管理

