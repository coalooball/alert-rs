# 🛡️ 网络安全告警监控系统

基于 Rust Axum + Vue3 + SSE 的分布式实时告警推送系统。

## 📋 系统架构

```
┌────────────────┐                      ┌──────────────────┐
│ Generator CLI  │  ─── HTTP POST ───>  │  Axum Server     │
│ (数据生成器)   │      JSON 数据        │  (接收+转发)     │
└────────────────┘                      └─────────┬────────┘
                                                  │
                                        Broadcast Channel
                                                  │
                                                  ▼
                                        ┌──────────────────┐
                                        │   SSE Stream     │
                                        │   (实时推送)     │
                                        └─────────┬────────┘
                                                  │
                                                  ▼
                                        ┌──────────────────┐
                                        │  Vue3 Frontend   │
                                        │  (浏览器展示)    │
                                        └──────────────────┘
```

**核心特性**：
- ✅ **解耦架构**：数据生成与推送分离
- ✅ **独立控制**：CLI 工具灵活控制数据生成
- ✅ **实时推送**：SSE 长连接零延迟
- ✅ **Broadcast**：支持多客户端同时订阅
- ✅ **可扩展**：可替换为真实数据源

## 🚀 快速启动

### 步骤 1：启动 Axum 服务器

```bash
# 方式 1：使用脚本（推荐）
./start-server.sh

# 方式 2：手动启动
# 2.1 构建前端
cd frontend && npm install && npm run build && cd ..

# 2.2 启动服务器
cargo run --bin server
```

服务器将在 `http://localhost:3000` 启动。

### 步骤 2：打开浏览器

访问：**http://localhost:3000**

你会看到前端界面，但此时还没有告警数据。

### 步骤 3：运行 Generator 生成数据

```bash
# 在新终端窗口运行
cargo run --bin generator -- all -c 0 -i 2
```

现在你会看到告警数据实时出现在浏览器中！

## 📦 项目结构

```
test-code/
├── src/
│   ├── main.rs              # Axum 服务器（SSE + 接收端点）
│   ├── lib.rs               # 库文件（导出公共模块）
│   ├── models.rs            # 数据模型定义
│   ├── generators.rs        # 数据生成器
│   ├── broadcast.rs         # Broadcast Channel 管理
│   └── bin/
│       └── generator.rs     # Generator CLI 程序
├── frontend/
│   ├── src/
│   │   ├── App.vue          # Vue3 主组件
│   │   └── main.js          # 入口文件
│   └── dist/                # 构建输出
├── Cargo.toml               # Rust 配置（2 个 binary）
└── README.md
```

## 🎯 两个独立程序

### 1. Server (Axum 服务器)

**启动**：
```bash
cargo run --bin server
```

**功能**：
- 📡 提供 SSE 推送端点（客户端订阅）
- 📥 提供 POST 接收端点（Generator 发送）
- 🔄 通过 Broadcast Channel 转发数据
- 🌐 服务前端静态文件

**端点**：

SSE 推送（GET）：
- `/api/alerts/network-attack/stream`
- `/api/alerts/malicious-sample/stream`
- `/api/alerts/host-behavior/stream`

数据接收（POST）：
- `/api/alerts/network-attack/push`
- `/api/alerts/malicious-sample/push`
- `/api/alerts/host-behavior/push`

### 2. Generator (CLI 工具)

**启动**：
```bash
cargo run --bin generator -- [COMMAND]
```

**功能**：
- 🎲 生成模拟告警数据
- 📤 通过 HTTP POST 发送到 Server
- 🎛️ 灵活控制生成频率和数量
- 🔄 支持持续生成模式

**命令示例**：

```bash
# 生成网络攻击告警
cargo run --bin generator -- network -c 10 -i 2

# 生成恶意样本告警
cargo run --bin generator -- sample -c 15 -i 3

# 生成主机行为告警
cargo run --bin generator -- host -c 20 -i 2

# 混合生成所有类型
cargo run --bin generator -- all -c 0 -i 2

# 单次测试
cargo run --bin generator -- once -t network
```

详细文档：[GENERATOR_README.md](GENERATOR_README.md)

## 📡 数据流转

```
1. Generator 生成告警
   ↓
2. HTTP POST 发送到 Server
   POST /api/alerts/[type]/push
   ↓
3. Server 接收并广播
   Broadcast Channel
   ↓
4. 分发给所有 SSE 连接
   GET /api/alerts/[type]/stream
   ↓
5. 前端实时接收展示
   EventSource API
```

## 🎨 三种告警类型

### 🔴 网络攻击告警
- APT 组织攻击
- SQL 注入
- 端口扫描
- DDoS 攻击
- Web Shell 后门

### 🟠 恶意样本告警
- 银行木马（Emotet）
- 勒索软件（WannaCry）
- 僵尸网络（Mirai）
- 挖矿木马（XMRig）
- 后门程序（Cobalt Strike）

### 🟡 主机行为告警
- 挖矿进程
- 文件加密
- 暴力破解
- 数据外传
- 横向移动

## 📚 技术栈

### 后端
- **Rust** - 系统编程语言
- **Axum 0.7** - Web 框架
- **Tokio** - 异步运行时
- **Broadcast Channel** - 多播通道
- **SSE** - Server-Sent Events
- **Reqwest** - HTTP 客户端
- **Clap** - CLI 参数解析
- **Tracing** - 日志系统

### 前端
- **Vue 3** - 渐进式框架
- **Element Plus** - UI 组件库
- **Vite** - 构建工具
- **EventSource** - SSE 客户端

## 🛠️ 开发指南

### 编译

```bash
# 编译所有程序
cargo build

# 编译 release 版本
cargo build --release

# 只编译服务器
cargo build --bin server

# 只编译 Generator
cargo build --bin generator
```

### 运行

```bash
# 开发模式
cargo run --bin server
cargo run --bin generator -- all

# 生产模式
cargo run --release --bin server
cargo run --release --bin generator -- all
```

### 独立可执行文件

```bash
# 构建
cargo build --release

# 使用
./target/release/server
./target/release/generator network -c 10
```

## 🎯 使用场景

### 场景 1：开发测试

```bash
# 终端 1：启动服务器
cargo run --bin server

# 终端 2：快速测试
cargo run --bin generator -- once -t network
```

### 场景 2：演示展示

```bash
# 终端 1：启动服务器
./start-server.sh

# 终端 2：持续生成
cargo run --bin generator -- all -c 0 -i 3

# 浏览器：打开 http://localhost:3000
```

### 场景 3：压力测试

```bash
# 终端 1：启动服务器
cargo run --release --bin server

# 终端 2：高频生成
cargo run --release --bin generator -- all -c 1000 -i 0.5
```

### 场景 4：真实数据集成

将 Generator 替换为真实数据源：
```bash
# 从 Kafka 读取 → POST 到 Server
# 从文件读取 → POST 到 Server
# 从数据库读取 → POST 到 Server
```

## 📊 性能特点

- ✅ **异步处理**：Tokio 异步运行时
- ✅ **零拷贝**：Broadcast Channel 高效分发
- ✅ **自动重连**：SSE 内置重连机制
- ✅ **背压处理**：Channel 容量控制
- ✅ **低延迟**：毫秒级推送

## 🔧 配置说明

### 修改服务器端口

编辑 `src/main.rs`：
```rust
let addr = SocketAddr::from(([0, 0, 0, 0], 8080)); // 改端口
```

### 修改 Channel 容量

编辑 `src/broadcast.rs`：
```rust
let (tx, _) = broadcast::channel(200); // 改容量
```

### 修改生成频率

```bash
# 使用命令行参数
cargo run --bin generator -- network -i 1  # 1秒间隔
```

## 🐛 故障排查

### Server 无法启动

```bash
# 检查端口占用
lsof -i :3000

# 查看日志
RUST_LOG=debug cargo run --bin server
```

### Generator 连接失败

```bash
# 测试连接
curl http://localhost:3000/api/alerts/network-attack/push

# 指定服务器地址
cargo run --bin generator -- -s http://localhost:3000 network
```

### 前端无数据

1. 确认 Server 正在运行
2. 确认 Generator 正在发送数据
3. 检查浏览器控制台错误
4. 查看 Server 日志

## 📖 相关文档

- [GENERATOR_README.md](GENERATOR_README.md) - Generator CLI 详细使用手册
- [API-Documentation.md](API-Documentation.md) - 告警数据结构规范
- [QUICKSTART.md](QUICKSTART.md) - 快速启动指南

## 💡 扩展建议

### 1. 集成真实数据源

替换 Generator，从真实系统获取数据：
```rust
// 伪代码
loop {
    let alert = read_from_kafka().await;
    post_to_server(alert).await;
}
```

### 2. 添加数据持久化

```rust
// 接收时保存到数据库
async fn push_alert(alert: Alert) {
    db.insert(&alert).await;
    broadcaster.send(alert);
}
```

### 3. 添加认证

```rust
// 验证 Generator 身份
.layer(middleware::from_fn(auth_middleware))
```

### 4. 添加告警过滤

```rust
// 前端可以订阅特定类型
.route("/alerts/stream?severity=3", get(high_severity_stream))
```

### 5. 添加消息队列

```
Generator → Kafka → Server → SSE → Frontend
```

## 🎓 学习资源

- [Axum 文档](https://docs.rs/axum/)
- [Tokio 异步编程](https://tokio.rs/)
- [SSE 规范](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [Broadcast Channel](https://docs.rs/tokio/latest/tokio/sync/broadcast/)

---

Made with ❤️ using Rust Axum + Vue 3 + SSE 🦀🛡️
