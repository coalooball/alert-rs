# ======================================
# 第一阶段：构建前端
# ======================================
FROM node:18-alpine AS frontend-builder

WORKDIR /app/frontend

# 复制前端文件
COPY frontend/package*.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# ======================================
# 第二阶段：构建 Rust 后端
# ======================================
FROM rust:1.88-slim-bookworm AS backend-builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    cmake \
    g++ \
    libsasl2-dev \
    libzstd-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 优化依赖缓存：先复制 Cargo.toml 和 Cargo.lock
COPY Cargo.toml Cargo.lock ./

# 创建虚拟 src 目录以缓存依赖
RUN mkdir -p src/bin && \
    echo "fn main() {}" > src/main.rs && \
    echo "fn main() {}" > src/bin/generator.rs && \
    cargo build --release && \
    rm -rf src

# 复制实际源代码
COPY src/ ./src/
COPY schema/ ./schema/

# 重新构建应用（利用缓存的依赖）
RUN cargo build --release && \
    strip target/release/server && \
    strip target/release/generator

# ======================================
# 第三阶段：运行时镜像（最小化）
# ======================================
FROM ubuntu:22.04

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive \
    RUST_LOG=info \
    TZ=Asia/Shanghai

# 安装运行时依赖（仅必需的库）
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libsasl2-2 \
    libzstd1 \
    tzdata \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 创建非 root 用户
RUN useradd -m -u 1000 alertapp && \
    mkdir -p /app && \
    chown -R alertapp:alertapp /app

WORKDIR /app

# 从构建阶段复制文件
COPY --from=backend-builder --chown=alertapp:alertapp /app/target/release/server ./
COPY --from=backend-builder --chown=alertapp:alertapp /app/target/release/generator ./
COPY --from=frontend-builder --chown=alertapp:alertapp /app/frontend/dist ./frontend/dist
COPY --chown=alertapp:alertapp config.toml ./
COPY --chown=alertapp:alertapp schema/ ./schema/

# 切换到非 root 用户
USER alertapp

# 暴露端口
EXPOSE 3000

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:3000/ || exit 1

# 默认启动服务器
CMD ["./server"]

