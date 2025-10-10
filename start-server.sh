#!/bin/bash

echo "╔══════════════════════════════════════════════╗"
echo "║  🚀 构建并启动 Axum 服务器                  ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# 检查前端依赖
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 首次运行，正在安装前端依赖..."
    cd frontend
    npm install
    cd ..
    echo "✅ 依赖安装完成"
    echo ""
fi

# 构建前端
echo "🎨 正在构建前端..."
cd frontend
npm run build
cd ..

if [ ! -d "frontend/dist" ]; then
    echo "❌ 前端构建失败！"
    exit 1
fi

echo "✅ 前端构建完成"
echo ""

# 启动服务器
echo "🦀 正在启动 Axum 服务器..."
echo ""
cargo run --bin server --release

