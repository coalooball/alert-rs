mod models;
mod config;
mod db;
mod kafka;

use axum::Router;
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber;
use crate::config::load_config;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 读取配置
    let config = load_config("config.toml").expect("读取配置失败");

    // 初始化数据库
    let rb = db::init_postgres(&config.postgres).await.expect("Postgres 初始化失败");

    // 启动 Kafka 消费任务
    let kafka_cfg = config.kafka.clone();
    let topics_cfg = config.topics.clone();
    let rb_clone = rb.clone();
    tokio::spawn(async move {
        if let Err(e) = kafka::run_consumer(kafka_cfg, topics_cfg, rb_clone).await {
            tracing::error!("Kafka consumer stopped: {}", e);
        }
    });

    // 移除所有 POST 接口，保留空路由
    let app = Router::new();

    // 服务器地址
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  🦀 Axum 告警推送服务器启动成功！                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("🌐 访问地址:");
    println!("   👉 http://localhost:3000");
    println!();
    println!("📥 当前未开放 HTTP 数据接收端点（已切换为 Kafka 通道）");
    println!();
    println!("💡 提示：使用 generator CLI 工具向 Kafka 发送告警数据");
    println!("   cargo run --bin generator -- --help");
    println!();
    println!("   按 Ctrl+C 停止服务");
    println!();

    info!("服务器启动在 http://localhost:3000（无路由）");
    info!("Kafka brokers={}", config.kafka.brokers);

    // 启动服务器
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// 已移除 POST 接口
