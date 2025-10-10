mod models;

use axum::{
    routing::post,
    Json, Router,
};
use models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};
use std::net::SocketAddr;
use tracing::info;
use tracing_subscriber;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 仅保留三类 POST 接口
    let app = Router::new()
        .route(
            "/api/alerts/network-attack/push",
            post(push_network_attack_alert),
        )
        .route(
            "/api/alerts/malicious-sample/push",
            post(push_malicious_sample_alert),
        )
        .route(
            "/api/alerts/host-behavior/push",
            post(push_host_behavior_alert),
        );

    // 服务器地址
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  🦀 Axum 告警推送服务器启动成功！                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("🌐 访问地址:");
    println!("   👉 http://localhost:3000");
    println!();
    println!("📥 数据接收端点:");
    println!("   🔴 POST /api/alerts/network-attack/push");
    println!("   🟠 POST /api/alerts/malicious-sample/push");
    println!("   🟡 POST /api/alerts/host-behavior/push");
    println!();
    println!("💡 提示：使用 generator CLI 工具生成告警数据");
    println!("   cargo run --bin generator -- --help");
    println!();
    println!("   按 Ctrl+C 停止服务");
    println!();

    info!("服务器启动在 http://localhost:3000");

    // 启动服务器
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ==================== POST 接收端点 ====================

/// 接收网络攻击告警
async fn push_network_attack_alert(
    Json(alert): Json<NetworkAttackAlert>,
) -> Json<serde_json::Value> {
    info!("收到网络攻击告警: {}", alert.alarm_id);
    Json(serde_json::json!({"status": "ok"}))
}

/// 接收恶意样本告警
async fn push_malicious_sample_alert(
    Json(alert): Json<MaliciousSampleAlert>,
) -> Json<serde_json::Value> {
    info!("收到恶意样本告警: {}", alert.alarm_id);
    Json(serde_json::json!({"status": "ok"}))
}

/// 接收主机行为告警
async fn push_host_behavior_alert(
    Json(alert): Json<HostBehaviorAlert>,
) -> Json<serde_json::Value> {
    info!("收到主机行为告警: {}", alert.alarm_id);
    Json(serde_json::json!({"status": "ok"}))
}
