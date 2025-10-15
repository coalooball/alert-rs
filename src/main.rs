mod config;
mod db;
mod kafka;
mod models;

use crate::config::{load_config, AlarmTypesConfig};
use axum::{
    Router,
    extract::{State, Query},
    response::Json,
    routing::get,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber;
use sqlx::PgPool;
use tower_http::cors::{CorsLayer, Any};
use tower_http::services::ServeDir;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "server", about = "Axum 告警推送服务器")] 
struct Args {
    /// 重置数据库（删除所有业务表后退出）
    #[arg(long, default_value_t = false)]
    reset_db: bool,
}

// 应用状态
struct AppState {
    pool: PgPool,
    alarm_types: AlarmTypesConfig,
}

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt::init();

    // 解析命令行
    let args = Args::parse();

    // 读取配置
    let config = load_config("config.toml").expect("读取配置失败");

    // 初始化数据库
    let pool = db::init_postgres(&config.postgres)
        .await
        .expect("Postgres 初始化失败");

    // 若指定 --reset-db，则删除表后退出
    if args.reset_db {
        if let Err(e) = db::reset_database(&pool).await {
            eprintln!("数据库重置失败: {}", e);
            std::process::exit(1);
        }
        println!("✅ 数据库已重置（相关表已删除）。");
        return;
    }

    // 启动 Kafka 消费任务
    let kafka_cfg = config.kafka.clone();
    let topics_cfg = config.topics.clone();
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        if let Err(e) = kafka::run_consumer(kafka_cfg, topics_cfg, pool_clone).await {
            tracing::error!("Kafka consumer stopped: {}", e);
        }
    });

    // 创建共享状态
    let app_state = Arc::new(AppState {
        pool,
        alarm_types: config.alarm_types,
    });

    // 配置 CORS
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // API 路由
    let api_routes = Router::new()
        .route("/api/network-attacks", get(get_network_attacks))
        .route("/api/malicious-samples", get(get_malicious_samples))
        .route("/api/host-behaviors", get(get_host_behaviors))
        .route("/api/invalid-alerts", get(get_invalid_alerts))
        .route("/api/alarm-types", get(get_alarm_types))
        .with_state(app_state);

    // 静态文件服务 - 为 SPA 路由提供 index.html fallback
    let serve_dir = ServeDir::new("frontend/dist");

    // 合并路由
    let app = Router::new()
        .merge(api_routes)
        .nest_service("/", serve_dir)
        .layer(cors);

    // 服务器地址
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  🦀 Axum 告警推送服务器启动成功！                       ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("🌐 访问地址:");
    println!("   👉 前端界面: http://localhost:3000");
    println!("   👉 API 接口: http://localhost:3000/api/*");
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

// 查询参数
#[derive(Deserialize)]
struct PageQuery {
    #[serde(default = "default_page")]
    page: u64,
    #[serde(default = "default_page_size")]
    page_size: u64,
}

fn default_page() -> u64 { 1 }
fn default_page_size() -> u64 { 20 }

// 响应结构
#[derive(Serialize)]
struct PageResponse<T> {
    data: Vec<T>,
    total: u64,
    page: u64,
    page_size: u64,
}

// API 处理函数
async fn get_network_attacks(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<db::NetworkAttackRecord>> {
    match db::query_network_attacks(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => Json(PageResponse {
            data,
            total,
            page: params.page,
            page_size: params.page_size,
        }),
        Err(e) => {
            tracing::error!("Query network attacks failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

async fn get_malicious_samples(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<db::MaliciousSampleRecord>> {
    match db::query_malicious_samples(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => Json(PageResponse {
            data,
            total,
            page: params.page,
            page_size: params.page_size,
        }),
        Err(e) => {
            tracing::error!("Query malicious samples failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

async fn get_host_behaviors(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<db::HostBehaviorRecord>> {
    match db::query_host_behaviors(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => Json(PageResponse {
            data,
            total,
            page: params.page,
            page_size: params.page_size,
        }),
        Err(e) => {
            tracing::error!("Query host behaviors failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

async fn get_invalid_alerts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<db::InvalidAlertRecord>> {
    match db::query_invalid_alerts(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => Json(PageResponse {
            data,
            total,
            page: params.page,
            page_size: params.page_size,
        }),
        Err(e) => {
            tracing::error!("Query invalid alerts failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

// 获取告警类型枚举
async fn get_alarm_types(
    State(state): State<Arc<AppState>>,
) -> Json<AlarmTypesConfig> {
    Json(state.alarm_types.clone())
}
