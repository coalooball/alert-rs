mod config;
mod db;
mod kafka;
mod models;
mod api;
mod dsl;

use crate::config::{load_config, AlarmTypesConfig};
use axum::{
    Router,
    extract::State,
    response::{Json, IntoResponse, Response},
    routing::{get, put, post, delete},
    http::{StatusCode, Uri},
};
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
    
    /// 插入威胁事件模拟数据后退出
    #[arg(long, default_value_t = false)]
    insert_mock_event_data: bool,
}

// 应用状态
pub struct AppState {
    pub pool: PgPool,
    pub alarm_types: AlarmTypesConfig,
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

    // 若指定 --insert-mock-event-data，则插入测试数据后退出
    if args.insert_mock_event_data {
        println!("🔄 正在插入威胁事件模拟数据...");
        match db::mock_threat_events::insert_mock_data(&pool).await {
            Ok(count) => {
                println!("✅ 成功插入 {} 条威胁事件模拟数据。", count);
            }
            Err(e) => {
                eprintln!("❌ 插入模拟数据失败: {}", e);
                std::process::exit(1);
            }
        }
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
        // 告警数据路由
        .route("/api/network-attacks", get(api::alert_data::get_network_attacks))
        .route("/api/malicious-samples", get(api::alert_data::get_malicious_samples))
        .route("/api/host-behaviors", get(api::alert_data::get_host_behaviors))
        .route("/api/invalid-alerts", get(api::alert_data::get_invalid_alerts))
        .route("/api/threat-events", get(api::alert_data::get_threat_events))
        .route("/api/threat-events/:id", put(api::alert_data::update_threat_event))
        // 标签管理路由
        .route("/api/tags", get(api::tag_management::get_tags))
        .route("/api/tags/all", get(api::tag_management::get_all_tags))
        .route("/api/tags/:id", get(api::tag_management::get_tag_by_id))
        .route("/api/tags", post(api::tag_management::create_tag))
        .route("/api/tags/:id", put(api::tag_management::update_tag))
        .route("/api/tags/:id", delete(api::tag_management::delete_tag))
        // 字段定义路由
        .route("/api/alert-fields", get(api::alert_fields::get_alert_fields))
        .route("/api/alert-fields/groups", get(api::alert_fields::get_common_field_groups))
        // DSL 编译路由
        .route("/api/rules/convergence/compile", post(api::dsl_compile::compile_converge_rule))
        .route("/api/rules/correlation/compile", post(api::dsl_compile::compile_correlate_rule))
        // 其他路由
        .route("/api/alarm-types", get(get_alarm_types))
        .with_state(app_state);

    // 合并路由（使用自定义 fallback 支持 SPA 路由）
    let app = Router::new()
        .merge(api_routes)
        .nest_service("/assets", ServeDir::new("frontend/dist/assets"))
        .fallback(spa_fallback)
        .layer(cors);

    // 服务器地址
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));

    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  Axum 告警推送服务器启动成功！                          ║");
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!("访问地址:");
    println!("   前端界面（告警数据）: http://localhost:3000/alert-data");
    println!("   前端界面（威胁事件）: http://localhost:3000/threat-event");
    println!("   前端界面（自动化配置）: http://localhost:3000/auto-config");
    println!("   API 接口: http://localhost:3000/api/*");
    println!();
    println!("可用路由:");
    println!("   • /alert-data         - 告警数据（统一 Tab 视图）");
    println!("   • /threat-event       - 威胁事件");
    println!("   • /auto-config        - 自动化配置");
    println!("   • /network-attack     - 精控流量");
    println!("   • /malicious-sample   - 恶意样本");
    println!("   • /host-behavior      - 终端日志");
    println!("   • /invalid-alert      - 无效告警");

    println!("   按 Ctrl+C 停止服务");
    println!();
    info!("Kafka brokers={}", config.kafka.brokers);

    // 启动服务器
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// 获取告警类型枚举
async fn get_alarm_types(
    State(state): State<Arc<AppState>>,
) -> Json<AlarmTypesConfig> {
    Json(state.alarm_types.clone())
}

// SPA fallback 处理器：对所有非 API 路由返回 index.html
async fn spa_fallback(_uri: Uri) -> Response {
    // 读取 index.html
    match tokio::fs::read_to_string("frontend/dist/index.html").await {
        Ok(contents) => {
            axum::response::Html(contents).into_response()
        }
        Err(_) => {
            (StatusCode::NOT_FOUND, "Frontend files not found").into_response()
        }
    }
}
