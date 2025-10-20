mod config;
mod db;
mod kafka;
mod models;
mod api;
mod dsl;

use crate::config::{load_config, AlarmTypesConfig, KafkaConfig, TopicsConfig};
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
    
    /// 插入标签模拟数据后退出
    #[arg(long, default_value_t = false)]
    insert_mock_tags: bool,
    
    /// 插入规则模拟数据后退出（包括收敛规则、关联规则、过滤规则、标签规则）
    #[arg(long, default_value_t = false)]
    insert_mock_rules: bool,
    
    /// 插入告警模拟数据（原始告警+收敛告警+映射关系）后退出
    #[arg(long, default_value_t = false)]
    insert_mock_alerts: bool,
}

// 应用状态
pub struct AppState {
    pub pool: PgPool,
    pub alarm_types: AlarmTypesConfig,
    pub kafka: KafkaConfig,
    pub topics: TopicsConfig,
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

    // 若指定 --insert-mock-tags，则插入标签模拟数据后退出
    if args.insert_mock_tags {
        println!("🔄 正在插入标签模拟数据...");
        match db::mock_tags::insert_mock_tags(&pool).await {
            Ok(count) => {
                println!("✅ 成功插入 {} 条标签模拟数据。", count);
            }
            Err(e) => {
                eprintln!("❌ 插入标签模拟数据失败: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // 若指定 --insert-mock-rules，则插入规则模拟数据后退出
    if args.insert_mock_rules {
        println!("🔄 正在插入规则模拟数据...");
        match db::mock_rules::insert_all_mock_rules(&pool).await {
            Ok((convergence_count, correlation_count, filter_count, tag_count)) => {
                println!("✅ 成功插入规则模拟数据：");
                println!("   - 收敛规则: {} 条", convergence_count);
                println!("   - 关联规则: {} 条", correlation_count);
                println!("   - 过滤规则: {} 条", filter_count);
                println!("   - 标签规则: {} 条", tag_count);
                println!("   - 总计: {} 条", convergence_count + correlation_count + filter_count + tag_count);
            }
            Err(e) => {
                eprintln!("❌ 插入规则模拟数据失败: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // 若指定 --insert-mock-alerts，则插入告警模拟数据后退出
    if args.insert_mock_alerts {
        println!("🔄 正在插入告警模拟数据（原始告警+收敛告警+映射关系）...");
        match db::mock_converged_alerts::insert_mock_converged_alerts(&pool).await {
            Ok(count) => {
                println!("✅ 成功插入告警数据，共 {} 条记录。", count);
                println!("   - 原始告警表 (raw_alerts)");
                println!("   - 收敛告警表 (converged_alerts)");
                println!("   - 映射关系表 (alert_mapping)");
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
        kafka: config.kafka.clone(),
        topics: config.topics.clone(),
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
        // 原始告警查询路由
        .route("/api/network-attacks/:id/raw", get(api::alert_data::get_raw_network_attacks_by_converged_id))
        .route("/api/malicious-samples/:id/raw", get(api::alert_data::get_raw_malicious_samples_by_converged_id))
        .route("/api/host-behaviors/:id/raw", get(api::alert_data::get_raw_host_behaviors_by_converged_id))
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
        // 收敛规则路由
        .route("/api/rules/convergence", get(api::rules::get_convergence_rules))
        .route("/api/rules/convergence", post(api::rules::create_convergence_rule))
        .route("/api/rules/convergence/:id", get(api::rules::get_convergence_rule_by_id))
        .route("/api/rules/convergence/:id", put(api::rules::update_convergence_rule))
        .route("/api/rules/convergence/:id", delete(api::rules::delete_convergence_rule))
        // 关联规则路由
        .route("/api/rules/correlation", get(api::rules::get_correlation_rules))
        .route("/api/rules/correlation", post(api::rules::create_correlation_rule))
        .route("/api/rules/correlation/:id", get(api::rules::get_correlation_rule_by_id))
        .route("/api/rules/correlation/:id", put(api::rules::update_correlation_rule))
        .route("/api/rules/correlation/:id", delete(api::rules::delete_correlation_rule))
        // 过滤规则路由
        .route("/api/rules/filter", get(api::rules::get_filter_rules))
        .route("/api/rules/filter", post(api::rules::create_filter_rule))
        .route("/api/rules/filter/:id", get(api::rules::get_filter_rule_by_id))
        .route("/api/rules/filter/:id", put(api::rules::update_filter_rule))
        .route("/api/rules/filter/:id", delete(api::rules::delete_filter_rule))
        // 标签规则路由
        .route("/api/rules/tag", get(api::rules::get_tag_rules))
        .route("/api/rules/tag", post(api::rules::create_tag_rule))
        .route("/api/rules/tag/:id", get(api::rules::get_tag_rule_by_id))
        .route("/api/rules/tag/:id", put(api::rules::update_tag_rule))
        .route("/api/rules/tag/:id", delete(api::rules::delete_tag_rule))
        // 其他路由
        .route("/api/alarm-types", get(get_alarm_types))
        // 自动推送配置路由 (CRUD)
        .route("/api/auto/push-configs", get(api::auto_publish::list_push_configs))
        .route("/api/auto/push-configs", post(api::auto_publish::create_push_config))
        .route("/api/auto/push-configs/:id", get(api::auto_publish::get_push_config_by_id))
        .route("/api/auto/push-configs/:id", put(api::auto_publish::update_push_config_by_id))
        .route("/api/auto/push-configs/:id", delete(api::auto_publish::delete_push_config_by_id))
        // 推送日志查询路由
        .route("/api/auto/push-logs", get(api::auto_publish::get_push_logs))
        // 自动推送收敛告警到 Kafka（按时间窗口）
        .route("/api/auto/publish-converged", post(api::auto_publish::publish_converged_by_window))
        .with_state(app_state.clone());

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
    let server = axum::serve(listener, app);

    // 启动后台自动推送循环
    let app_state_for_auto = app_state.clone();
    tokio::spawn(async move {
        api::auto_publish::run_auto_publisher(app_state_for_auto).await;
    });

    server.await.unwrap();
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
