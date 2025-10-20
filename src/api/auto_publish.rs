use axum::{extract::State, response::{IntoResponse, Response}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use anyhow::Result;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use chrono::{Utc, Duration};
use uuid::Uuid;

use crate::db::{
    query_converged_network_attacks,
    query_converged_malicious_samples,
    query_converged_host_behaviors,
};
use crate::db::auto_push::{
    has_been_pushed, insert_push_log, 
    list_auto_push_configs, get_auto_push_config, create_auto_push_config, 
    update_auto_push_config, delete_auto_push_config, get_enabled_configs,
    list_push_logs, list_push_logs_by_type,
};
// no model structs needed here
use crate::api::{ErrorResponse, SuccessResponse};
use crate::AppState;

#[derive(Deserialize)]
pub struct PublishWindowReq {
    /// 窗口大小（分钟）
    pub window_minutes: u64,
}

#[derive(Serialize)]
pub struct PublishWindowResp {
    pub sent_count: usize,
}

pub async fn publish_converged_by_window(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PublishWindowReq>,
) -> Response {
    if req.window_minutes == 0 {
        let err = ErrorResponse { success: false, message: "window_minutes must be > 0".to_string() };
        return (axum::http::StatusCode::BAD_REQUEST, axum::response::Json(err)).into_response();
    }

    match do_publish(&state, req.window_minutes).await {
        Ok(count) => {
            let resp = SuccessResponse { success: true, message: "published".to_string(), data: Some(PublishWindowResp { sent_count: count }) };
            axum::response::Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

// ===== 推送配置 CRUD =====
#[derive(Deserialize)]
pub struct CreatePushConfigReq { 
    pub name: String,
    pub enabled: bool, 
    pub window_minutes: i32, 
    pub interval_seconds: i32 
}

#[derive(Deserialize)]
pub struct UpdatePushConfigReq { 
    pub name: String,
    pub enabled: bool, 
    pub window_minutes: i32, 
    pub interval_seconds: i32 
}

#[derive(Serialize)]
pub struct PushConfigResp { 
    pub id: String,
    pub name: String,
    pub enabled: bool, 
    pub window_minutes: i32, 
    pub interval_seconds: i32, 
    pub created_at: i64,
    pub updated_at: i64 
}

impl From<crate::db::auto_push::AutoPushConfig> for PushConfigResp {
    fn from(cfg: crate::db::auto_push::AutoPushConfig) -> Self {
        Self {
            id: cfg.id.to_string(),
            name: cfg.name,
            enabled: cfg.enabled,
            window_minutes: cfg.window_minutes,
            interval_seconds: cfg.interval_seconds,
            created_at: cfg.created_at.timestamp_millis(),
            updated_at: cfg.updated_at.timestamp_millis(),
        }
    }
}

// GET /api/auto/push-configs - 获取所有配置
pub async fn list_push_configs(State(state): State<Arc<AppState>>) -> Response {
    match list_auto_push_configs(&state.pool).await {
        Ok(configs) => {
            let resp: Vec<PushConfigResp> = configs.into_iter().map(|c| c.into()).collect();
            axum::response::Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

// GET /api/auto/push-configs/:id - 获取单个配置
pub async fn get_push_config_by_id(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            let err = ErrorResponse { success: false, message: "Invalid UUID".to_string() };
            return (axum::http::StatusCode::BAD_REQUEST, axum::response::Json(err)).into_response();
        }
    };
    
    match get_auto_push_config(&state.pool, uuid).await {
        Ok(cfg) => {
            let resp: PushConfigResp = cfg.into();
            axum::response::Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::NOT_FOUND, axum::response::Json(err)).into_response()
        }
    }
}

// POST /api/auto/push-configs - 创建配置
pub async fn create_push_config(
    State(state): State<Arc<AppState>>, 
    Json(req): Json<CreatePushConfigReq>
) -> Response {
    if req.window_minutes <= 0 || req.interval_seconds <= 0 { 
        let err = ErrorResponse { success: false, message: "window_minutes/interval_seconds must be > 0".to_string() }; 
        return (axum::http::StatusCode::BAD_REQUEST, axum::response::Json(err)).into_response();
    }
    
    match create_auto_push_config(&state.pool, req.name, req.enabled, req.window_minutes, req.interval_seconds).await {
        Ok(id) => {
            let ok = SuccessResponse { success: true, message: "created".to_string(), data: Some(serde_json::json!({"id": id.to_string()})) };
            axum::response::Json(ok).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

// PUT /api/auto/push-configs/:id - 更新配置
pub async fn update_push_config_by_id(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(req): Json<UpdatePushConfigReq>
) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            let err = ErrorResponse { success: false, message: "Invalid UUID".to_string() };
            return (axum::http::StatusCode::BAD_REQUEST, axum::response::Json(err)).into_response();
        }
    };
    
    if req.window_minutes <= 0 || req.interval_seconds <= 0 { 
        let err = ErrorResponse { success: false, message: "window_minutes/interval_seconds must be > 0".to_string() }; 
        return (axum::http::StatusCode::BAD_REQUEST, axum::response::Json(err)).into_response();
    }
    
    match update_auto_push_config(&state.pool, uuid, req.name, req.enabled, req.window_minutes, req.interval_seconds).await {
        Ok(_) => {
            let ok = SuccessResponse::<()> { success: true, message: "updated".to_string(), data: None };
            axum::response::Json(ok).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

// DELETE /api/auto/push-configs/:id - 删除配置
pub async fn delete_push_config_by_id(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Response {
    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            let err = ErrorResponse { success: false, message: "Invalid UUID".to_string() };
            return (axum::http::StatusCode::BAD_REQUEST, axum::response::Json(err)).into_response();
        }
    };
    
    match delete_auto_push_config(&state.pool, uuid).await {
        Ok(_) => {
            let ok = SuccessResponse::<()> { success: true, message: "deleted".to_string(), data: None };
            axum::response::Json(ok).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

pub(crate) async fn do_publish(state: &AppState, window_minutes: u64) -> Result<usize> {
    let since = Utc::now() - Duration::minutes(window_minutes as i64);

    // 查询最近窗口内的收敛数据（使用简单分页循环以防数据量大）
    let mut out_na: Vec<OutNetworkAttack> = Vec::new();
    let mut out_ms: Vec<OutMaliciousSample> = Vec::new();
    let mut out_hb: Vec<OutHostBehavior> = Vec::new();
    let mut na_ids: Vec<Uuid> = Vec::new();
    let mut ms_ids: Vec<Uuid> = Vec::new();
    let mut hb_ids: Vec<Uuid> = Vec::new();
    let mut page = 1u64;
    let page_size = 500u64;
    loop {
        let (na_page, _total) = query_converged_network_attacks(&state.pool, page, page_size).await?;
        let (ms_page, _total2) = query_converged_malicious_samples(&state.pool, page, page_size).await?;
        let (hb_page, _total3) = query_converged_host_behaviors(&state.pool, page, page_size).await?;

        let cutoff = since;
        let mut page_empty = true;

        for r in na_page.into_iter().filter(|r| r.created_at >= cutoff) {
            page_empty = false;
            if !has_been_pushed(&state.pool, 1, r.id).await? {
                na_ids.push(r.id);
                out_na.push(to_payload_na(&r));
            }
        }
        for r in ms_page.into_iter().filter(|r| r.created_at >= cutoff) {
            page_empty = false;
            if !has_been_pushed(&state.pool, 2, r.id).await? {
                ms_ids.push(r.id);
                out_ms.push(to_payload_ms(&r));
            }
        }
        for r in hb_page.into_iter().filter(|r| r.created_at >= cutoff) {
            page_empty = false;
            if !has_been_pushed(&state.pool, 3, r.id).await? {
                hb_ids.push(r.id);
                out_hb.push(to_payload_hb(&r));
            }
        }

        if page_empty { break; }
        page += 1;
    }

    // Kafka 生产者
    let producer: FutureProducer = rdkafka::ClientConfig::new()
        .set("bootstrap.servers", &state.kafka.brokers)
        .set("client.id", &state.kafka.client_id)
        .create()?;

    // 发送（每种类型发送一个数组报文），并记录日志（去重）
    let mut sent = 0usize;
    if !out_na.is_empty() {
        let payload = serde_json::to_string(&out_na)?;
        let bytes: Vec<u8> = payload.into_bytes();
        let _ = producer
            .send(FutureRecord::<(), _>::to(&state.topics.converged_alerts).payload(bytes.as_slice()), Timeout::After(std::time::Duration::from_secs(3)))
            .await;
        for r in na_ids.iter() { insert_push_log(&state.pool, 1, *r).await?; }
        tracing::info!(target: "auto_push", "Published network_attack converged: count={}", na_ids.len());
        sent += na_ids.len();
    }
    if !out_ms.is_empty() {
        let payload = serde_json::to_string(&out_ms)?;
        let bytes: Vec<u8> = payload.into_bytes();
        let _ = producer
            .send(FutureRecord::<(), _>::to(&state.topics.converged_alerts).payload(bytes.as_slice()), Timeout::After(std::time::Duration::from_secs(3)))
            .await;
        for r in ms_ids.iter() { insert_push_log(&state.pool, 2, *r).await?; }
        tracing::info!(target: "auto_push", "Published malicious_sample converged: count={}", ms_ids.len());
        sent += ms_ids.len();
    }
    if !out_hb.is_empty() {
        let payload = serde_json::to_string(&out_hb)?;
        let bytes: Vec<u8> = payload.into_bytes();
        let _ = producer
            .send(FutureRecord::<(), _>::to(&state.topics.converged_alerts).payload(bytes.as_slice()), Timeout::After(std::time::Duration::from_secs(3)))
            .await;
        for r in hb_ids.iter() { insert_push_log(&state.pool, 3, *r).await?; }
        tracing::info!(target: "auto_push", "Published host_behavior converged: count={}", hb_ids.len());
        sent += hb_ids.len();
    }

    Ok(sent)
}

// 输出结构体（符合用户给定格式，字段为小驼峰，并补充 modelType 等）

#[derive(Serialize)]
struct OutNetworkAttack {
    modelType: &'static str,
    alarmId: Option<String>,
    alarmDate: Option<i64>,
    alarmSeverity: Option<i16>,
    alarmName: Option<String>,
    alarmDescription: Option<String>,
    alarmType: i16,
    alarmSubType: Option<i32>,
    controlRuleId: Option<String>,
    controlTaskId: Option<String>,
    procedureTechniqueId: Option<serde_json::Value>,
    sessionId: Option<String>,
    ipVersion: Option<i16>,
    srcIp: Option<String>,
    srcPort: Option<i32>,
    dstIp: Option<String>,
    dstPort: Option<i32>,
    protocol: Option<String>,
    terminalId: Option<String>,
    sourceFilePath: Option<String>,
    createdAt: i64,
    updatedAt: i64,
    signatureId: Option<String>,
    attackPayload: Option<String>,
    attackStage: Option<String>,
    attackIp: Option<String>,
    attackedIp: Option<String>,
    aptGroup: Option<String>,
    vulType: Option<String>,
    cveId: Option<String>,
    vulDesc: Option<String>,
}

fn to_payload_na(r: &crate::db::ConvergedNetworkAttackRecord) -> OutNetworkAttack {
    OutNetworkAttack {
        modelType: "ALM_CLU_ACT",
        alarmId: r.alarm_id.clone(),
        alarmDate: r.alarm_date,
        alarmSeverity: r.alarm_severity,
        alarmName: r.alarm_name.clone(),
        alarmDescription: r.alarm_description.clone(),
        alarmType: 1,
        alarmSubType: Some(r.alarm_subtype),
        controlRuleId: r.control_rule_id.clone(),
        controlTaskId: r.control_task_id.clone(),
        procedureTechniqueId: r.procedure_technique_id.clone(),
        sessionId: r.session_id.clone(),
        ipVersion: r.ip_version,
        srcIp: r.src_ip.clone(),
        srcPort: r.src_port,
        dstIp: r.dst_ip.clone(),
        dstPort: r.dst_port,
        protocol: r.protocol.clone(),
        terminalId: r.terminal_id.clone(),
        sourceFilePath: r.source_file_path.clone(),
        createdAt: r.created_at.timestamp_millis(),
        updatedAt: Utc::now().timestamp_millis(),
        signatureId: r.signature_id.clone(),
        attackPayload: r.attack_payload.clone(),
        attackStage: r.attack_stage.clone(),
        attackIp: r.attack_ip.clone(),
        attackedIp: r.attacked_ip.clone(),
        aptGroup: r.apt_group.clone(),
        vulType: r.vul_type.clone(),
        cveId: r.cve_id.clone(),
        vulDesc: r.vul_desc.clone(),
    }
}

#[derive(Serialize)]
struct OutMaliciousSample {
    modelType: &'static str,
    alarmDate: Option<i64>,
    alarmDescription: Option<String>,
    alarmId: Option<String>,
    alarmName: Option<String>,
    alarmSeverity: Option<i16>,
    alarmType: i16,
    alarmSubType: Option<i32>,
    controlRuleId: Option<String>,
    controlTaskId: Option<String>,
    procedureTechniqueId: Option<serde_json::Value>,
    sessionId: Option<String>,
    createdAt: i64,
    dstIp: Option<String>,
    dstPort: Option<i32>,
    fileSize: Option<i64>,
    fileType: Option<String>,
    ipVersion: Option<i16>,
    md5: Option<String>,
    sampleFamily: Option<String>,
    sampleOriginalName: Option<String>,
    sampleSource: Option<i16>,
    sha1: Option<String>,
    sha256: Option<String>,
    srcIp: Option<String>,
    srcPort: Option<i32>,
    sha512: Option<String>,
    ssdeep: Option<String>,
    aptGroup: Option<String>,
    sampleDescription: Option<String>,
    sampleAlarmEngine: Option<serde_json::Value>,
    targetPlatform: Option<String>,
    language: Option<String>,
    rule: Option<String>,
    targetContent: Option<String>,
    compileDate: Option<i64>,
    lastAnalyDate: Option<i64>,
    sampleAlarmDetail: Option<String>,
    updatedAt: i64,
}

fn to_payload_ms(r: &crate::db::ConvergedMaliciousSampleRecord) -> OutMaliciousSample {
    OutMaliciousSample {
        modelType: "ALM_CLU_ACT",
        alarmDate: r.alarm_date,
        alarmDescription: r.alarm_description.clone(),
        alarmId: r.alarm_id.clone(),
        alarmName: r.alarm_name.clone(),
        alarmSeverity: r.alarm_severity,
        alarmType: 2,
        alarmSubType: Some(r.alarm_subtype),
        controlRuleId: r.control_rule_id.clone(),
        controlTaskId: r.control_task_id.clone(),
        procedureTechniqueId: r.procedure_technique_id.clone(),
        sessionId: r.session_id.clone(),
        createdAt: r.created_at.timestamp_millis(),
        dstIp: r.dst_ip.clone(),
        dstPort: r.dst_port,
        fileSize: r.file_size,
        fileType: r.file_type.clone(),
        ipVersion: r.ip_version,
        md5: r.md5.clone(),
        sampleFamily: r.sample_family.clone(),
        sampleOriginalName: r.sample_original_name.clone(),
        sampleSource: r.sample_source,
        sha1: r.sha1.clone(),
        sha256: r.sha256.clone(),
        srcIp: r.src_ip.clone(),
        srcPort: r.src_port,
        sha512: r.sha512.clone(),
        ssdeep: r.ssdeep.clone(),
        aptGroup: r.apt_group.clone(),
        sampleDescription: r.sample_description.clone(),
        sampleAlarmEngine: r.sample_alarm_engine.clone(),
        targetPlatform: r.target_platform.clone(),
        language: r.language.clone(),
        rule: r.rule.clone(),
        targetContent: r.target_content.clone(),
        compileDate: r.compile_date,
        lastAnalyDate: r.last_analy_date,
        sampleAlarmDetail: r.sample_alarm_detail.clone(),
        updatedAt: Utc::now().timestamp_millis(),
    }
}

#[derive(Serialize)]
struct OutHostBehavior {
    modelType: &'static str,
    alarmDate: Option<i64>,
    alarmDescription: Option<String>,
    alarmId: Option<String>,
    alarmName: Option<String>,
    alarmSeverity: Option<i16>,
    alarmType: i16,
    alarmSubType: Option<i32>,
    controlRuleId: Option<String>,
    controlTaskId: Option<String>,
    procedureTechniqueId: Option<serde_json::Value>,
    sessionId: Option<String>,
    createdAt: i64,
    dstIp: Option<String>,
    dstPort: Option<i32>,
    dstProcessMd5: Option<String>,
    fileMd5: Option<String>,
    fileName: Option<String>,
    filePath: Option<String>,
    hostName: Option<String>,
    ipVersion: Option<i16>,
    srcIp: Option<String>,
    srcPort: Option<i32>,
    terminalIp: Option<String>,
    terminalOs: Option<String>,
    dstProcessPath: Option<String>,
    dstProcessCli: Option<String>,
    srcProcessMd5: Option<String>,
    srcProcessPath: Option<String>,
    srcProcessCli: Option<String>,
    registerKeyName: Option<String>,
    registerKeyValue: Option<String>,
    registerPath: Option<String>,
    updatedAt: i64,
    userAccount: Option<String>,
}

fn to_payload_hb(r: &crate::db::ConvergedHostBehaviorRecord) -> OutHostBehavior {
    OutHostBehavior {
        modelType: "ALM_CLU_ACT",
        alarmDate: r.alarm_date,
        alarmDescription: r.alarm_description.clone(),
        alarmId: r.alarm_id.clone(),
        alarmName: r.alarm_name.clone(),
        alarmSeverity: r.alarm_severity,
        alarmType: 3,
        alarmSubType: Some(r.alarm_subtype),
        controlRuleId: r.control_rule_id.clone(),
        controlTaskId: r.control_task_id.clone(),
        procedureTechniqueId: r.procedure_technique_id.clone(),
        sessionId: r.session_id.clone(),
        createdAt: r.created_at.timestamp_millis(),
        dstIp: r.dst_ip.clone(),
        dstPort: r.dst_port,
        dstProcessMd5: r.dst_process_md5.clone(),
        fileMd5: r.file_md5.clone(),
        fileName: r.file_name.clone(),
        filePath: r.file_path.clone(),
        hostName: r.host_name.clone(),
        ipVersion: r.ip_version,
        srcIp: r.src_ip.clone(),
        srcPort: r.src_port,
        terminalIp: r.terminal_ip.clone(),
        terminalOs: r.terminal_os.clone(),
        dstProcessPath: r.dst_process_path.clone(),
        dstProcessCli: r.dst_process_cli.clone(),
        srcProcessMd5: r.src_process_md5.clone(),
        srcProcessPath: r.src_process_path.clone(),
        srcProcessCli: r.src_process_cli.clone(),
        registerKeyName: r.register_key_name.clone(),
        registerKeyValue: r.register_key_value.clone(),
        registerPath: r.register_path.clone(),
        updatedAt: Utc::now().timestamp_millis(),
        userAccount: r.user_account.clone(),
    }
}

// ===== 推送日志查询 =====
#[derive(Serialize)]
pub struct PushLogResp {
    pub id: String,
    pub alert_type: i16,
    pub alert_type_name: String,
    pub converged_id: String,
    pub pushed_at: i64,
}

impl From<crate::db::auto_push::PushLogRecord> for PushLogResp {
    fn from(log: crate::db::auto_push::PushLogRecord) -> Self {
        let alert_type_name = match log.alert_type {
            1 => "网络攻击",
            2 => "恶意样本",
            3 => "主机行为",
            _ => "未知",
        }.to_string();
        
        Self {
            id: log.id.to_string(),
            alert_type: log.alert_type,
            alert_type_name,
            converged_id: log.converged_id.to_string(),
            pushed_at: log.pushed_at.timestamp_millis(),
        }
    }
}

#[derive(Serialize)]
pub struct PushLogsResp {
    pub logs: Vec<PushLogResp>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

// GET /api/auto/push-logs?page=1&page_size=20&alert_type=1
pub async fn get_push_logs(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let page = params.get("page").and_then(|s| s.parse::<u64>().ok()).unwrap_or(1);
    let page_size = params.get("page_size").and_then(|s| s.parse::<u64>().ok()).unwrap_or(20);
    let alert_type = params.get("alert_type").and_then(|s| s.parse::<i16>().ok());
    
    let result = if let Some(at) = alert_type {
        list_push_logs_by_type(&state.pool, at, page, page_size).await
    } else {
        list_push_logs(&state.pool, page, page_size).await
    };
    
    match result {
        Ok((logs, total)) => {
            let resp = PushLogsResp {
                logs: logs.into_iter().map(|l| l.into()).collect(),
                total,
                page,
                page_size,
            };
            axum::response::Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

// 后台自动发布循环 - 支持多配置并发执行
pub async fn run_auto_publisher(state: Arc<AppState>) {
    loop {
        // 读取所有启用的配置
        match get_enabled_configs(&state.pool).await {
            Ok(configs) => {
                if configs.is_empty() {
                    tracing::debug!(target = "auto_push", "No enabled push configs found");
                } else {
                    // 为每个配置执行推送任务
                    for cfg in configs {
                        let window = cfg.window_minutes as u64;
                        match do_publish(&state, window).await {
                            Ok(count) => {
                                tracing::info!(target = "auto_push", "Auto published for config '{}': sent={}", cfg.name, count);
                            }
                            Err(e) => {
                                tracing::error!(target = "auto_push", "Auto publish failed for config '{}': {}", cfg.name, e);
                            }
                        }
                    }
                }
                // 使用最小的 interval_seconds 作为睡眠时间，如果没有配置则默认30秒
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
            Err(e) => {
                tracing::error!(target = "auto_push", "Load push configs failed: {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        }
    }
}


