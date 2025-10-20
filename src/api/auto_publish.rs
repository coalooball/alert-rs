use axum::{extract::State, response::{IntoResponse, Response}, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use anyhow::Result;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use chrono::{Utc, Duration};
use uuid::Uuid;

use crate::db::{
    query_new_converged_network_attacks,
    query_new_converged_malicious_samples,
    query_new_converged_host_behaviors,
};
use crate::db::auto_push::{
    has_been_pushed, insert_push_log, 
    get_auto_push_config, update_auto_push_config,
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
pub struct UpdatePushConfigReq {
    pub name: String,
    pub enabled: bool,
    pub window_minutes: i32,
    pub interval_seconds: i32,
}

/// 获取推送配置
pub async fn get_push_config(
    State(state): State<Arc<AppState>>,
) -> Response {
    match get_auto_push_config(&state.pool).await {
        Ok(config) => {
            (axum::http::StatusCode::OK, Json(config)).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}

/// 更新推送配置
pub async fn update_push_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpdatePushConfigReq>,
) -> Response {
    match update_auto_push_config(
        &state.pool,
        req.name,
        req.enabled,
        req.window_minutes,
        req.interval_seconds,
    ).await {
        Ok(_) => {
            let resp = SuccessResponse { success: true, message: "配置已更新".to_string(), data: None::<()> };
            Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse { success: false, message: e.to_string() };
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, axum::response::Json(err)).into_response()
        }
    }
}


// (之前的 CRUD APIs 已移除：list_push_configs, create_push_config, get_push_config_by_id, delete_push_config_by_id)

// 定义一个统一的告警载体，用于序列化
#[derive(Serialize)]
#[serde(untagged)]
enum UnifiedAlert {
    NetworkAttack(OutNetworkAttack),
    MaliciousSample(OutMaliciousSample),
    HostBehavior(OutHostBehavior),
}

pub(crate) async fn do_publish(state: &AppState, window_minutes: u64) -> Result<usize> {
    let since = Utc::now() - Duration::minutes(window_minutes as i64);

    // 1. 使用新函数高效查询所有未推送的告警
    let na_records = query_new_converged_network_attacks(&state.pool, since).await?;
    let ms_records = query_new_converged_malicious_samples(&state.pool, since).await?;
    let hb_records = query_new_converged_host_behaviors(&state.pool, since).await?;

    // 2. 将所有告警合并到一个 Vec 中，并记录其 ID 和类型用于后续日志
    let mut unified_alerts: Vec<UnifiedAlert> = Vec::new();
    let mut logs_to_insert: Vec<(i16, Uuid)> = Vec::new();

    for r in na_records {
        logs_to_insert.push((1, r.id));
        unified_alerts.push(UnifiedAlert::NetworkAttack(to_payload_na(&r)));
    }
    for r in ms_records {
        logs_to_insert.push((2, r.id));
        unified_alerts.push(UnifiedAlert::MaliciousSample(to_payload_ms(&r)));
    }
    for r in hb_records {
        logs_to_insert.push((3, r.id));
        unified_alerts.push(UnifiedAlert::HostBehavior(to_payload_hb(&r)));
    }
    
    // 3. 如果有新告警，则合并为单条消息进行推送
    if unified_alerts.is_empty() {
        return Ok(0);
    }

    let producer: FutureProducer = state.kafka.producer_config().create()?;
    
    let payload = serde_json::to_string(&unified_alerts)?;
    let bytes: Vec<u8> = payload.into_bytes();
    
    let delivery_status = producer
        .send(
            FutureRecord::<(), _>::to(&state.topics.converged_alerts).payload(&bytes),
            Timeout::After(std::time::Duration::from_secs(3)),
        )
        .await;

    // 4. 推送成功后，批量记录日志
    if delivery_status.is_ok() {
        for (alert_type, converged_id) in &logs_to_insert {
            insert_push_log(&state.pool, *alert_type, *converged_id).await?;
        }
        tracing::info!(target: "auto_push", "Published {} alerts in a single batch.", unified_alerts.len());
        Ok(unified_alerts.len())
    } else {
        tracing::error!(target: "auto_push", "Failed to send unified alert batch to Kafka.");
        Err(anyhow::anyhow!("Kafka delivery failed"))
    }
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
        // 每次循环都从数据库读取最新配置
        match get_auto_push_config(&state.pool).await {
            Ok(config) => {
                if config.enabled {
                    let window = config.window_minutes as u64;
                    match do_publish(&state, window).await {
                        Ok(count) => {
                            if count > 0 {
                                tracing::info!(target = "auto_push", "Auto published for config '{}': sent={}", config.name, count);
                            } else {
                                tracing::debug!(target = "auto_push", "Auto publish for config '{}' completed, no new alerts to push.", config.name);
                            }
                        }
                        Err(e) => {
                            tracing::error!(target = "auto_push", "Auto publish failed for config '{}': {}", config.name, e);
                        }
                    }
                    // 使用配置的间隔时间
                    let sleep_duration = std::time::Duration::from_secs(config.interval_seconds as u64);
                    tracing::debug!(target = "auto_push", "Sleeping for {} seconds.", sleep_duration.as_secs());
                    tokio::time::sleep(sleep_duration).await;
                } else {
                    tracing::info!(target = "auto_push", "Auto publishing is disabled. Checking again in 60 seconds.");
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
            }
            Err(e) => {
                tracing::error!(target = "auto_push", "Failed to load push config: {}. Retrying in 60 seconds.", e);
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    }
}


