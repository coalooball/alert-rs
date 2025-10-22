use anyhow::Result;
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration, Utc};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::auto_push::{
    get_auto_push_config, insert_push_log, list_push_logs, list_push_logs_by_type,
    update_auto_push_config,
};
use crate::db::{
    query_new_converged_host_behaviors, query_new_converged_malicious_samples,
    query_new_converged_network_attacks,
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
        let err = ErrorResponse {
            success: false,
            message: "window_minutes must be > 0".to_string(),
        };
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::response::Json(err),
        )
            .into_response();
    }

    match do_publish(&state, req.window_minutes).await {
        Ok(count) => {
            let resp = SuccessResponse {
                success: true,
                message: "published".to_string(),
                data: Some(PublishWindowResp { sent_count: count }),
            };
            axum::response::Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse {
                success: false,
                message: e.to_string(),
            };
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Json(err),
            )
                .into_response()
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
pub async fn get_push_config(State(state): State<Arc<AppState>>) -> Response {
    match get_auto_push_config(&state.pool).await {
        Ok(config) => (axum::http::StatusCode::OK, Json(config)).into_response(),
        Err(e) => {
            let err = ErrorResponse {
                success: false,
                message: e.to_string(),
            };
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Json(err),
            )
                .into_response()
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
    )
    .await
    {
        Ok(_) => {
            let resp = SuccessResponse {
                success: true,
                message: "配置已更新".to_string(),
                data: None::<()>,
            };
            Json(resp).into_response()
        }
        Err(e) => {
            let err = ErrorResponse {
                success: false,
                message: e.to_string(),
            };
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Json(err),
            )
                .into_response()
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

// 辅助函数：确保时间戳是毫秒格式
// 如果值小于 10000000000 (10位数)，认为是秒时间戳，需要转换为毫秒
fn ensure_millis(timestamp: Option<i64>) -> Option<i64> {
    timestamp.map(|ts| if ts < 10000000000 { ts * 1000 } else { ts })
}

// 输出结构体（符合用户给定格式，字段为小驼峰，并补充 modelType 等）
#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct OutNetworkAttack {
    #[serde(rename = "modelType")]
    pub model_type: &'static str,
    #[serde(rename = "alarmId")]
    pub alarm_id: Option<String>,
    #[serde(rename = "alarmDate")]
    pub alarm_date: Option<i64>,
    #[serde(rename = "alarmSeverity")]
    pub alarm_severity: Option<i16>,
    #[serde(rename = "alarmName")]
    pub alarm_name: Option<String>,
    #[serde(rename = "alarmDescription")]
    pub alarm_description: Option<String>,
    #[serde(rename = "alarmType")]
    pub alarm_type: i16,
    #[serde(rename = "alarmSubType")]
    pub alarm_sub_type: Option<i32>,
    #[serde(rename = "controlRuleId")]
    pub control_rule_id: Option<String>,
    #[serde(rename = "controlTaskId")]
    pub control_task_id: Option<String>,
    #[serde(rename = "procedureTechniqueId")]
    pub procedure_technique_id: Option<serde_json::Value>,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
    #[serde(rename = "ipVersion")]
    pub ip_version: Option<i16>,
    #[serde(rename = "srcIp")]
    pub src_ip: Option<String>,
    #[serde(rename = "srcPort")]
    pub src_port: Option<i32>,
    #[serde(rename = "dstIp")]
    pub dst_ip: Option<String>,
    #[serde(rename = "dstPort")]
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    #[serde(rename = "terminalId")]
    pub terminal_id: Option<String>,
    #[serde(rename = "sourceFilePath")]
    pub source_file_path: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    #[serde(rename = "signatureId")]
    pub signature_id: Option<String>,
    #[serde(rename = "attackPayload")]
    pub attack_payload: Option<String>,
    #[serde(rename = "attackStage")]
    pub attack_stage: Option<String>,
    #[serde(rename = "attackIp")]
    pub attack_ip: Option<String>,
    #[serde(rename = "attackedIp")]
    pub attacked_ip: Option<String>,
    #[serde(rename = "aptGroup")]
    pub apt_group: Option<String>,
    #[serde(rename = "vulType")]
    pub vul_type: Option<String>,
    #[serde(rename = "cveId")]
    pub cve_id: Option<String>,
    #[serde(rename = "vulDesc")]
    pub vul_desc: Option<String>,
}

fn to_payload_na(r: &crate::db::ConvergedNetworkAttackRecord) -> OutNetworkAttack {
    OutNetworkAttack {
        model_type: "ALM_STR_NA",
        alarm_id: r.alarm_id.clone(),
        alarm_date: ensure_millis(r.alarm_date),
        alarm_severity: r.alarm_severity,
        alarm_name: r.alarm_name.clone(),
        alarm_description: r.alarm_description.clone(),
        alarm_type: 1,
        alarm_sub_type: Some(r.alarm_subtype),
        control_rule_id: r.control_rule_id.clone(),
        control_task_id: r.control_task_id.clone(),
        procedure_technique_id: r.procedure_technique_id.clone(),
        session_id: r.session_id.clone(),
        ip_version: r.ip_version,
        src_ip: r.src_ip.clone(),
        src_port: r.src_port,
        dst_ip: r.dst_ip.clone(),
        dst_port: r.dst_port,
        protocol: r.protocol.clone(),
        terminal_id: r.terminal_id.clone(),
        source_file_path: r.source_file_path.clone(),
        created_at: r.created_at.timestamp_millis(),
        updated_at: Utc::now().timestamp_millis(),
        signature_id: r.signature_id.clone(),
        attack_payload: r.attack_payload.clone(),
        attack_stage: r.attack_stage.clone(),
        attack_ip: r.attack_ip.clone(),
        attacked_ip: r.attacked_ip.clone(),
        apt_group: r.apt_group.clone(),
        vul_type: r.vul_type.clone(),
        cve_id: r.cve_id.clone(),
        vul_desc: r.vul_desc.clone(),
    }
}

#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct OutMaliciousSample {
    #[serde(rename = "modelType")]
    pub model_type: &'static str,
    #[serde(rename = "alarmDate")]
    pub alarm_date: Option<i64>,
    #[serde(rename = "alarmDescription")]
    pub alarm_description: Option<String>,
    #[serde(rename = "alarmId")]
    pub alarm_id: Option<String>,
    #[serde(rename = "alarmName")]
    pub alarm_name: Option<String>,
    #[serde(rename = "alarmSeverity")]
    pub alarm_severity: Option<i16>,
    #[serde(rename = "alarmType")]
    pub alarm_type: i16,
    #[serde(rename = "alarmSubType")]
    pub alarm_sub_type: Option<i32>,
    #[serde(rename = "controlRuleId")]
    pub control_rule_id: Option<String>,
    #[serde(rename = "controlTaskId")]
    pub control_task_id: Option<String>,
    #[serde(rename = "procedureTechniqueId")]
    pub procedure_technique_id: Option<serde_json::Value>,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "dstIp")]
    pub dst_ip: Option<String>,
    #[serde(rename = "dstPort")]
    pub dst_port: Option<i32>,
    #[serde(rename = "fileSize")]
    pub file_size: Option<i64>,
    #[serde(rename = "fileType")]
    pub file_type: Option<String>,
    #[serde(rename = "ipVersion")]
    pub ip_version: Option<i16>,
    pub md5: Option<String>,
    #[serde(rename = "sampleFamily")]
    pub sample_family: Option<String>,
    #[serde(rename = "sampleOriginalName")]
    pub sample_original_name: Option<String>,
    #[serde(rename = "sampleSource")]
    pub sample_source: Option<i16>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    #[serde(rename = "srcIp")]
    pub src_ip: Option<String>,
    #[serde(rename = "srcPort")]
    pub src_port: Option<i32>,
    pub ssdeep: Option<String>,
    #[serde(rename = "terminalId")]
    pub terminal_id: Option<String>,
    #[serde(rename = "aptGroup")]
    pub apt_group: Option<String>,
    #[serde(rename = "sampleDescription")]
    pub sample_description: Option<String>,
    #[serde(rename = "sampleAlarmEngine")]
    pub sample_alarm_engine: Option<serde_json::Value>,
    #[serde(rename = "targetPlatform")]
    pub target_platform: Option<String>,
    pub language: Option<String>,
    pub rule: Option<String>,
    #[serde(rename = "targetContent")]
    pub target_content: Option<String>,
    #[serde(rename = "compileDate")]
    pub compile_date: Option<i64>,
    #[serde(rename = "lastAnalyDate")]
    pub last_analy_date: Option<i64>,
    #[serde(rename = "sampleAlarmDetail")]
    pub sample_alarm_detail: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
}

fn to_payload_ms(r: &crate::db::ConvergedMaliciousSampleRecord) -> OutMaliciousSample {
    OutMaliciousSample {
        model_type: "ALM_STR_MS",
        alarm_date: ensure_millis(r.alarm_date),
        alarm_description: r.alarm_description.clone(),
        alarm_id: r.alarm_id.clone(),
        alarm_name: r.alarm_name.clone(),
        alarm_severity: r.alarm_severity,
        alarm_type: 2,
        alarm_sub_type: Some(r.alarm_subtype),
        control_rule_id: r.control_rule_id.clone(),
        control_task_id: r.control_task_id.clone(),
        procedure_technique_id: r.procedure_technique_id.clone(),
        session_id: r.session_id.clone(),
        created_at: r.created_at.timestamp_millis(),
        dst_ip: r.dst_ip.clone(),
        dst_port: r.dst_port,
        file_size: r.file_size,
        file_type: r.file_type.clone(),
        ip_version: r.ip_version,
        md5: r.md5.clone(),
        sample_family: r.sample_family.clone(),
        sample_original_name: r.sample_original_name.clone(),
        sample_source: r.sample_source,
        sha1: r.sha1.clone(),
        sha256: r.sha256.clone(),
        src_ip: r.src_ip.clone(),
        src_port: r.src_port,
        ssdeep: r.ssdeep.clone(),
        terminal_id: r.terminal_id.clone(),
        apt_group: r.apt_group.clone(),
        sample_description: r.sample_description.clone(),
        sample_alarm_engine: r.sample_alarm_engine.clone(),
        target_platform: r.target_platform.clone(),
        language: r.language.clone(),
        rule: r.rule.clone(),
        target_content: r.target_content.clone(),
        compile_date: ensure_millis(r.compile_date),
        last_analy_date: ensure_millis(r.last_analy_date),
        sample_alarm_detail: r.sample_alarm_detail.clone(),
        updated_at: Utc::now().timestamp_millis(),
    }
}

#[derive(Serialize)]
#[allow(non_snake_case)]
pub struct OutHostBehavior {
    #[serde(rename = "modelType")]
    pub model_type: &'static str,
    #[serde(rename = "alarmDate")]
    pub alarm_date: Option<i64>,
    #[serde(rename = "alarmDescription")]
    pub alarm_description: Option<String>,
    #[serde(rename = "alarmId")]
    pub alarm_id: Option<String>,
    #[serde(rename = "alarmName")]
    pub alarm_name: Option<String>,
    #[serde(rename = "alarmSeverity")]
    pub alarm_severity: Option<i16>,
    #[serde(rename = "alarmType")]
    pub alarm_type: i16,
    #[serde(rename = "alarmSubType")]
    pub alarm_sub_type: Option<i32>,
    #[serde(rename = "controlRuleId")]
    pub control_rule_id: Option<String>,
    #[serde(rename = "controlTaskId")]
    pub control_task_id: Option<String>,
    #[serde(rename = "procedureTechniqueId")]
    pub procedure_technique_id: Option<serde_json::Value>,
    #[serde(rename = "sessionId")]
    pub session_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    #[serde(rename = "dstIp")]
    pub dst_ip: Option<String>,
    #[serde(rename = "dstPort")]
    pub dst_port: Option<i32>,
    #[serde(rename = "dstProcessMd5")]
    pub dst_process_md5: Option<String>,
    #[serde(rename = "fileMd5")]
    pub file_md5: Option<String>,
    #[serde(rename = "fileName")]
    pub file_name: Option<String>,
    #[serde(rename = "filePath")]
    pub file_path: Option<String>,
    #[serde(rename = "hostName")]
    pub host_name: Option<String>,
    #[serde(rename = "ipVersion")]
    pub ip_version: Option<i16>,
    #[serde(rename = "srcIp")]
    pub src_ip: Option<String>,
    #[serde(rename = "srcPort")]
    pub src_port: Option<i32>,
    #[serde(rename = "terminalIp")]
    pub terminal_ip: Option<String>,
    #[serde(rename = "terminalOs")]
    pub terminal_os: Option<String>,
    #[serde(rename = "dstProcessPath")]
    pub dst_process_path: Option<String>,
    #[serde(rename = "dstProcessCli")]
    pub dst_process_cli: Option<String>,
    #[serde(rename = "srcProcessMd5")]
    pub src_process_md5: Option<String>,
    #[serde(rename = "srcProcessPath")]
    pub src_process_path: Option<String>,
    #[serde(rename = "srcProcessCli")]
    pub src_process_cli: Option<String>,
    #[serde(rename = "registerKeyName")]
    pub register_key_name: Option<String>,
    #[serde(rename = "registerKeyValue")]
    pub register_key_value: Option<String>,
    #[serde(rename = "registerPath")]
    pub register_path: Option<String>,
    #[serde(rename = "updatedAt")]
    pub updated_at: i64,
    #[serde(rename = "userAccount")]
    pub user_account: Option<String>,
}

fn to_payload_hb(r: &crate::db::ConvergedHostBehaviorRecord) -> OutHostBehavior {
    OutHostBehavior {
        model_type: "ALM_CLU_ACT",
        alarm_date: ensure_millis(r.alarm_date),
        alarm_description: r.alarm_description.clone(),
        alarm_id: r.alarm_id.clone(),
        alarm_name: r.alarm_name.clone(),
        alarm_severity: r.alarm_severity,
        alarm_type: 3,
        alarm_sub_type: Some(r.alarm_subtype),
        control_rule_id: r.control_rule_id.clone(),
        control_task_id: r.control_task_id.clone(),
        procedure_technique_id: r.procedure_technique_id.clone(),
        session_id: r.session_id.clone(),
        created_at: r.created_at.timestamp_millis(),
        dst_ip: r.dst_ip.clone(),
        dst_port: r.dst_port,
        dst_process_md5: r.dst_process_md5.clone(),
        file_md5: r.file_md5.clone(),
        file_name: r.file_name.clone(),
        file_path: r.file_path.clone(),
        host_name: r.host_name.clone(),
        ip_version: r.ip_version,
        src_ip: r.src_ip.clone(),
        src_port: r.src_port,
        terminal_ip: r.terminal_ip.clone(),
        terminal_os: r.terminal_os.clone(),
        dst_process_path: r.dst_process_path.clone(),
        dst_process_cli: r.dst_process_cli.clone(),
        src_process_md5: r.src_process_md5.clone(),
        src_process_path: r.src_process_path.clone(),
        src_process_cli: r.src_process_cli.clone(),
        register_key_name: r.register_key_name.clone(),
        register_key_value: r.register_key_value.clone(),
        register_path: r.register_path.clone(),
        updated_at: Utc::now().timestamp_millis(),
        user_account: r.user_account.clone(),
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
        }
        .to_string();

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
    let page = params
        .get("page")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1);
    let page_size = params
        .get("page_size")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(20);
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
            let err = ErrorResponse {
                success: false,
                message: e.to_string(),
            };
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                axum::response::Json(err),
            )
                .into_response()
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
                                tracing::info!(
                                    target = "auto_push",
                                    "Auto published for config '{}': sent={}",
                                    config.name,
                                    count
                                );
                            } else {
                                tracing::debug!(target = "auto_push", "Auto publish for config '{}' completed, no new alerts to push.", config.name);
                            }
                        }
                        Err(e) => {
                            tracing::error!(
                                target = "auto_push",
                                "Auto publish failed for config '{}': {}",
                                config.name,
                                e
                            );
                        }
                    }
                    // 使用配置的间隔时间
                    let sleep_duration =
                        std::time::Duration::from_secs(config.interval_seconds as u64);
                    tracing::debug!(
                        target = "auto_push",
                        "Sleeping for {} seconds.",
                        sleep_duration.as_secs()
                    );
                    tokio::time::sleep(sleep_duration).await;
                } else {
                    tracing::info!(
                        target = "auto_push",
                        "Auto publishing is disabled. Checking again in 60 seconds."
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                }
            }
            Err(e) => {
                tracing::error!(
                    target = "auto_push",
                    "Failed to load push config: {}. Retrying in 60 seconds.",
                    e
                );
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        }
    }
}
