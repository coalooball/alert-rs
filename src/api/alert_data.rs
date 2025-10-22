use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use super::PageResponse;
use crate::db::{self, ThreatEventInput};
use crate::AppState;

// 为前端响应创建新的结构体，添加 alarm_subtype_name 字段
#[derive(Serialize)]
pub struct NetworkAttackResp {
    #[serde(flatten)]
    pub inner: db::ConvergedNetworkAttackRecord,
    pub alarm_subtype_name: String,
}

#[derive(Serialize)]
pub struct MaliciousSampleResp {
    #[serde(flatten)]
    pub inner: db::ConvergedMaliciousSampleRecord,
    pub alarm_subtype_name: String,
}

#[derive(Serialize)]
pub struct HostBehaviorResp {
    #[serde(flatten)]
    pub inner: db::ConvergedHostBehaviorRecord,
    pub alarm_subtype_name: String,
}

/// 查询参数
#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
}

fn default_page() -> u64 {
    1
}

fn default_page_size() -> u64 {
    20
}

/// 获取网络攻击告警（收敛后）
pub async fn get_network_attacks(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<NetworkAttackResp>> {
    match db::query_converged_network_attacks(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => {
            let data_with_subtype_name: Vec<NetworkAttackResp> = data
                .into_iter()
                .map(|r| {
                    let subtype_name = state
                        .alarm_types
                        .network_attack
                        .subtypes
                        .get(&r.alarm_subtype.to_string())
                        .cloned()
                        .unwrap_or_else(|| "未知".to_string());
                    NetworkAttackResp {
                        inner: r,
                        alarm_subtype_name: subtype_name,
                    }
                })
                .collect();

            Json(PageResponse {
                data: data_with_subtype_name,
                total,
                page: params.page,
                page_size: params.page_size,
            })
        }
        Err(e) => {
            tracing::error!("Query converged network attacks failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

/// 获取恶意样本告警（收敛后）
pub async fn get_malicious_samples(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<MaliciousSampleResp>> {
    match db::query_converged_malicious_samples(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => {
            let data_with_subtype_name: Vec<MaliciousSampleResp> = data
                .into_iter()
                .map(|r| {
                    let subtype_name = state
                        .alarm_types
                        .malicious_sample
                        .subtypes
                        .get(&r.alarm_subtype.to_string())
                        .cloned()
                        .unwrap_or_else(|| "未知".to_string());
                    MaliciousSampleResp {
                        inner: r,
                        alarm_subtype_name: subtype_name,
                    }
                })
                .collect();

            Json(PageResponse {
                data: data_with_subtype_name,
                total,
                page: params.page,
                page_size: params.page_size,
            })
        }
        Err(e) => {
            tracing::error!("Query converged malicious samples failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

/// 获取主机行为告警（收敛后）
pub async fn get_host_behaviors(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<HostBehaviorResp>> {
    match db::query_converged_host_behaviors(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => {
            let data_with_subtype_name: Vec<HostBehaviorResp> = data
                .into_iter()
                .map(|r| {
                    let subtype_name = state
                        .alarm_types
                        .host_behavior
                        .subtypes
                        .get(&r.alarm_subtype.to_string())
                        .cloned()
                        .unwrap_or_else(|| "未知".to_string());
                    HostBehaviorResp {
                        inner: r,
                        alarm_subtype_name: subtype_name,
                    }
                })
                .collect();

            Json(PageResponse {
                data: data_with_subtype_name,
                total,
                page: params.page,
                page_size: params.page_size,
            })
        }
        Err(e) => {
            tracing::error!("Query converged host behaviors failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

/// 获取无效告警
pub async fn get_invalid_alerts(
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

/// 获取威胁事件
pub async fn get_threat_events(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PageQuery>,
) -> Json<PageResponse<db::ThreatEventRecord>> {
    match db::threat_event::query_threat_events(&state.pool, params.page, params.page_size).await {
        Ok((data, total)) => Json(PageResponse {
            data,
            total,
            page: params.page,
            page_size: params.page_size,
        }),
        Err(e) => {
            tracing::error!("Query threat events failed: {}", e);
            Json(PageResponse {
                data: vec![],
                total: 0,
                page: params.page,
                page_size: params.page_size,
            })
        }
    }
}

/// 更新威胁事件
pub async fn update_threat_event(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(event): Json<ThreatEventInput>,
) -> impl IntoResponse {
    match db::threat_event::update_threat_event(&state.pool, id, &event).await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "message": "威胁事件更新成功"
            })),
        ),
        Err(e) => {
            tracing::error!("Update threat event failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "message": format!("更新失败: {}", e)
                })),
            )
        }
    }
}

/// 根据收敛告警ID查询网络攻击原始告警列表
pub async fn get_raw_network_attacks_by_converged_id(
    State(state): State<Arc<AppState>>,
    Path(converged_id): Path<Uuid>,
) -> Json<Vec<db::NetworkAttackRecord>> {
    match db::query_raw_network_attacks_by_converged_id(&state.pool, converged_id).await {
        Ok(alerts) => Json(alerts),
        Err(e) => {
            tracing::error!("Query raw network attacks by converged id failed: {}", e);
            Json(vec![])
        }
    }
}

/// 根据收敛告警ID查询恶意样本原始告警列表
pub async fn get_raw_malicious_samples_by_converged_id(
    State(state): State<Arc<AppState>>,
    Path(converged_id): Path<Uuid>,
) -> Json<Vec<db::MaliciousSampleRecord>> {
    match db::query_raw_malicious_samples_by_converged_id(&state.pool, converged_id).await {
        Ok(alerts) => Json(alerts),
        Err(e) => {
            tracing::error!("Query raw malicious samples by converged id failed: {}", e);
            Json(vec![])
        }
    }
}

/// 根据收敛告警ID查询主机行为原始告警列表
pub async fn get_raw_host_behaviors_by_converged_id(
    State(state): State<Arc<AppState>>,
    Path(converged_id): Path<Uuid>,
) -> Json<Vec<db::HostBehaviorRecord>> {
    match db::query_raw_host_behaviors_by_converged_id(&state.pool, converged_id).await {
        Ok(alerts) => Json(alerts),
        Err(e) => {
            tracing::error!("Query raw host behaviors by converged id failed: {}", e);
            Json(vec![])
        }
    }
}
