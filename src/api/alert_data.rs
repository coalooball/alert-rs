use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::{self, ThreatEventInput};
use crate::AppState;
use super::PageResponse;

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

/// 获取网络攻击告警
pub async fn get_network_attacks(
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

/// 获取恶意样本告警
pub async fn get_malicious_samples(
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

/// 获取主机行为告警
pub async fn get_host_behaviors(
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
    match db::threat_event::query_threat_events(&state.pool, params.page, params.page_size).await
    {
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

