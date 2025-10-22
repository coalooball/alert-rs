use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::{ErrorResponse, SuccessResponse};
use crate::db::alert_tag_mapping::{self, AlertTagMappingInput};
use crate::AppState;

/// 添加标签到告警的请求体
#[derive(Debug, Deserialize)]
pub struct AddAlertTagRequest {
    pub tag_id: Uuid,
}

/// 批量添加标签到告警的请求体
#[derive(Debug, Deserialize)]
pub struct BatchAddAlertTagsRequest {
    pub tag_ids: Vec<Uuid>,
}

/// 获取告警的所有标签
pub async fn get_alert_tags(
    State(state): State<Arc<AppState>>,
    Path((alert_type, alert_id)): Path<(String, Uuid)>,
) -> impl IntoResponse {
    match alert_tag_mapping::get_alert_tags(&state.pool, alert_id, &alert_type).await {
        Ok(tags) => {
            let response = SuccessResponse {
                success: true,
                message: "获取成功".to_string(),
                data: Some(tags),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Get alert tags failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("获取告警标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 给告警添加标签
pub async fn add_alert_tag(
    State(state): State<Arc<AppState>>,
    Path((alert_type, alert_id)): Path<(String, Uuid)>,
    Json(req): Json<AddAlertTagRequest>,
) -> impl IntoResponse {
    let input = AlertTagMappingInput {
        alert_id,
        alert_type: alert_type.clone(),
        tag_id: req.tag_id,
    };

    match alert_tag_mapping::add_alert_tag(&state.pool, &input).await {
        Ok(mapping) => {
            let response = SuccessResponse {
                success: true,
                message: "添加成功".to_string(),
                data: Some(mapping),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Add alert tag failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("添加标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 批量给告警添加标签
pub async fn batch_add_alert_tags(
    State(state): State<Arc<AppState>>,
    Path((alert_type, alert_id)): Path<(String, Uuid)>,
    Json(req): Json<BatchAddAlertTagsRequest>,
) -> impl IntoResponse {
    match alert_tag_mapping::add_alert_tags_batch(&state.pool, alert_id, &alert_type, &req.tag_ids)
        .await
    {
        Ok(mappings) => {
            let response = SuccessResponse {
                success: true,
                message: format!("成功添加 {} 个标签", mappings.len()),
                data: Some(mappings),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Batch add alert tags failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("批量添加标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 从告警中移除标签
pub async fn remove_alert_tag(
    State(state): State<Arc<AppState>>,
    Path((alert_type, alert_id, tag_id)): Path<(String, Uuid, Uuid)>,
) -> impl IntoResponse {
    match alert_tag_mapping::remove_alert_tag(&state.pool, alert_id, &alert_type, tag_id).await {
        Ok(_) => {
            let response = SuccessResponse::<()> {
                success: true,
                message: "移除成功".to_string(),
                data: None,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Remove alert tag failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("移除标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 移除告警的所有标签
pub async fn remove_all_alert_tags(
    State(state): State<Arc<AppState>>,
    Path((alert_type, alert_id)): Path<(String, Uuid)>,
) -> impl IntoResponse {
    match alert_tag_mapping::remove_all_alert_tags(&state.pool, alert_id, &alert_type).await {
        Ok(_) => {
            let response = SuccessResponse::<()> {
                success: true,
                message: "移除成功".to_string(),
                data: None,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Remove all alert tags failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("移除所有标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 获取某个标签关联的所有告警
pub async fn get_alerts_by_tag(
    State(state): State<Arc<AppState>>,
    Path(tag_id): Path<Uuid>,
) -> impl IntoResponse {
    match alert_tag_mapping::get_alerts_by_tag(&state.pool, tag_id).await {
        Ok(mappings) => {
            let response = SuccessResponse {
                success: true,
                message: "获取成功".to_string(),
                data: Some(mappings),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Get alerts by tag failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("获取标签关联告警失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}
