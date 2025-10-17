use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::db::tag_management::{self, TagInput};
use crate::AppState;
use super::{ErrorResponse, PageResponse, SuccessResponse};

/// 查询参数
#[derive(Deserialize)]
pub struct TagQueryParams {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    pub search: Option<String>,
    pub category: Option<String>,
}

fn default_page() -> u64 {
    1
}

fn default_page_size() -> u64 {
    10
}

/// 获取标签列表
pub async fn get_tags(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TagQueryParams>,
) -> impl IntoResponse {
    match tag_management::query_tags(
        &state.pool,
        params.page,
        params.page_size,
        params.search,
        params.category,
    )
    .await
    {
        Ok((data, total)) => {
            let response = PageResponse {
                data,
                total,
                page: params.page,
                page_size: params.page_size,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Query tags failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("查询标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 获取所有标签（不分页）
pub async fn get_all_tags(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match tag_management::get_all_tags(&state.pool).await {
        Ok(data) => {
            let response = SuccessResponse {
                success: true,
                message: "获取成功".to_string(),
                data: Some(data),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Get all tags failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("获取标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 根据 ID 获取单个标签
pub async fn get_tag_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match tag_management::get_tag_by_id(&state.pool, id).await {
        Ok(tag) => {
            let response = SuccessResponse {
                success: true,
                message: "获取成功".to_string(),
                data: Some(tag),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Get tag by id failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("获取标签失败: {}", e),
            };
            (StatusCode::NOT_FOUND, Json(error)).into_response()
        }
    }
}

/// 创建标签
pub async fn create_tag(
    State(state): State<Arc<AppState>>,
    Json(input): Json<TagInput>,
) -> impl IntoResponse {
    // 验证输入
    if input.name.trim().is_empty() {
        let error = ErrorResponse {
            success: false,
            message: "标签名称不能为空".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    if input.category.trim().is_empty() {
        let error = ErrorResponse {
            success: false,
            message: "标签分类不能为空".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    // 检查名称是否已存在
    match tag_management::get_tag_by_name(&state.pool, &input.name).await {
        Ok(Some(_)) => {
            let error = ErrorResponse {
                success: false,
                message: "标签名称已存在".to_string(),
            };
            return (StatusCode::CONFLICT, Json(error)).into_response();
        }
        Ok(None) => {
            // 名称不存在，可以创建
        }
        Err(e) => {
            tracing::error!("Check tag name failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("检查标签名称失败: {}", e),
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response();
        }
    }

    match tag_management::create_tag(&state.pool, &input).await {
        Ok(tag) => {
            let response = SuccessResponse {
                success: true,
                message: "创建成功".to_string(),
                data: Some(tag),
            };
            (StatusCode::CREATED, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Create tag failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("创建标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 更新标签
pub async fn update_tag(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(input): Json<TagInput>,
) -> impl IntoResponse {
    // 验证输入
    if input.name.trim().is_empty() {
        let error = ErrorResponse {
            success: false,
            message: "标签名称不能为空".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    if input.category.trim().is_empty() {
        let error = ErrorResponse {
            success: false,
            message: "标签分类不能为空".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error)).into_response();
    }

    // 检查标签是否存在
    match tag_management::get_tag_by_id(&state.pool, id).await {
        Ok(existing) => {
            // 如果更改了名称，检查新名称是否与其他标签冲突
            if existing.name != input.name {
                match tag_management::get_tag_by_name(&state.pool, &input.name).await {
                    Ok(Some(_)) => {
                        let error = ErrorResponse {
                            success: false,
                            message: "标签名称已存在".to_string(),
                        };
                        return (StatusCode::CONFLICT, Json(error)).into_response();
                    }
                    Ok(None) => {
                        // 新名称不存在，可以更新
                    }
                    Err(e) => {
                        tracing::error!("Check tag name failed: {}", e);
                        let error = ErrorResponse {
                            success: false,
                            message: format!("检查标签名称失败: {}", e),
                        };
                        return (StatusCode::INTERNAL_SERVER_ERROR, Json(error))
                            .into_response();
                    }
                }
            }
        }
        Err(_) => {
            let error = ErrorResponse {
                success: false,
                message: "标签不存在".to_string(),
            };
            return (StatusCode::NOT_FOUND, Json(error)).into_response();
        }
    }

    match tag_management::update_tag(&state.pool, id, &input).await {
        Ok(tag) => {
            let response = SuccessResponse {
                success: true,
                message: "更新成功".to_string(),
                data: Some(tag),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Update tag failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("更新标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 删除标签
pub async fn delete_tag(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // 检查标签是否存在
    match tag_management::get_tag_by_id(&state.pool, id).await {
        Ok(_) => {
            // 标签存在，可以删除
        }
        Err(_) => {
            let error = ErrorResponse {
                success: false,
                message: "标签不存在".to_string(),
            };
            return (StatusCode::NOT_FOUND, Json(error)).into_response();
        }
    }

    match tag_management::delete_tag(&state.pool, id).await {
        Ok(_) => {
            let response = SuccessResponse::<()> {
                success: true,
                message: "删除成功".to_string(),
                data: None,
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Delete tag failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("删除标签失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

