use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::{convergence_rules, correlation_rules, filter_rules, tag_rules};
use crate::AppState;

/// 分页查询参数
#[derive(Debug, Deserialize)]
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
    10
}

/// 通用响应结构
#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

/// 分页响应数据
#[derive(Debug, Serialize)]
pub struct PageData<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

// ==================== 收敛规则 API ====================

/// 查询收敛规则列表
pub async fn get_convergence_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApiResponse<PageData<convergence_rules::ConvergenceRuleRecord>>>, StatusCode> {
    match convergence_rules::query_convergence_rules(&state.pool, query.page, query.page_size).await
    {
        Ok((items, total)) => Ok(Json(ApiResponse {
            success: true,
            data: Some(PageData {
                items,
                total,
                page: query.page,
                page_size: query.page_size,
            }),
            error: None,
        })),
        Err(e) => {
            eprintln!("查询收敛规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 根据ID获取收敛规则
pub async fn get_convergence_rule_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<convergence_rules::ConvergenceRuleRecord>>, StatusCode> {
    match convergence_rules::get_convergence_rule_by_id(&state.pool, id).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// 创建收敛规则
pub async fn create_convergence_rule(
    State(state): State<Arc<AppState>>,
    Json(input): Json<convergence_rules::ConvergenceRuleInput>,
) -> Result<Json<ApiResponse<convergence_rules::ConvergenceRuleRecord>>, StatusCode> {
    match convergence_rules::create_convergence_rule(&state.pool, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("创建收敛规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 更新收敛规则
pub async fn update_convergence_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(input): Json<convergence_rules::ConvergenceRuleInput>,
) -> Result<Json<ApiResponse<convergence_rules::ConvergenceRuleRecord>>, StatusCode> {
    match convergence_rules::update_convergence_rule(&state.pool, id, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("更新收敛规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 删除收敛规则
pub async fn delete_convergence_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    match convergence_rules::delete_convergence_rule(&state.pool, id).await {
        Ok(_) => Ok(Json(ApiResponse {
            success: true,
            data: Some(()),
            error: None,
        })),
        Err(e) => {
            eprintln!("删除收敛规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ==================== 关联规则 API ====================

/// 查询关联规则列表
pub async fn get_correlation_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApiResponse<PageData<correlation_rules::CorrelationRuleRecord>>>, StatusCode> {
    match correlation_rules::query_correlation_rules(&state.pool, query.page, query.page_size).await
    {
        Ok((items, total)) => Ok(Json(ApiResponse {
            success: true,
            data: Some(PageData {
                items,
                total,
                page: query.page,
                page_size: query.page_size,
            }),
            error: None,
        })),
        Err(e) => {
            eprintln!("查询关联规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 根据ID获取关联规则
pub async fn get_correlation_rule_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<correlation_rules::CorrelationRuleRecord>>, StatusCode> {
    match correlation_rules::get_correlation_rule_by_id(&state.pool, id).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// 创建关联规则
pub async fn create_correlation_rule(
    State(state): State<Arc<AppState>>,
    Json(input): Json<correlation_rules::CorrelationRuleInput>,
) -> Result<Json<ApiResponse<correlation_rules::CorrelationRuleRecord>>, StatusCode> {
    match correlation_rules::create_correlation_rule(&state.pool, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("创建关联规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 更新关联规则
pub async fn update_correlation_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(input): Json<correlation_rules::CorrelationRuleInput>,
) -> Result<Json<ApiResponse<correlation_rules::CorrelationRuleRecord>>, StatusCode> {
    match correlation_rules::update_correlation_rule(&state.pool, id, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("更新关联规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 删除关联规则
pub async fn delete_correlation_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    match correlation_rules::delete_correlation_rule(&state.pool, id).await {
        Ok(_) => Ok(Json(ApiResponse {
            success: true,
            data: Some(()),
            error: None,
        })),
        Err(e) => {
            eprintln!("删除关联规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ==================== 过滤规则 API ====================

/// 查询过滤规则列表
pub async fn get_filter_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApiResponse<PageData<filter_rules::FilterRuleRecord>>>, StatusCode> {
    match filter_rules::query_filter_rules(&state.pool, query.page, query.page_size).await {
        Ok((items, total)) => Ok(Json(ApiResponse {
            success: true,
            data: Some(PageData {
                items,
                total,
                page: query.page,
                page_size: query.page_size,
            }),
            error: None,
        })),
        Err(e) => {
            eprintln!("查询过滤规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 根据ID获取过滤规则
pub async fn get_filter_rule_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<filter_rules::FilterRuleRecord>>, StatusCode> {
    match filter_rules::get_filter_rule_by_id(&state.pool, id).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// 创建过滤规则
pub async fn create_filter_rule(
    State(state): State<Arc<AppState>>,
    Json(input): Json<filter_rules::FilterRuleInput>,
) -> Result<Json<ApiResponse<filter_rules::FilterRuleRecord>>, StatusCode> {
    match filter_rules::create_filter_rule(&state.pool, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("创建过滤规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 更新过滤规则
pub async fn update_filter_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(input): Json<filter_rules::FilterRuleInput>,
) -> Result<Json<ApiResponse<filter_rules::FilterRuleRecord>>, StatusCode> {
    match filter_rules::update_filter_rule(&state.pool, id, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("更新过滤规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 删除过滤规则
pub async fn delete_filter_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    match filter_rules::delete_filter_rule(&state.pool, id).await {
        Ok(_) => Ok(Json(ApiResponse {
            success: true,
            data: Some(()),
            error: None,
        })),
        Err(e) => {
            eprintln!("删除过滤规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// ==================== 标签规则 API ====================

/// 查询标签规则列表
pub async fn get_tag_rules(
    State(state): State<Arc<AppState>>,
    Query(query): Query<PageQuery>,
) -> Result<Json<ApiResponse<PageData<tag_rules::TagRuleRecord>>>, StatusCode> {
    match tag_rules::query_tag_rules(&state.pool, query.page, query.page_size).await {
        Ok((items, total)) => Ok(Json(ApiResponse {
            success: true,
            data: Some(PageData {
                items,
                total,
                page: query.page,
                page_size: query.page_size,
            }),
            error: None,
        })),
        Err(e) => {
            eprintln!("查询标签规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 根据ID获取标签规则
pub async fn get_tag_rule_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<tag_rules::TagRuleRecord>>, StatusCode> {
    match tag_rules::get_tag_rule_by_id(&state.pool, id).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

/// 创建标签规则
pub async fn create_tag_rule(
    State(state): State<Arc<AppState>>,
    Json(input): Json<tag_rules::TagRuleInput>,
) -> Result<Json<ApiResponse<tag_rules::TagRuleRecord>>, StatusCode> {
    match tag_rules::create_tag_rule(&state.pool, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("创建标签规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 更新标签规则
pub async fn update_tag_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(input): Json<tag_rules::TagRuleInput>,
) -> Result<Json<ApiResponse<tag_rules::TagRuleRecord>>, StatusCode> {
    match tag_rules::update_tag_rule(&state.pool, id, &input).await {
        Ok(rule) => Ok(Json(ApiResponse {
            success: true,
            data: Some(rule),
            error: None,
        })),
        Err(e) => {
            eprintln!("更新标签规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 删除标签规则
pub async fn delete_tag_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, StatusCode> {
    match tag_rules::delete_tag_rule(&state.pool, id).await {
        Ok(_) => Ok(Json(ApiResponse {
            success: true,
            data: Some(()),
            error: None,
        })),
        Err(e) => {
            eprintln!("删除标签规则失败: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

