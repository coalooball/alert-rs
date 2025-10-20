pub mod tag_management;
pub mod alert_data;
pub mod alert_fields;
pub mod dsl_compile;
pub mod rules;
pub mod auto_publish;

use serde::Serialize;

/// 通用分页响应结构
#[derive(Serialize)]
pub struct PageResponse<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub page_size: u64,
}

/// 通用成功响应
#[derive(Serialize)]
pub struct SuccessResponse<T> {
    pub success: bool,
    pub message: String,
    pub data: Option<T>,
}

/// 通用错误响应
#[derive(Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub message: String,
}

