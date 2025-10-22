use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use super::{ErrorResponse, SuccessResponse};
use crate::AppState;

/// 字段定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldDefinition {
    pub name: String,
    pub field_type: String,
    pub optional: bool,
    pub description: String,
}

/// 告警类型字段集合
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertTypeFields {
    pub alert_type: String,
    pub display_name: String,
    pub fields: Vec<FieldDefinition>,
}

/// 获取所有告警字段定义
pub async fn get_alert_fields(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    match load_alert_fields() {
        Ok(fields) => {
            let response = SuccessResponse {
                success: true,
                message: "获取成功".to_string(),
                data: Some(fields),
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            tracing::error!("Load alert fields failed: {}", e);
            let error = ErrorResponse {
                success: false,
                message: format!("加载字段定义失败: {}", e),
            };
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error)).into_response()
        }
    }
}

/// 从 alert_fields.toml 加载字段定义
fn load_alert_fields() -> Result<Vec<AlertTypeFields>, Box<dyn std::error::Error>> {
    let toml_content = std::fs::read_to_string("alert_fields.toml")?;
    let parsed: toml::Value = toml::from_str(&toml_content)?;

    let mut result = Vec::new();

    // 解析主机行为告警
    if let Some(host_behavior) = parsed.get("host_behavior_alert") {
        result.push(parse_alert_type_fields(
            "host_behavior_alert",
            "主机行为告警",
            host_behavior,
        )?);
    }

    // 解析恶意样本告警
    if let Some(malicious_sample) = parsed.get("malicious_sample_alert") {
        result.push(parse_alert_type_fields(
            "malicious_sample_alert",
            "恶意样本告警",
            malicious_sample,
        )?);
    }

    // 解析网络攻击告警
    if let Some(network_attack) = parsed.get("network_attack_alert") {
        result.push(parse_alert_type_fields(
            "network_attack_alert",
            "网络攻击告警",
            network_attack,
        )?);
    }

    Ok(result)
}

/// 解析单个告警类型的字段定义
fn parse_alert_type_fields(
    alert_type: &str,
    display_name: &str,
    value: &toml::Value,
) -> Result<AlertTypeFields, Box<dyn std::error::Error>> {
    let mut fields = Vec::new();

    if let Some(table) = value.as_table() {
        for (field_name, field_value) in table {
            if let Some(field_table) = field_value.as_table() {
                let field_type = field_table
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("String")
                    .to_string();

                let optional = field_table
                    .get("optional")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);

                let description = field_table
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                fields.push(FieldDefinition {
                    name: field_name.clone(),
                    field_type,
                    optional,
                    description,
                });
            }
        }
    }

    Ok(AlertTypeFields {
        alert_type: alert_type.to_string(),
        display_name: display_name.to_string(),
        fields,
    })
}

/// 字段分组信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldGroup {
    pub group_name: String,
    pub fields: Vec<String>,
}

/// 获取常用字段分组
pub async fn get_common_field_groups(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let groups = vec![
        FieldGroup {
            group_name: "基础信息".to_string(),
            fields: vec![
                "alarm_id".to_string(),
                "alarm_date".to_string(),
                "alarm_severity".to_string(),
                "alarm_name".to_string(),
                "alarm_description".to_string(),
                "alarm_type".to_string(),
                "alarm_subtype".to_string(),
                "source".to_string(),
            ],
        },
        FieldGroup {
            group_name: "网络信息".to_string(),
            fields: vec![
                "ip_version".to_string(),
                "src_ip".to_string(),
                "src_port".to_string(),
                "dst_ip".to_string(),
                "dst_port".to_string(),
                "protocol".to_string(),
            ],
        },
        FieldGroup {
            group_name: "终端信息".to_string(),
            fields: vec![
                "terminal_id".to_string(),
                "host_name".to_string(),
                "terminal_ip".to_string(),
                "terminal_os".to_string(),
                "user_account".to_string(),
            ],
        },
        FieldGroup {
            group_name: "进程信息".to_string(),
            fields: vec![
                "src_process_path".to_string(),
                "src_process_md5".to_string(),
                "src_process_cli".to_string(),
                "dst_process_path".to_string(),
                "dst_process_md5".to_string(),
                "dst_process_cli".to_string(),
            ],
        },
        FieldGroup {
            group_name: "文件信息".to_string(),
            fields: vec![
                "file_name".to_string(),
                "file_path".to_string(),
                "file_md5".to_string(),
                "file_type".to_string(),
                "file_size".to_string(),
            ],
        },
        FieldGroup {
            group_name: "样本信息".to_string(),
            fields: vec![
                "md5".to_string(),
                "sha1".to_string(),
                "sha256".to_string(),
                "sample_family".to_string(),
                "sample_original_name".to_string(),
            ],
        },
        FieldGroup {
            group_name: "攻击信息".to_string(),
            fields: vec![
                "attack_ip".to_string(),
                "attacked_ip".to_string(),
                "attack_stage".to_string(),
                "attack_payload".to_string(),
                "apt_group".to_string(),
                "vul_type".to_string(),
                "cve_id".to_string(),
            ],
        },
    ];

    let response = SuccessResponse {
        success: true,
        message: "获取成功".to_string(),
        data: Some(groups),
    };

    (StatusCode::OK, Json(response)).into_response()
}
