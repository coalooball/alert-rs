use axum::{extract::Json, response::Json as JsonResponse};
use crate::dsl::{parse_converge_rule, parse_correlate_rule, validate_fields, validator};
use crate::dsl::types::{CompileRequest, CompileResponse};

/// 编译收敛规则
pub async fn compile_converge_rule(
    Json(payload): Json<CompileRequest>,
) -> JsonResponse<CompileResponse> {
    match parse_converge_rule(&payload.dsl_rule) {
        Ok(rule) => {
            // 验证字段
            match validate_fields(&rule) {
                Ok(_) => {
                    JsonResponse(CompileResponse::success(
                        format!(
                            "DSL 规则语法正确，可以正常使用。已验证规则结构、字段名称和操作符。\n\
                            - 条件子句: {} 个\n\
                            - 分组字段: {} 个\n\
                            - 时间窗口: {} {:?}\n\
                            - 收敛阈值: {}",
                            rule.condition.clauses.len(),
                            rule.group_by.len(),
                            rule.window.value,
                            rule.window.unit,
                            rule.threshold
                        )
                    ))
                }
                Err(e) => {
                    JsonResponse(CompileResponse::error(
                        format!("字段验证失败: {}", e)
                    ))
                }
            }
        }
        Err(e) => {
            JsonResponse(CompileResponse::error(
                format!("语法解析失败: {}", e)
            ))
        }
    }
}

/// 编译关联规则
pub async fn compile_correlate_rule(
    Json(payload): Json<CompileRequest>,
) -> JsonResponse<CompileResponse> {
    match parse_correlate_rule(&payload.dsl_rule) {
        Ok(rule) => {
            // 验证字段
            match validator::validate_correlate_fields(&rule) {
                Ok(_) => {
                    JsonResponse(CompileResponse::success(
                        format!(
                            "DSL 规则语法正确，可以正常使用。已验证规则结构、事件定义、关联条件和字段名称。\n\
                            - 关联事件: {} 个\n\
                            - 关联条件: {} 个\n\
                            - 时间窗口: {} {:?}\n\
                            - 生成威胁等级: {}\n\
                            - 告警名称: {}",
                            rule.events.len(),
                            rule.join_on.clauses.len(),
                            rule.window.value,
                            rule.window.unit,
                            rule.generate.severity,
                            rule.generate.name
                        )
                    ))
                }
                Err(e) => {
                    JsonResponse(CompileResponse::error(
                        format!("字段验证失败: {}", e)
                    ))
                }
            }
        }
        Err(e) => {
            JsonResponse(CompileResponse::error(
                format!("语法解析失败: {}", e)
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_compile_converge_rule() {
        let request = CompileRequest {
            dsl_rule: r#"CONVERGE
                WHERE alarm_severity >= 3
                GROUP BY src_ip, alarm_type
                WINDOW 5m
                THRESHOLD 10"#.to_string(),
        };

        let response = compile_converge_rule(Json(request)).await;
        assert!(response.0.success);
    }

    #[tokio::test]
    async fn test_compile_correlate_rule() {
        let request = CompileRequest {
            dsl_rule: r#"CORRELATE
                EVENT attack WHERE alarm_type == 1
                EVENT behavior WHERE alarm_type == 2
                JOIN ON attack.dst_ip == behavior.terminal_ip
                WINDOW 10m
                GENERATE
                    SEVERITY 3
                    NAME "攻击链检测"
                    DESCRIPTION "检测到攻击链活动""#.to_string(),
        };

        let response = compile_correlate_rule(Json(request)).await;
        if !response.0.success {
            eprintln!("Error: {:?}", response.0.error);
        }
        assert!(response.0.success);
    }

    #[tokio::test]
    async fn test_compile_converge_rule_with_invalid_field() {
        let request = CompileRequest {
            dsl_rule: r#"CONVERGE
                WHERE invalid_field_name >= 3
                GROUP BY src_ip
                WINDOW 5m
                THRESHOLD 10"#.to_string(),
        };

        let response = compile_converge_rule(Json(request)).await;
        assert!(!response.0.success);
        assert!(response.0.error.is_some());
        assert!(response.0.error.as_ref().unwrap().contains("invalid_field_name"));
    }

    #[tokio::test]
    async fn test_compile_converge_rule_with_syntax_error() {
        let request = CompileRequest {
            dsl_rule: r#"CONVERGE
                WHERE alarm_severity >= 3
                GROUP BY
                WINDOW 5m
                THRESHOLD 10"#.to_string(),
        };

        let response = compile_converge_rule(Json(request)).await;
        assert!(!response.0.success);
        assert!(response.0.error.is_some());
    }

    #[tokio::test]
    async fn test_compile_correlate_rule_with_invalid_event_alias() {
        let request = CompileRequest {
            dsl_rule: r#"CORRELATE
                EVENT attack WHERE alarm_type == 1
                EVENT behavior WHERE alarm_type == 2
                JOIN ON attack.dst_ip == unknown_event.terminal_ip
                WINDOW 10m
                GENERATE
                    SEVERITY 3
                    NAME "测试"
                    DESCRIPTION "测试""#.to_string(),
        };

        let response = compile_correlate_rule(Json(request)).await;
        assert!(!response.0.success);
        assert!(response.0.error.is_some());
        assert!(response.0.error.as_ref().unwrap().contains("unknown_event"));
    }
}

