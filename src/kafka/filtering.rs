use crate::db::filter_rules::FilterRuleRecord;
use regex::Regex;
use serde_json::Value;
use tracing::warn;

/// 检查告警是否应该根据提供的规则被过滤
pub fn should_filter(alert_json: &Value, alert_type_str: &str, rules: &[FilterRuleRecord]) -> bool {
    for rule in rules.iter().filter(|r| r.alert_type == alert_type_str) {
        // 如果规则定义了子类型，则必须匹配
        if !rule.alert_subtype.is_empty() {
            let subtype_matches = alert_json
                .get("alert_subtype")
                .map(|v| v.to_string().replace('\"', "")) // 统一处理为字符串
                .map_or(false, |sub| sub == rule.alert_subtype);

            if !subtype_matches {
                continue;
            }
        }

        // 检查核心过滤条件
        if check_condition(alert_json, &rule.field, &rule.operator, &rule.value) {
            // 只要有一条规则匹配，就应该过滤
            return true;
        }
    }

    // 没有任何规则匹配，则不过滤
    false
}

/// 检查告警数据是否满足单个规则的条件
fn check_condition(alert_json: &Value, field: &str, operator: &str, value: &str) -> bool {
    let alert_field = match alert_json.get(field) {
        Some(v) => v,
        None => return false,
    };

    let alert_field_str = match alert_field {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "".to_string(),
        _ => return false, // 不处理复杂类型
    };

    match operator {
        "eq" => alert_field_str == value,
        "ne" => alert_field_str != value,
        "contains" => alert_field_str.contains(value),
        "not_contains" => !alert_field_str.contains(value),
        "regex" => Regex::new(value).map_or(false, |re| re.is_match(&alert_field_str)),
        _ => {
            warn!("未知的过滤操作符: {}", operator);
            false
        }
    }
}
