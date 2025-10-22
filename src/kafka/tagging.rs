use crate::db::tag_rules::TagRuleRecord;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

/// 对单个告警应用所有标签规则，并返回匹配的标签ID列表
pub fn get_matched_tag_ids(
    alert_json: &Value,
    alert_type_str: &str,
    rules: &[TagRuleRecord],
    tag_map: &HashMap<String, Uuid>,
) -> Vec<Uuid> {
    let mut tags_to_add = std::collections::HashSet::new();

    for rule in rules.iter().filter(|r| r.alert_type == alert_type_str) {
        // 如果规则定义了子类型，则必须匹配
        if !rule.alert_subtype.is_empty() {
            let subtype_matches = alert_json
                .get("alert_subtype")
                .map(|v| v.to_string().replace('"', "")) // 将数字或字符串统一转为字符串并去除引号
                .map_or(false, |sub| sub == rule.alert_subtype);

            if !subtype_matches {
                continue;
            }
        }

        // 检查核心条件
        if check_condition(
            alert_json,
            &rule.condition_field,
            &rule.condition_operator,
            &rule.condition_value,
        ) {
            // 规则匹配，将其所有标签加入待添加列表
            for tag_name in &rule.tags {
                tags_to_add.insert(tag_name.clone());
            }
        }
    }

    if tags_to_add.is_empty() {
        return Vec::new();
    }

    // 从 tag name -> Uuid 的映射中查找ID
    let tag_ids: Vec<Uuid> = tags_to_add
        .iter()
        .filter_map(|name| tag_map.get(name).copied())
        .collect();

    if !tag_ids.is_empty() {
        info!(
            "Alert of type '{}' matched tags: {:?}",
            alert_type_str, tags_to_add
        );
    } else {
        warn!(
            "Alert matched tag names {:?} but they were not found in the tag map.",
            tags_to_add
        );
    }

    tag_ids
}

/// 检查告警数据是否满足单个规则的条件
fn check_condition(alert_json: &Value, field: &str, operator: &str, value: &str) -> bool {
    // 使用 .get() 安全地访问字段，如果字段不存在则条件不匹配
    let alert_field = match alert_json.get(field) {
        Some(v) => v,
        None => return false,
    };

    // 将告警字段的值转换为字符串以便比较
    let alert_field_str = match alert_field {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        // 对空值进行特殊处理
        Value::Null => {
            // 如果规则要求 "ne" 且 value 是空字符串，那么 null 字段应该算 "ne" "" -> true
            if operator == "ne" && value.is_empty() {
                return true;
            }
            // 其他情况，可以视为空字符串或特定标记
            "".to_string()
        }
        _ => return false, // 目前不处理数组或对象类型的字段
    };

    match operator {
        "eq" => alert_field_str == value,
        "ne" => alert_field_str != value,
        "contains" => alert_field_str.contains(value),
        "not_contains" => !alert_field_str.contains(value),
        "regex" => Regex::new(value).map_or(false, |re| re.is_match(&alert_field_str)),
        _ => {
            warn!("未知的操作符: {}", operator);
            false
        }
    }
}
