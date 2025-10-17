use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use std::collections::HashSet;
use std::fs;

use super::types::*;

lazy_static! {
    static ref VALID_FIELDS: HashSet<String> = load_valid_fields();
}

fn load_valid_fields() -> HashSet<String> {
    let mut fields = HashSet::new();
    
    // 尝试从 alert_fields.toml 读取字段定义
    if let Ok(content) = fs::read_to_string("alert_fields.toml") {
        if let Ok(toml_value) = content.parse::<toml::Value>() {
            if let Some(table) = toml_value.as_table() {
                for (_section_name, section_value) in table {
                    if let Some(section_table) = section_value.as_table() {
                        for (field_name, _) in section_table {
                            fields.insert(field_name.clone());
                        }
                    }
                }
            }
        }
    }
    
    // 如果文件不存在或解析失败，添加一些默认字段
    if fields.is_empty() {
        // 通用字段
        fields.insert("alarm_id".to_string());
        fields.insert("alarm_date".to_string());
        fields.insert("alarm_severity".to_string());
        fields.insert("alarm_name".to_string());
        fields.insert("alarm_description".to_string());
        fields.insert("alarm_type".to_string());
        fields.insert("alarm_subtype".to_string());
        fields.insert("source".to_string());
        
        // 网络字段
        fields.insert("src_ip".to_string());
        fields.insert("src_port".to_string());
        fields.insert("dst_ip".to_string());
        fields.insert("dst_port".to_string());
        fields.insert("protocol".to_string());
        fields.insert("session_id".to_string());
        fields.insert("ip_version".to_string());
        
        // 主机字段
        fields.insert("host_name".to_string());
        fields.insert("terminal_ip".to_string());
        fields.insert("user_account".to_string());
        fields.insert("terminal_os".to_string());
        fields.insert("terminal_id".to_string());
        fields.insert("dst_process_path".to_string());
        fields.insert("dst_process_md5".to_string());
        fields.insert("dst_process_cli".to_string());
        fields.insert("src_process_path".to_string());
        fields.insert("src_process_md5".to_string());
        fields.insert("src_process_cli".to_string());
        fields.insert("file_name".to_string());
        fields.insert("file_md5".to_string());
        fields.insert("file_path".to_string());
        fields.insert("register_key_name".to_string());
        fields.insert("register_key_value".to_string());
        fields.insert("register_path".to_string());
        
        // 样本字段
        fields.insert("md5".to_string());
        fields.insert("sha1".to_string());
        fields.insert("sha256".to_string());
        fields.insert("sha512".to_string());
        fields.insert("ssdeep".to_string());
        fields.insert("sample_family".to_string());
        fields.insert("apt_group".to_string());
        fields.insert("file_type".to_string());
        fields.insert("file_size".to_string());
        fields.insert("sample_source".to_string());
        fields.insert("sample_original_name".to_string());
        fields.insert("sample_description".to_string());
        fields.insert("target_platform".to_string());
        fields.insert("language".to_string());
        fields.insert("rule".to_string());
        fields.insert("target_content".to_string());
        fields.insert("compile_date".to_string());
        fields.insert("last_analy_date".to_string());
        fields.insert("sample_alarm_detail".to_string());
        
        // 网络攻击特有字段
        fields.insert("signature_id".to_string());
        fields.insert("attack_payload".to_string());
        fields.insert("attack_stage".to_string());
        fields.insert("attack_ip".to_string());
        fields.insert("attacked_ip".to_string());
        fields.insert("vul_type".to_string());
        fields.insert("cve_id".to_string());
        fields.insert("vul_desc".to_string());
        
        // 其他
        fields.insert("control_rule_id".to_string());
        fields.insert("control_task_id".to_string());
        fields.insert("procedure_technique_id".to_string());
        fields.insert("source_file_path".to_string());
        fields.insert("data".to_string());
    }
    
    fields
}

pub fn validate_fields(rule: &ConvergeRule) -> Result<()> {
    // 验证条件中的字段
    validate_condition_fields(&rule.condition)?;
    
    // 验证分组字段
    for field in &rule.group_by {
        if !VALID_FIELDS.contains(field) {
            return Err(anyhow!("未知字段: {}", field));
        }
    }
    
    Ok(())
}

pub fn validate_correlate_fields(rule: &CorrelateRule) -> Result<()> {
    // 收集所有事件别名
    let mut event_aliases = HashSet::new();
    for event in &rule.events {
        event_aliases.insert(event.alias.clone());
        validate_condition_fields(&event.condition)?;
    }
    
    // 验证 JOIN ON 条件中的字段引用
    for clause in &rule.join_on.clauses {
        validate_field_ref(&clause.left, &event_aliases)?;
        validate_field_ref(&clause.right, &event_aliases)?;
    }
    
    // 验证生成块中的严重程度
    if rule.generate.severity > 4 {
        return Err(anyhow!("SEVERITY 值必须在 1-4 之间，当前值: {}", rule.generate.severity));
    }
    
    Ok(())
}

fn validate_condition_fields(condition: &Condition) -> Result<()> {
    for clause in &condition.clauses {
        validate_field_ref(&clause.field, &HashSet::new())?;
    }
    Ok(())
}

fn validate_field_ref(field_ref: &FieldRef, event_aliases: &HashSet<String>) -> Result<()> {
    // 如果有事件别名，验证别名是否存在
    if let Some(alias) = &field_ref.event_alias {
        if !event_aliases.is_empty() && !event_aliases.contains(alias) {
            return Err(anyhow!("未定义的事件别名: {}", alias));
        }
    }
    
    // 验证字段名是否有效
    if !VALID_FIELDS.contains(&field_ref.field_name) {
        return Err(anyhow!("未知字段: {}", field_ref.field_name));
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_fields() {
        let fields = load_valid_fields();
        assert!(!fields.is_empty());
        assert!(fields.contains("alarm_id"));
        assert!(fields.contains("src_ip"));
    }
}

