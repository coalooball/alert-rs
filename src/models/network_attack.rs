use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 网络攻击告警
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAttackAlert {
    pub alarm_id: String,
    pub alarm_date: i64,
    pub alarm_severity: u8,
    pub alarm_name: String,
    pub alarm_description: String,
    pub alarm_type: u8,
    pub alarm_subtype: u16,
    pub source: u8,
    pub control_rule_id: String,
    pub control_task_id: String,
    pub procedure_technique_id: Vec<String>,
    pub session_id: String,
    pub ip_version: u8,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub terminal_id: String,
    pub source_file_path: String,
    pub signature_id: String,
    pub attack_payload: String,
    pub attack_stage: String,
    pub attack_ip: String,
    pub attacked_ip: String,
    pub apt_group: String,
    pub vul_type: String,
    #[serde(rename = "CVE_id")]
    pub cve_id: String,
    pub vul_desc: String,
    pub data: Option<Value>,
}


