use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 网络攻击告警
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAttackAlert {
    pub alarm_id: Option<String>,
    pub alarm_date: Option<i64>,
    pub alarm_severity: Option<u8>,
    pub alarm_name: Option<String>,
    pub alarm_description: Option<String>,
    pub alarm_type: u8,
    pub alarm_subtype: u16,
    pub source: u8,
    pub control_rule_id: Option<String>,
    pub control_task_id: Option<String>,
    pub procedure_technique_id: Option<Vec<String>>,
    pub session_id: Option<String>,
    pub ip_version: Option<u8>,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub terminal_id: Option<String>,
    pub source_file_path: Option<String>,
    pub signature_id: Option<String>,
    pub attack_payload: Option<String>,
    pub attack_stage: Option<String>,
    pub attack_ip: Option<String>,
    pub attacked_ip: Option<String>,
    pub apt_group: Option<String>,
    pub vul_type: Option<String>,
    #[serde(rename = "CVE_id")]
    pub cve_id: Option<String>,
    pub vul_desc: Option<String>,
    pub data: Option<Value>,
}
