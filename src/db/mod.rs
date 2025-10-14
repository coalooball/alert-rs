use anyhow::Result;
use rbatis::crud;
use rbatis::rbdc::datetime::DateTime;
use rbatis::RBatis;
use rbdc_pg::driver::PgDriver;
use uuid::Uuid;

use crate::config::PostgresConfig;
use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};

pub async fn init_postgres(pg: &PostgresConfig) -> Result<RBatis> {
    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        pg.user, pg.password, pg.host, pg.port, pg.database
    );
    let rb = RBatis::new();
    rb.init(PgDriver {}, &dsn)?;

    // 启用 pgcrypto 扩展以支持 gen_random_uuid()
    rb.exec(
        "CREATE EXTENSION IF NOT EXISTS pgcrypto",
        vec![],
    )
    .await?;

    // 网络攻击告警表 - 包含所有字段
    rb.exec(
        "CREATE TABLE IF NOT EXISTS network_attack_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alarm_id TEXT NOT NULL,
            alarm_date BIGINT NOT NULL,
            alarm_severity SMALLINT NOT NULL,
            alarm_name TEXT NOT NULL,
            alarm_description TEXT NOT NULL,
            alarm_type SMALLINT NOT NULL,
            alarm_subtype INTEGER NOT NULL,
            source SMALLINT NOT NULL,
            control_rule_id TEXT NOT NULL,
            control_task_id TEXT NOT NULL,
            procedure_technique_id JSONB NOT NULL,
            session_id TEXT NOT NULL,
            ip_version SMALLINT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            terminal_id TEXT NOT NULL,
            source_file_path TEXT NOT NULL,
            signature_id TEXT NOT NULL,
            attack_payload TEXT NOT NULL,
            attack_stage TEXT NOT NULL,
            attack_ip TEXT NOT NULL,
            attacked_ip TEXT NOT NULL,
            apt_group TEXT NOT NULL,
            vul_type TEXT NOT NULL,
            cve_id TEXT NOT NULL,
            vul_desc TEXT NOT NULL,
            data JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
        vec![],
    )
    .await?;

    // 恶意样本告警表 - 包含所有字段
    rb.exec(
        "CREATE TABLE IF NOT EXISTS malicious_sample_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alarm_id TEXT NOT NULL,
            alarm_date BIGINT NOT NULL,
            alarm_severity SMALLINT NOT NULL,
            alarm_name TEXT NOT NULL,
            alarm_description TEXT NOT NULL,
            alarm_type SMALLINT NOT NULL,
            alarm_subtype INTEGER NOT NULL,
            source SMALLINT NOT NULL,
            control_rule_id TEXT NOT NULL,
            control_task_id TEXT NOT NULL,
            procedure_technique_id JSONB NOT NULL,
            session_id TEXT NOT NULL,
            ip_version SMALLINT,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            terminal_id TEXT NOT NULL,
            source_file_path TEXT NOT NULL,
            sample_source SMALLINT NOT NULL,
            md5 TEXT NOT NULL,
            sha1 TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            sha512 TEXT NOT NULL,
            ssdeep TEXT NOT NULL,
            sample_original_name TEXT NOT NULL,
            sample_description TEXT NOT NULL,
            sample_family TEXT NOT NULL,
            apt_group TEXT NOT NULL,
            sample_alarm_engine JSONB NOT NULL,
            target_platform TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size BIGINT NOT NULL,
            language TEXT NOT NULL,
            rule TEXT NOT NULL,
            target_content TEXT NOT NULL,
            compile_date BIGINT NOT NULL,
            last_analy_date BIGINT NOT NULL,
            sample_alarm_detail TEXT NOT NULL,
            data JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
        vec![],
    )
    .await?;

    // 主机行为告警表 - 包含所有字段
    rb.exec(
        "CREATE TABLE IF NOT EXISTS host_behavior_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alarm_id TEXT NOT NULL,
            alarm_date BIGINT NOT NULL,
            alarm_severity SMALLINT NOT NULL,
            alarm_name TEXT NOT NULL,
            alarm_description TEXT NOT NULL,
            alarm_type SMALLINT NOT NULL,
            alarm_subtype INTEGER NOT NULL,
            source SMALLINT NOT NULL,
            control_rule_id TEXT NOT NULL,
            control_task_id TEXT NOT NULL,
            procedure_technique_id JSONB NOT NULL,
            session_id TEXT NOT NULL,
            ip_version SMALLINT,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            protocol TEXT NOT NULL,
            terminal_id TEXT NOT NULL,
            source_file_path TEXT NOT NULL,
            host_name TEXT NOT NULL,
            terminal_ip TEXT NOT NULL,
            user_account TEXT NOT NULL,
            terminal_os TEXT NOT NULL,
            dst_process_md5 TEXT NOT NULL,
            dst_process_path TEXT NOT NULL,
            dst_process_cli TEXT NOT NULL,
            src_process_md5 TEXT NOT NULL,
            src_process_path TEXT NOT NULL,
            src_process_cli TEXT NOT NULL,
            register_key_name TEXT NOT NULL,
            register_key_value TEXT NOT NULL,
            register_path TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_md5 TEXT NOT NULL,
            file_path TEXT NOT NULL,
            data JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
        vec![],
    )
    .await?;

    Ok(rb)
}

/// 清空数据库中的业务表
pub async fn reset_database(rb: &RBatis) -> Result<()> {
    // 依赖顺序较少，直接尝试删除三张业务表
    rb.exec("DROP TABLE IF EXISTS network_attack_alerts CASCADE", vec![]).await?;
    rb.exec("DROP TABLE IF EXISTS malicious_sample_alerts CASCADE", vec![]).await?;
    rb.exec("DROP TABLE IF EXISTS host_behavior_alerts CASCADE", vec![]).await?;
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NetworkAttackRecord {
    pub id: Option<Uuid>,
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
    pub procedure_technique_id: serde_json::Value,
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
    #[serde(rename = "cve_id")]
    pub cve_id: String,
    pub vul_desc: String,
    pub data: Option<serde_json::Value>,
    pub created_at: Option<DateTime>,
}
crud!(NetworkAttackRecord {}, "network_attack_alerts");

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MaliciousSampleRecord {
    pub id: Option<Uuid>,
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
    pub procedure_technique_id: serde_json::Value,
    pub session_id: String,
    pub ip_version: Option<u8>,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub terminal_id: String,
    pub source_file_path: String,
    pub sample_source: u8,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub ssdeep: String,
    pub sample_original_name: String,
    pub sample_description: String,
    pub sample_family: String,
    pub apt_group: String,
    pub sample_alarm_engine: serde_json::Value,
    pub target_platform: String,
    pub file_type: String,
    pub file_size: u64,
    pub language: String,
    pub rule: String,
    pub target_content: String,
    pub compile_date: i64,
    pub last_analy_date: i64,
    pub sample_alarm_detail: String,
    pub data: Option<serde_json::Value>,
    pub created_at: Option<DateTime>,
}
crud!(MaliciousSampleRecord {}, "malicious_sample_alerts");

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HostBehaviorRecord {
    pub id: Option<Uuid>,
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
    pub procedure_technique_id: serde_json::Value,
    pub session_id: String,
    pub ip_version: Option<u8>,
    pub src_ip: String,
    pub src_port: Option<u16>,
    pub dst_ip: String,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub terminal_id: String,
    pub source_file_path: String,
    pub host_name: String,
    pub terminal_ip: String,
    pub user_account: String,
    pub terminal_os: String,
    pub dst_process_md5: String,
    pub dst_process_path: String,
    pub dst_process_cli: String,
    pub src_process_md5: String,
    pub src_process_path: String,
    pub src_process_cli: String,
    pub register_key_name: String,
    pub register_key_value: String,
    pub register_path: String,
    pub file_name: String,
    pub file_md5: String,
    pub file_path: String,
    pub data: Option<serde_json::Value>,
    pub created_at: Option<DateTime>,
}
crud!(HostBehaviorRecord {}, "host_behavior_alerts");

pub async fn insert_network_attack(rb: &RBatis, alert: &NetworkAttackAlert) -> Result<()> {
    let record = NetworkAttackRecord {
        id: None,
        alarm_id: alert.alarm_id.clone(),
        alarm_date: alert.alarm_date,
        alarm_severity: alert.alarm_severity,
        alarm_name: alert.alarm_name.clone(),
        alarm_description: alert.alarm_description.clone(),
        alarm_type: alert.alarm_type,
        alarm_subtype: alert.alarm_subtype,
        source: alert.source,
        control_rule_id: alert.control_rule_id.clone(),
        control_task_id: alert.control_task_id.clone(),
        procedure_technique_id: serde_json::Value::Array(
            alert
                .procedure_technique_id
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
        session_id: alert.session_id.clone(),
        ip_version: alert.ip_version,
        src_ip: alert.src_ip.clone(),
        src_port: alert.src_port,
        dst_ip: alert.dst_ip.clone(),
        dst_port: alert.dst_port,
        protocol: alert.protocol.clone(),
        terminal_id: alert.terminal_id.clone(),
        source_file_path: alert.source_file_path.clone(),
        signature_id: alert.signature_id.clone(),
        attack_payload: alert.attack_payload.clone(),
        attack_stage: alert.attack_stage.clone(),
        attack_ip: alert.attack_ip.clone(),
        attacked_ip: alert.attacked_ip.clone(),
        apt_group: alert.apt_group.clone(),
        vul_type: alert.vul_type.clone(),
        cve_id: alert.cve_id.clone(),
        vul_desc: alert.vul_desc.clone(),
        data: alert.data.clone(),
        created_at: None,
    };
    NetworkAttackRecord::insert(rb, &record).await?;
    Ok(())
}

pub async fn insert_malicious_sample(rb: &RBatis, alert: &MaliciousSampleAlert) -> Result<()> {
    let record = MaliciousSampleRecord {
        id: None,
        alarm_id: alert.alarm_id.clone(),
        alarm_date: alert.alarm_date,
        alarm_severity: alert.alarm_severity,
        alarm_name: alert.alarm_name.clone(),
        alarm_description: alert.alarm_description.clone(),
        alarm_type: alert.alarm_type,
        alarm_subtype: alert.alarm_subtype,
        source: alert.source,
        control_rule_id: alert.control_rule_id.clone(),
        control_task_id: alert.control_task_id.clone(),
        procedure_technique_id: serde_json::Value::Array(
            alert
                .procedure_technique_id
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
        session_id: alert.session_id.clone(),
        ip_version: alert.ip_version,
        src_ip: alert.src_ip.clone(),
        src_port: alert.src_port,
        dst_ip: alert.dst_ip.clone(),
        dst_port: alert.dst_port,
        protocol: alert.protocol.clone(),
        terminal_id: alert.terminal_id.clone(),
        source_file_path: alert.source_file_path.clone(),
        sample_source: alert.sample_source,
        md5: alert.md5.clone(),
        sha1: alert.sha1.clone(),
        sha256: alert.sha256.clone(),
        sha512: alert.sha512.clone(),
        ssdeep: alert.ssdeep.clone(),
        sample_original_name: alert.sample_original_name.clone(),
        sample_description: alert.sample_description.clone(),
        sample_family: alert.sample_family.clone(),
        apt_group: alert.apt_group.clone(),
        sample_alarm_engine: serde_json::Value::Array(
            alert
                .sample_alarm_engine
                .iter()
                .cloned()
                .map(|n| serde_json::Value::Number(serde_json::Number::from(n)))
                .collect(),
        ),
        target_platform: alert.target_platform.clone(),
        file_type: alert.file_type.clone(),
        file_size: alert.file_size,
        language: alert.language.clone(),
        rule: alert.rule.clone(),
        target_content: alert.target_content.clone(),
        compile_date: alert.compile_date,
        last_analy_date: alert.last_analy_date,
        sample_alarm_detail: alert.sample_alarm_detail.clone(),
        data: alert.data.clone(),
        created_at: None,
    };
    MaliciousSampleRecord::insert(rb, &record).await?;
    Ok(())
}

pub async fn insert_host_behavior(rb: &RBatis, alert: &HostBehaviorAlert) -> Result<()> {
    let record = HostBehaviorRecord {
        id: None,
        alarm_id: alert.alarm_id.clone(),
        alarm_date: alert.alarm_date,
        alarm_severity: alert.alarm_severity,
        alarm_name: alert.alarm_name.clone(),
        alarm_description: alert.alarm_description.clone(),
        alarm_type: alert.alarm_type,
        alarm_subtype: alert.alarm_subtype,
        source: alert.source,
        control_rule_id: alert.control_rule_id.clone(),
        control_task_id: alert.control_task_id.clone(),
        procedure_technique_id: serde_json::Value::Array(
            alert
                .procedure_technique_id
                .iter()
                .cloned()
                .map(serde_json::Value::String)
                .collect(),
        ),
        session_id: alert.session_id.clone(),
        ip_version: alert.ip_version,
        src_ip: alert.src_ip.clone(),
        src_port: alert.src_port,
        dst_ip: alert.dst_ip.clone(),
        dst_port: alert.dst_port,
        protocol: alert.protocol.clone(),
        terminal_id: alert.terminal_id.clone(),
        source_file_path: alert.source_file_path.clone(),
        host_name: alert.host_name.clone(),
        terminal_ip: alert.terminal_ip.clone(),
        user_account: alert.user_account.clone(),
        terminal_os: alert.terminal_os.clone(),
        dst_process_md5: alert.dst_process_md5.clone(),
        dst_process_path: alert.dst_process_path.clone(),
        dst_process_cli: alert.dst_process_cli.clone(),
        src_process_md5: alert.src_process_md5.clone(),
        src_process_path: alert.src_process_path.clone(),
        src_process_cli: alert.src_process_cli.clone(),
        register_key_name: alert.register_key_name.clone(),
        register_key_value: alert.register_key_value.clone(),
        register_path: alert.register_path.clone(),
        file_name: alert.file_name.clone(),
        file_md5: alert.file_md5.clone(),
        file_path: alert.file_path.clone(),
        data: alert.data.clone(),
        created_at: None,
    };
    HostBehaviorRecord::insert(rb, &record).await?;
    Ok(())
}

// 查询函数
pub async fn query_network_attacks(rb: &RBatis, page: u64, page_size: u64) -> Result<(Vec<NetworkAttackRecord>, u64)> {
    let offset = (page - 1) * page_size;
    let sql = format!(
        "SELECT * FROM network_attack_alerts ORDER BY created_at DESC LIMIT {} OFFSET {}",
        page_size, offset
    );
    let records: Vec<NetworkAttackRecord> = rb.query_decode(&sql, vec![]).await?;
    
    let count_sql = "SELECT COUNT(*) as count FROM network_attack_alerts";
    let count: Option<i64> = rb.query_decode(count_sql, vec![]).await?;
    let total = count.unwrap_or(0) as u64;
    
    Ok((records, total))
}

pub async fn query_malicious_samples(rb: &RBatis, page: u64, page_size: u64) -> Result<(Vec<MaliciousSampleRecord>, u64)> {
    let offset = (page - 1) * page_size;
    let sql = format!(
        "SELECT * FROM malicious_sample_alerts ORDER BY created_at DESC LIMIT {} OFFSET {}",
        page_size, offset
    );
    let records: Vec<MaliciousSampleRecord> = rb.query_decode(&sql, vec![]).await?;
    
    let count_sql = "SELECT COUNT(*) as count FROM malicious_sample_alerts";
    let count: Option<i64> = rb.query_decode(count_sql, vec![]).await?;
    let total = count.unwrap_or(0) as u64;
    
    Ok((records, total))
}

pub async fn query_host_behaviors(rb: &RBatis, page: u64, page_size: u64) -> Result<(Vec<HostBehaviorRecord>, u64)> {
    let offset = (page - 1) * page_size;
    let sql = format!(
        "SELECT * FROM host_behavior_alerts ORDER BY created_at DESC LIMIT {} OFFSET {}",
        page_size, offset
    );
    let records: Vec<HostBehaviorRecord> = rb.query_decode(&sql, vec![]).await?;
    
    let count_sql = "SELECT COUNT(*) as count FROM host_behavior_alerts";
    let count: Option<i64> = rb.query_decode(count_sql, vec![]).await?;
    let total = count.unwrap_or(0) as u64;
    
    Ok((records, total))
}
