use anyhow::Result;
use sqlx::{PgPool, postgres::PgPoolOptions};
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::config::PostgresConfig;
use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};

pub async fn init_postgres(pg: &PostgresConfig) -> Result<PgPool> {
    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        pg.user, pg.password, pg.host, pg.port, pg.database
    );
    
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await?;

    // 启用 pgcrypto 扩展以支持 gen_random_uuid()
    sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        .execute(&pool)
        .await?;

    // 网络攻击告警表 - 包含所有字段
    sqlx::query(
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
        )"
    )
    .execute(&pool)
    .await?;

    // 恶意样本告警表 - 包含所有字段
    sqlx::query(
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
        )"
    )
    .execute(&pool)
    .await?;

    // 主机行为告警表 - 包含所有字段
    sqlx::query(
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
        )"
    )
    .execute(&pool)
    .await?;

    // 无效告警表 - 保存解析失败的原始数据与错误信息
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS invalid_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            data JSONB NOT NULL,
            error TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )"
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}

/// 清空数据库中的业务表
pub async fn reset_database(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS network_attack_alerts CASCADE")
        .execute(pool)
        .await?;
    sqlx::query("DROP TABLE IF EXISTS malicious_sample_alerts CASCADE")
        .execute(pool)
        .await?;
    sqlx::query("DROP TABLE IF EXISTS host_behavior_alerts CASCADE")
        .execute(pool)
        .await?;
    sqlx::query("DROP TABLE IF EXISTS invalid_alerts CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct NetworkAttackRecord {
    pub id: Uuid,
    pub alarm_id: String,
    pub alarm_date: i64,
    pub alarm_severity: i16,
    pub alarm_name: String,
    pub alarm_description: String,
    pub alarm_type: i16,
    pub alarm_subtype: i32,
    pub source: i16,
    pub control_rule_id: String,
    pub control_task_id: String,
    pub procedure_technique_id: serde_json::Value,
    pub session_id: String,
    pub ip_version: i16,
    pub src_ip: String,
    pub src_port: i32,
    pub dst_ip: String,
    pub dst_port: i32,
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
    pub cve_id: String,
    pub vul_desc: String,
    pub data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct MaliciousSampleRecord {
    pub id: Uuid,
    pub alarm_id: String,
    pub alarm_date: i64,
    pub alarm_severity: i16,
    pub alarm_name: String,
    pub alarm_description: String,
    pub alarm_type: i16,
    pub alarm_subtype: i32,
    pub source: i16,
    pub control_rule_id: String,
    pub control_task_id: String,
    pub procedure_technique_id: serde_json::Value,
    pub session_id: String,
    pub ip_version: Option<i16>,
    pub src_ip: String,
    pub src_port: Option<i32>,
    pub dst_ip: String,
    pub dst_port: Option<i32>,
    pub protocol: String,
    pub terminal_id: String,
    pub source_file_path: String,
    pub sample_source: i16,
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
    pub file_size: i64,
    pub language: String,
    pub rule: String,
    pub target_content: String,
    pub compile_date: i64,
    pub last_analy_date: i64,
    pub sample_alarm_detail: String,
    pub data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct HostBehaviorRecord {
    pub id: Uuid,
    pub alarm_id: String,
    pub alarm_date: i64,
    pub alarm_severity: i16,
    pub alarm_name: String,
    pub alarm_description: String,
    pub alarm_type: i16,
    pub alarm_subtype: i32,
    pub source: i16,
    pub control_rule_id: String,
    pub control_task_id: String,
    pub procedure_technique_id: serde_json::Value,
    pub session_id: String,
    pub ip_version: Option<i16>,
    pub src_ip: String,
    pub src_port: Option<i32>,
    pub dst_ip: String,
    pub dst_port: Option<i32>,
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
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct InvalidAlertRecord {
    pub id: Uuid,
    pub data: serde_json::Value,
    pub error: String,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_network_attack(pool: &PgPool, alert: &NetworkAttackAlert) -> Result<()> {
    let procedure_technique_id = serde_json::Value::Array(
        alert
            .procedure_technique_id
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );

    sqlx::query(
        "INSERT INTO network_attack_alerts (
            alarm_id, alarm_date, alarm_severity, alarm_name, alarm_description,
            alarm_type, alarm_subtype, source, control_rule_id, control_task_id,
            procedure_technique_id, session_id, ip_version, src_ip, src_port,
            dst_ip, dst_port, protocol, terminal_id, source_file_path,
            signature_id, attack_payload, attack_stage, attack_ip, attacked_ip,
            apt_group, vul_type, cve_id, vul_desc, data
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30
        )"
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity as i16)
    .bind(&alert.alarm_name)
    .bind(&alert.alarm_description)
    .bind(alert.alarm_type as i16)
    .bind(alert.alarm_subtype as i32)
    .bind(alert.source as i16)
    .bind(&alert.control_rule_id)
    .bind(&alert.control_task_id)
    .bind(&procedure_technique_id)
    .bind(&alert.session_id)
    .bind(alert.ip_version as i16)
    .bind(&alert.src_ip)
    .bind(alert.src_port as i32)
    .bind(&alert.dst_ip)
    .bind(alert.dst_port as i32)
    .bind(&alert.protocol)
    .bind(&alert.terminal_id)
    .bind(&alert.source_file_path)
    .bind(&alert.signature_id)
    .bind(&alert.attack_payload)
    .bind(&alert.attack_stage)
    .bind(&alert.attack_ip)
    .bind(&alert.attacked_ip)
    .bind(&alert.apt_group)
    .bind(&alert.vul_type)
    .bind(&alert.cve_id)
    .bind(&alert.vul_desc)
    .bind(&alert.data)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_malicious_sample(pool: &PgPool, alert: &MaliciousSampleAlert) -> Result<()> {
    let procedure_technique_id = serde_json::Value::Array(
        alert
            .procedure_technique_id
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );

    let sample_alarm_engine = serde_json::Value::Array(
        alert
            .sample_alarm_engine
            .iter()
            .cloned()
            .map(|n| serde_json::Value::Number(serde_json::Number::from(n)))
            .collect(),
    );

    sqlx::query(
        "INSERT INTO malicious_sample_alerts (
            alarm_id, alarm_date, alarm_severity, alarm_name, alarm_description,
            alarm_type, alarm_subtype, source, control_rule_id, control_task_id,
            procedure_technique_id, session_id, ip_version, src_ip, src_port,
            dst_ip, dst_port, protocol, terminal_id, source_file_path,
            sample_source, md5, sha1, sha256, sha512, ssdeep,
            sample_original_name, sample_description, sample_family, apt_group,
            sample_alarm_engine, target_platform, file_type, file_size, language,
            rule, target_content, compile_date, last_analy_date, sample_alarm_detail, data
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41
        )"
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity as i16)
    .bind(&alert.alarm_name)
    .bind(&alert.alarm_description)
    .bind(alert.alarm_type as i16)
    .bind(alert.alarm_subtype as i32)
    .bind(alert.source as i16)
    .bind(&alert.control_rule_id)
    .bind(&alert.control_task_id)
    .bind(&procedure_technique_id)
    .bind(&alert.session_id)
    .bind(alert.ip_version.map(|v| v as i16))
    .bind(&alert.src_ip)
    .bind(alert.src_port.map(|v| v as i32))
    .bind(&alert.dst_ip)
    .bind(alert.dst_port.map(|v| v as i32))
    .bind(&alert.protocol)
    .bind(&alert.terminal_id)
    .bind(&alert.source_file_path)
    .bind(alert.sample_source as i16)
    .bind(&alert.md5)
    .bind(&alert.sha1)
    .bind(&alert.sha256)
    .bind(&alert.sha512)
    .bind(&alert.ssdeep)
    .bind(&alert.sample_original_name)
    .bind(&alert.sample_description)
    .bind(&alert.sample_family)
    .bind(&alert.apt_group)
    .bind(&sample_alarm_engine)
    .bind(&alert.target_platform)
    .bind(&alert.file_type)
    .bind(alert.file_size as i64)
    .bind(&alert.language)
    .bind(&alert.rule)
    .bind(&alert.target_content)
    .bind(alert.compile_date)
    .bind(alert.last_analy_date)
    .bind(&alert.sample_alarm_detail)
    .bind(&alert.data)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn insert_host_behavior(pool: &PgPool, alert: &HostBehaviorAlert) -> Result<()> {
    let procedure_technique_id = serde_json::Value::Array(
        alert
            .procedure_technique_id
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );

    sqlx::query(
        "INSERT INTO host_behavior_alerts (
            alarm_id, alarm_date, alarm_severity, alarm_name, alarm_description,
            alarm_type, alarm_subtype, source, control_rule_id, control_task_id,
            procedure_technique_id, session_id, ip_version, src_ip, src_port,
            dst_ip, dst_port, protocol, terminal_id, source_file_path,
            host_name, terminal_ip, user_account, terminal_os,
            dst_process_md5, dst_process_path, dst_process_cli,
            src_process_md5, src_process_path, src_process_cli,
            register_key_name, register_key_value, register_path,
            file_name, file_md5, file_path, data
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35, $36, $37
        )"
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity as i16)
    .bind(&alert.alarm_name)
    .bind(&alert.alarm_description)
    .bind(alert.alarm_type as i16)
    .bind(alert.alarm_subtype as i32)
    .bind(alert.source as i16)
    .bind(&alert.control_rule_id)
    .bind(&alert.control_task_id)
    .bind(&procedure_technique_id)
    .bind(&alert.session_id)
    .bind(alert.ip_version.map(|v| v as i16))
    .bind(&alert.src_ip)
    .bind(alert.src_port.map(|v| v as i32))
    .bind(&alert.dst_ip)
    .bind(alert.dst_port.map(|v| v as i32))
    .bind(&alert.protocol)
    .bind(&alert.terminal_id)
    .bind(&alert.source_file_path)
    .bind(&alert.host_name)
    .bind(&alert.terminal_ip)
    .bind(&alert.user_account)
    .bind(&alert.terminal_os)
    .bind(&alert.dst_process_md5)
    .bind(&alert.dst_process_path)
    .bind(&alert.dst_process_cli)
    .bind(&alert.src_process_md5)
    .bind(&alert.src_process_path)
    .bind(&alert.src_process_cli)
    .bind(&alert.register_key_name)
    .bind(&alert.register_key_value)
    .bind(&alert.register_path)
    .bind(&alert.file_name)
    .bind(&alert.file_md5)
    .bind(&alert.file_path)
    .bind(&alert.data)
    .execute(pool)
    .await?;

    Ok(())
}

// 查询函数
pub async fn query_network_attacks(pool: &PgPool, page: u64, page_size: u64) -> Result<(Vec<NetworkAttackRecord>, u64)> {
    let offset = (page - 1) * page_size;
    
    let records = sqlx::query_as::<_, NetworkAttackRecord>(
        "SELECT * FROM network_attack_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;
    
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM network_attack_alerts")
        .fetch_one(pool)
        .await?;
    
    Ok((records, total.0 as u64))
}

pub async fn query_malicious_samples(pool: &PgPool, page: u64, page_size: u64) -> Result<(Vec<MaliciousSampleRecord>, u64)> {
    let offset = (page - 1) * page_size;
    
    let records = sqlx::query_as::<_, MaliciousSampleRecord>(
        "SELECT * FROM malicious_sample_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;
    
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM malicious_sample_alerts")
        .fetch_one(pool)
        .await?;
    
    Ok((records, total.0 as u64))
}

pub async fn query_host_behaviors(pool: &PgPool, page: u64, page_size: u64) -> Result<(Vec<HostBehaviorRecord>, u64)> {
    let offset = (page - 1) * page_size;
    
    let records = sqlx::query_as::<_, HostBehaviorRecord>(
        "SELECT * FROM host_behavior_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;
    
    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM host_behavior_alerts")
        .fetch_one(pool)
        .await?;
    
    Ok((records, total.0 as u64))
}

pub async fn insert_invalid_alert(pool: &PgPool, data: serde_json::Value, error: String) -> Result<()> {
    sqlx::query(
        "INSERT INTO invalid_alerts (data, error) VALUES ($1, $2)"
    )
    .bind(&data)
    .bind(&error)
    .execute(pool)
    .await?;
    
    Ok(())
}

pub async fn query_invalid_alerts(pool: &PgPool, page: u64, page_size: u64) -> Result<(Vec<InvalidAlertRecord>, u64)> {
    let offset = (page - 1) * page_size;
    
    let records = sqlx::query_as::<_, InvalidAlertRecord>(
        "SELECT * FROM invalid_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM invalid_alerts")
        .fetch_one(pool)
        .await?;

    Ok((records, total.0 as u64))
}
