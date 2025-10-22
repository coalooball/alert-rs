//! 原始告警表及相关操作
//!
//! 本模块包含三类原始告警表的定义和操作：
//! - 网络攻击告警表 (network_attack_alerts)
//! - 恶意样本告警表 (malicious_sample_alerts)  
//! - 主机行为告警表 (host_behavior_alerts)
//! - 无效告警表 (invalid_alerts)
//!
//! 提供的功能包括：
//! - 建表/删表操作
//! - 插入告警数据
//! - 分页查询告警数据

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};

// ============================================================================
// Record 结构体定义
// ============================================================================

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct NetworkAttackRecord {
    pub id: Uuid,
    pub alarm_id: Option<String>,
    pub alarm_date: Option<i64>,
    pub alarm_severity: Option<i16>,
    pub alarm_name: Option<String>,
    pub alarm_description: Option<String>,
    pub alarm_type: i16,
    pub alarm_subtype: i32,
    pub source: i16,
    pub control_rule_id: Option<String>,
    pub control_task_id: Option<String>,
    pub procedure_technique_id: Option<serde_json::Value>,
    pub session_id: Option<String>,
    pub ip_version: Option<i16>,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
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
    pub cve_id: Option<String>,
    pub vul_desc: Option<String>,
    pub data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct MaliciousSampleRecord {
    pub id: Uuid,
    pub alarm_id: Option<String>,
    pub alarm_date: Option<i64>,
    pub alarm_severity: Option<i16>,
    pub alarm_name: Option<String>,
    pub alarm_description: Option<String>,
    pub alarm_type: i16,
    pub alarm_subtype: i32,
    pub source: i16,
    pub control_rule_id: Option<String>,
    pub control_task_id: Option<String>,
    pub procedure_technique_id: Option<serde_json::Value>,
    pub session_id: Option<String>,
    pub ip_version: Option<i16>,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    pub terminal_id: Option<String>,
    pub source_file_path: Option<String>,
    pub sample_source: Option<i16>,
    pub md5: Option<String>,
    pub sha1: Option<String>,
    pub sha256: Option<String>,
    pub sha512: Option<String>,
    pub ssdeep: Option<String>,
    pub sample_original_name: Option<String>,
    pub sample_description: Option<String>,
    pub sample_family: Option<String>,
    pub apt_group: Option<String>,
    pub sample_alarm_engine: Option<serde_json::Value>,
    pub target_platform: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<i64>,
    pub language: Option<String>,
    pub rule: Option<String>,
    pub target_content: Option<String>,
    pub compile_date: Option<i64>,
    pub last_analy_date: Option<i64>,
    pub sample_alarm_detail: Option<String>,
    pub data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct HostBehaviorRecord {
    pub id: Uuid,
    pub alarm_id: Option<String>,
    pub alarm_date: Option<i64>,
    pub alarm_severity: Option<i16>,
    pub alarm_name: Option<String>,
    pub alarm_description: Option<String>,
    pub alarm_type: i16,
    pub alarm_subtype: i32,
    pub source: i16,
    pub control_rule_id: Option<String>,
    pub control_task_id: Option<String>,
    pub procedure_technique_id: Option<serde_json::Value>,
    pub session_id: Option<String>,
    pub ip_version: Option<i16>,
    pub src_ip: Option<String>,
    pub src_port: Option<i32>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<i32>,
    pub protocol: Option<String>,
    pub terminal_id: Option<String>,
    pub source_file_path: Option<String>,
    pub host_name: Option<String>,
    pub terminal_ip: Option<String>,
    pub user_account: Option<String>,
    pub terminal_os: Option<String>,
    pub dst_process_md5: Option<String>,
    pub dst_process_path: Option<String>,
    pub dst_process_cli: Option<String>,
    pub src_process_md5: Option<String>,
    pub src_process_path: Option<String>,
    pub src_process_cli: Option<String>,
    pub register_key_name: Option<String>,
    pub register_key_value: Option<String>,
    pub register_path: Option<String>,
    pub file_name: Option<String>,
    pub file_md5: Option<String>,
    pub file_path: Option<String>,
    pub data: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct InvalidAlertRecord {
    pub id: Uuid,
    pub data: serde_json::Value,
    pub alert_type: String, // 新增字段
    pub error: String,
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// 建表/删表操作
// ============================================================================

/// 创建所有原始告警表
pub async fn create_raw_alerts_tables(pool: &PgPool) -> Result<()> {
    // 网络攻击告警表 - 包含所有字段
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS network_attack_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alarm_id TEXT,
            alarm_date BIGINT,
            alarm_severity SMALLINT,
            alarm_name TEXT,
            alarm_description TEXT,
            alarm_type SMALLINT NOT NULL,
            alarm_subtype INTEGER NOT NULL,
            source SMALLINT NOT NULL,
            control_rule_id TEXT,
            control_task_id TEXT,
            procedure_technique_id JSONB,
            session_id TEXT,
            ip_version SMALLINT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            terminal_id TEXT,
            source_file_path TEXT,
            signature_id TEXT,
            attack_payload TEXT,
            attack_stage TEXT,
            attack_ip TEXT,
            attacked_ip TEXT,
            apt_group TEXT,
            vul_type TEXT,
            cve_id TEXT,
            vul_desc TEXT,
            data JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    // 恶意样本告警表 - 包含所有字段
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS malicious_sample_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alarm_id TEXT,
            alarm_date BIGINT,
            alarm_severity SMALLINT,
            alarm_name TEXT,
            alarm_description TEXT,
            alarm_type SMALLINT NOT NULL,
            alarm_subtype INTEGER NOT NULL,
            source SMALLINT NOT NULL,
            control_rule_id TEXT,
            control_task_id TEXT,
            procedure_technique_id JSONB,
            session_id TEXT,
            ip_version SMALLINT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            terminal_id TEXT,
            source_file_path TEXT,
            sample_source SMALLINT,
            md5 TEXT,
            sha1 TEXT,
            sha256 TEXT,
            sha512 TEXT,
            ssdeep TEXT,
            sample_original_name TEXT,
            sample_description TEXT,
            sample_family TEXT,
            apt_group TEXT,
            sample_alarm_engine JSONB,
            target_platform TEXT,
            file_type TEXT,
            file_size BIGINT,
            language TEXT,
            rule TEXT,
            target_content TEXT,
            compile_date BIGINT,
            last_analy_date BIGINT,
            sample_alarm_detail TEXT,
            data JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    // 主机行为告警表 - 包含所有字段
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS host_behavior_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alarm_id TEXT,
            alarm_date BIGINT,
            alarm_severity SMALLINT,
            alarm_name TEXT,
            alarm_description TEXT,
            alarm_type SMALLINT NOT NULL,
            alarm_subtype INTEGER NOT NULL,
            source SMALLINT NOT NULL,
            control_rule_id TEXT,
            control_task_id TEXT,
            procedure_technique_id JSONB,
            session_id TEXT,
            ip_version SMALLINT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            terminal_id TEXT,
            source_file_path TEXT,
            host_name TEXT,
            terminal_ip TEXT,
            user_account TEXT,
            terminal_os TEXT,
            dst_process_md5 TEXT,
            dst_process_path TEXT,
            dst_process_cli TEXT,
            src_process_md5 TEXT,
            src_process_path TEXT,
            src_process_cli TEXT,
            register_key_name TEXT,
            register_key_value TEXT,
            register_path TEXT,
            file_name TEXT,
            file_md5 TEXT,
            file_path TEXT,
            data JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    // 无效告警表 - 保存解析失败的原始数据与错误信息
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS invalid_alerts (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            data JSONB NOT NULL,
            alert_type TEXT NOT NULL,
            error TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// 删除所有原始告警表
pub async fn drop_raw_alerts_tables(pool: &PgPool) -> Result<()> {
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

// ============================================================================
// 插入操作
// ============================================================================

/// 统一的原始告警存储函数
pub async fn store_raw_alert(pool: &PgPool, alert_json: &Value, alert_type: &str) -> Result<Uuid> {
    let id = match alert_type {
        "network_attack" => {
            let alert: NetworkAttackAlert = serde_json::from_value(alert_json.clone())?;
            insert_network_attack(pool, &alert).await?
        }
        "malicious_sample" => {
            let alert: MaliciousSampleAlert = serde_json::from_value(alert_json.clone())?;
            insert_malicious_sample(pool, &alert).await?
        }
        "host_behavior" => {
            let alert: HostBehaviorAlert = serde_json::from_value(alert_json.clone())?;
            insert_host_behavior(pool, &alert).await?
        }
        _ => return Err(anyhow::anyhow!("Unsupported alert type: {}", alert_type)),
    };
    Ok(id)
}

pub async fn insert_network_attack(pool: &PgPool, alert: &NetworkAttackAlert) -> Result<Uuid> {
    let procedure_technique_id = alert.procedure_technique_id.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
    });

    let id: (Uuid,) = sqlx::query_as(
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
        ) RETURNING id",
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity.map(|v| v as i16))
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
    .fetch_one(pool)
    .await?;

    Ok(id.0)
}

pub async fn insert_malicious_sample(pool: &PgPool, alert: &MaliciousSampleAlert) -> Result<Uuid> {
    let procedure_technique_id = alert.procedure_technique_id.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
    });

    let sample_alarm_engine = alert.sample_alarm_engine.as_ref().map(|v| {
        serde_json::Value::Array(
            v.iter()
                .cloned()
                .map(|n| serde_json::Value::Number(serde_json::Number::from(n)))
                .collect(),
        )
    });

    let id: (Uuid,) = sqlx::query_as(
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
        ) RETURNING id",
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity.map(|v| v as i16))
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
    .bind(alert.sample_source.map(|v| v as i16))
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
    .bind(alert.file_size.map(|v| v as i64))
    .bind(&alert.language)
    .bind(&alert.rule)
    .bind(&alert.target_content)
    .bind(alert.compile_date)
    .bind(alert.last_analy_date)
    .bind(&alert.sample_alarm_detail)
    .bind(&alert.data)
    .fetch_one(pool)
    .await?;

    Ok(id.0)
}

pub async fn insert_host_behavior(pool: &PgPool, alert: &HostBehaviorAlert) -> Result<Uuid> {
    let procedure_technique_id = alert.procedure_technique_id.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
    });

    let id: (Uuid,) = sqlx::query_as(
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
        ) RETURNING id",
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity.map(|v| v as i16))
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
    .fetch_one(pool)
    .await?;

    Ok(id.0)
}

pub async fn store_invalid_alert(
    pool: &PgPool,
    data: &Value,
    alert_type: &str,
    error: String,
) -> Result<()> {
    sqlx::query("INSERT INTO invalid_alerts (data, alert_type, error) VALUES ($1, $2, $3)")
        .bind(data)
        .bind(alert_type)
        .bind(&error)
        .execute(pool)
        .await?;

    Ok(())
}

// ============================================================================
// 查询操作
// ============================================================================

#[allow(dead_code)]
pub async fn query_network_attacks(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<NetworkAttackRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, NetworkAttackRecord>(
        "SELECT * FROM network_attack_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2",
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

#[allow(dead_code)]
pub async fn query_malicious_samples(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<MaliciousSampleRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, MaliciousSampleRecord>(
        "SELECT * FROM malicious_sample_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2",
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

#[allow(dead_code)]
pub async fn query_host_behaviors(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<HostBehaviorRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, HostBehaviorRecord>(
        "SELECT * FROM host_behavior_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2",
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

pub async fn query_invalid_alerts(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<InvalidAlertRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, InvalidAlertRecord>(
        "SELECT * FROM invalid_alerts ORDER BY created_at DESC LIMIT $1 OFFSET $2",
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

// ============================================================================
// 根据收敛告警ID查询原始告警
// ============================================================================

/// 根据收敛告警ID查询网络攻击原始告警列表
pub async fn query_raw_network_attacks_by_converged_id(
    pool: &PgPool,
    converged_id: Uuid,
) -> Result<Vec<NetworkAttackRecord>> {
    // 先从映射表获取原始告警ID列表
    let raw_ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT raw_alert_id FROM alert_convergence_mapping 
         WHERE converged_alert_id = $1 AND alert_type = 1
         ORDER BY created_at ASC",
    )
    .bind(converged_id)
    .fetch_all(pool)
    .await?;

    if raw_ids.is_empty() {
        return Ok(vec![]);
    }

    // 提取ID列表
    let ids: Vec<Uuid> = raw_ids.into_iter().map(|(id,)| id).collect();

    // 查询原始告警详情
    let records = sqlx::query_as::<_, NetworkAttackRecord>(
        "SELECT * FROM network_attack_alerts 
         WHERE id = ANY($1)
         ORDER BY created_at ASC",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

/// 根据收敛告警ID查询恶意样本原始告警列表
pub async fn query_raw_malicious_samples_by_converged_id(
    pool: &PgPool,
    converged_id: Uuid,
) -> Result<Vec<MaliciousSampleRecord>> {
    // 先从映射表获取原始告警ID列表
    let raw_ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT raw_alert_id FROM alert_convergence_mapping 
         WHERE converged_alert_id = $1 AND alert_type = 2
         ORDER BY created_at ASC",
    )
    .bind(converged_id)
    .fetch_all(pool)
    .await?;

    if raw_ids.is_empty() {
        return Ok(vec![]);
    }

    // 提取ID列表
    let ids: Vec<Uuid> = raw_ids.into_iter().map(|(id,)| id).collect();

    // 查询原始告警详情
    let records = sqlx::query_as::<_, MaliciousSampleRecord>(
        "SELECT * FROM malicious_sample_alerts 
         WHERE id = ANY($1)
         ORDER BY created_at ASC",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    Ok(records)
}

/// 根据收敛告警ID查询主机行为原始告警列表
pub async fn query_raw_host_behaviors_by_converged_id(
    pool: &PgPool,
    converged_id: Uuid,
) -> Result<Vec<HostBehaviorRecord>> {
    // 先从映射表获取原始告警ID列表
    let raw_ids: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT raw_alert_id FROM alert_convergence_mapping 
         WHERE converged_alert_id = $1 AND alert_type = 3
         ORDER BY created_at ASC",
    )
    .bind(converged_id)
    .fetch_all(pool)
    .await?;

    if raw_ids.is_empty() {
        return Ok(vec![]);
    }

    // 提取ID列表
    let ids: Vec<Uuid> = raw_ids.into_iter().map(|(id,)| id).collect();

    // 查询原始告警详情
    let records = sqlx::query_as::<_, HostBehaviorRecord>(
        "SELECT * FROM host_behavior_alerts 
         WHERE id = ANY($1)
         ORDER BY created_at ASC",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    Ok(records)
}
