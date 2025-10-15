use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 威胁事件数据库记录
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ThreatEventRecord {
    pub id: Uuid,
    pub event_id: Option<i64>,
    pub system_code: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub event_type: Option<String>,
    pub attacker: Option<String>,
    pub victimer: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub found_time: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub mitre_technique_id: Option<String>,
    pub attsck_list: Option<String>,
    pub attack_tool: Option<String>,
    pub first_found_time: Option<DateTime<Utc>>,
    pub priority: Option<String>,
    pub severity: Option<String>,
    pub dispose_status: Option<String>,
    pub app: Option<String>,
    pub impact_assessment: Option<String>,
    pub merge_alerts: Option<serde_json::Value>,
    pub threat_actor: Option<serde_json::Value>,
    pub org: Option<serde_json::Value>,
    pub attack_asset_ip: Option<serde_json::Value>,
    pub victim_asset_ip: Option<serde_json::Value>,
    pub attack_asset_ip_port: Option<serde_json::Value>,
    pub victim_asset_ip_port: Option<serde_json::Value>,
    pub attack_asset_domain: Option<serde_json::Value>,
    pub victim_asset_domain: Option<serde_json::Value>,
    pub attack_url: Option<serde_json::Value>,
    pub victim_url: Option<serde_json::Value>,
    pub attack_malware: Option<serde_json::Value>,
    pub attack_malware_sample: Option<serde_json::Value>,
    pub attack_malware_sample_family: Option<serde_json::Value>,
    pub attack_email_address: Option<serde_json::Value>,
    pub victim_email_address: Option<serde_json::Value>,
    pub attack_email: Option<serde_json::Value>,
    pub victim_email: Option<serde_json::Value>,
    pub attack_software: Option<serde_json::Value>,
    pub victim_software: Option<serde_json::Value>,
    pub attack_vulnerability: Option<serde_json::Value>,
    pub attack_certificate: Option<serde_json::Value>,
    pub victim_certificate: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

/// 创建威胁事件表
pub async fn create_threat_event_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS threat_events (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            event_id BIGINT,
            system_code VARCHAR(32),
            name VARCHAR(256),
            description TEXT,
            event_type VARCHAR(32),
            attacker VARCHAR(256),
            victimer VARCHAR(256),
            start_time TIMESTAMPTZ,
            end_time TIMESTAMPTZ,
            found_time TIMESTAMPTZ,
            source TEXT,
            mitre_technique_id TEXT,
            attsck_list TEXT,
            attack_tool TEXT,
            first_found_time TIMESTAMPTZ,
            priority VARCHAR(32),
            severity VARCHAR(32),
            dispose_status VARCHAR(32),
            app TEXT,
            impact_assessment TEXT,
            merge_alerts JSONB,
            threat_actor JSONB,
            org JSONB,
            attack_asset_ip JSONB,
            victim_asset_ip JSONB,
            attack_asset_ip_port JSONB,
            victim_asset_ip_port JSONB,
            attack_asset_domain JSONB,
            victim_asset_domain JSONB,
            attack_url JSONB,
            victim_url JSONB,
            attack_malware JSONB,
            attack_malware_sample JSONB,
            attack_malware_sample_family JSONB,
            attack_email_address JSONB,
            victim_email_address JSONB,
            attack_email JSONB,
            victim_email JSONB,
            attack_software JSONB,
            victim_software JSONB,
            attack_vulnerability JSONB,
            attack_certificate JSONB,
            victim_certificate JSONB,
            created_at TIMESTAMPTZ DEFAULT now()
        )"
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// 插入威胁事件
#[allow(dead_code)]
pub async fn insert_threat_event(pool: &PgPool, event: &ThreatEventInput) -> Result<Uuid> {
    let id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO threat_events (
            event_id, system_code, name, description, event_type,
            attacker, victimer, start_time, end_time, found_time,
            source, mitre_technique_id, attsck_list, attack_tool, first_found_time,
            priority, severity, dispose_status, app, impact_assessment,
            merge_alerts, threat_actor, org,
            attack_asset_ip, victim_asset_ip, attack_asset_ip_port, victim_asset_ip_port,
            attack_asset_domain, victim_asset_domain, attack_url, victim_url,
            attack_malware, attack_malware_sample, attack_malware_sample_family,
            attack_email_address, victim_email_address, attack_email, victim_email,
            attack_software, victim_software, attack_vulnerability,
            attack_certificate, victim_certificate
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
            $41, $42, $43
        ) RETURNING id"
    )
    .bind(&event.event_id)
    .bind(&event.system_code)
    .bind(&event.name)
    .bind(&event.description)
    .bind(&event.event_type)
    .bind(&event.attacker)
    .bind(&event.victimer)
    .bind(&event.start_time)
    .bind(&event.end_time)
    .bind(&event.found_time)
    .bind(&event.source)
    .bind(&event.mitre_technique_id)
    .bind(&event.attsck_list)
    .bind(&event.attack_tool)
    .bind(&event.first_found_time)
    .bind(&event.priority)
    .bind(&event.severity)
    .bind(&event.dispose_status)
    .bind(&event.app)
    .bind(&event.impact_assessment)
    .bind(&event.merge_alerts)
    .bind(&event.threat_actor)
    .bind(&event.org)
    .bind(&event.attack_asset_ip)
    .bind(&event.victim_asset_ip)
    .bind(&event.attack_asset_ip_port)
    .bind(&event.victim_asset_ip_port)
    .bind(&event.attack_asset_domain)
    .bind(&event.victim_asset_domain)
    .bind(&event.attack_url)
    .bind(&event.victim_url)
    .bind(&event.attack_malware)
    .bind(&event.attack_malware_sample)
    .bind(&event.attack_malware_sample_family)
    .bind(&event.attack_email_address)
    .bind(&event.victim_email_address)
    .bind(&event.attack_email)
    .bind(&event.victim_email)
    .bind(&event.attack_software)
    .bind(&event.victim_software)
    .bind(&event.attack_vulnerability)
    .bind(&event.attack_certificate)
    .bind(&event.victim_certificate)
    .fetch_one(pool)
    .await?;

    Ok(id)
}

/// 查询威胁事件（分页）
pub async fn query_threat_events(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<ThreatEventRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, ThreatEventRecord>(
        "SELECT * FROM threat_events ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM threat_events")
        .fetch_one(pool)
        .await?;

    Ok((records, total.0 as u64))
}

/// 根据ID查询单个威胁事件
#[allow(dead_code)]
pub async fn get_threat_event_by_id(pool: &PgPool, id: Uuid) -> Result<Option<ThreatEventRecord>> {
    let record = sqlx::query_as::<_, ThreatEventRecord>(
        "SELECT * FROM threat_events WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

/// 更新威胁事件
pub async fn update_threat_event(pool: &PgPool, id: Uuid, event: &ThreatEventInput) -> Result<()> {
    sqlx::query(
        "UPDATE threat_events SET
            event_id = $2,
            system_code = $3,
            name = $4,
            description = $5,
            event_type = $6,
            attacker = $7,
            victimer = $8,
            start_time = $9,
            end_time = $10,
            found_time = $11,
            source = $12,
            mitre_technique_id = $13,
            attsck_list = $14,
            attack_tool = $15,
            first_found_time = $16,
            priority = $17,
            severity = $18,
            dispose_status = $19,
            app = $20,
            impact_assessment = $21,
            merge_alerts = $22,
            threat_actor = $23,
            org = $24,
            attack_asset_ip = $25,
            victim_asset_ip = $26,
            attack_asset_ip_port = $27,
            victim_asset_ip_port = $28,
            attack_asset_domain = $29,
            victim_asset_domain = $30,
            attack_url = $31,
            victim_url = $32,
            attack_malware = $33,
            attack_malware_sample = $34,
            attack_malware_sample_family = $35,
            attack_email_address = $36,
            victim_email_address = $37,
            attack_email = $38,
            victim_email = $39,
            attack_software = $40,
            victim_software = $41,
            attack_vulnerability = $42,
            attack_certificate = $43,
            victim_certificate = $44
        WHERE id = $1"
    )
    .bind(id)
    .bind(&event.event_id)
    .bind(&event.system_code)
    .bind(&event.name)
    .bind(&event.description)
    .bind(&event.event_type)
    .bind(&event.attacker)
    .bind(&event.victimer)
    .bind(&event.start_time)
    .bind(&event.end_time)
    .bind(&event.found_time)
    .bind(&event.source)
    .bind(&event.mitre_technique_id)
    .bind(&event.attsck_list)
    .bind(&event.attack_tool)
    .bind(&event.first_found_time)
    .bind(&event.priority)
    .bind(&event.severity)
    .bind(&event.dispose_status)
    .bind(&event.app)
    .bind(&event.impact_assessment)
    .bind(&event.merge_alerts)
    .bind(&event.threat_actor)
    .bind(&event.org)
    .bind(&event.attack_asset_ip)
    .bind(&event.victim_asset_ip)
    .bind(&event.attack_asset_ip_port)
    .bind(&event.victim_asset_ip_port)
    .bind(&event.attack_asset_domain)
    .bind(&event.victim_asset_domain)
    .bind(&event.attack_url)
    .bind(&event.victim_url)
    .bind(&event.attack_malware)
    .bind(&event.attack_malware_sample)
    .bind(&event.attack_malware_sample_family)
    .bind(&event.attack_email_address)
    .bind(&event.victim_email_address)
    .bind(&event.attack_email)
    .bind(&event.victim_email)
    .bind(&event.attack_software)
    .bind(&event.victim_software)
    .bind(&event.attack_vulnerability)
    .bind(&event.attack_certificate)
    .bind(&event.victim_certificate)
    .execute(pool)
    .await?;

    Ok(())
}

/// 删除威胁事件表
pub async fn drop_threat_event_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS threat_events CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 威胁事件输入结构（用于插入）
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatEventInput {
    pub event_id: Option<i64>,
    pub system_code: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub event_type: Option<String>,
    pub attacker: Option<String>,
    pub victimer: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub found_time: Option<DateTime<Utc>>,
    pub source: Option<String>,
    pub mitre_technique_id: Option<String>,
    pub attsck_list: Option<String>,
    pub attack_tool: Option<String>,
    pub first_found_time: Option<DateTime<Utc>>,
    pub priority: Option<String>,
    pub severity: Option<String>,
    pub dispose_status: Option<String>,
    pub app: Option<String>,
    pub impact_assessment: Option<String>,
    pub merge_alerts: Option<serde_json::Value>,
    pub threat_actor: Option<serde_json::Value>,
    pub org: Option<serde_json::Value>,
    pub attack_asset_ip: Option<serde_json::Value>,
    pub victim_asset_ip: Option<serde_json::Value>,
    pub attack_asset_ip_port: Option<serde_json::Value>,
    pub victim_asset_ip_port: Option<serde_json::Value>,
    pub attack_asset_domain: Option<serde_json::Value>,
    pub victim_asset_domain: Option<serde_json::Value>,
    pub attack_url: Option<serde_json::Value>,
    pub victim_url: Option<serde_json::Value>,
    pub attack_malware: Option<serde_json::Value>,
    pub attack_malware_sample: Option<serde_json::Value>,
    pub attack_malware_sample_family: Option<serde_json::Value>,
    pub attack_email_address: Option<serde_json::Value>,
    pub victim_email_address: Option<serde_json::Value>,
    pub attack_email: Option<serde_json::Value>,
    pub victim_email: Option<serde_json::Value>,
    pub attack_software: Option<serde_json::Value>,
    pub victim_software: Option<serde_json::Value>,
    pub attack_vulnerability: Option<serde_json::Value>,
    pub attack_certificate: Option<serde_json::Value>,
    pub victim_certificate: Option<serde_json::Value>,
}

