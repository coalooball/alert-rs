use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 告警-标签映射记录 - 数据库模型
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AlertTagMappingRecord {
    pub id: Uuid,
    pub alert_id: Uuid,
    pub alert_type: String, // "network_attack", "malicious_sample", "host_behavior"
    pub tag_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// 告警标签映射输入
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AlertTagMappingInput {
    pub alert_id: Uuid,
    pub alert_type: String,
    pub tag_id: Uuid,
}

/// 创建告警-标签映射表
pub async fn create_alert_tag_mapping_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alert_tag_mapping (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            alert_id UUID NOT NULL,
            alert_type TEXT NOT NULL,
            tag_id UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ DEFAULT now(),
            UNIQUE(alert_id, alert_type, tag_id)
        )",
    )
    .execute(pool)
    .await?;

    // 创建索引以优化查询
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_alert_tag_mapping_alert ON alert_tag_mapping(alert_id, alert_type)"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_alert_tag_mapping_tag ON alert_tag_mapping(tag_id)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// 删除告警-标签映射表
pub async fn drop_alert_tag_mapping_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS alert_tag_mapping CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 添加告警-标签映射
pub async fn add_alert_tag(
    pool: &PgPool,
    input: &AlertTagMappingInput,
) -> Result<AlertTagMappingRecord> {
    let record = sqlx::query_as::<_, AlertTagMappingRecord>(
        "INSERT INTO alert_tag_mapping (alert_id, alert_type, tag_id)
         VALUES ($1, $2, $3)
         ON CONFLICT (alert_id, alert_type, tag_id) DO UPDATE 
         SET created_at = alert_tag_mapping.created_at
         RETURNING *",
    )
    .bind(input.alert_id)
    .bind(&input.alert_type)
    .bind(input.tag_id)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 删除告警-标签映射
pub async fn remove_alert_tag(
    pool: &PgPool,
    alert_id: Uuid,
    alert_type: &str,
    tag_id: Uuid,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM alert_tag_mapping 
         WHERE alert_id = $1 AND alert_type = $2 AND tag_id = $3",
    )
    .bind(alert_id)
    .bind(alert_type)
    .bind(tag_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 获取告警的所有标签
pub async fn get_alert_tags(
    pool: &PgPool,
    alert_id: Uuid,
    alert_type: &str,
) -> Result<Vec<crate::db::tag_management::TagRecord>> {
    let tags = sqlx::query_as(
        "SELECT t.* FROM tags t
         INNER JOIN alert_tag_mapping atm ON t.id = atm.tag_id
         WHERE atm.alert_id = $1 AND atm.alert_type = $2
         ORDER BY t.name",
    )
    .bind(alert_id)
    .bind(alert_type)
    .fetch_all(pool)
    .await?;

    Ok(tags)
}

/// 获取某个标签关联的所有告警
pub async fn get_alerts_by_tag(pool: &PgPool, tag_id: Uuid) -> Result<Vec<AlertTagMappingRecord>> {
    let mappings = sqlx::query_as::<_, AlertTagMappingRecord>(
        "SELECT * FROM alert_tag_mapping WHERE tag_id = $1 ORDER BY created_at DESC",
    )
    .bind(tag_id)
    .fetch_all(pool)
    .await?;

    Ok(mappings)
}

/// 删除某个告警的所有标签
pub async fn remove_all_alert_tags(pool: &PgPool, alert_id: Uuid, alert_type: &str) -> Result<()> {
    sqlx::query("DELETE FROM alert_tag_mapping WHERE alert_id = $1 AND alert_type = $2")
        .bind(alert_id)
        .bind(alert_type)
        .execute(pool)
        .await?;

    Ok(())
}

/// 批量添加告警-标签映射
pub async fn add_alert_tags_batch(
    pool: &PgPool,
    alert_id: Uuid,
    alert_type: &str,
    tag_ids: &[Uuid],
) -> Result<Vec<AlertTagMappingRecord>> {
    let mut records = Vec::new();

    for tag_id in tag_ids {
        let input = AlertTagMappingInput {
            alert_id,
            alert_type: alert_type.to_string(),
            tag_id: *tag_id,
        };
        let record = add_alert_tag(pool, &input).await?;
        records.push(record);
    }

    Ok(records)
}
