use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 标签规则记录 - 数据库模型
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct TagRuleRecord {
    pub id: Uuid,
    pub name: String,
    pub alert_type: String,
    pub alert_subtype: String,
    pub condition_field: String,
    pub condition_operator: String,
    pub condition_value: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 标签规则输入 - 用于创建和更新
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagRuleInput {
    pub name: String,
    pub alert_type: String,
    pub alert_subtype: String,
    pub condition_field: String,
    pub condition_operator: String,
    pub condition_value: String,
    pub tags: Vec<String>,
    pub description: Option<String>,
    pub enabled: bool,
}

/// 创建标签规则表
pub async fn create_tag_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tag_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            alert_subtype TEXT NOT NULL,
            condition_field TEXT NOT NULL,
            condition_operator TEXT NOT NULL,
            condition_value TEXT NOT NULL,
            tags TEXT[] NOT NULL,
            description TEXT,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tag_rules_alert_type ON tag_rules(alert_type)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tag_rules_enabled ON tag_rules(enabled)")
        .execute(pool)
        .await?;

    Ok(())
}

/// 删除标签规则表
pub async fn drop_tag_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS tag_rules CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 创建标签规则
pub async fn create_tag_rule(pool: &PgPool, input: &TagRuleInput) -> Result<TagRuleRecord> {
    let record = sqlx::query_as::<_, TagRuleRecord>(
        "INSERT INTO tag_rules (name, alert_type, alert_subtype, condition_field, 
                                condition_operator, condition_value, tags, description, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING *",
    )
    .bind(&input.name)
    .bind(&input.alert_type)
    .bind(&input.alert_subtype)
    .bind(&input.condition_field)
    .bind(&input.condition_operator)
    .bind(&input.condition_value)
    .bind(&input.tags)
    .bind(&input.description)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 更新标签规则
pub async fn update_tag_rule(
    pool: &PgPool,
    id: Uuid,
    input: &TagRuleInput,
) -> Result<TagRuleRecord> {
    let record = sqlx::query_as::<_, TagRuleRecord>(
        "UPDATE tag_rules
         SET name = $2, alert_type = $3, alert_subtype = $4, condition_field = $5,
             condition_operator = $6, condition_value = $7, tags = $8, 
             description = $9, enabled = $10, updated_at = now()
         WHERE id = $1
         RETURNING *",
    )
    .bind(id)
    .bind(&input.name)
    .bind(&input.alert_type)
    .bind(&input.alert_subtype)
    .bind(&input.condition_field)
    .bind(&input.condition_operator)
    .bind(&input.condition_value)
    .bind(&input.tags)
    .bind(&input.description)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 删除标签规则
pub async fn delete_tag_rule(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM tag_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 根据ID查询单个标签规则
pub async fn get_tag_rule_by_id(pool: &PgPool, id: Uuid) -> Result<TagRuleRecord> {
    let record = sqlx::query_as::<_, TagRuleRecord>("SELECT * FROM tag_rules WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;

    Ok(record)
}

/// 查询标签规则列表（支持分页）
pub async fn query_tag_rules(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<TagRuleRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, TagRuleRecord>(
        "SELECT * FROM tag_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tag_rules")
        .fetch_one(pool)
        .await?;

    Ok((records, total.0 as u64))
}

/// 查询所有启用的标签规则
#[allow(dead_code)]
pub async fn get_enabled_tag_rules(pool: &PgPool) -> Result<Vec<TagRuleRecord>> {
    let records = sqlx::query_as::<_, TagRuleRecord>(
        "SELECT * FROM tag_rules WHERE enabled = true ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}
