use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 过滤规则记录 - 数据库模型
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct FilterRuleRecord {
    pub id: Uuid,
    pub name: String,
    pub alert_type: String,
    pub alert_subtype: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 过滤规则输入 - 用于创建和更新
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FilterRuleInput {
    pub name: String,
    pub alert_type: String,
    pub alert_subtype: String,
    pub field: String,
    pub operator: String,
    pub value: String,
    pub enabled: bool,
}

/// 创建过滤规则表
pub async fn create_filter_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS filter_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            alert_subtype TEXT NOT NULL,
            field TEXT NOT NULL,
            operator TEXT NOT NULL,
            value TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_filter_rules_alert_type ON filter_rules(alert_type)",
    )
    .execute(pool)
    .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_filter_rules_enabled ON filter_rules(enabled)")
        .execute(pool)
        .await?;

    Ok(())
}

/// 删除过滤规则表
pub async fn drop_filter_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS filter_rules CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 创建过滤规则
pub async fn create_filter_rule(
    pool: &PgPool,
    input: &FilterRuleInput,
) -> Result<FilterRuleRecord> {
    let record = sqlx::query_as::<_, FilterRuleRecord>(
        "INSERT INTO filter_rules (name, alert_type, alert_subtype, field, operator, value, enabled)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *"
    )
    .bind(&input.name)
    .bind(&input.alert_type)
    .bind(&input.alert_subtype)
    .bind(&input.field)
    .bind(&input.operator)
    .bind(&input.value)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 更新过滤规则
pub async fn update_filter_rule(
    pool: &PgPool,
    id: Uuid,
    input: &FilterRuleInput,
) -> Result<FilterRuleRecord> {
    let record = sqlx::query_as::<_, FilterRuleRecord>(
        "UPDATE filter_rules
         SET name = $2, alert_type = $3, alert_subtype = $4, field = $5, 
             operator = $6, value = $7, enabled = $8, updated_at = now()
         WHERE id = $1
         RETURNING *",
    )
    .bind(id)
    .bind(&input.name)
    .bind(&input.alert_type)
    .bind(&input.alert_subtype)
    .bind(&input.field)
    .bind(&input.operator)
    .bind(&input.value)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 删除过滤规则
pub async fn delete_filter_rule(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM filter_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 根据ID查询单个过滤规则
pub async fn get_filter_rule_by_id(pool: &PgPool, id: Uuid) -> Result<FilterRuleRecord> {
    let record = sqlx::query_as::<_, FilterRuleRecord>("SELECT * FROM filter_rules WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;

    Ok(record)
}

/// 查询过滤规则列表（支持分页）
pub async fn query_filter_rules(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<FilterRuleRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, FilterRuleRecord>(
        "SELECT * FROM filter_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM filter_rules")
        .fetch_one(pool)
        .await?;

    Ok((records, total.0 as u64))
}

/// 查询所有启用的过滤规则
#[allow(dead_code)]
pub async fn get_enabled_filter_rules(pool: &PgPool) -> Result<Vec<FilterRuleRecord>> {
    let records = sqlx::query_as::<_, FilterRuleRecord>(
        "SELECT * FROM filter_rules WHERE enabled = true ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}
