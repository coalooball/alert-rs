use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 关联规则记录 - 数据库模型
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct CorrelationRuleRecord {
    pub id: Uuid,
    pub name: String,
    pub dsl_rule: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 关联规则输入 - 用于创建和更新
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorrelationRuleInput {
    pub name: String,
    pub dsl_rule: String,
    pub description: Option<String>,
    pub enabled: bool,
}

/// 创建关联规则表
pub async fn create_correlation_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS correlation_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            dsl_rule TEXT NOT NULL,
            description TEXT,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )"
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_correlation_rules_enabled ON correlation_rules(enabled)"
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// 删除关联规则表
pub async fn drop_correlation_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS correlation_rules CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 创建关联规则
pub async fn create_correlation_rule(pool: &PgPool, input: &CorrelationRuleInput) -> Result<CorrelationRuleRecord> {
    let record = sqlx::query_as::<_, CorrelationRuleRecord>(
        "INSERT INTO correlation_rules (name, dsl_rule, description, enabled)
         VALUES ($1, $2, $3, $4)
         RETURNING *"
    )
    .bind(&input.name)
    .bind(&input.dsl_rule)
    .bind(&input.description)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 更新关联规则
pub async fn update_correlation_rule(pool: &PgPool, id: Uuid, input: &CorrelationRuleInput) -> Result<CorrelationRuleRecord> {
    let record = sqlx::query_as::<_, CorrelationRuleRecord>(
        "UPDATE correlation_rules
         SET name = $2, dsl_rule = $3, description = $4, enabled = $5, updated_at = now()
         WHERE id = $1
         RETURNING *"
    )
    .bind(id)
    .bind(&input.name)
    .bind(&input.dsl_rule)
    .bind(&input.description)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 删除关联规则
pub async fn delete_correlation_rule(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM correlation_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 根据ID查询单个关联规则
pub async fn get_correlation_rule_by_id(pool: &PgPool, id: Uuid) -> Result<CorrelationRuleRecord> {
    let record = sqlx::query_as::<_, CorrelationRuleRecord>(
        "SELECT * FROM correlation_rules WHERE id = $1"
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 查询关联规则列表（支持分页）
pub async fn query_correlation_rules(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<CorrelationRuleRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, CorrelationRuleRecord>(
        "SELECT * FROM correlation_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2"
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM correlation_rules")
        .fetch_one(pool)
        .await?;

    Ok((records, total.0 as u64))
}

/// 查询所有启用的关联规则
#[allow(dead_code)]
pub async fn get_enabled_correlation_rules(pool: &PgPool) -> Result<Vec<CorrelationRuleRecord>> {
    let records = sqlx::query_as::<_, CorrelationRuleRecord>(
        "SELECT * FROM correlation_rules WHERE enabled = true ORDER BY created_at DESC"
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

