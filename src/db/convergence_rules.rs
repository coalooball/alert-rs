use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 收敛规则记录 - 数据库模型
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct ConvergenceRuleRecord {
    pub id: Uuid,
    pub name: String,
    pub dsl_rule: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 收敛规则输入 - 用于创建和更新
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConvergenceRuleInput {
    pub name: String,
    pub dsl_rule: String,
    pub description: Option<String>,
    pub enabled: bool,
}

/// 创建收敛规则表
pub async fn create_convergence_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS convergence_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            dsl_rule TEXT NOT NULL,
            description TEXT,
            enabled BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_convergence_rules_enabled ON convergence_rules(enabled)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// 删除收敛规则表
pub async fn drop_convergence_rules_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS convergence_rules CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 创建收敛规则
pub async fn create_convergence_rule(
    pool: &PgPool,
    input: &ConvergenceRuleInput,
) -> Result<ConvergenceRuleRecord> {
    let record = sqlx::query_as::<_, ConvergenceRuleRecord>(
        "INSERT INTO convergence_rules (name, dsl_rule, description, enabled)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
    )
    .bind(&input.name)
    .bind(&input.dsl_rule)
    .bind(&input.description)
    .bind(input.enabled)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 更新收敛规则
pub async fn update_convergence_rule(
    pool: &PgPool,
    id: Uuid,
    input: &ConvergenceRuleInput,
) -> Result<ConvergenceRuleRecord> {
    let record = sqlx::query_as::<_, ConvergenceRuleRecord>(
        "UPDATE convergence_rules
         SET name = $2, dsl_rule = $3, description = $4, enabled = $5, updated_at = now()
         WHERE id = $1
         RETURNING *",
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

/// 删除收敛规则
pub async fn delete_convergence_rule(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM convergence_rules WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 根据ID查询单个收敛规则
pub async fn get_convergence_rule_by_id(pool: &PgPool, id: Uuid) -> Result<ConvergenceRuleRecord> {
    let record =
        sqlx::query_as::<_, ConvergenceRuleRecord>("SELECT * FROM convergence_rules WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;

    Ok(record)
}

/// 查询收敛规则列表（支持分页）
pub async fn query_convergence_rules(
    pool: &PgPool,
    page: u64,
    page_size: u64,
) -> Result<(Vec<ConvergenceRuleRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let records = sqlx::query_as::<_, ConvergenceRuleRecord>(
        "SELECT * FROM convergence_rules ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(page_size as i64)
    .bind(offset as i64)
    .fetch_all(pool)
    .await?;

    let total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM convergence_rules")
        .fetch_one(pool)
        .await?;

    Ok((records, total.0 as u64))
}

/// 查询所有启用的收敛规则
#[allow(dead_code)]
pub async fn get_enabled_convergence_rules(pool: &PgPool) -> Result<Vec<ConvergenceRuleRecord>> {
    let records = sqlx::query_as::<_, ConvergenceRuleRecord>(
        "SELECT * FROM convergence_rules WHERE enabled = true ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}
