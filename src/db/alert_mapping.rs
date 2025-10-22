//! 告警收敛映射表
//!
//! 本模块定义原始告警与收敛后告警之间的映射关系表
//! 用于追溯收敛后告警对应的所有原始告警

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

// ============================================================================
// Record 结构体定义
// ============================================================================

/// 告警收敛映射记录
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AlertConvergenceMappingRecord {
    pub id: Uuid,
    pub raw_alert_id: Uuid,       // 原始告警的UUID
    pub converged_alert_id: Uuid, // 收敛后告警的UUID
    pub alert_type: i16,          // 告警类型 (1: 网络攻击, 2: 恶意样本, 3: 主机行为)
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// 建表/删表操作
// ============================================================================

/// 创建告警收敛映射表
pub async fn create_alert_mapping_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alert_convergence_mapping (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            raw_alert_id uuid NOT NULL,
            converged_alert_id uuid NOT NULL,
            alert_type SMALLINT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now(),
            CONSTRAINT fk_alert_type CHECK (alert_type IN (1, 2, 3))
        )",
    )
    .execute(pool)
    .await?;

    // 创建索引以提高查询性能
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_raw_alert_id 
         ON alert_convergence_mapping(raw_alert_id)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_converged_alert_id 
         ON alert_convergence_mapping(converged_alert_id)",
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// 删除告警收敛映射表
pub async fn drop_alert_mapping_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS alert_convergence_mapping CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

// ============================================================================
// 插入操作
// ============================================================================

/// 插入单个映射记录
pub async fn insert_mapping(
    pool: &PgPool,
    raw_alert_id: Uuid,
    converged_alert_id: Uuid,
    alert_type: i16,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO alert_convergence_mapping (raw_alert_id, converged_alert_id, alert_type)
         VALUES ($1, $2, $3)",
    )
    .bind(raw_alert_id)
    .bind(converged_alert_id)
    .bind(alert_type)
    .execute(pool)
    .await?;

    Ok(())
}

/// 批量插入映射记录
#[allow(dead_code)]
pub async fn insert_mappings_batch(
    pool: &PgPool,
    raw_alert_ids: &[Uuid],
    converged_alert_id: Uuid,
    alert_type: i16,
) -> Result<()> {
    let mut tx = pool.begin().await?;

    for raw_alert_id in raw_alert_ids {
        sqlx::query(
            "INSERT INTO alert_convergence_mapping (raw_alert_id, converged_alert_id, alert_type)
             VALUES ($1, $2, $3)",
        )
        .bind(raw_alert_id)
        .bind(converged_alert_id)
        .bind(alert_type)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

// ============================================================================
// 查询操作
// ============================================================================

/// 根据收敛后告警ID查询所有原始告警ID
#[allow(dead_code)]
pub async fn query_raw_alerts_by_converged_id(
    pool: &PgPool,
    converged_alert_id: Uuid,
) -> Result<Vec<Uuid>> {
    let records: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT raw_alert_id FROM alert_convergence_mapping 
         WHERE converged_alert_id = $1 
         ORDER BY created_at ASC",
    )
    .bind(converged_alert_id)
    .fetch_all(pool)
    .await?;

    Ok(records.into_iter().map(|(id,)| id).collect())
}

/// 根据原始告警ID查询对应的收敛后告警ID
#[allow(dead_code)]
pub async fn query_converged_alert_by_raw_id(
    pool: &PgPool,
    raw_alert_id: Uuid,
) -> Result<Option<Uuid>> {
    let record: Option<(Uuid,)> = sqlx::query_as(
        "SELECT converged_alert_id FROM alert_convergence_mapping 
         WHERE raw_alert_id = $1 
         LIMIT 1",
    )
    .bind(raw_alert_id)
    .fetch_optional(pool)
    .await?;

    Ok(record.map(|(id,)| id))
}

/// 查询收敛后告警包含的原始告警数量
#[allow(dead_code)]
pub async fn count_raw_alerts_by_converged_id(
    pool: &PgPool,
    converged_alert_id: Uuid,
) -> Result<i64> {
    let count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM alert_convergence_mapping 
         WHERE converged_alert_id = $1",
    )
    .bind(converged_alert_id)
    .fetch_one(pool)
    .await?;

    Ok(count.0)
}

/// 查询指定收敛告警的所有映射记录（包含完整信息）
#[allow(dead_code)]
pub async fn query_mappings_by_converged_id(
    pool: &PgPool,
    converged_alert_id: Uuid,
) -> Result<Vec<AlertConvergenceMappingRecord>> {
    let records = sqlx::query_as::<_, AlertConvergenceMappingRecord>(
        "SELECT * FROM alert_convergence_mapping 
         WHERE converged_alert_id = $1 
         ORDER BY created_at ASC",
    )
    .bind(converged_alert_id)
    .fetch_all(pool)
    .await?;

    Ok(records)
}
