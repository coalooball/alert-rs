use anyhow::Result;
use sqlx::{PgPool};
use chrono::{DateTime, Utc};
// use uuid::Uuid;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AutoPushConfig {
    pub id: i16,
    pub name: String,
    pub enabled: bool,
    pub window_minutes: i32,
    pub interval_seconds: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct PushLogRecord {
    pub id: uuid::Uuid,
    pub alert_type: i16,          // 1/2/3
    pub converged_id: uuid::Uuid,       // 收敛告警ID
    pub pushed_at: DateTime<Utc>,
}

pub async fn create_auto_push_tables(pool: &PgPool) -> Result<()> {
    // 创建配置表，如果不存在
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS auto_push_config (
            id SMALLINT PRIMARY KEY DEFAULT 1,
            name TEXT NOT NULL,
            enabled BOOLEAN NOT NULL DEFAULT FALSE,
            window_minutes INTEGER NOT NULL DEFAULT 60,
            interval_seconds INTEGER NOT NULL DEFAULT 60,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )"
    ).execute(pool).await?;

    // 检查是否已有默认配置
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auto_push_config WHERE id=1)")
        .fetch_one(pool)
        .await?;

    if !exists {
        sqlx::query(
            "INSERT INTO auto_push_config (id, name) VALUES (1, '默认配置')"
        ).execute(pool).await?;
    }

    // 推送日志表
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS converged_push_logs (
            id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
            alert_type SMALLINT NOT NULL,
            converged_id uuid NOT NULL,
            pushed_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )"
    ).execute(pool).await?;
    Ok(())
}

// 获取唯一配置
pub async fn get_auto_push_config(pool: &PgPool) -> Result<AutoPushConfig> {
    let cfg = sqlx::query_as::<_, AutoPushConfig>(
        "SELECT id, name, enabled, window_minutes, interval_seconds, created_at, updated_at 
         FROM auto_push_config WHERE id = 1"
    ).fetch_one(pool).await?;
    Ok(cfg)
}

// 更新唯一配置
pub async fn update_auto_push_config(pool: &PgPool, name: String, enabled: bool, window_minutes: i32, interval_seconds: i32) -> Result<()> {
    sqlx::query(
        "UPDATE auto_push_config 
         SET name=$1, enabled=$2, window_minutes=$3, interval_seconds=$4, updated_at=now() 
         WHERE id=1"
    ).bind(name).bind(enabled).bind(window_minutes).bind(interval_seconds)
    .execute(pool).await?;
    Ok(())
}

pub async fn insert_push_log(pool: &PgPool, alert_type: i16, converged_id: uuid::Uuid) -> Result<()> {
    sqlx::query(
        "INSERT INTO converged_push_logs (alert_type, converged_id) VALUES ($1, $2)"
    ).bind(alert_type).bind(converged_id).execute(pool).await?;
    Ok(())
}

// 查询推送日志（分页）
pub async fn list_push_logs(pool: &PgPool, page: u64, page_size: u64) -> Result<(Vec<PushLogRecord>, u64)> {
    let offset = (page - 1) * page_size;
    
    // 查询总数
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM converged_push_logs")
        .fetch_one(pool).await?;
    let total = row.0 as u64;
    
    // 查询数据
    let logs = sqlx::query_as::<_, PushLogRecord>(
        "SELECT id, alert_type, converged_id, pushed_at 
         FROM converged_push_logs 
         ORDER BY pushed_at DESC 
         LIMIT $1 OFFSET $2"
    ).bind(page_size as i64).bind(offset as i64)
    .fetch_all(pool).await?;
    
    Ok((logs, total))
}

// 根据告警类型查询推送日志
pub async fn list_push_logs_by_type(pool: &PgPool, alert_type: i16, page: u64, page_size: u64) -> Result<(Vec<PushLogRecord>, u64)> {
    let offset = (page - 1) * page_size;
    
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM converged_push_logs WHERE alert_type=$1")
        .bind(alert_type).fetch_one(pool).await?;
    let total = row.0 as u64;
    
    let logs = sqlx::query_as::<_, PushLogRecord>(
        "SELECT id, alert_type, converged_id, pushed_at 
         FROM converged_push_logs 
         WHERE alert_type = $1
         ORDER BY pushed_at DESC 
         LIMIT $2 OFFSET $3"
    ).bind(alert_type).bind(page_size as i64).bind(offset as i64)
    .fetch_all(pool).await?;
    
    Ok((logs, total))
}


