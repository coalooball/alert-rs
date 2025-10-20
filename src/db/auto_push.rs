use anyhow::Result;
use sqlx::{PgPool};
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct AutoPushConfig {
    pub id: Uuid,
    pub name: String,
    pub enabled: bool,
    pub window_minutes: i32,
    pub interval_seconds: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct PushLogRecord {
    pub id: Uuid,
    pub alert_type: i16,          // 1/2/3
    pub converged_id: Uuid,       // 收敛告警ID
    pub pushed_at: DateTime<Utc>,
}

pub async fn create_auto_push_tables(pool: &PgPool) -> Result<()> {
    // 检查旧表是否存在，如果存在则迁移 
    let table_exists: (bool,) = sqlx::query_as(
        "SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = 'auto_push_config'
        )"
    ).fetch_one(pool).await?;
    
    if table_exists.0 {
        // 检查是否是旧结构（通过检查 name 列是否存在）
        let name_col_exists: (bool,) = sqlx::query_as( 
            "SELECT EXISTS ( 
                SELECT FROM information_schema.columns 
                WHERE table_name = 'auto_push_config' 
                AND column_name = 'name'
            )"
        ).fetch_one(pool).await?;
        
        if !name_col_exists.0 {
            // 旧结构，需要迁移
            tracing::info!("Migrating auto_push_config table from old structure to new structure...");
            
            // 读取旧数据
            let old_config: Option<(bool, i32, i32)> = sqlx::query_as(
                "SELECT enabled, window_minutes, interval_seconds FROM auto_push_config WHERE id = 1"
            ).fetch_optional(pool).await?;
            
            // 删除旧表
            sqlx::query("DROP TABLE IF EXISTS auto_push_config").execute(pool).await?;
            
            // 创建新表
            sqlx::query(
                "CREATE TABLE auto_push_config (
                    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                    name TEXT NOT NULL,
                    enabled BOOLEAN NOT NULL DEFAULT FALSE,
                    window_minutes INTEGER NOT NULL DEFAULT 60,
                    interval_seconds INTEGER NOT NULL DEFAULT 60,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )"
            ).execute(pool).await?;
            
            // 如果有旧数据，迁移过来
            if let Some((enabled, window_minutes, interval_seconds)) = old_config {
                sqlx::query(
                    "INSERT INTO auto_push_config (name, enabled, window_minutes, interval_seconds) 
                     VALUES ($1, $2, $3, $4)"
                ).bind("默认配置").bind(enabled).bind(window_minutes).bind(interval_seconds)
                .execute(pool).await?;
                
                tracing::info!("Migrated old config to new structure with name '默认配置'");
            }
            
            tracing::info!("Migration completed successfully");
        }
    } else {
        // 表不存在，直接创建新表
        sqlx::query(
            "CREATE TABLE auto_push_config (
                id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL,
                enabled BOOLEAN NOT NULL DEFAULT FALSE,
                window_minutes INTEGER NOT NULL DEFAULT 60,
                interval_seconds INTEGER NOT NULL DEFAULT 60,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )"
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

// CRUD 操作
pub async fn list_auto_push_configs(pool: &PgPool) -> Result<Vec<AutoPushConfig>> {
    let configs = sqlx::query_as::<_, AutoPushConfig>(
        "SELECT id, name, enabled, window_minutes, interval_seconds, created_at, updated_at 
         FROM auto_push_config 
         ORDER BY created_at DESC"
    ).fetch_all(pool).await?;
    Ok(configs)
}

pub async fn get_auto_push_config(pool: &PgPool, id: Uuid) -> Result<AutoPushConfig> {
    let cfg = sqlx::query_as::<_, AutoPushConfig>(
        "SELECT id, name, enabled, window_minutes, interval_seconds, created_at, updated_at 
         FROM auto_push_config WHERE id = $1"
    ).bind(id).fetch_one(pool).await?;
    Ok(cfg)
}

pub async fn create_auto_push_config(pool: &PgPool, name: String, enabled: bool, window_minutes: i32, interval_seconds: i32) -> Result<Uuid> {
    let row: (Uuid,) = sqlx::query_as(
        "INSERT INTO auto_push_config (name, enabled, window_minutes, interval_seconds) 
         VALUES ($1, $2, $3, $4) RETURNING id"
    ).bind(name).bind(enabled).bind(window_minutes).bind(interval_seconds)
    .fetch_one(pool).await?;
    Ok(row.0)
}

pub async fn update_auto_push_config(pool: &PgPool, id: Uuid, name: String, enabled: bool, window_minutes: i32, interval_seconds: i32) -> Result<()> {
    sqlx::query(
        "UPDATE auto_push_config SET name=$1, enabled=$2, window_minutes=$3, interval_seconds=$4, updated_at=now() WHERE id=$5"
    ).bind(name).bind(enabled).bind(window_minutes).bind(interval_seconds).bind(id)
    .execute(pool).await?;
    Ok(())
}

pub async fn delete_auto_push_config(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM auto_push_config WHERE id = $1")
        .bind(id).execute(pool).await?;
    Ok(())
}

// 获取所有启用的配置（用于自动推送任务）
pub async fn get_enabled_configs(pool: &PgPool) -> Result<Vec<AutoPushConfig>> {
    let configs = sqlx::query_as::<_, AutoPushConfig>(
        "SELECT id, name, enabled, window_minutes, interval_seconds, created_at, updated_at 
         FROM auto_push_config 
         WHERE enabled = true
         ORDER BY created_at"
    ).fetch_all(pool).await?;
    Ok(configs)
}

pub async fn has_been_pushed(pool: &PgPool, alert_type: i16, converged_id: Uuid) -> Result<bool> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM converged_push_logs WHERE alert_type=$1 AND converged_id=$2"
    ).bind(alert_type).bind(converged_id).fetch_one(pool).await?;
    Ok(row.0 > 0)
}

pub async fn insert_push_log(pool: &PgPool, alert_type: i16, converged_id: Uuid) -> Result<()> {
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


