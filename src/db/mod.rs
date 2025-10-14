use anyhow::Result;
use rbatis::RBatis;
use rbdc_pg::driver::PgDriver;
use rbs::value;
use uuid::Uuid;

use crate::config::PostgresConfig;
use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};

pub async fn init_postgres(pg: &PostgresConfig) -> Result<RBatis> {
    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        pg.user, pg.password, pg.host, pg.port, pg.database
    );
    let rb = RBatis::new();
    rb.init(PgDriver {}, &dsn)?;

    // DDL: 最小必要字段 + 原始JSON
    rb.exec(
        "CREATE TABLE IF NOT EXISTS network_attack_alerts (
            id uuid PRIMARY KEY,
            alarm_id TEXT NOT NULL,
            alarm_date BIGINT NOT NULL,
            payload TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
        vec![],
    ).await?;

    rb.exec(
        "CREATE TABLE IF NOT EXISTS malicious_sample_alerts (
            id uuid PRIMARY KEY,
            alarm_id TEXT NOT NULL,
            alarm_date BIGINT NOT NULL,
            payload TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
        vec![],
    ).await?;

    rb.exec(
        "CREATE TABLE IF NOT EXISTS host_behavior_alerts (
            id uuid PRIMARY KEY,
            alarm_id TEXT NOT NULL,
            alarm_date BIGINT NOT NULL,
            payload TEXT NOT NULL,
            created_at TIMESTAMPTZ DEFAULT now()
        )",
        vec![],
    ).await?;

    Ok(rb)
}

pub async fn insert_network_attack(rb: &RBatis, alert: &NetworkAttackAlert, raw: &str) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    rb.exec(
        "INSERT INTO network_attack_alerts (id, alarm_id, alarm_date, payload) VALUES (?,?,?,?)",
        vec![
            value!(id),
            value!(alert.alarm_id.clone()),
            value!(alert.alarm_date),
            value!(raw.to_string()),
        ],
    ).await?;
    Ok(())
}

pub async fn insert_malicious_sample(rb: &RBatis, alert: &MaliciousSampleAlert, raw: &str) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    rb.exec(
        "INSERT INTO malicious_sample_alerts (id, alarm_id, alarm_date, payload) VALUES (?,?,?,?)",
        vec![
            value!(id),
            value!(alert.alarm_id.clone()),
            value!(alert.alarm_date),
            value!(raw.to_string()),
        ],
    ).await?;
    Ok(())
}

pub async fn insert_host_behavior(rb: &RBatis, alert: &HostBehaviorAlert, raw: &str) -> Result<()> {
    let id = Uuid::new_v4().to_string();
    rb.exec(
        "INSERT INTO host_behavior_alerts (id, alarm_id, alarm_date, payload) VALUES (?,?,?,?)",
        vec![
            value!(id),
            value!(alert.alarm_id.clone()),
            value!(alert.alarm_date),
            value!(raw.to_string()),
        ],
    ).await?;
    Ok(())
}


