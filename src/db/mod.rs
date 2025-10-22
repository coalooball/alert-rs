pub mod alert_mapping;
pub mod alert_tag_mapping;
pub mod auto_push;
pub mod converged_alerts;
pub mod convergence_rules;
pub mod correlation_rules;
pub mod filter_rules;
pub mod mock_converged_alerts;
pub mod mock_rules;
pub mod mock_tags;
pub mod mock_threat_events;
pub mod raw_alerts;
pub mod tag_management;
pub mod tag_rules;
pub mod threat_event;

use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::PostgresConfig;

pub use threat_event::{ThreatEventInput, ThreatEventRecord};

// 原始告警
pub use raw_alerts::{
    insert_host_behavior,
    insert_malicious_sample,
    insert_network_attack,
    query_invalid_alerts,
    query_raw_host_behaviors_by_converged_id,
    query_raw_malicious_samples_by_converged_id,
    // 根据收敛告警ID查询原始告警
    query_raw_network_attacks_by_converged_id,
    HostBehaviorRecord,
    InvalidAlertRecord,
    MaliciousSampleRecord,
    NetworkAttackRecord,
};

// 保留以备将来直接查询原始告警表使用
#[allow(unused_imports)]
pub use raw_alerts::{query_host_behaviors, query_malicious_samples, query_network_attacks};

// 收敛后告警 - 当前使用的主要查询接口
pub use converged_alerts::{
    query_converged_host_behaviors, query_converged_malicious_samples,
    query_converged_network_attacks, query_new_converged_host_behaviors,
    query_new_converged_malicious_samples, query_new_converged_network_attacks,
    ConvergedHostBehaviorRecord, ConvergedMaliciousSampleRecord, ConvergedNetworkAttackRecord,
};

// 收敛插入函数
pub use converged_alerts::{
    insert_converged_host_behavior, insert_converged_malicious_sample,
    insert_converged_network_attack,
};

// 收敛查询和更新函数
pub use converged_alerts::{
    find_converged_host_behavior_by_host_info, find_converged_malicious_sample_by_hash,
    find_converged_network_attack_by_five_tuple, increment_convergence_count_host_behavior,
    increment_convergence_count_malicious_sample, increment_convergence_count_network_attack,
};

// 映射表操作
pub use alert_mapping::insert_mapping;

// 统一导出存储函数
pub use raw_alerts::{store_invalid_alert, store_raw_alert};

// 映射表查询函数 - 保留给未来使用
#[allow(unused_imports)]
pub use alert_mapping::{
    count_raw_alerts_by_converged_id, insert_mappings_batch, query_converged_alert_by_raw_id,
    query_mappings_by_converged_id, query_raw_alerts_by_converged_id,
    AlertConvergenceMappingRecord,
};

pub async fn init_postgres(pg: &PostgresConfig) -> Result<PgPool> {
    let dsn = format!(
        "postgres://{}:{}@{}:{}/{}",
        pg.user, pg.password, pg.host, pg.port, pg.database
    );

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&dsn)
        .await?;

    // 启用 pgcrypto 扩展以支持 gen_random_uuid()
    sqlx::query("CREATE EXTENSION IF NOT EXISTS pgcrypto")
        .execute(&pool)
        .await?;

    // 原始告警表（网络攻击/恶意样本/主机行为/无效告警）
    raw_alerts::create_raw_alerts_tables(&pool).await?;

    // 收敛后告警表
    converged_alerts::create_converged_alerts_tables(&pool).await?;

    // 告警收敛映射表
    alert_mapping::create_alert_mapping_table(&pool).await?;

    // 自动推送配置与推送日志表
    auto_push::create_auto_push_tables(&pool).await?;

    // 威胁事件表
    threat_event::create_threat_event_table(&pool).await?;

    // 标签管理表
    tag_management::create_tag_table(&pool).await?;

    // 告警-标签映射表
    alert_tag_mapping::create_alert_tag_mapping_table(&pool).await?;

    // 自动化规则表
    convergence_rules::create_convergence_rules_table(&pool).await?;
    correlation_rules::create_correlation_rules_table(&pool).await?;
    filter_rules::create_filter_rules_table(&pool).await?;
    tag_rules::create_tag_rules_table(&pool).await?;

    Ok(pool)
}

/// 清空数据库中的业务表
pub async fn reset_database(pool: &PgPool) -> Result<()> {
    // 注意删除顺序：先删除映射表，再删除告警表
    alert_mapping::drop_alert_mapping_table(pool).await?;
    converged_alerts::drop_converged_alerts_tables(pool).await?;
    raw_alerts::drop_raw_alerts_tables(pool).await?;
    threat_event::drop_threat_event_table(pool).await?;
    alert_tag_mapping::drop_alert_tag_mapping_table(pool).await?;
    tag_management::drop_tag_table(pool).await?;
    // 删除自动化规则表
    convergence_rules::drop_convergence_rules_table(pool).await?;
    correlation_rules::drop_correlation_rules_table(pool).await?;
    filter_rules::drop_filter_rules_table(pool).await?;
    tag_rules::drop_tag_rules_table(pool).await?;
    // 注意：自动推送相关表通常不在 reset 中删除，这里保持不删
    Ok(())
}
