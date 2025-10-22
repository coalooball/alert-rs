use crate::db::{self, alert_tag_mapping};
use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};
use anyhow::Result;
use serde_json::Value;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// 根据告警类型执行相应的收敛逻辑，并为最终的收敛告警打上标签
pub async fn process_and_tag_convergence(
    pool: &PgPool,
    alert_json: &Value,
    alert_type_str: &str,
    raw_alert_id: Uuid,
    matched_tag_ids: Vec<Uuid>,
) -> Result<()> {
    // 1. 根据告警类型，执行不同的收敛算法，找到或创建收敛告警ID
    let converged_alert_id = match alert_type_str {
        "network_attack" => {
            let alert: NetworkAttackAlert = serde_json::from_value(alert_json.clone())?;
            handle_network_attack_convergence(pool, &alert).await?
        }
        "malicious_sample" => {
            let alert: MaliciousSampleAlert = serde_json::from_value(alert_json.clone())?;
            handle_malicious_sample_convergence(pool, &alert).await?
        }
        "host_behavior" => {
            let alert: HostBehaviorAlert = serde_json::from_value(alert_json.clone())?;
            handle_host_behavior_convergence(pool, &alert).await?
        }
        _ => {
            warn!("未知的告警类型 '{}'，无法进行收敛", alert_type_str);
            return Ok(());
        }
    };

    // 2. 建立原始告警与收敛告警的映射关系
    let alert_type_code = match alert_type_str {
        "network_attack" => 1,
        "malicious_sample" => 2,
        "host_behavior" => 3,
        _ => 0,
    };
    db::insert_mapping(pool, raw_alert_id, converged_alert_id, alert_type_code).await?;

    // 3. 如果有匹配的标签，将它们关联到收敛告警上
    if !matched_tag_ids.is_empty() {
        info!(
            "为收敛告警 {} (类型: {}) 关联 {} 个标签: {:?}",
            converged_alert_id,
            alert_type_str,
            matched_tag_ids.len(),
            matched_tag_ids
        );
        alert_tag_mapping::add_alert_tags_batch(
            pool,
            converged_alert_id,
            alert_type_str,
            &matched_tag_ids,
        )
        .await?;
    }

    Ok(())
}

/// 处理网络攻击告警的收敛（基于五元组）
async fn handle_network_attack_convergence(
    pool: &PgPool,
    alert: &NetworkAttackAlert,
) -> Result<Uuid> {
    match db::find_converged_network_attack_by_five_tuple(pool, alert).await? {
        Some(existing_id) => {
            db::increment_convergence_count_network_attack(pool, existing_id).await?;
            Ok(existing_id)
        }
        None => {
            let new_id = db::insert_converged_network_attack(pool, alert, 1).await?;
            Ok(new_id)
        }
    }
}

/// 处理恶意样本告警的收敛（基于哈希）
async fn handle_malicious_sample_convergence(
    pool: &PgPool,
    alert: &MaliciousSampleAlert,
) -> Result<Uuid> {
    match db::find_converged_malicious_sample_by_hash(pool, alert).await? {
        Some(existing_id) => {
            db::increment_convergence_count_malicious_sample(pool, existing_id).await?;
            Ok(existing_id)
        }
        None => {
            let new_id = db::insert_converged_malicious_sample(pool, alert, 1).await?;
            Ok(new_id)
        }
    }
}

/// 处理主机行为告警的收敛（基于主机信息）
async fn handle_host_behavior_convergence(
    pool: &PgPool,
    alert: &HostBehaviorAlert,
) -> Result<Uuid> {
    match db::find_converged_host_behavior_by_host_info(pool, alert).await? {
        Some(existing_id) => {
            db::increment_convergence_count_host_behavior(pool, existing_id).await?;
            Ok(existing_id)
        }
        None => {
            let new_id = db::insert_converged_host_behavior(pool, alert, 1).await?;
            Ok(new_id)
        }
    }
}
