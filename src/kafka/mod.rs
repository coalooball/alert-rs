use anyhow::Result;
use futures::StreamExt;
use sqlx::PgPool;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{ClientConfig, Message};

use crate::config::{KafkaConfig, TopicsConfig};
use crate::db::{
    insert_network_attack, insert_malicious_sample, insert_host_behavior, insert_invalid_alert,
    insert_converged_network_attack, insert_converged_malicious_sample, insert_converged_host_behavior,
    find_converged_network_attack_by_five_tuple, find_converged_malicious_sample_by_hash, find_converged_host_behavior_by_host_info,
    increment_convergence_count_network_attack, increment_convergence_count_malicious_sample, increment_convergence_count_host_behavior,
    insert_mapping,
};
use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};

pub async fn run_consumer(kafka: KafkaConfig, topics: TopicsConfig, pool: PgPool) -> Result<()> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &kafka.brokers)
        .set("group.id", &kafka.group_id)
        .set("client.id", &kafka.client_id)
        .set("enable.partition.eof", "false")
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", &kafka.auto_offset_reset)
        .create()?;

    consumer.subscribe(&[
        &topics.network_attack,
        &topics.malicious_sample,
        &topics.host_behavior,
    ])?;

    let mut stream = consumer.stream();
    while let Some(message) = stream.next().await {
        match message {
            Ok(m) => {
                if let Some(payload) = m.payload_view::<str>() {
                    let topic = m.topic();
                    match payload {
                        Ok(text) => {
                            if topic == topics.network_attack {
                                match serde_json::from_str::<NetworkAttackAlert>(text) {
                                    Ok(alert) => {
                                        if let Err(e) = process_network_attack(&pool, &alert).await {
                                            tracing::error!("process network_attack failed: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::info!("Failed to parse network_attack alert: {} | raw: {}", e, text);
                                        let data = serde_json::json!({
                                            "topic": topic,
                                            "raw": text,
                                        });
                                        if let Err(err) = insert_invalid_alert(&pool, data, e.to_string()).await {
                                            tracing::error!("insert invalid_alert failed: {}", err);
                                        }
                                    }
                                }
                            } else if topic == topics.malicious_sample {
                                match serde_json::from_str::<MaliciousSampleAlert>(text) {
                                    Ok(alert) => {
                                        if let Err(e) = process_malicious_sample(&pool, &alert).await {
                                            tracing::error!("process malicious_sample failed: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::info!("Failed to parse malicious_sample alert: {} | raw: {}", e, text);
                                        let data = serde_json::json!({
                                            "topic": topic,
                                            "raw": text,
                                        });
                                        if let Err(err) = insert_invalid_alert(&pool, data, e.to_string()).await {
                                            tracing::error!("insert invalid_alert failed: {}", err);
                                        }
                                    }
                                }
                            } else if topic == topics.host_behavior {
                                match serde_json::from_str::<HostBehaviorAlert>(text) {
                                    Ok(alert) => {
                                        if let Err(e) = process_host_behavior(&pool, &alert).await {
                                            tracing::error!("process host_behavior failed: {}", e);
                                        }
                                    }
                                    Err(e) => {
                                        tracing::info!("Failed to parse host_behavior alert: {} | raw: {}", e, text);
                                        let data = serde_json::json!({
                                            "topic": topic,
                                            "raw": text,
                                        });
                                        if let Err(err) = insert_invalid_alert(&pool, data, e.to_string()).await {
                                            tracing::error!("insert invalid_alert failed: {}", err);
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            // 非UTF-8，跳过
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!("Kafka error: {}", e);
            }
        }
    }
    Ok(())
}

/// 处理网络攻击告警：实现基于五元组的收敛逻辑
async fn process_network_attack(pool: &PgPool, alert: &NetworkAttackAlert) -> Result<()> {
    // 1. 始终插入到原始告警表并获取ID
    let raw_id = insert_network_attack(pool, alert).await?;
    
    // 2. 查询是否已存在相同五元组的收敛告警
    let converged_id = match find_converged_network_attack_by_five_tuple(pool, alert).await? {
        Some(existing_id) => {
            // 找到已存在的收敛告警，更新收敛计数
            increment_convergence_count_network_attack(pool, existing_id).await?;
            tracing::debug!("Found existing converged network_attack: converged_id={}, incrementing count", existing_id);
            existing_id
        }
        None => {
            // 未找到，插入新的收敛告警（收敛数为1）
            let new_id = insert_converged_network_attack(pool, alert, 1).await?;
            tracing::debug!("Created new converged network_attack: converged_id={}", new_id);
            new_id
        }
    };
    
    // 3. 建立原始告警与收敛告警的映射关系（alert_type = 1 表示网络攻击）
    insert_mapping(pool, raw_id, converged_id, 1).await?;
    
    tracing::info!("Processed network_attack: raw_id={}, converged_id={}", raw_id, converged_id);
    Ok(())
}

/// 处理恶意样本告警：实现基于哈希的收敛逻辑
async fn process_malicious_sample(pool: &PgPool, alert: &MaliciousSampleAlert) -> Result<()> {
    // 1. 始终插入到原始告警表并获取ID
    let raw_id = insert_malicious_sample(pool, alert).await?;
    
    // 2. 查询是否已存在相同哈希的收敛告警
    let converged_id = match find_converged_malicious_sample_by_hash(pool, alert).await? {
        Some(existing_id) => {
            // 找到已存在的收敛告警，更新收敛计数
            increment_convergence_count_malicious_sample(pool, existing_id).await?;
            tracing::debug!("Found existing converged malicious_sample: converged_id={}, incrementing count", existing_id);
            existing_id
        }
        None => {
            // 未找到，插入新的收敛告警（收敛数为1）
            let new_id = insert_converged_malicious_sample(pool, alert, 1).await?;
            tracing::debug!("Created new converged malicious_sample: converged_id={}", new_id);
            new_id
        }
    };
    
    // 3. 建立原始告警与收敛告警的映射关系（alert_type = 2 表示恶意样本）
    insert_mapping(pool, raw_id, converged_id, 2).await?;
    
    tracing::info!("Processed malicious_sample: raw_id={}, converged_id={}", raw_id, converged_id);
    Ok(())
}

/// 处理主机行为告警：实现基于主机信息的收敛逻辑
async fn process_host_behavior(pool: &PgPool, alert: &HostBehaviorAlert) -> Result<()> {
    // 1. 始终插入到原始告警表并获取ID
    let raw_id = insert_host_behavior(pool, alert).await?;
    
    // 2. 查询是否已存在相同主机信息的收敛告警
    let converged_id = match find_converged_host_behavior_by_host_info(pool, alert).await? {
        Some(existing_id) => {
            // 找到已存在的收敛告警，更新收敛计数
            increment_convergence_count_host_behavior(pool, existing_id).await?;
            tracing::debug!("Found existing converged host_behavior: converged_id={}, incrementing count", existing_id);
            existing_id
        }
        None => {
            // 未找到，插入新的收敛告警（收敛数为1）
            let new_id = insert_converged_host_behavior(pool, alert, 1).await?;
            tracing::debug!("Created new converged host_behavior: converged_id={}", new_id);
            new_id
        }
    };
    
    // 3. 建立原始告警与收敛告警的映射关系（alert_type = 3 表示主机行为）
    insert_mapping(pool, raw_id, converged_id, 3).await?;
    
    tracing::info!("Processed host_behavior: raw_id={}, converged_id={}", raw_id, converged_id);
    Ok(())
}
