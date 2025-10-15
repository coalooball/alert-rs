use anyhow::Result;
use futures::StreamExt;
use sqlx::PgPool;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{ClientConfig, Message};

use crate::config::{KafkaConfig, TopicsConfig};
use crate::db::{insert_host_behavior, insert_malicious_sample, insert_network_attack, insert_invalid_alert};
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
                                        if let Err(e) = insert_network_attack(&pool, &alert).await {
                                            tracing::error!("insert network_attack failed: {}", e);
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
                                        if let Err(e) = insert_malicious_sample(&pool, &alert).await {
                                            tracing::error!("insert malicious_sample failed: {}", e);
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
                                        if let Err(e) = insert_host_behavior(&pool, &alert).await {
                                            tracing::error!("insert host_behavior failed: {}", e);
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
