use anyhow::Result;
use futures::StreamExt;
use rbatis::RBatis;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::{ClientConfig, Message};

use crate::config::{KafkaConfig, TopicsConfig};
use crate::db::{insert_host_behavior, insert_malicious_sample, insert_network_attack};
use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};

pub async fn run_consumer(kafka: KafkaConfig, topics: TopicsConfig, rb: RBatis) -> Result<()> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("bootstrap.servers", &kafka.brokers)
        .set("group.id", &kafka.group_id)
        .set("client.id", &kafka.client_id)
        .set("enable.partition.eof", "false")
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", "earliest")
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
                                if let Ok(alert) = serde_json::from_str::<NetworkAttackAlert>(text)
                                {
                                    if let Err(e) = insert_network_attack(&rb, &alert).await {
                                        tracing::error!("insert network_attack failed: {}", e);
                                    }
                                }
                            } else if topic == topics.malicious_sample {
                                if let Ok(alert) =
                                    serde_json::from_str::<MaliciousSampleAlert>(text)
                                {
                                    if let Err(e) = insert_malicious_sample(&rb, &alert).await {
                                        tracing::error!("insert malicious_sample failed: {}", e);
                                    }
                                }
                            } else if topic == topics.host_behavior {
                                if let Ok(alert) = serde_json::from_str::<HostBehaviorAlert>(text) {
                                    if let Err(e) = insert_host_behavior(&rb, &alert).await {
                                        tracing::error!("insert host_behavior failed: {}", e);
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
