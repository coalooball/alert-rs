use anyhow::Result;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::{Message, OwnedMessage};
use rdkafka::ClientConfig;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::{KafkaConfig, TopicsConfig};
use crate::db::{self, filter_rules::FilterRuleRecord, tag_rules};

mod convergence;
mod filtering;
mod tagging;

/// 运行 Kafka 消费者
pub async fn run_consumer(
    kafka_cfg: KafkaConfig,
    topics_cfg: TopicsConfig,
    pool: PgPool,
) -> Result<()> {
    let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &kafka_cfg.group_id)
        .set("bootstrap.servers", &kafka_cfg.brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "true")
        .set("auto.offset.reset", &kafka_cfg.auto_offset_reset)
        .create()?;

    let topics = [
        topics_cfg.network_attack.as_str(),
        topics_cfg.malicious_sample.as_str(),
        topics_cfg.host_behavior.as_str(),
    ];
    consumer.subscribe(&topics)?;
    info!("Subscribed to topics: {:?}", topics);

    // 加载过滤规则
    let filter_rules = db::filter_rules::get_enabled_filter_rules(&pool).await?;
    info!("Loaded {} enabled filter rules.", filter_rules.len());

    // 加载标签规则
    let tag_rules = db::tag_rules::get_enabled_tag_rules(&pool).await?;
    info!("Loaded {} enabled tag rules.", tag_rules.len());

    // 加载所有标签定义，用于名称到ID的映射
    let all_tags = db::tag_management::get_all_tags(&pool).await?;
    let tag_map: std::collections::HashMap<String, Uuid> =
        all_tags.into_iter().map(|tag| (tag.name, tag.id)).collect();
    info!("Loaded {} tag definitions into map.", tag_map.len());

    // 将规则和映射封装以便在任务间共享
    let processing_assets = Arc::new(ProcessingAssets {
        filter_rules,
        tag_rules,
        tag_map,
    });

    // 主消费循环
    loop {
        match consumer.recv().await {
            Err(e) => warn!("Kafka error: {}", e),
            Ok(m) => {
                let owned_message = m.detach();
                let pool_clone = pool.clone();
                let assets_clone = processing_assets.clone();

                tokio::spawn(async move {
                    if let Err(e) = process_message(owned_message, pool_clone, assets_clone).await {
                        error!("Error processing message: {}", e);
                    }
                });
            }
        }
    }
}

/// 共享的处理资源
struct ProcessingAssets {
    filter_rules: Vec<FilterRuleRecord>,
    tag_rules: Vec<tag_rules::TagRuleRecord>,
    tag_map: HashMap<String, Uuid>,
}

/// 处理单条 Kafka 消息
async fn process_message(
    m: OwnedMessage,
    pool: PgPool,
    assets: Arc<ProcessingAssets>,
) -> Result<()> {
    let payload = match m.payload_view::<str>() {
        Some(Ok(payload)) => payload,
        Some(Err(e)) => {
            warn!("Error viewing message payload: {}", e);
            return Ok(());
        }
        None => {
            warn!("Message with empty payload");
            return Ok(());
        }
    };

    let topic = m.topic();
    let alert_type_str = topic.split('.').last().unwrap_or("unknown");

    // 反序列化为 JSON Value
    let payload_json: Value = match serde_json::from_str(payload) {
        Ok(json) => json,
        Err(e) => {
            error!("Failed to parse message payload into JSON: {}", e);
            // 可以在这里将错误消息存入一个专门的“坏消息”表或队列
            return Ok(());
        }
    };

    // 过滤逻辑
    if filtering::should_filter(&payload_json, alert_type_str, &assets.filter_rules) {
        info!(
            "Alert of type '{}' was filtered. Storing as invalid alert.",
            alert_type_str
        );
        db::store_invalid_alert(&pool, &payload_json, alert_type_str, "filtered".to_string())
            .await?;
        return Ok(());
    }

    // 存储原始告警
    let raw_alert_id = db::store_raw_alert(&pool, &payload_json, alert_type_str).await?;

    // 对原始告警应用标签规则，获取待添加的标签
    let matched_tag_ids = tagging::get_matched_tag_ids(
        &payload_json,
        alert_type_str,
        &assets.tag_rules,
        &assets.tag_map,
    );

    // 应用收敛规则，并将匹配到的标签ID传递过去
    convergence::process_and_tag_convergence(
        &pool,
        &payload_json,
        alert_type_str,
        raw_alert_id,
        matched_tag_ids,
    )
    .await?;

    Ok(())
}
