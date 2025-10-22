use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{fs, path::Path};

#[derive(Debug, Deserialize, Clone)]
pub struct KafkaConfig {
    pub brokers: String,
    pub client_id: String,
    pub group_id: String,
    #[allow(dead_code)]
    pub acks: String,
    #[allow(dead_code)]
    pub linger_ms: u64,
    #[allow(dead_code)]
    pub compression: String,
    /// Kafka offset reset策略: "earliest" (从最早的消息开始) 或 "latest" (只消费新消息)
    #[serde(default = "default_auto_offset_reset")]
    pub auto_offset_reset: String,
}

impl KafkaConfig {
    pub fn producer_config(&self) -> rdkafka::ClientConfig {
        let mut config = rdkafka::ClientConfig::new();
        config
            .set("bootstrap.servers", &self.brokers)
            .set("client.id", &self.client_id)
            .set("acks", &self.acks)
            .set("linger.ms", self.linger_ms.to_string())
            .set("compression.type", &self.compression);
        config
    }
}

fn default_auto_offset_reset() -> String {
    "earliest".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct TopicsConfig {
    pub network_attack: String,
    pub malicious_sample: String,
    pub host_behavior: String,
    /// 聚合后的收敛告警推送主题
    pub converged_alerts: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlarmTypeInfo {
    pub code: String,
    pub name: String,
    pub category: String,
    pub subtypes: HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlarmTypesConfig {
    pub network_attack: AlarmTypeInfo,
    pub malicious_sample: AlarmTypeInfo,
    pub host_behavior: AlarmTypeInfo,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub kafka: KafkaConfig,
    pub topics: TopicsConfig,
    pub postgres: PostgresConfig,
    pub alarm_types: AlarmTypesConfig,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<AppConfig> {
    let text = fs::read_to_string(path)?;
    let cfg: AppConfig = toml::from_str(&text)?;
    Ok(cfg)
}
