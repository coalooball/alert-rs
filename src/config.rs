use serde::Deserialize;
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
}

#[derive(Debug, Deserialize, Clone)]
pub struct TopicsConfig {
    pub network_attack: String,
    pub malicious_sample: String,
    pub host_behavior: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub kafka: KafkaConfig,
    pub topics: TopicsConfig,
    pub postgres: PostgresConfig,
}

pub fn load_config<P: AsRef<Path>>(path: P) -> anyhow::Result<AppConfig> {
    let text = fs::read_to_string(path)?;
    let cfg: AppConfig = toml::from_str(&text)?;
    Ok(cfg)
}


