use clap::{Parser, Subcommand};
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
use serde::Deserialize;
use std::fs;
use std::time::Duration;
use tokio::time;

// 重用库中的模块
use alert_rs::generators;

#[derive(Parser)]
#[command(name = "generator")]
#[command(about = "告警数据生成器 - 生成并发送模拟告警数据到 Kafka", long_about = None)]
struct Cli {
    /// TOML 配置文件路径（Kafka 配置与主题名）
    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 生成网络攻击告警
    Network {
        /// 生成数量 (0 表示持续生成)
        #[arg(short, long, default_value = "10")]
        count: u32,

        /// 生成间隔(秒)
        #[arg(short, long, default_value = "2")]
        interval: u64,
    },
    /// 生成恶意样本告警
    Sample {
        /// 生成数量 (0 表示持续生成)
        #[arg(short, long, default_value = "10")]
        count: u32,

        /// 生成间隔(秒)
        #[arg(short, long, default_value = "3")]
        interval: u64,
    },
    /// 生成主机行为告警
    Host {
        /// 生成数量 (0 表示持续生成)
        #[arg(short, long, default_value = "10")]
        count: u32,

        /// 生成间隔(秒)
        #[arg(short, long, default_value = "2")]
        interval: u64,
    },
    /// 生成所有类型告警（混合模式）
    All {
        /// 每种类型生成数量 (0 表示持续生成)
        #[arg(short, long, default_value = "5")]
        count: u32,

        /// 生成间隔(秒)
        #[arg(short, long, default_value = "2")]
        interval: u64,
    },
    /// 单次生成一条告警（用于测试）
    Once {
        /// 告警类型: network, sample, host
        #[arg(short, long, default_value = "network")]
        alert_type: String,
    },
}

#[derive(Debug, Deserialize, Clone)]
struct AppConfig {
    kafka: KafkaSection,
    topics: Topics,
}

#[derive(Debug, Deserialize, Clone)]
struct KafkaSection {
    brokers: String,
    client_id: Option<String>,
    group_id: Option<String>,
    acks: Option<String>,
    linger_ms: Option<u64>,
    compression: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct Topics {
    network_attack: String,
    malicious_sample: String,
    host_behavior: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    // 读取 TOML 配置
    let cfg_str = fs::read_to_string(&cli.config)?;
    let app_cfg: AppConfig = toml::from_str(&cfg_str)?;

    // 初始化 Kafka 生产者
    let mut cc = ClientConfig::new();
    cc.set("bootstrap.servers", &app_cfg.kafka.brokers);
    if let Some(client_id) = &app_cfg.kafka.client_id {
        cc.set("client.id", client_id);
    }
    if let Some(group_id) = &app_cfg.kafka.group_id {
        cc.set("group.id", group_id);
    }
    if let Some(acks) = &app_cfg.kafka.acks {
        cc.set("acks", acks);
    }
    if let Some(linger_ms) = app_cfg.kafka.linger_ms {
        cc.set("linger.ms", linger_ms.to_string());
    }
    if let Some(compression) = &app_cfg.kafka.compression {
        cc.set("compression.type", compression);
    }

    let producer: FutureProducer = cc.create()?;

    println!("╔══════════════════════════════════════════════╗");
    println!("║  🎲 告警数据生成器已启动                    ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("📡 Kafka: {}", app_cfg.kafka.brokers);
    println!();

    match cli.command {
        Commands::Network { count, interval } => {
            generate_network_attacks(&producer, &app_cfg.topics, count, interval).await?;
        }
        Commands::Sample { count, interval } => {
            generate_malicious_samples(&producer, &app_cfg.topics, count, interval).await?;
        }
        Commands::Host { count, interval } => {
            generate_host_behaviors(&producer, &app_cfg.topics, count, interval).await?;
        }
        Commands::All { count, interval } => {
            generate_all_types(&producer, &app_cfg.topics, count, interval).await?;
        }
        Commands::Once { alert_type } => {
            generate_once(&producer, &app_cfg.topics, &alert_type).await?;
        }
    }

    println!("\n✅ 生成任务完成！");
    Ok(())
}

/// 生成网络攻击告警
async fn generate_network_attacks(
    producer: &FutureProducer,
    topics: &Topics,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let continuous = count == 0;

    println!("🔴 生成网络攻击告警");
    println!(
        "   数量: {}",
        if continuous {
            "持续".to_string()
        } else {
            count.to_string()
        }
    );
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        let alert = generators::generate_network_attack_alert();
        println!(
            "📤 发送: {} - {}",
            alert.alarm_id.as_ref().unwrap(),
            alert.alarm_name.as_ref().unwrap()
        );

        let payload = serde_json::to_vec(&alert)?;
        let delivery = producer
            .send(
                FutureRecord::to(&topics.network_attack)
                    .payload(payload.as_slice())
                    .key(""),
                Timeout::After(Duration::from_secs(5)),
            )
            .await;

        match delivery {
            Ok(_) => {
                println!("   ✓ 成功");
                sent += 1;
            }
            Err((e, _)) => {
                println!("   ✗ 失败: {}", e);
            }
        }

        if !continuous && sent >= count {
            break;
        }

        time::sleep(Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// 生成恶意样本告警
async fn generate_malicious_samples(
    producer: &FutureProducer,
    topics: &Topics,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let continuous = count == 0;

    println!("🟠 生成恶意样本告警");
    println!(
        "   数量: {}",
        if continuous {
            "持续".to_string()
        } else {
            count.to_string()
        }
    );
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        let alert = generators::generate_malicious_sample_alert();
        println!(
            "📤 发送: {} - {}",
            alert.alarm_id.as_ref().unwrap(),
            alert.alarm_name.as_ref().unwrap()
        );

        let payload = serde_json::to_vec(&alert)?;
        let delivery = producer
            .send(
                FutureRecord::to(&topics.malicious_sample)
                    .payload(payload.as_slice())
                    .key(""),
                Timeout::After(Duration::from_secs(5)),
            )
            .await;

        match delivery {
            Ok(_) => {
                println!("   ✓ 成功");
                sent += 1;
            }
            Err((e, _)) => {
                println!("   ✗ 失败: {}", e);
            }
        }

        if !continuous && sent >= count {
            break;
        }

        time::sleep(Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// 生成主机行为告警
async fn generate_host_behaviors(
    producer: &FutureProducer,
    topics: &Topics,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let continuous = count == 0;

    println!("🟡 生成主机行为告警");
    println!(
        "   数量: {}",
        if continuous {
            "持续".to_string()
        } else {
            count.to_string()
        }
    );
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        let alert = generators::generate_host_behavior_alert();
        println!(
            "📤 发送: {} - {}",
            alert.alarm_id.as_ref().unwrap(),
            alert.alarm_name.as_ref().unwrap()
        );

        let payload = serde_json::to_vec(&alert)?;
        let delivery = producer
            .send(
                FutureRecord::to(&topics.host_behavior)
                    .payload(payload.as_slice())
                    .key(""),
                Timeout::After(Duration::from_secs(5)),
            )
            .await;

        match delivery {
            Ok(_) => {
                println!("   ✓ 成功");
                sent += 1;
            }
            Err((e, _)) => {
                println!("   ✗ 失败: {}", e);
            }
        }

        if !continuous && sent >= count {
            break;
        }

        time::sleep(Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// 生成所有类型告警（混合模式）
async fn generate_all_types(
    producer: &FutureProducer,
    topics: &Topics,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let continuous = count == 0;

    println!("🌈 生成所有类型告警（混合模式）");
    println!(
        "   每种数量: {}",
        if continuous {
            "持续".to_string()
        } else {
            count.to_string()
        }
    );
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        // 轮流生成三种告警
        let alert_type = sent % 3;

        match alert_type {
            0 => {
                let alert = generators::generate_network_attack_alert();
                println!(
                    "📤 [网络攻击] {}: {}",
                    alert.alarm_id.as_ref().unwrap(),
                    alert.alarm_name.as_ref().unwrap()
                );
                let payload = serde_json::to_vec(&alert)?;
                let res = producer
                    .send(
                        FutureRecord::to(&topics.network_attack)
                            .payload(payload.as_slice())
                            .key(""),
                        Timeout::After(Duration::from_secs(5)),
                    )
                    .await;
                println!("   {}", if res.is_ok() { "✓" } else { "✗" });
            }
            1 => {
                let alert = generators::generate_malicious_sample_alert();
                println!(
                    "📤 [恶意样本] {}: {}",
                    alert.alarm_id.as_ref().unwrap(),
                    alert.alarm_name.as_ref().unwrap()
                );
                let payload = serde_json::to_vec(&alert)?;
                let res = producer
                    .send(
                        FutureRecord::to(&topics.malicious_sample)
                            .payload(payload.as_slice())
                            .key(""),
                        Timeout::After(Duration::from_secs(5)),
                    )
                    .await;
                println!("   {}", if res.is_ok() { "✓" } else { "✗" });
            }
            _ => {
                let alert = generators::generate_host_behavior_alert();
                println!(
                    "📤 [主机行为] {}: {}",
                    alert.alarm_id.as_ref().unwrap(),
                    alert.alarm_name.as_ref().unwrap()
                );
                let payload = serde_json::to_vec(&alert)?;
                let res = producer
                    .send(
                        FutureRecord::to(&topics.host_behavior)
                            .payload(payload.as_slice())
                            .key(""),
                        Timeout::After(Duration::from_secs(5)),
                    )
                    .await;
                println!("   {}", if res.is_ok() { "✓" } else { "✗" });
            }
        }

        sent += 1;

        if !continuous && sent >= count * 3 {
            break;
        }

        time::sleep(Duration::from_secs(interval)).await;
    }

    Ok(())
}

/// 单次生成一条告警（用于测试）
async fn generate_once(
    producer: &FutureProducer,
    topics: &Topics,
    alert_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 单次生成告警: {}", alert_type);
    println!();

    match alert_type {
        "network" => {
            let alert = generators::generate_network_attack_alert();
            println!("📤 发送网络攻击告警:");
            println!("   ID: {}", alert.alarm_id.as_ref().unwrap());
            println!("   名称: {}", alert.alarm_name.as_ref().unwrap());
            println!("   严重程度: {}", alert.alarm_severity.unwrap());

            let payload = serde_json::to_vec(&alert)?;
            let res = producer
                .send(
                    FutureRecord::to(&topics.network_attack)
                        .payload(payload.as_slice())
                        .key(""),
                    Timeout::After(Duration::from_secs(5)),
                )
                .await;
            println!(
                "   状态: {}",
                if res.is_ok() {
                    "✓ 成功"
                } else {
                    "✗ 失败"
                }
            );
        }
        "sample" => {
            let alert = generators::generate_malicious_sample_alert();
            println!("📤 发送恶意样本告警:");
            println!("   ID: {}", alert.alarm_id.as_ref().unwrap());
            println!("   名称: {}", alert.alarm_name.as_ref().unwrap());
            println!("   家族: {}", alert.sample_family.as_ref().unwrap());

            let payload = serde_json::to_vec(&alert)?;
            let res = producer
                .send(
                    FutureRecord::to(&topics.malicious_sample)
                        .payload(payload.as_slice())
                        .key(""),
                    Timeout::After(Duration::from_secs(5)),
                )
                .await;
            println!(
                "   状态: {}",
                if res.is_ok() {
                    "✓ 成功"
                } else {
                    "✗ 失败"
                }
            );
        }
        "host" => {
            let alert = generators::generate_host_behavior_alert();
            println!("📤 发送主机行为告警:");
            println!("   ID: {}", alert.alarm_id.as_ref().unwrap());
            println!("   名称: {}", alert.alarm_name.as_ref().unwrap());
            println!("   主机: {}", alert.host_name.as_ref().unwrap());

            let payload = serde_json::to_vec(&alert)?;
            let res = producer
                .send(
                    FutureRecord::to(&topics.host_behavior)
                        .payload(payload.as_slice())
                        .key(""),
                    Timeout::After(Duration::from_secs(5)),
                )
                .await;
            println!(
                "   状态: {}",
                if res.is_ok() {
                    "✓ 成功"
                } else {
                    "✗ 失败"
                }
            );
        }
        _ => {
            println!(
                "❌ 未知的告警类型: {}. 可选: network, sample, host",
                alert_type
            );
        }
    }

    Ok(())
}
