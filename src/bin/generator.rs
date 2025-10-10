use clap::{Parser, Subcommand};
use reqwest::Client;
use std::time::Duration;
use tokio::time;

// 重用库中的模块
use rust_hello::generators;

#[derive(Parser)]
#[command(name = "generator")]
#[command(about = "告警数据生成器 - 生成并推送模拟告警数据到 Axum 服务器", long_about = None)]
struct Cli {
    /// Axum 服务器地址
    #[arg(short, long, default_value = "http://localhost:3000")]
    server: String,

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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let client = Client::new();

    println!("╔══════════════════════════════════════════════╗");
    println!("║  🎲 告警数据生成器已启动                    ║");
    println!("╚══════════════════════════════════════════════╝");
    println!("📡 目标服务器: {}", cli.server);
    println!();

    match cli.command {
        Commands::Network { count, interval } => {
            generate_network_attacks(&client, &cli.server, count, interval).await?;
        }
        Commands::Sample { count, interval } => {
            generate_malicious_samples(&client, &cli.server, count, interval).await?;
        }
        Commands::Host { count, interval } => {
            generate_host_behaviors(&client, &cli.server, count, interval).await?;
        }
        Commands::All { count, interval } => {
            generate_all_types(&client, &cli.server, count, interval).await?;
        }
        Commands::Once { alert_type } => {
            generate_once(&client, &cli.server, &alert_type).await?;
        }
    }

    println!("\n✅ 生成任务完成！");
    Ok(())
}

/// 生成网络攻击告警
async fn generate_network_attacks(
    client: &Client,
    server: &str,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/alerts/network-attack/push", server);
    let continuous = count == 0;

    println!("🔴 生成网络攻击告警");
    println!("   数量: {}", if continuous { "持续".to_string() } else { count.to_string() });
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        let alert = generators::generate_network_attack_alert();
        println!("📤 发送: {} - {}", alert.alarm_id, alert.alarm_name);

        let response = client.post(&url).json(&alert).send().await?;

        if response.status().is_success() {
            println!("   ✓ 成功");
            sent += 1;
        } else {
            println!("   ✗ 失败: {}", response.status());
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
    client: &Client,
    server: &str,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/alerts/malicious-sample/push", server);
    let continuous = count == 0;

    println!("🟠 生成恶意样本告警");
    println!("   数量: {}", if continuous { "持续".to_string() } else { count.to_string() });
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        let alert = generators::generate_malicious_sample_alert();
        println!("📤 发送: {} - {}", alert.alarm_id, alert.alarm_name);

        let response = client.post(&url).json(&alert).send().await?;

        if response.status().is_success() {
            println!("   ✓ 成功");
            sent += 1;
        } else {
            println!("   ✗ 失败: {}", response.status());
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
    client: &Client,
    server: &str,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{}/api/alerts/host-behavior/push", server);
    let continuous = count == 0;

    println!("🟡 生成主机行为告警");
    println!("   数量: {}", if continuous { "持续".to_string() } else { count.to_string() });
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        let alert = generators::generate_host_behavior_alert();
        println!("📤 发送: {} - {}", alert.alarm_id, alert.alarm_name);

        let response = client.post(&url).json(&alert).send().await?;

        if response.status().is_success() {
            println!("   ✓ 成功");
            sent += 1;
        } else {
            println!("   ✗ 失败: {}", response.status());
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
    client: &Client,
    server: &str,
    count: u32,
    interval: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let continuous = count == 0;

    println!("🌈 生成所有类型告警（混合模式）");
    println!("   每种数量: {}", if continuous { "持续".to_string() } else { count.to_string() });
    println!("   间隔: {}秒", interval);
    println!();

    let mut sent = 0;
    loop {
        // 轮流生成三种告警
        let alert_type = sent % 3;

        match alert_type {
            0 => {
                let alert = generators::generate_network_attack_alert();
                let url = format!("{}/api/alerts/network-attack/push", server);
                println!("📤 [网络攻击] {}: {}", alert.alarm_id, alert.alarm_name);
                let response = client.post(&url).json(&alert).send().await?;
                println!("   {}", if response.status().is_success() { "✓" } else { "✗" });
            }
            1 => {
                let alert = generators::generate_malicious_sample_alert();
                let url = format!("{}/api/alerts/malicious-sample/push", server);
                println!("📤 [恶意样本] {}: {}", alert.alarm_id, alert.alarm_name);
                let response = client.post(&url).json(&alert).send().await?;
                println!("   {}", if response.status().is_success() { "✓" } else { "✗" });
            }
            _ => {
                let alert = generators::generate_host_behavior_alert();
                let url = format!("{}/api/alerts/host-behavior/push", server);
                println!("📤 [主机行为] {}: {}", alert.alarm_id, alert.alarm_name);
                let response = client.post(&url).json(&alert).send().await?;
                println!("   {}", if response.status().is_success() { "✓" } else { "✗" });
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
    client: &Client,
    server: &str,
    alert_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🎯 单次生成告警: {}", alert_type);
    println!();

    match alert_type {
        "network" => {
            let alert = generators::generate_network_attack_alert();
            let url = format!("{}/api/alerts/network-attack/push", server);
            println!("📤 发送网络攻击告警:");
            println!("   ID: {}", alert.alarm_id);
            println!("   名称: {}", alert.alarm_name);
            println!("   严重程度: {}", alert.alarm_severity);
            
            let response = client.post(&url).json(&alert).send().await?;
            println!("   状态: {}", if response.status().is_success() { "✓ 成功" } else { "✗ 失败" });
        }
        "sample" => {
            let alert = generators::generate_malicious_sample_alert();
            let url = format!("{}/api/alerts/malicious-sample/push", server);
            println!("📤 发送恶意样本告警:");
            println!("   ID: {}", alert.alarm_id);
            println!("   名称: {}", alert.alarm_name);
            println!("   家族: {}", alert.sample_family);
            
            let response = client.post(&url).json(&alert).send().await?;
            println!("   状态: {}", if response.status().is_success() { "✓ 成功" } else { "✗ 失败" });
        }
        "host" => {
            let alert = generators::generate_host_behavior_alert();
            let url = format!("{}/api/alerts/host-behavior/push", server);
            println!("📤 发送主机行为告警:");
            println!("   ID: {}", alert.alarm_id);
            println!("   名称: {}", alert.alarm_name);
            println!("   主机: {}", alert.host_name);
            
            let response = client.post(&url).json(&alert).send().await?;
            println!("   状态: {}", if response.status().is_success() { "✓ 成功" } else { "✗ 失败" });
        }
        _ => {
            println!("❌ 未知的告警类型: {}. 可选: network, sample, host", alert_type);
        }
    }

    Ok(())
}

