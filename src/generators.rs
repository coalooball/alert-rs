use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};
use chrono::Utc;
use rand::Rng;

/// 生成网络攻击告警数据
pub fn generate_network_attack_alert() -> NetworkAttackAlert {
    let mut rng = rand::thread_rng();
    let alert_types = [
        (
            "APT组织Lazarus后门通信检测",
            "检测到终端与已知APT组织Lazarus的C2服务器进行加密通信，存在数据泄露风险",
            "Lazarus Group",
            1004,
        ),
        (
            "SQL注入漏洞利用尝试",
            "检测到针对Web应用程序的SQL注入攻击尝试，攻击者试图获取数据库信息",
            "",
            1003,
        ),
        (
            "端口扫描探测行为",
            "检测到大规模端口扫描行为，可能是攻击者进行网络侦察",
            "",
            1001,
        ),
        (
            "DDoS拒绝服务攻击",
            "检测到大量异常流量，目标系统面临拒绝服务攻击",
            "",
            1006,
        ),
        (
            "Web Shell后门检测",
            "检测到可疑的Web Shell访问行为，服务器可能已被植入后门",
            "",
            1004,
        ),
    ];

    let (name, desc, apt, subtype) = alert_types[rng.gen_range(0..alert_types.len())];
    let severity = rng.gen_range(1..=3);
    let timestamp = Utc::now().timestamp_millis();
    let id = format!(
        "NA-2024-{:03}-{:06X}",
        rng.gen_range(1..999),
        rng.gen::<u32>() & 0xFFFFFF
    );

    let src_ips = ["192.168.1.100", "10.0.1.50", "172.16.0.10", "192.168.2.200"];
    let dst_ips = [
        "185.234.218.100",
        "45.67.89.123",
        "203.0.113.50",
        "198.51.100.20",
    ];

    NetworkAttackAlert {
        alarm_id: Some(id),
        alarm_date: Some(timestamp),
        alarm_severity: Some(severity),
        alarm_name: Some(name.to_string()),
        alarm_description: Some(desc.to_string()),
        alarm_type: 1,
        alarm_subtype: subtype,
        source: rng.gen_range(1..=4),
        control_rule_id: Some(format!(
            "RULE-{}-2024-{:03}",
            if apt.is_empty() { "SEC" } else { "APT" },
            rng.gen_range(1..999)
        )),
        control_task_id: Some(format!("TASK-SEC-2024-{:03}", rng.gen_range(100..999))),
        procedure_technique_id: Some(vec!["T1071.001".to_string(), "T1573.001".to_string()]),
        session_id: Some(format!(
            "SESSION-{}-{:06}",
            Utc::now().format("%Y%m%d"),
            rng.gen::<u32>() % 999999
        )),
        ip_version: Some(4),
        src_ip: Some(src_ips[rng.gen_range(0..src_ips.len())].to_string()),
        src_port: Some(rng.gen_range(30000..60000)),
        dst_ip: Some(dst_ips[rng.gen_range(0..dst_ips.len())].to_string()),
        dst_port: Some(if subtype == 1003 { 80 } else { 443 }),
        protocol: Some("HTTPS".to_string()),
        terminal_id: Some(format!("TERM-OFFICE-PC-{:03}", rng.gen_range(1..100))),
        source_file_path: Some(format!(
            "/data/traffic/2024/12/25/capture_{}.pcap",
            timestamp % 999999
        )),
        signature_id: Some(format!(
            "SIG-{}-{:03}",
            if apt.is_empty() { "ATK" } else { "APT" },
            rng.gen_range(1..999)
        )),
        attack_payload: Some(format!(
            r#"{{"method":"GET","uri":"/api/data?id={}"}}"#,
            rng.gen::<u32>()
        )),
        attack_stage: Some("Command and Control".to_string()),
        attack_ip: Some(dst_ips[rng.gen_range(0..dst_ips.len())].to_string()),
        attacked_ip: Some(src_ips[rng.gen_range(0..src_ips.len())].to_string()),
        apt_group: Some(apt.to_string()),
        vul_type: if subtype == 1003 {
            Some("SQL注入".to_string())
        } else {
            Some(String::new())
        },
        cve_id: if subtype == 1003 {
            Some(format!("CVE-2024-{}", rng.gen_range(1000..9999)))
        } else {
            Some(String::new())
        },
        vul_desc: if subtype == 1003 {
            Some("应用程序未对用户输入进行适当验证".to_string())
        } else {
            Some(String::new())
        },
        data: None,
    }
}

/// 生成恶意样本告警数据
pub fn generate_malicious_sample_alert() -> MaliciousSampleAlert {
    let mut rng = rand::thread_rng();
    let sample_types = [
        (
            "Emotet银行木马变种检测",
            "检测到Emotet银行木马最新变种，该样本具有窃取银行凭证和传播能力",
            "Emotet",
            2003,
            "Trojan",
        ),
        (
            "WannaCry勒索软件检测",
            "发现WannaCry勒索软件样本，该样本会加密系统文件并索要比特币赎金",
            "WannaCry",
            2005,
            "Ransomware",
        ),
        (
            "Mirai僵尸网络样本",
            "检测到Mirai僵尸网络恶意样本，可能用于DDoS攻击",
            "Mirai",
            2004,
            "Botnet",
        ),
        (
            "挖矿木马XMRig变种",
            "发现门罗币挖矿木马XMRig变种，会消耗大量系统资源",
            "XMRig",
            2006,
            "Miner",
        ),
        (
            "Cobalt Strike后门",
            "检测到Cobalt Strike木马样本，常用于APT攻击",
            "CobaltStrike",
            2003,
            "Backdoor",
        ),
    ];

    let (name, desc, family, subtype, type_name) =
        sample_types[rng.gen_range(0..sample_types.len())];
    let severity = rng.gen_range(2..=3);
    let timestamp = Utc::now().timestamp_millis();
    let id = format!(
        "MS-2024-{:03}-{:06X}",
        rng.gen_range(1..999),
        rng.gen::<u32>() & 0xFFFFFF
    );

    MaliciousSampleAlert {
        alarm_id: Some(id),
        alarm_date: Some(timestamp),
        alarm_severity: Some(severity),
        alarm_name: Some(name.to_string()),
        alarm_description: Some(desc.to_string()),
        alarm_type: 2,
        alarm_subtype: subtype,
        source: rng.gen_range(1..=4),
        control_rule_id: Some(format!("RULE-{}-2024-{:03}", type_name, rng.gen_range(1..999))),
        control_task_id: Some(format!("TASK-MAL-2024-{:03}", rng.gen_range(100..999))),
        procedure_technique_id: Some(vec!["T1055".to_string(), "T1566.001".to_string()]),
        session_id: Some(String::new()),
        ip_version: Some(4),
        src_ip: Some(String::new()),
        src_port: None,
        dst_ip: Some(String::new()),
        dst_port: None,
        protocol: Some(String::new()),
        terminal_id: Some(format!("TERM-FIN-PC-{:03}", rng.gen_range(1..100))),
        source_file_path: Some(format!("/data/samples/2024/12/25/sample_{}.exe", timestamp % 999999)),
        sample_source: Some(rng.gen_range(1..=3)),
        md5: Some(format!("{:032x}", rng.gen::<u128>())),
        sha1: Some(format!("{:040x}", rng.gen::<u128>() as u128)),
        sha256: Some(format!("{:064x}", rng.gen::<u128>() as u128)),
        sha512: Some(format!("{:0128x}", rng.gen::<u128>() as u128)),
        ssdeep: Some(format!("96:{}:S{}", rng.gen::<u64>(), rng.gen::<u32>())),
        sample_original_name: Some(format!("{}.exe", family.to_lowercase())),
        sample_description: Some(String::new()),
        sample_family: Some(family.to_string()),
        apt_group: Some(if family == "CobaltStrike" {
            "APT29".to_string()
        } else {
            String::new()
        }),
        sample_alarm_engine: Some(vec![1, 2]),
        target_platform: Some("Windows x64".to_string()),
        file_type: Some("PE32+ executable".to_string()),
        file_size: Some(rng.gen_range(100000..5000000)),
        language: Some("C++".to_string()),
        rule: Some(format!("YARA:{}_{}", family, type_name)),
        target_content: Some(String::new()),
        compile_date: Some(timestamp - rng.gen_range(86400000..31536000000)),
        last_analy_date: Some(timestamp),
        sample_alarm_detail: Some(format!(r#"[{{"rule_name":"{}_{}_2024"}}]"#, family, type_name)),
        data: None,
    }
}

/// 生成主机行为告警数据
pub fn generate_host_behavior_alert() -> HostBehaviorAlert {
    let mut rng = rand::thread_rng();
    let behavior_types = [
        (
            "XMRig挖矿进程检测",
            "检测到主机运行XMRig挖矿程序，占用大量CPU资源进行门罗币挖矿",
            3001,
            "/tmp/.system/xmrig",
            "挖矿",
        ),
        (
            "勒索软件文件加密行为",
            "检测到大量文件被加密并添加.locked扩展名，疑似勒索软件攻击",
            3002,
            "C:\\Users\\admin\\AppData\\Roaming\\svchost.exe",
            "加密",
        ),
        (
            "远程桌面暴力破解",
            "检测到针对RDP服务的大量失败登录尝试",
            3004,
            "",
            "爆破",
        ),
        (
            "敏感数据外传",
            "检测到大量敏感文件被上传到外部服务器",
            3008,
            "/usr/bin/curl",
            "窃取",
        ),
        (
            "横向移动攻击",
            "检测到使用WMI进行横向移动的可疑行为",
            3007,
            "C:\\Windows\\System32\\wbem\\wmic.exe",
            "移动",
        ),
    ];

    let (name, desc, subtype, process_path, attack_type) =
        behavior_types[rng.gen_range(0..behavior_types.len())];
    let severity = rng.gen_range(2..=3);
    let timestamp = Utc::now().timestamp_millis();
    let id = format!(
        "HB-2024-{:03}-{:06X}",
        rng.gen_range(1..999),
        rng.gen::<u32>() & 0xFFFFFF
    );

    let hostnames = [
        "DB-SERVER-01",
        "WEB-SERVER-02",
        "FIN-WORKSTATION-10",
        "DEV-PC-05",
    ];
    let ips = [
        "192.168.10.50",
        "10.0.2.100",
        "172.16.5.20",
        "192.168.2.110",
    ];

    HostBehaviorAlert {
        alarm_id: Some(id),
        alarm_date: Some(timestamp),
        alarm_severity: Some(severity),
        alarm_name: Some(name.to_string()),
        alarm_description: Some(desc.to_string()),
        alarm_type: 3,
        alarm_subtype: subtype,
        source: rng.gen_range(3..=8),
        control_rule_id: Some(format!(
            "RULE-{}-2024-{:03}",
            attack_type.to_uppercase(),
            rng.gen_range(1..999)
        )),
        control_task_id: Some(format!("TASK-HOST-2024-{:03}", rng.gen_range(100..999))),
        procedure_technique_id: Some(vec!["T1496".to_string()]),
        session_id: Some(String::new()),
        ip_version: Some(4),
        src_ip: Some(String::new()),
        src_port: None,
        dst_ip: Some(if subtype == 3001 {
            "pool.minexmr.com".to_string()
        } else {
            String::new()
        }),
        dst_port: if subtype == 3001 { Some(4444) } else { None },
        protocol: Some(if subtype == 3001 {
            "TCP".to_string()
        } else {
            String::new()
        }),
        terminal_id: Some(format!("TERM-SVR-{:03}", rng.gen_range(1..100))),
        source_file_path: Some(format!("/data/logs/2024/12/25/host_{}.log", timestamp % 999999)),
        host_name: Some(hostnames[rng.gen_range(0..hostnames.len())].to_string()),
        terminal_ip: Some(ips[rng.gen_range(0..ips.len())].to_string()),
        user_account: Some(if subtype == 3001 {
            "www-data".to_string()
        } else {
            "admin".to_string()
        }),
        terminal_os: Some(if process_path.starts_with('/') {
            "Ubuntu 20.04.3 LTS".to_string()
        } else {
            "Windows 10 Pro".to_string()
        }),
        dst_process_md5: Some(format!("{:032x}", rng.gen::<u128>())),
        dst_process_path: Some(process_path.to_string()),
        dst_process_cli: Some(format!("{} --param value", process_path)),
        src_process_md5: Some(format!("{:032x}", rng.gen::<u128>())),
        src_process_path: Some(if process_path.starts_with('/') {
            "/usr/sbin/apache2".to_string()
        } else {
            "C:\\Windows\\System32\\explorer.exe".to_string()
        }),
        src_process_cli: Some(String::new()),
        register_key_name: Some(if !process_path.starts_with('/') {
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()
        } else {
            String::new()
        }),
        register_key_value: Some(if !process_path.starts_with('/') {
            process_path.to_string()
        } else {
            String::new()
        }),
        register_path: Some(if !process_path.starts_with('/') {
            "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()
        } else {
            String::new()
        }),
        file_name: Some(if subtype == 3001 {
            "xmrig".to_string()
        } else {
            "suspicious.exe".to_string()
        }),
        file_md5: Some(format!("{:032x}", rng.gen::<u128>())),
        file_path: Some(process_path.to_string()),
        data: None,
    }
}
