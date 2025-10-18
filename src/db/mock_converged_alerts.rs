//! 生成收敛告警、原始告警和映射关系的模拟数据
//!
//! 本模块用于快速生成测试数据，包括：
//! - 原始告警数据（raw_alerts）
//! - 收敛后告警数据（converged_alerts）
//! - 告警映射关系（alert_mapping）

use anyhow::Result;
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::{HostBehaviorAlert, MaliciousSampleAlert, NetworkAttackAlert};
use super::{
    converged_alerts::{insert_converged_network_attack, insert_converged_malicious_sample, insert_converged_host_behavior},
    alert_mapping::insert_mappings_batch,
};

/// 插入模拟的收敛告警数据
pub async fn insert_mock_converged_alerts(pool: &PgPool) -> Result<usize> {
    let mut total_count = 0;

    // 1. 插入网络攻击告警数据（5个原始告警 -> 2个收敛告警）
    total_count += insert_mock_network_attacks(pool).await?;

    // 2. 插入恶意样本告警数据（4个原始告警 -> 2个收敛告警）
    total_count += insert_mock_malicious_samples(pool).await?;

    // 3. 插入主机行为告警数据（6个原始告警 -> 2个收敛告警）
    total_count += insert_mock_host_behaviors(pool).await?;

    Ok(total_count)
}

/// 插入模拟的网络攻击告警
async fn insert_mock_network_attacks(pool: &PgPool) -> Result<usize> {
    let base_time = Utc::now().timestamp();
    
    // 第一组：3个类似的 SQL 注入攻击 -> 收敛为1个
    let mut group1_raw_ids = Vec::new();
    for i in 0..3 {
        let alert = NetworkAttackAlert {
            alarm_id: Some(format!("NA-2024-001-{:03}", i)),
            alarm_date: Some(base_time - 3600 + i * 300),
            alarm_severity: Some(3), // 高危
            alarm_name: Some("SQL注入攻击".to_string()),
            alarm_description: Some(format!("检测到SQL注入攻击尝试 #{}", i + 1)),
            alarm_type: 1, // 网络攻击
            alarm_subtype: 1001, // SQL注入
            source: 1, // 网络流量
            control_rule_id: Some("rule-001".to_string()),
            control_task_id: None,
            procedure_technique_id: Some(vec!["T1190".to_string()]),
            session_id: Some(format!("session-{}", i)),
            ip_version: Some(4),
            src_ip: Some("192.168.1.100".to_string()),
            src_port: Some(50000 + i as u16),
            dst_ip: Some("10.0.0.10".to_string()),
            dst_port: Some(3306),
            protocol: Some("TCP".to_string()),
            terminal_id: Some("term-001".to_string()),
            source_file_path: None,
            signature_id: Some("SIG-SQL-001".to_string()),
            attack_payload: Some("' OR '1'='1".to_string()),
            attack_stage: Some("初始访问".to_string()),
            attack_ip: Some("192.168.1.100".to_string()),
            attacked_ip: Some("10.0.0.10".to_string()),
            apt_group: None,
            vul_type: Some("SQL注入".to_string()),
            cve_id: Some("CVE-2024-1234".to_string()),
            vul_desc: Some("MySQL服务器SQL注入漏洞".to_string()),
            data: None,
        };
        
        let raw_id = insert_network_attack_and_get_id(pool, &alert).await?;
        group1_raw_ids.push(raw_id);
    }
    
    // 创建第一个收敛告警
    let converged_alert_1 = NetworkAttackAlert {
        alarm_id: Some("CNA-2024-001".to_string()),
        alarm_date: Some(base_time - 3600),
        alarm_severity: Some(3),
        alarm_name: Some("SQL注入攻击（收敛）".to_string()),
        alarm_description: Some("检测到3次类似的SQL注入攻击尝试".to_string()),
        alarm_type: 1,
        alarm_subtype: 1001,
        source: 1,
        control_rule_id: Some("rule-001".to_string()),
        control_task_id: None,
        procedure_technique_id: Some(vec!["T1190".to_string()]),
        session_id: Some("session-converged-1".to_string()),
        ip_version: Some(4),
        src_ip: Some("192.168.1.100".to_string()),
        src_port: Some(50000),
        dst_ip: Some("10.0.0.10".to_string()),
        dst_port: Some(3306),
        protocol: Some("TCP".to_string()),
        terminal_id: Some("term-001".to_string()),
        source_file_path: None,
        signature_id: Some("SIG-SQL-001".to_string()),
        attack_payload: Some("' OR '1'='1".to_string()),
        attack_stage: Some("初始访问".to_string()),
        attack_ip: Some("192.168.1.100".to_string()),
        attacked_ip: Some("10.0.0.10".to_string()),
        apt_group: None,
        vul_type: Some("SQL注入".to_string()),
        cve_id: Some("CVE-2024-1234".to_string()),
        vul_desc: Some("MySQL服务器SQL注入漏洞".to_string()),
        data: None,
    };
    
    let converged_id_1 = insert_converged_network_attack(pool, &converged_alert_1, 3).await?;
    insert_mappings_batch(pool, &group1_raw_ids, converged_id_1, 1).await?;

    // 第二组：2个类似的端口扫描 -> 收敛为1个
    let mut group2_raw_ids = Vec::new();
    for i in 0..2 {
        let alert = NetworkAttackAlert {
            alarm_id: Some(format!("NA-2024-002-{:03}", i)),
            alarm_date: Some(base_time - 1800 + i * 300),
            alarm_severity: Some(2), // 中危
            alarm_name: Some("端口扫描".to_string()),
            alarm_description: Some(format!("检测到端口扫描活动 #{}", i + 1)),
            alarm_type: 1,
            alarm_subtype: 1002,
            source: 1,
            control_rule_id: Some("rule-002".to_string()),
            control_task_id: None,
            procedure_technique_id: Some(vec!["T1046".to_string()]),
            session_id: Some(format!("session-scan-{}", i)),
            ip_version: Some(4),
            src_ip: Some("192.168.1.200".to_string()),
            src_port: Some(60000 + i as u16),
            dst_ip: Some("10.0.0.20".to_string()),
            dst_port: Some(80 + i as u16),
            protocol: Some("TCP".to_string()),
            terminal_id: None,
            source_file_path: None,
            signature_id: Some("SIG-SCAN-001".to_string()),
            attack_payload: None,
            attack_stage: Some("侦察".to_string()),
            attack_ip: Some("192.168.1.200".to_string()),
            attacked_ip: Some("10.0.0.20".to_string()),
            apt_group: None,
            vul_type: Some("端口扫描".to_string()),
            cve_id: None,
            vul_desc: Some("网络端口扫描行为".to_string()),
            data: None,
        };
        
        let raw_id = insert_network_attack_and_get_id(pool, &alert).await?;
        group2_raw_ids.push(raw_id);
    }
    
    let converged_alert_2 = NetworkAttackAlert {
        alarm_id: Some("CNA-2024-002".to_string()),
        alarm_date: Some(base_time - 1800),
        alarm_severity: Some(2),
        alarm_name: Some("端口扫描（收敛）".to_string()),
        alarm_description: Some("检测到2次端口扫描活动".to_string()),
        alarm_type: 1,
        alarm_subtype: 1002,
        source: 1,
        control_rule_id: Some("rule-002".to_string()),
        control_task_id: None,
        procedure_technique_id: Some(vec!["T1046".to_string()]),
        session_id: Some("session-scan-converged".to_string()),
        ip_version: Some(4),
        src_ip: Some("192.168.1.200".to_string()),
        src_port: Some(60000),
        dst_ip: Some("10.0.0.20".to_string()),
        dst_port: Some(80),
        protocol: Some("TCP".to_string()),
        terminal_id: None,
        source_file_path: None,
        signature_id: Some("SIG-SCAN-001".to_string()),
        attack_payload: None,
        attack_stage: Some("侦察".to_string()),
        attack_ip: Some("192.168.1.200".to_string()),
        attacked_ip: Some("10.0.0.20".to_string()),
        apt_group: None,
        vul_type: Some("端口扫描".to_string()),
        cve_id: None,
        vul_desc: Some("网络端口扫描行为".to_string()),
        data: None,
    };
    
    let converged_id_2 = insert_converged_network_attack(pool, &converged_alert_2, 2).await?;
    insert_mappings_batch(pool, &group2_raw_ids, converged_id_2, 1).await?;

    Ok(7) // 5个原始告警 + 2个收敛告警
}

/// 插入模拟的恶意样本告警
async fn insert_mock_malicious_samples(pool: &PgPool) -> Result<usize> {
    let base_time = Utc::now().timestamp();
    
    // 第一组：3个相同MD5的样本 -> 收敛为1个
    let mut group1_raw_ids = Vec::new();
    let md5_hash = "5d41402abc4b2a76b9719d911017c592";
    
    for i in 0..3 {
        let alert = MaliciousSampleAlert {
            alarm_id: Some(format!("MS-2024-001-{:03}", i)),
            alarm_date: Some(base_time - 2400 + i * 200),
            alarm_severity: Some(3),
            alarm_name: Some("勒索软件检测".to_string()),
            alarm_description: Some(format!("检测到勒索软件样本 #{}", i + 1)),
            alarm_type: 2,
            alarm_subtype: 2005,
            source: 2,
            control_rule_id: None,
            control_task_id: None,
            procedure_technique_id: Some(vec!["T1486".to_string()]),
            session_id: None,
            ip_version: Some(4),
            src_ip: Some(format!("10.0.0.{}", 100 + i)),
            src_port: Some(443),
            dst_ip: Some("8.8.8.8".to_string()),
            dst_port: Some(443),
            protocol: Some("HTTPS".to_string()),
            terminal_id: Some(format!("term-{:03}", i)),
            source_file_path: Some(format!("/tmp/malware_{}.exe", i)),
            sample_source: Some(2), // 本地检测
            md5: Some(md5_hash.to_string()),
            sha1: Some("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_string()),
            sha256: Some("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string()),
            sha512: None,
            ssdeep: None,
            sample_original_name: Some("ransomware.exe".to_string()),
            sample_description: Some("勒索软件变种".to_string()),
            sample_family: Some("WannaCry".to_string()),
            apt_group: None,
            sample_alarm_engine: Some(vec![1, 2]), // AV + YARA
            target_platform: Some("Windows".to_string()),
            file_type: Some("PE32".to_string()),
            file_size: Some(1024000),
            language: None,
            rule: Some("YARA_Ransomware_Rule".to_string()),
            target_content: None,
            compile_date: Some(base_time - 86400 * 30),
            last_analy_date: Some(base_time - 3600),
            sample_alarm_detail: Some("加密文件行为".to_string()),
            data: None,
        };
        
        let raw_id = insert_malicious_sample_and_get_id(pool, &alert).await?;
        group1_raw_ids.push(raw_id);
    }
    
    let converged_sample_1 = MaliciousSampleAlert {
        alarm_id: Some("CMS-2024-001".to_string()),
        alarm_date: Some(base_time - 2400),
        alarm_severity: Some(3),
        alarm_name: Some("勒索软件检测（收敛）".to_string()),
        alarm_description: Some("检测到3个相同的勒索软件样本".to_string()),
        alarm_type: 2,
        alarm_subtype: 2005,
        source: 2,
        control_rule_id: None,
        control_task_id: None,
        procedure_technique_id: Some(vec!["T1486".to_string()]),
        session_id: None,
        ip_version: Some(4),
        src_ip: Some("10.0.0.100".to_string()),
        src_port: Some(443),
        dst_ip: Some("8.8.8.8".to_string()),
        dst_port: Some(443),
        protocol: Some("HTTPS".to_string()),
        terminal_id: Some("term-000".to_string()),
        source_file_path: Some("/tmp/malware_0.exe".to_string()),
        sample_source: Some(2),
        md5: Some(md5_hash.to_string()),
        sha1: Some("2fd4e1c67a2d28fced849ee1bb76e7391b93eb12".to_string()),
        sha256: Some("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3".to_string()),
        sha512: None,
        ssdeep: None,
        sample_original_name: Some("ransomware.exe".to_string()),
        sample_description: Some("勒索软件变种（收敛）".to_string()),
        sample_family: Some("WannaCry".to_string()),
        apt_group: None,
        sample_alarm_engine: Some(vec![1, 2]),
        target_platform: Some("Windows".to_string()),
        file_type: Some("PE32".to_string()),
        file_size: Some(1024000),
        language: None,
        rule: Some("YARA_Ransomware_Rule".to_string()),
        target_content: None,
        compile_date: Some(base_time - 86400 * 30),
        last_analy_date: Some(base_time - 3600),
        sample_alarm_detail: Some("加密文件行为".to_string()),
        data: None,
    };
    
    let converged_id_1 = insert_converged_malicious_sample(pool, &converged_sample_1, 3).await?;
    insert_mappings_batch(pool, &group1_raw_ids, converged_id_1, 2).await?;

    // 第二组：1个木马样本（不收敛，直接作为收敛告警）
    let trojan_alert = MaliciousSampleAlert {
        alarm_id: Some("MS-2024-002-000".to_string()),
        alarm_date: Some(base_time - 1200),
        alarm_severity: Some(2),
        alarm_name: Some("特洛伊木马".to_string()),
        alarm_description: Some("检测到特洛伊木马".to_string()),
        alarm_type: 2,
        alarm_subtype: 2003,
        source: 2,
        control_rule_id: None,
        control_task_id: None,
        procedure_technique_id: Some(vec!["T1204".to_string()]),
        session_id: None,
        ip_version: Some(4),
        src_ip: Some("10.0.0.50".to_string()),
        src_port: None,
        dst_ip: None,
        dst_port: None,
        protocol: None,
        terminal_id: Some("term-050".to_string()),
        source_file_path: Some("/usr/bin/backdoor".to_string()),
        sample_source: Some(2),
        md5: Some("098f6bcd4621d373cade4e832627b4f6".to_string()),
        sha1: Some("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3".to_string()),
        sha256: Some("9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7".to_string()),
        sha512: None,
        ssdeep: None,
        sample_original_name: Some("trojan.elf".to_string()),
        sample_description: Some("Linux后门木马".to_string()),
        sample_family: Some("Mirai".to_string()),
        apt_group: None,
        sample_alarm_engine: Some(vec![1]),
        target_platform: Some("Linux".to_string()),
        file_type: Some("ELF".to_string()),
        file_size: Some(512000),
        language: None,
        rule: Some("YARA_Trojan_Rule".to_string()),
        target_content: None,
        compile_date: Some(base_time - 86400 * 7),
        last_analy_date: Some(base_time - 600),
        sample_alarm_detail: Some("后门连接行为".to_string()),
        data: None,
    };
    
    let raw_id = insert_malicious_sample_and_get_id(pool, &trojan_alert).await?;
    let converged_id_2 = insert_converged_malicious_sample(pool, &trojan_alert, 1).await?;
    insert_mappings_batch(pool, &[raw_id], converged_id_2, 2).await?;

    Ok(6) // 4个原始告警 + 2个收敛告警
}

/// 插入模拟的主机行为告警
async fn insert_mock_host_behaviors(pool: &PgPool) -> Result<usize> {
    let base_time = Utc::now().timestamp();
    
    // 第一组：4个相同主机的注册表修改 -> 收敛为1个
    let mut group1_raw_ids = Vec::new();
    
    for i in 0..4 {
        let alert = HostBehaviorAlert {
            alarm_id: Some(format!("HB-2024-001-{:03}", i)),
            alarm_date: Some(base_time - 3000 + i * 150),
            alarm_severity: Some(2),
            alarm_name: Some("注册表修改".to_string()),
            alarm_description: Some(format!("检测到注册表修改行为 #{}", i + 1)),
            alarm_type: 3,
            alarm_subtype: 3001,
            source: 2,
            control_rule_id: Some("rule-003".to_string()),
            control_task_id: None,
            procedure_technique_id: Some(vec!["T1112".to_string()]),
            session_id: Some(format!("session-reg-{}", i)),
            ip_version: None,
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            terminal_id: Some("term-win-001".to_string()),
            source_file_path: None,
            host_name: Some("DESKTOP-ABC123".to_string()),
            terminal_ip: Some("10.0.1.100".to_string()),
            user_account: Some("Administrator".to_string()),
            terminal_os: Some("Windows 10".to_string()),
            dst_process_md5: None,
            dst_process_path: None,
            dst_process_cli: None,
            src_process_md5: Some("d8e8fca2dc0f896fd7cb4cb0031ba249".to_string()),
            src_process_path: Some("C:\\Windows\\System32\\reg.exe".to_string()),
            src_process_cli: Some(format!("reg add HKLM\\Software\\Test{}", i)),
            register_key_name: Some(format!("TestKey{}", i)),
            register_key_value: Some("1".to_string()),
            register_path: Some("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()),
            file_name: None,
            file_md5: None,
            file_path: None,
            data: None,
        };
        
        let raw_id = insert_host_behavior_and_get_id(pool, &alert).await?;
        group1_raw_ids.push(raw_id);
    }
    
    let converged_behavior_1 = HostBehaviorAlert {
        alarm_id: Some("CHB-2024-001".to_string()),
        alarm_date: Some(base_time - 3000),
        alarm_severity: Some(2),
        alarm_name: Some("注册表修改（收敛）".to_string()),
        alarm_description: Some("检测到4次注册表修改行为".to_string()),
        alarm_type: 3,
        alarm_subtype: 3001,
        source: 2,
        control_rule_id: Some("rule-003".to_string()),
        control_task_id: None,
        procedure_technique_id: Some(vec!["T1112".to_string()]),
        session_id: Some("session-reg-converged".to_string()),
        ip_version: None,
        src_ip: None,
        src_port: None,
        dst_ip: None,
        dst_port: None,
        protocol: None,
        terminal_id: Some("term-win-001".to_string()),
        source_file_path: None,
        host_name: Some("DESKTOP-ABC123".to_string()),
        terminal_ip: Some("10.0.1.100".to_string()),
        user_account: Some("Administrator".to_string()),
        terminal_os: Some("Windows 10".to_string()),
        dst_process_md5: None,
        dst_process_path: None,
        dst_process_cli: None,
        src_process_md5: Some("d8e8fca2dc0f896fd7cb4cb0031ba249".to_string()),
        src_process_path: Some("C:\\Windows\\System32\\reg.exe".to_string()),
        src_process_cli: Some("reg add HKLM\\Software\\Test0".to_string()),
        register_key_name: Some("TestKey0".to_string()),
        register_key_value: Some("1".to_string()),
        register_path: Some("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".to_string()),
        file_name: None,
        file_md5: None,
        file_path: None,
        data: None,
    };
    
    let converged_id_1 = insert_converged_host_behavior(pool, &converged_behavior_1, 4).await?;
    insert_mappings_batch(pool, &group1_raw_ids, converged_id_1, 3).await?;

    // 第二组：2个进程注入 -> 收敛为1个
    let mut group2_raw_ids = Vec::new();
    
    for i in 0..2 {
        let alert = HostBehaviorAlert {
            alarm_id: Some(format!("HB-2024-002-{:03}", i)),
            alarm_date: Some(base_time - 1500 + i * 200),
            alarm_severity: Some(3),
            alarm_name: Some("进程注入".to_string()),
            alarm_description: Some(format!("检测到进程注入行为 #{}", i + 1)),
            alarm_type: 3,
            alarm_subtype: 3002,
            source: 2,
            control_rule_id: Some("rule-004".to_string()),
            control_task_id: None,
            procedure_technique_id: Some(vec!["T1055".to_string()]),
            session_id: Some(format!("session-inject-{}", i)),
            ip_version: None,
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            protocol: None,
            terminal_id: Some("term-win-002".to_string()),
            source_file_path: None,
            host_name: Some("LAPTOP-XYZ789".to_string()),
            terminal_ip: Some("10.0.1.200".to_string()),
            user_account: Some("User".to_string()),
            terminal_os: Some("Windows 11".to_string()),
            dst_process_md5: Some("5f4dcc3b5aa765d61d8327deb882cf99".to_string()),
            dst_process_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
            dst_process_cli: Some("svchost.exe -k netsvcs".to_string()),
            src_process_md5: Some("e99a18c428cb38d5f260853678922e03".to_string()),
            src_process_path: Some("C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe".to_string()),
            src_process_cli: Some("malware.exe".to_string()),
            register_key_name: None,
            register_key_value: None,
            register_path: None,
            file_name: None,
            file_md5: None,
            file_path: None,
            data: None,
        };
        
        let raw_id = insert_host_behavior_and_get_id(pool, &alert).await?;
        group2_raw_ids.push(raw_id);
    }
    
    let converged_behavior_2 = HostBehaviorAlert {
        alarm_id: Some("CHB-2024-002".to_string()),
        alarm_date: Some(base_time - 1500),
        alarm_severity: Some(3),
        alarm_name: Some("进程注入（收敛）".to_string()),
        alarm_description: Some("检测到2次进程注入行为".to_string()),
        alarm_type: 3,
        alarm_subtype: 3002,
        source: 2,
        control_rule_id: Some("rule-004".to_string()),
        control_task_id: None,
        procedure_technique_id: Some(vec!["T1055".to_string()]),
        session_id: Some("session-inject-converged".to_string()),
        ip_version: None,
        src_ip: None,
        src_port: None,
        dst_ip: None,
        dst_port: None,
        protocol: None,
        terminal_id: Some("term-win-002".to_string()),
        source_file_path: None,
        host_name: Some("LAPTOP-XYZ789".to_string()),
        terminal_ip: Some("10.0.1.200".to_string()),
        user_account: Some("User".to_string()),
        terminal_os: Some("Windows 11".to_string()),
        dst_process_md5: Some("5f4dcc3b5aa765d61d8327deb882cf99".to_string()),
        dst_process_path: Some("C:\\Windows\\System32\\svchost.exe".to_string()),
        dst_process_cli: Some("svchost.exe -k netsvcs".to_string()),
        src_process_md5: Some("e99a18c428cb38d5f260853678922e03".to_string()),
        src_process_path: Some("C:\\Users\\User\\AppData\\Local\\Temp\\malware.exe".to_string()),
        src_process_cli: Some("malware.exe".to_string()),
        register_key_name: None,
        register_key_value: None,
        register_path: None,
        file_name: None,
        file_md5: None,
        file_path: None,
        data: None,
    };
    
    let converged_id_2 = insert_converged_host_behavior(pool, &converged_behavior_2, 2).await?;
    insert_mappings_batch(pool, &group2_raw_ids, converged_id_2, 3).await?;

    Ok(8) // 6个原始告警 + 2个收敛告警
}

// ============================================================================
// 辅助函数：插入并返回ID
// ============================================================================

async fn insert_network_attack_and_get_id(pool: &PgPool, alert: &NetworkAttackAlert) -> Result<Uuid> {
    let id: (Uuid,) = sqlx::query_as(
        "INSERT INTO network_attack_alerts (
            alarm_id, alarm_date, alarm_severity, alarm_name, alarm_description,
            alarm_type, alarm_subtype, source, control_rule_id, control_task_id,
            procedure_technique_id, session_id, ip_version, src_ip, src_port,
            dst_ip, dst_port, protocol, terminal_id, source_file_path,
            signature_id, attack_payload, attack_stage, attack_ip, attacked_ip,
            apt_group, vul_type, cve_id, vul_desc, data
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30
        ) RETURNING id"
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity.map(|v| v as i16))
    .bind(&alert.alarm_name)
    .bind(&alert.alarm_description)
    .bind(alert.alarm_type as i16)
    .bind(alert.alarm_subtype as i32)
    .bind(alert.source as i16)
    .bind(&alert.control_rule_id)
    .bind(&alert.control_task_id)
    .bind(&alert.procedure_technique_id.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
    }))
    .bind(&alert.session_id)
    .bind(alert.ip_version.map(|v| v as i16))
    .bind(&alert.src_ip)
    .bind(alert.src_port.map(|v| v as i32))
    .bind(&alert.dst_ip)
    .bind(alert.dst_port.map(|v| v as i32))
    .bind(&alert.protocol)
    .bind(&alert.terminal_id)
    .bind(&alert.source_file_path)
    .bind(&alert.signature_id)
    .bind(&alert.attack_payload)
    .bind(&alert.attack_stage)
    .bind(&alert.attack_ip)
    .bind(&alert.attacked_ip)
    .bind(&alert.apt_group)
    .bind(&alert.vul_type)
    .bind(&alert.cve_id)
    .bind(&alert.vul_desc)
    .bind(&alert.data)
    .fetch_one(pool)
    .await?;

    Ok(id.0)
}

async fn insert_malicious_sample_and_get_id(pool: &PgPool, alert: &MaliciousSampleAlert) -> Result<Uuid> {
    let id: (Uuid,) = sqlx::query_as(
        "INSERT INTO malicious_sample_alerts (
            alarm_id, alarm_date, alarm_severity, alarm_name, alarm_description,
            alarm_type, alarm_subtype, source, control_rule_id, control_task_id,
            procedure_technique_id, session_id, ip_version, src_ip, src_port,
            dst_ip, dst_port, protocol, terminal_id, source_file_path,
            sample_source, md5, sha1, sha256, sha512, ssdeep,
            sample_original_name, sample_description, sample_family, apt_group,
            sample_alarm_engine, target_platform, file_type, file_size, language,
            rule, target_content, compile_date, last_analy_date, sample_alarm_detail, data
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41
        ) RETURNING id"
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity.map(|v| v as i16))
    .bind(&alert.alarm_name)
    .bind(&alert.alarm_description)
    .bind(alert.alarm_type as i16)
    .bind(alert.alarm_subtype as i32)
    .bind(alert.source as i16)
    .bind(&alert.control_rule_id)
    .bind(&alert.control_task_id)
    .bind(&alert.procedure_technique_id.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
    }))
    .bind(&alert.session_id)
    .bind(alert.ip_version.map(|v| v as i16))
    .bind(&alert.src_ip)
    .bind(alert.src_port.map(|v| v as i32))
    .bind(&alert.dst_ip)
    .bind(alert.dst_port.map(|v| v as i32))
    .bind(&alert.protocol)
    .bind(&alert.terminal_id)
    .bind(&alert.source_file_path)
    .bind(alert.sample_source.map(|v| v as i16))
    .bind(&alert.md5)
    .bind(&alert.sha1)
    .bind(&alert.sha256)
    .bind(&alert.sha512)
    .bind(&alert.ssdeep)
    .bind(&alert.sample_original_name)
    .bind(&alert.sample_description)
    .bind(&alert.sample_family)
    .bind(&alert.apt_group)
    .bind(&alert.sample_alarm_engine.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(|n| serde_json::Value::Number(serde_json::Number::from(n))).collect())
    }))
    .bind(&alert.target_platform)
    .bind(&alert.file_type)
    .bind(alert.file_size.map(|v| v as i64))
    .bind(&alert.language)
    .bind(&alert.rule)
    .bind(&alert.target_content)
    .bind(alert.compile_date)
    .bind(alert.last_analy_date)
    .bind(&alert.sample_alarm_detail)
    .bind(&alert.data)
    .fetch_one(pool)
    .await?;

    Ok(id.0)
}

async fn insert_host_behavior_and_get_id(pool: &PgPool, alert: &HostBehaviorAlert) -> Result<Uuid> {
    let id: (Uuid,) = sqlx::query_as(
        "INSERT INTO host_behavior_alerts (
            alarm_id, alarm_date, alarm_severity, alarm_name, alarm_description,
            alarm_type, alarm_subtype, source, control_rule_id, control_task_id,
            procedure_technique_id, session_id, ip_version, src_ip, src_port,
            dst_ip, dst_port, protocol, terminal_id, source_file_path,
            host_name, terminal_ip, user_account, terminal_os,
            dst_process_md5, dst_process_path, dst_process_cli,
            src_process_md5, src_process_path, src_process_cli,
            register_key_name, register_key_value, register_path,
            file_name, file_md5, file_path, data
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35, $36, $37
        ) RETURNING id"
    )
    .bind(&alert.alarm_id)
    .bind(alert.alarm_date)
    .bind(alert.alarm_severity.map(|v| v as i16))
    .bind(&alert.alarm_name)
    .bind(&alert.alarm_description)
    .bind(alert.alarm_type as i16)
    .bind(alert.alarm_subtype as i32)
    .bind(alert.source as i16)
    .bind(&alert.control_rule_id)
    .bind(&alert.control_task_id)
    .bind(&alert.procedure_technique_id.as_ref().map(|v| {
        serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
    }))
    .bind(&alert.session_id)
    .bind(alert.ip_version.map(|v| v as i16))
    .bind(&alert.src_ip)
    .bind(alert.src_port.map(|v| v as i32))
    .bind(&alert.dst_ip)
    .bind(alert.dst_port.map(|v| v as i32))
    .bind(&alert.protocol)
    .bind(&alert.terminal_id)
    .bind(&alert.source_file_path)
    .bind(&alert.host_name)
    .bind(&alert.terminal_ip)
    .bind(&alert.user_account)
    .bind(&alert.terminal_os)
    .bind(&alert.dst_process_md5)
    .bind(&alert.dst_process_path)
    .bind(&alert.dst_process_cli)
    .bind(&alert.src_process_md5)
    .bind(&alert.src_process_path)
    .bind(&alert.src_process_cli)
    .bind(&alert.register_key_name)
    .bind(&alert.register_key_value)
    .bind(&alert.register_path)
    .bind(&alert.file_name)
    .bind(&alert.file_md5)
    .bind(&alert.file_path)
    .bind(&alert.data)
    .fetch_one(pool)
    .await?;

    Ok(id.0)
}

