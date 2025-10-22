use anyhow::Result;
use chrono::{DateTime, NaiveDateTime, Utc};
use sqlx::PgPool;

/// 插入威胁事件模拟数据
/// 返回插入的记录数
pub async fn insert_mock_data(pool: &PgPool) -> Result<usize> {
    let mut count = 0;

    // 示例1: APT攻击事件
    sqlx::query(
        "INSERT INTO threat_events (
            event_id, system_code, name, description, event_type,
            attacker, victimer, start_time, end_time, found_time,
            source, mitre_technique_id, attsck_list, attack_tool, first_found_time,
            priority, severity, dispose_status, app, impact_assessment,
            merge_alerts, threat_actor, org,
            attack_asset_ip, victim_asset_ip, attack_asset_ip_port, victim_asset_ip_port,
            attack_asset_domain, victim_asset_domain, attack_url, victim_url,
            attack_malware, attack_malware_sample, attack_malware_sample_family,
            attack_email_address, victim_email_address, attack_email, victim_email,
            attack_software, victim_software, attack_vulnerability,
            attack_certificate, victim_certificate
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23, $24, $25, $26, $27, $28, $29, $30,
            $31, $32, $33, $34, $35, $36, $37, $38, $39, $40,
            $41, $42, $43
        )",
    )
    .bind(1000001_i64)
    .bind("SYS-2025-001")
    .bind("APT攻击事件样例")
    .bind("模拟APT组织通过钓鱼邮件投递恶意文档，利用系统漏洞入侵受害者网络。")
    .bind("网络攻击")
    .bind("APT-XYZ组织")
    .bind("某能源企业")
    .bind(parse_time("2025-09-10 08:30:00"))
    .bind(parse_time("2025-09-10 12:45:00"))
    .bind(parse_time("2025-09-10 09:00:00"))
    .bind("IDS/威胁情报平台")
    .bind("T1566,T1203,T1059")
    .bind("鱼叉式钓鱼,利用漏洞,脚本执行")
    .bind("Cobalt Strike, Metasploit")
    .bind(parse_time("2025-09-10 08:45:00"))
    .bind("高")
    .bind("严重")
    .bind("未审核")
    .bind("Microsoft Word, Apache Tomcat")
    .bind("可能导致核心业务系统数据泄露")
    .bind(serde_json::json!([
        {"alert_id": "AL-001", "alert_type": "钓鱼邮件", "alert_time": "2025-09-10 08:35:00"},
        {"alert_id": "AL-002", "alert_type": "漏洞利用", "alert_time": "2025-09-10 08:50:00"}
    ]))
    .bind(serde_json::json!([
        {"name": "APT-XYZ", "country": "未知", "group": "APT组织"}
    ]))
    .bind(serde_json::json!([
        {"name": "某能源企业总部", "location": "北京"}
    ]))
    .bind(serde_json::json!(["192.168.10.15", "45.67.89.101"]))
    .bind(serde_json::json!(["10.0.5.20", "172.16.3.45"]))
    .bind(serde_json::json!(["192.168.10.15:443", "45.67.89.101:80"]))
    .bind(serde_json::json!(["10.0.5.20:8080", "172.16.3.45:445"]))
    .bind(serde_json::json!(["evil-apt.com", "malicious.cn"]))
    .bind(serde_json::json!(["victim-energy.com"]))
    .bind(serde_json::json!([
        "http://evil-apt.com/phishing.doc",
        "http://malicious.cn/exploit"
    ]))
    .bind(serde_json::json!(["http://victim-energy.com/login"]))
    .bind(serde_json::json!([
        "Trojan.Win32.APTXYZ",
        "Backdoor.Linux.Cobalt"
    ]))
    .bind(serde_json::json!(["hash:123abc...", "hash:456def..."]))
    .bind(serde_json::json!(["Cobalt Strike", "PlugX"]))
    .bind(serde_json::json!([
        "aptxyz@evil-apt.com",
        "attacker@phish.cn"
    ]))
    .bind(serde_json::json!([
        "admin@victim-energy.com",
        "it@victim-energy.com"
    ]))
    .bind(serde_json::json!(["钓鱼邮件主题：紧急安全更新"]))
    .bind(serde_json::json!(["回复邮件：确认收到安全更新"]))
    .bind(serde_json::json!(["Cobalt Strike", "Mimikatz"]))
    .bind(serde_json::json!([
        "Windows Server 2019",
        "Oracle Database 12c"
    ]))
    .bind(serde_json::json!(["CVE-2023-21768", "CVE-2024-12345"]))
    .bind(serde_json::json!(["恶意证书 SHA1: abcd1234efgh5678"]))
    .bind(serde_json::json!(["企业证书 SHA1: xyz9876abcd5432"]))
    .execute(pool)
    .await?;
    count += 1;

    // 示例2: 勒索软件攻击事件
    sqlx::query(
        "INSERT INTO threat_events (
            event_id, system_code, name, description, event_type,
            attacker, victimer, start_time, end_time, found_time,
            source, mitre_technique_id, attsck_list, attack_tool, first_found_time,
            priority, severity, dispose_status, app, impact_assessment,
            attack_asset_ip, victim_asset_ip, attack_vulnerability
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
            $21, $22, $23
        )",
    )
    .bind(1000002_i64)
    .bind("SYS-2025-002")
    .bind("勒索软件加密事件")
    .bind("检测到勒索软件通过RDP弱口令入侵，加密服务器文件并索要赎金。")
    .bind("勒索攻击")
    .bind("勒索团伙X")
    .bind("某制造企业")
    .bind(parse_time("2025-10-01 14:20:00"))
    .bind(parse_time("2025-10-01 16:30:00"))
    .bind(parse_time("2025-10-01 14:45:00"))
    .bind("终端安全系统")
    .bind("T1078,T1486,T1490")
    .bind("有效账户,数据加密勒索,抑制系统恢复")
    .bind("RDP工具, WannaCry变种")
    .bind(parse_time("2025-10-01 14:30:00"))
    .bind("高")
    .bind("严重")
    .bind("已审核")
    .bind("Windows Server, SQL Server")
    .bind("重要生产数据被加密，业务中断")
    .bind(serde_json::json!(["203.0.113.45"]))
    .bind(serde_json::json!(["192.168.1.100", "192.168.1.101"]))
    .bind(serde_json::json!(["CVE-2019-0708"]))
    .execute(pool)
    .await?;
    count += 1;

    // 示例3: DDoS攻击事件
    sqlx::query(
        "INSERT INTO threat_events (
            event_id, system_code, name, description, event_type,
            attacker, victimer, start_time, end_time, found_time,
            source, attsck_list, attack_tool, first_found_time,
            priority, severity, dispose_status, impact_assessment,
            attack_asset_ip, victim_asset_ip
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
        )",
    )
    .bind(1000003_i64)
    .bind("SYS-2025-003")
    .bind("大规模DDoS攻击")
    .bind("检测到针对公司官网的大规模DDoS攻击，峰值流量达500Gbps。")
    .bind("网络攻击")
    .bind("未知攻击者")
    .bind("某互联网公司")
    .bind(parse_time("2025-10-05 10:00:00"))
    .bind(parse_time("2025-10-05 12:00:00"))
    .bind(parse_time("2025-10-05 10:05:00"))
    .bind("云WAF/DDoS防护")
    .bind("SYN Flood, UDP Flood")
    .bind("Mirai僵尸网络")
    .bind(parse_time("2025-10-05 10:02:00"))
    .bind("中")
    .bind("高危")
    .bind("未审核")
    .bind("官网服务短暂中断，部分用户无法访问")
    .bind(serde_json::json!(["198.51.100.0/24", "203.0.113.0/24"]))
    .bind(serde_json::json!(["104.28.1.100"]))
    .execute(pool)
    .await?;
    count += 1;

    // 示例4: 数据泄露事件
    sqlx::query(
        "INSERT INTO threat_events (
            event_id, system_code, name, description, event_type,
            attacker, victimer, start_time, end_time, found_time,
            source, mitre_technique_id, attsck_list, first_found_time,
            priority, severity, dispose_status, app, impact_assessment
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18, $19
        )",
    )
    .bind(1000004_i64)
    .bind("SYS-2025-004")
    .bind("敏感数据外传事件")
    .bind("发现内部员工通过邮件外发大量客户敏感数据。")
    .bind("数据泄露")
    .bind("内部人员")
    .bind("某金融机构")
    .bind(parse_time("2025-10-10 16:30:00"))
    .bind(parse_time("2025-10-10 17:00:00"))
    .bind(parse_time("2025-10-10 16:45:00"))
    .bind("数据防泄露系统(DLP)")
    .bind("T1041,T1567")
    .bind("数据泄露,传输到云账户")
    .bind(parse_time("2025-10-10 16:35:00"))
    .bind("高")
    .bind("严重")
    .bind("已审核")
    .bind("Email系统, 文件服务器")
    .bind("约5000条客户个人信息可能泄露")
    .execute(pool)
    .await?;
    count += 1;

    // 示例5: 供应链攻击事件
    sqlx::query(
        "INSERT INTO threat_events (
            event_id, system_code, name, description, event_type,
            attacker, victimer, start_time, found_time,
            source, mitre_technique_id, attsck_list, first_found_time,
            priority, severity, dispose_status, impact_assessment,
            attack_software
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15, $16, $17, $18
        )",
    )
    .bind(1000005_i64)
    .bind("SYS-2025-005")
    .bind("第三方软件后门植入")
    .bind("发现某第三方监控软件被植入后门，可能影响多个客户。")
    .bind("供应链攻击")
    .bind("APT-Supply组织")
    .bind("多家企业客户")
    .bind(parse_time("2025-10-15 09:00:00"))
    .bind(parse_time("2025-10-15 11:00:00"))
    .bind("威胁情报共享平台")
    .bind("T1195.002")
    .bind("供应链破坏-软件供应链")
    .bind(parse_time("2025-10-15 09:30:00"))
    .bind("高")
    .bind("严重")
    .bind("未审核")
    .bind("可能导致多个客户环境被渗透")
    .bind(serde_json::json!(["MonitoringSoftware v3.2.1"]))
    .execute(pool)
    .await?;
    count += 1;

    Ok(count)
}

/// 辅助函数：解析时间字符串为 UTC DateTime
fn parse_time(time_str: &str) -> Option<DateTime<Utc>> {
    // 解析格式: "2025-10-15 09:00:00"
    NaiveDateTime::parse_from_str(time_str, "%Y-%m-%d %H:%M:%S")
        .ok()
        .map(|dt| dt.and_utc())
}
