use anyhow::Result;
use sqlx::PgPool;

use super::{
    convergence_rules::{self, ConvergenceRuleInput},
    correlation_rules::{self, CorrelationRuleInput},
    filter_rules::{self, FilterRuleInput},
    tag_rules::{self, TagRuleInput},
};

/// 插入收敛规则模拟数据
pub async fn insert_mock_convergence_rules(pool: &PgPool) -> Result<usize> {
    let rules = vec![
        ConvergenceRuleInput {
            name: "相同源IP高危告警收敛".to_string(),
            dsl_rule: "CONVERGE\n  WHERE alarm_severity >= 3\n  GROUP BY src_ip, alarm_type\n  WINDOW 5m\n  THRESHOLD 10".to_string(),
            description: Some("对来自相同源IP的高危告警在5分钟内进行收敛，超过10条则触发".to_string()),
            enabled: true,
        },
        ConvergenceRuleInput {
            name: "主机行为告警收敛".to_string(),
            dsl_rule: "CONVERGE\n  WHERE alarm_type == 2\n  GROUP BY host_name, user_account\n  WINDOW 10m\n  THRESHOLD 20".to_string(),
            description: Some("对同一主机和用户的行为告警进行收敛".to_string()),
            enabled: true,
        },
        ConvergenceRuleInput {
            name: "APT组织相关告警收敛".to_string(),
            dsl_rule: "CONVERGE\n  WHERE apt_group != \"\" AND alarm_severity >= 2\n  GROUP BY apt_group, dst_ip\n  WINDOW 30m\n  THRESHOLD 5".to_string(),
            description: Some("对APT组织相关的告警按组织和目标IP收敛".to_string()),
            enabled: true,
        },
        ConvergenceRuleInput {
            name: "端口扫描行为收敛".to_string(),
            dsl_rule: "CONVERGE\n  WHERE alarm_subtype IN (1001, 1002, 1003) AND dst_port IN (22, 3389, 445)\n  GROUP BY src_ip, dst_port\n  WINDOW 15m\n  THRESHOLD 50".to_string(),
            description: Some("对端口扫描行为进行收敛，15分钟内超过50次则告警".to_string()),
            enabled: true,
        },
        ConvergenceRuleInput {
            name: "恶意样本告警收敛".to_string(),
            dsl_rule: "CONVERGE\n  WHERE alarm_type == 3\n  GROUP BY md5, sample_family\n  WINDOW 20m\n  THRESHOLD 3".to_string(),
            description: Some("相同MD5和样本家族的恶意样本告警收敛".to_string()),
            enabled: false,
        },
    ];

    let mut count = 0;
    for rule in rules {
        convergence_rules::create_convergence_rule(pool, &rule).await?;
        count += 1;
    }

    Ok(count)
}

/// 插入关联规则模拟数据
pub async fn insert_mock_correlation_rules(pool: &PgPool) -> Result<usize> {
    let rules = vec![
        CorrelationRuleInput {
            name: "攻击链关联检测".to_string(),
            dsl_rule: "CORRELATE\n  EVENT attack WHERE alarm_type == 1 AND alarm_severity >= 2\n  EVENT behavior WHERE alarm_type == 2 AND dst_process_path CONTAINS \"cmd.exe\"\n  JOIN ON attack.dst_ip == behavior.terminal_ip\n  WINDOW 10m\n  GENERATE\n    SEVERITY 3\n    NAME \"检测到攻击链活动\"\n    DESCRIPTION \"网络攻击后发现可疑主机行为\"".to_string(),
            description: Some("检测网络攻击后的可疑主机行为，识别攻击链".to_string()),
            enabled: true,
        },
        CorrelationRuleInput {
            name: "横向移动检测".to_string(),
            dsl_rule: "CORRELATE\n  EVENT login WHERE alarm_subtype == 2001 AND alarm_name CONTAINS \"登录\"\n  EVENT access WHERE alarm_subtype == 2002 AND alarm_name CONTAINS \"访问\"\n  EVENT lateral WHERE alarm_subtype == 1005\n  JOIN ON login.user_account == access.user_account AND access.dst_ip == lateral.src_ip\n  WINDOW 30m\n  GENERATE\n    SEVERITY 4\n    NAME \"检测到横向移动\"\n    DESCRIPTION \"发现异常登录后的横向移动行为\"".to_string(),
            description: Some("检测攻击者在内网中的横向移动行为".to_string()),
            enabled: true,
        },
        CorrelationRuleInput {
            name: "APT攻击场景关联".to_string(),
            dsl_rule: "CORRELATE\n  EVENT sample WHERE alarm_type == 3 AND apt_group != \"\"\n  EVENT c2 WHERE alarm_subtype == 1020 AND alarm_name CONTAINS \"C2\"\n  EVENT exfil WHERE alarm_name REGEX \".*数据泄露.*\"\n  JOIN ON sample.terminal_ip == c2.src_ip AND c2.src_ip == exfil.src_ip\n  WINDOW 60m\n  GENERATE\n    SEVERITY 4\n    NAME \"APT攻击活动检测\"\n    DESCRIPTION \"检测到完整的APT攻击链\"".to_string(),
            description: Some("检测APT攻击的完整链条：恶意样本->C2通信->数据泄露".to_string()),
            enabled: true,
        },
        CorrelationRuleInput {
            name: "漏洞利用后行为检测".to_string(),
            dsl_rule: "CORRELATE\n  EVENT exploit WHERE vul_type != \"\" AND cve_id != \"\"\n  EVENT proc WHERE src_process_path REGEX \".*(powershell|cmd|wscript).*\"\n  JOIN ON exploit.attacked_ip == proc.terminal_ip\n  WINDOW 5m\n  GENERATE\n    SEVERITY 3\n    NAME \"漏洞利用成功\"\n    DESCRIPTION \"漏洞利用后检测到可疑进程执行\"".to_string(),
            description: Some("检测漏洞利用成功后的可疑进程行为".to_string()),
            enabled: true,
        },
        CorrelationRuleInput {
            name: "多源协同攻击检测".to_string(),
            dsl_rule: "CORRELATE\n  EVENT scan WHERE alarm_subtype IN (1001, 1002)\n  EVENT brute WHERE alarm_subtype == 1010\n  EVENT exploit WHERE alarm_severity >= 3\n  JOIN ON scan.dst_ip == brute.dst_ip AND brute.dst_ip == exploit.attacked_ip\n  WINDOW 120m\n  GENERATE\n    SEVERITY 4\n    NAME \"协同攻击检测\"\n    DESCRIPTION \"检测到扫描、暴力破解、漏洞利用的完整攻击流程\"".to_string(),
            description: Some("检测多阶段的协同攻击行为".to_string()),
            enabled: false,
        },
    ];

    let mut count = 0;
    for rule in rules {
        correlation_rules::create_correlation_rule(pool, &rule).await?;
        count += 1;
    }

    Ok(count)
}

/// 插入过滤规则模拟数据
pub async fn insert_mock_filter_rules(pool: &PgPool) -> Result<usize> {
    let rules = vec![
        FilterRuleInput {
            name: "过滤低危网络攻击".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1001".to_string(),
            field: "alarm_severity".to_string(),
            operator: "eq".to_string(),
            value: "1".to_string(),
            enabled: true,
        },
        FilterRuleInput {
            name: "过滤测试环境IP".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1009".to_string(),
            field: "src_ip".to_string(),
            operator: "contains".to_string(),
            value: "192.168.100".to_string(),
            enabled: true,
        },
        FilterRuleInput {
            name: "过滤已知误报样本".to_string(),
            alert_type: "malicious_sample".to_string(),
            alert_subtype: "2001".to_string(),
            field: "md5".to_string(),
            operator: "regex".to_string(),
            value: "^(abc123|def456).*".to_string(),
            enabled: false,
        },
        FilterRuleInput {
            name: "过滤白名单进程".to_string(),
            alert_type: "host_behavior".to_string(),
            alert_subtype: "3001".to_string(),
            field: "src_process_path".to_string(),
            operator: "contains".to_string(),
            value: "System32\\svchost.exe".to_string(),
            enabled: true,
        },
        FilterRuleInput {
            name: "过滤内网扫描".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1001".to_string(),
            field: "src_ip".to_string(),
            operator: "regex".to_string(),
            value: "^10\\.(0|1|2)\\..+".to_string(),
            enabled: false,
        },
        FilterRuleInput {
            name: "过滤信息类告警".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1002".to_string(),
            field: "alarm_severity".to_string(),
            operator: "eq".to_string(),
            value: "0".to_string(),
            enabled: true,
        },
    ];

    let mut count = 0;
    for rule in rules {
        filter_rules::create_filter_rule(pool, &rule).await?;
        count += 1;
    }

    Ok(count)
}

/// 插入标签规则模拟数据
pub async fn insert_mock_tag_rules(pool: &PgPool) -> Result<usize> {
    let rules = vec![
        TagRuleInput {
            name: "高危事件标记".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1009".to_string(),
            condition_field: "alarm_severity".to_string(),
            condition_operator: "eq".to_string(),
            condition_value: "3".to_string(),
            tags: vec!["高危".to_string(), "需人工审核".to_string()],
            description: Some("为高危网络攻击事件添加标签".to_string()),
            enabled: true,
        },
        TagRuleInput {
            name: "APT攻击标记".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1009".to_string(),
            condition_field: "apt_group".to_string(),
            condition_operator: "ne".to_string(),
            condition_value: "".to_string(),
            tags: vec!["APT攻击".to_string(), "高优先级".to_string()],
            description: Some("为APT组织相关攻击添加标签".to_string()),
            enabled: true,
        },
        TagRuleInput {
            name: "勒索软件标记".to_string(),
            alert_type: "malicious_sample".to_string(),
            alert_subtype: "2005".to_string(), // 勒索软件对应 2005
            condition_field: "sample_family".to_string(),
            condition_operator: "regex".to_string(),
            condition_value: ".*(Ransom|Crypto|Locker).*".to_string(),
            tags: vec![
                "勒索软件".to_string(),
                "严重".to_string(),
                "紧急处理".to_string(),
            ],
            description: Some("识别并标记勒索软件家族".to_string()),
            enabled: true,
        },
        TagRuleInput {
            name: "内网横向移动标记".to_string(),
            alert_type: "host_behavior".to_string(),
            alert_subtype: "3007".to_string(), // 横向移动对应 3007
            condition_field: "alarm_name".to_string(),
            condition_operator: "contains".to_string(),
            condition_value: "横向".to_string(),
            tags: vec!["横向移动".to_string(), "内网渗透".to_string()],
            description: Some("标记可能的内网横向移动行为".to_string()),
            enabled: true,
        },
        TagRuleInput {
            name: "外联C2标记".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1004".to_string(), // 后门通信/C2 对应 1004
            condition_field: "alarm_name".to_string(),
            condition_operator: "contains".to_string(),
            condition_value: "C2".to_string(),
            tags: vec![
                "C2通信".to_string(),
                "高优先级".to_string(),
                "需阻断".to_string(),
            ],
            description: Some("标记C2通信行为".to_string()),
            enabled: true,
        },
        TagRuleInput {
            name: "数据泄露标记".to_string(),
            alert_type: "host_behavior".to_string(),
            alert_subtype: "3008".to_string(), // 数据窃取对应 3008
            condition_field: "alarm_name".to_string(),
            condition_operator: "regex".to_string(),
            condition_value: ".*(泄露|外传|上传).*".to_string(),
            tags: vec!["数据泄露".to_string(), "严重".to_string()],
            description: Some("标记可能的数据泄露事件".to_string()),
            enabled: true,
        },
        TagRuleInput {
            name: "已知威胁情报标记".to_string(),
            alert_type: "network_attack".to_string(),
            alert_subtype: "1009".to_string(),
            condition_field: "source".to_string(),
            condition_operator: "contains".to_string(),
            condition_value: "威胁情报".to_string(),
            tags: vec!["威胁情报".to_string(), "已确认".to_string()],
            description: Some("标记来自威胁情报的告警".to_string()),
            enabled: false,
        },
    ];

    let mut count = 0;
    for rule in rules {
        tag_rules::create_tag_rule(pool, &rule).await?;
        count += 1;
    }

    Ok(count)
}

/// 插入所有规则的模拟数据
pub async fn insert_all_mock_rules(pool: &PgPool) -> Result<(usize, usize, usize, usize)> {
    let convergence_count = insert_mock_convergence_rules(pool).await?;
    let correlation_count = insert_mock_correlation_rules(pool).await?;
    let filter_count = insert_mock_filter_rules(pool).await?;
    let tag_count = insert_mock_tag_rules(pool).await?;

    Ok((
        convergence_count,
        correlation_count,
        filter_count,
        tag_count,
    ))
}
