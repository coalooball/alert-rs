# 告警查询接口文档

## 1. 网络攻击告警查询接口`

### 接口说明
根据告警ID查询网络攻击告警详细数据，支持批量查询

### 请求方式
`POST /api/alerts/network-attack/query`

### 请求头
```json
{
  "Content-Type": "application/json",
  "Authorization": "Bearer <token>"
}
```

### 请求参数
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| alarm_ids | string[] | 是 | 告警ID列表，支持批量查询 |

### 请求示例
```json
{
  "alarm_ids": [
    "NA-2024-001-ABC123",
    "NA-2024-002-DEF456"
  ]
}
```

### 响应参数
| 参数名 | 类型 | 说明 |
|--------|------|------|
| code | integer | 响应码 |
| message | string | 响应消息 |
| data | array | 告警记录数组 |

### 响应示例
```json
{
  "code": 200,
  "message": "查询成功",
  "data": [
    {
      "alarm_id": "NA-2024-001-ABC123",
      "alarm_date": 1735142400000,
      "alarm_severity": 3,
      "alarm_name": "APT组织Lazarus后门通信检测",
      "alarm_description": "检测到终端与已知APT组织Lazarus的C2服务器进行加密通信，存在数据泄露风险",
      "alarm_type": 1,
      "alarm_subtype": 1004,
      "source": 1,
      "control_rule_id": "RULE-APT-2024-001",
      "control_task_id": "TASK-SEC-2024-100",
      "procedure_technique_id": ["T1071.001", "T1573.001"],
      "session_id": "SESSION-20241225-142300-001",
      "ip_version": 4,
      "src_ip": "192.168.1.100",
      "src_port": 54321,
      "dst_ip": "185.234.218.100",
      "dst_port": 443,
      "protocol": "HTTPS",
      "terminal_id": "TERM-OFFICE-PC-001",
      "source_file_path": "/data/traffic/2024/12/25/capture_142300.pcap",
      "signature_id": "SIG-APT-LAZARUS-001",
      "attack_payload": "{\"tls_version\":\"1.3\",\"cipher_suite\":\"TLS_AES_256_GCM_SHA384\",\"sni\":\"update.microsoft-services.com\"}",
      "attack_stage": "Command and Control",
      "attack_ip": "185.234.218.100",
      "attacked_ip": "192.168.1.100",
      "apt_group": "Lazarus Group",
      "vul_type": "",
      "CVE_id": "",
      "vul_desc": ""
    },
    {
      "alarm_id": "NA-2024-002-DEF456",
      "alarm_date": 1735146000000,
      "alarm_severity": 2,
      "alarm_name": "SQL注入漏洞利用尝试",
      "alarm_description": "检测到针对Web应用程序的SQL注入攻击尝试，攻击者试图获取数据库信息",
      "alarm_type": 1,
      "alarm_subtype": 1003,
      "source": 2,
      "control_rule_id": "RULE-SQLI-2024-002",
      "control_task_id": "TASK-WEB-2024-050",
      "procedure_technique_id": ["T1190"],
      "session_id": "SESSION-20241225-150000-002",
      "ip_version": 4,
      "src_ip": "45.67.89.123",
      "src_port": 38745,
      "dst_ip": "10.0.1.50",
      "dst_port": 80,
      "protocol": "HTTP",
      "terminal_id": "",
      "source_file_path": "/data/traffic/2024/12/25/capture_150000.pcap",
      "signature_id": "SIG-SQLI-001",
      "attack_payload": "{\"method\":\"GET\",\"uri\":\"/products.php?id=1' OR '1'='1\",\"user_agent\":\"sqlmap/1.5\"}",
      "attack_stage": "Initial Access",
      "attack_ip": "45.67.89.123",
      "attacked_ip": "10.0.1.50",
      "apt_group": "",
      "vul_type": "SQL注入",
      "CVE_id": "CVE-2024-1234",
      "vul_desc": "应用程序未对用户输入进行适当验证，导致SQL注入漏洞"
    }
  ]
}
```

### 错误响应示例（404 - 资源不存在）
```json
{
  "code": 404,
  "message": "未找到指定告警",
  "error": {
    "alarm_ids": ["NA-2024-999-XXX999", "NA-2024-888-YYY888"],
    "reason": "告警ID不存在"
  }
}
```

### 错误响应示例（401 - 未授权）
```json
{
  "code": 401,
  "message": "认证失败",
  "error": {
    "reason": "Token已过期或无效"
  }
}
```

### 错误响应示例（400 - 请求参数错误）
```json
{
  "code": 400,
  "message": "请求参数错误",
  "error": {
    "field": "alarm_ids",
    "reason": "告警ID列表不能为空"
  }
}
```

### 告警子类编码
| 编码 | 说明 |
|------|------|
| 01001 | 网络扫描探测 |
| 01002 | 网络钓鱼 |
| 01003 | 漏洞利用 |
| 01004 | 后门通信 |
| 01005 | 凭据攻击 |
| 01006 | 拒绝服务 |
| 01007 | 网页篡改 |
| 01008 | 失陷主机 |
| 01009 | APT攻击 |
| 01010 | 其他网络攻击 |

---

## 2. 恶意样本告警查询接口

### 接口说明
根据告警ID查询恶意样本告警详细数据，支持批量查询

### 请求方式
`POST /api/alerts/malicious-sample/query`

### 请求头
```json
{
  "Content-Type": "application/json",
  "Authorization": "Bearer <token>"
}
```

### 请求参数
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| alarm_ids | string[] | 是 | 告警ID列表，支持批量查询 |

### 请求示例
```json
{
  "alarm_ids": [
    "MS-2024-001-ABC456",
    "MS-2024-002-DEF789"
  ]
}
```

### 响应参数
| 参数名 | 类型 | 说明 |
|--------|------|------|
| code | integer | 响应码 |
| message | string | 响应消息 |
| data | array | 告警记录数组 |

### 响应示例
```json
{
  "code": 200,
  "message": "查询成功",
  "data": [
    {
      "alarm_id": "MS-2024-001-ABC456",
      "alarm_date": 1735142400000,
      "alarm_severity": 3,
      "alarm_name": "Emotet银行木马变种检测",
      "alarm_description": "检测到Emotet银行木马最新变种，该样本具有窃取银行凭证和传播能力",
      "alarm_type": 2,
      "alarm_subtype": 2003,
      "source": 4,
      "control_rule_id": "RULE-TROJAN-2024-001",
      "control_task_id": "TASK-MAL-2024-200",
      "procedure_technique_id": ["T1055", "T1566.001"],
      "session_id": "",
      "ip_version": null,
      "src_ip": "",
      "src_port": null,
      "dst_ip": "",
      "dst_port": null,
      "protocol": "",
      "terminal_id": "TERM-FIN-PC-002",
      "source_file_path": "/data/samples/2024/12/25/sample_142400.exe",
      "sample_source": 2,
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      "ssdeep": "96:K7tqRtpEDC6J0wn9JNJNJv:S85DJ0wnxJv",
      "sample_original_name": "invoice_2024.exe",
      "sample_description": "",
      "sample_family": "Emotet",
      "apt_group": "",
      "sample_alarm_engine": [1, 2],
      "target_platform": "Windows x64",
      "file_type": "PE32+ executable",
      "file_size": 458752,
      "language": "C++",
      "rule": "YARA:Emotet_Dropper_2024, AV:Trojan.Win32.Emotet",
      "target_content": "",
      "compile_date": 1735056000000,
      "last_analy_date": 1735142400000,
      "sample_alarm_detail": "[{\"rule_name\":\"Emotet_Dropper_2024\"},{\"av_engine_name\":\"Kaspersky\",\"av_label\":\"Trojan.Win32.Emotet.gen\"},{\"av_engine_name\":\"BitDefender\",\"av_label\":\"Trojan.GenericKD.65432\"}]"
    },
    {
      "alarm_id": "MS-2024-002-DEF789",
      "alarm_date": 1735146000000,
      "alarm_severity": 3,
      "alarm_name": "WannaCry勒索软件检测",
      "alarm_description": "发现WannaCry勒索软件样本，该样本会加密系统文件并索要比特币赎金",
      "alarm_type": 2,
      "alarm_subtype": 2005,
      "source": 1,
      "control_rule_id": "0",
      "control_task_id": "0",
      "procedure_technique_id": ["T1486", "T1083"],
      "session_id": "SESSION-20241225-150000-010",
      "ip_version": 4,
      "src_ip": "192.168.1.50",
      "src_port": 54321,
      "dst_ip": "185.234.218.100",
      "dst_port": 443,
      "protocol": "HTTPS",
      "terminal_id": "",
      "source_file_path": "/data/samples/2024/12/25/sample_150000.exe",
      "sample_source": 1,
      "md5": "84c82835a5d21bbcf75a61706d8ab549",
      "sha1": "51e4307093f8ca8854359c0ac882ddca427a813c",
      "sha256": "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
      "sha512": "7fff17b2e650d6b6fe06a15451d50d03c3e5ef9b1f8523a96e1c3c239b7c45f6a862f889c3e2e1a8e5c8f1234567890abcdef1234567890abcdef1234567890ab",
      "ssdeep": "12288:WnCylRJQKGFtLoBSKxFLBoBJCFLBJFx:WnCy1JhGF3oBDx3oBhF3hx",
      "sample_original_name": "tasksche.exe",
      "sample_description": "",
      "sample_family": "WannaCry",
      "apt_group": "Lazarus Group",
      "sample_alarm_engine": [1, 2, 3],
      "target_platform": "Windows x86/x64",
      "file_type": "PE32 executable",
      "file_size": 3514368,
      "language": "C++",
      "rule": "YARA:WannaCry_Ransomware, IOC:SHA256_Match",
      "target_content": "Encrypted file extensions: .WNCRY",
      "compile_date": 1494547200000,
      "last_analy_date": 1735146000000,
      "sample_alarm_detail": "{\"ioc_type\":\"SHA256\",\"ioc_value\":\"24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c\"}"
    }
  ]
}
```

### 错误响应示例（404 - 资源不存在）
```json
{
  "code": 404,
  "message": "未找到指定告警",
  "error": {
    "alarm_ids": ["MS-2024-999-XXX999"],
    "reason": "告警ID不存在"
  }
}
```

### 错误响应示例（401 - 未授权）
```json
{
  "code": 401,
  "message": "认证失败",
  "error": {
    "reason": "Token已过期或无效"
  }
}
```

### 告警子类编码
| 编码 | 说明 |
|------|------|
| 02001 | 计算机病毒 |
| 02002 | 网络蠕虫 |
| 02003 | 特洛伊木马 |
| 02004 | 僵尸网络 |
| 02005 | 勒索软件 |
| 02006 | 挖矿软件 |
| 02007 | 其他恶意样本 |

### 告警引擎类型
| 值 | 说明 |
|----|------|
| 1 | AV (杀毒引擎) |
| 2 | YARA |
| 3 | IOC |

---

## 3. 主机行为告警查询接口

### 接口说明
根据告警ID查询主机行为告警详细数据，支持批量查询

### 请求方式
`POST /api/alerts/host-behavior/query`

### 请求头
```json
{
  "Content-Type": "application/json",
  "Authorization": "Bearer <token>"
}
```

### 请求参数
| 参数名 | 类型 | 必填 | 说明 |
|--------|------|------|------|
| alarm_ids | string[] | 是 | 告警ID列表，支持批量查询 |

### 请求示例
```json
{
  "alarm_ids": [
    "HB-2024-001-ABC789",
    "HB-2024-002-DEF012"
  ]
}
```

### 响应参数
| 参数名 | 类型 | 说明 |
|--------|------|------|
| code | integer | 响应码 |
| message | string | 响应消息 |
| data | array | 告警记录数组 |

### 响应示例
```json
{
  "code": 200,
  "message": "查询成功",
  "data": [
    {
      "alarm_id": "HB-2024-001-ABC789",
      "alarm_date": 1735142400000,
      "alarm_severity": 3,
      "alarm_name": "XMRig挖矿进程检测",
      "alarm_description": "检测到主机运行XMRig挖矿程序，占用大量CPU资源进行门罗币挖矿",
      "alarm_type": 3,
      "alarm_subtype": 3001,
      "source": 3,
      "control_rule_id": "RULE-MINING-2024-001",
      "control_task_id": "TASK-HOST-2024-300",
      "procedure_technique_id": ["T1496"],
      "session_id": "",
      "ip_version": 4,
      "src_ip": "",
      "src_port": null,
      "dst_ip": "pool.minexmr.com",
      "dst_port": 4444,
      "protocol": "TCP",
      "terminal_id": "TERM-SVR-DB-001",
      "source_file_path": "/data/logs/2024/12/25/host_142400.log",
      "host_name": "DB-SERVER-01",
      "terminal_ip": "192.168.10.50",
      "user_account": "www-data",
      "terminal_os": "Ubuntu 20.04.3 LTS",
      "dst_process_md5": "d41d8cd98f00b204e9800998ecf8427e",
      "dst_process_path": "/tmp/.system/xmrig",
      "dst_process_cli": "/tmp/.system/xmrig -o pool.minexmr.com:4444 -u wallet_address -p x",
      "src_process_md5": "a1b2c3d4e5f6789012345678901234567",
      "src_process_path": "/usr/sbin/apache2",
      "src_process_cli": "/usr/sbin/apache2 -k start",
      "register_key_name": "",
      "register_key_value": "",
      "register_path": "",
      "file_name": "xmrig",
      "file_md5": "d41d8cd98f00b204e9800998ecf8427e",
      "file_path": "/tmp/.system/xmrig"
    },
    {
      "alarm_id": "HB-2024-002-DEF012",
      "alarm_date": 1735146000000,
      "alarm_severity": 3,
      "alarm_name": "勒索软件文件加密行为",
      "alarm_description": "检测到大量文件被加密并添加.locked扩展名，疑似勒索软件攻击",
      "alarm_type": 3,
      "alarm_subtype": 3002,
      "source": 8,
      "control_rule_id": "RULE-RANSOM-2024-002",
      "control_task_id": "TASK-INCIDENT-2024-001",
      "procedure_technique_id": ["T1486", "T1490"],
      "session_id": "",
      "ip_version": null,
      "src_ip": "",
      "src_port": null,
      "dst_ip": "",
      "dst_port": null,
      "protocol": "",
      "terminal_id": "TERM-FIN-PC-010",
      "source_file_path": "/data/logs/2024/12/25/host_150000.log",
      "host_name": "FIN-WORKSTATION-10",
      "terminal_ip": "192.168.2.110",
      "user_account": "john.smith",
      "terminal_os": "Windows 10 Pro",
      "dst_process_md5": "98765432109876543210987654321098",
      "dst_process_path": "C:\\Users\\john.smith\\AppData\\Roaming\\svchost.exe",
      "dst_process_cli": "C:\\Users\\john.smith\\AppData\\Roaming\\svchost.exe --encrypt-all",
      "src_process_md5": "",
      "src_process_path": "",
      "src_process_cli": "",
      "register_key_name": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "register_key_value": "C:\\Users\\john.smith\\AppData\\Roaming\\svchost.exe",
      "register_path": "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "file_name": "HOW_TO_DECRYPT.txt",
      "file_md5": "",
      "file_path": "C:\\Users\\john.smith\\Desktop\\HOW_TO_DECRYPT.txt"
    }
  ]
}
```

### 错误响应示例（404 - 资源不存在）
```json
{
  "code": 404,
  "message": "未找到指定告警",
  "error": {
    "alarm_ids": ["HB-2024-999-XXX999", "HB-2024-888-YYY888"],
    "reason": "告警ID不存在"
  }
}
```

### 错误响应示例（401 - 未授权）
```json
{
  "code": 401,
  "message": "认证失败",
  "error": {
    "reason": "Token已过期或无效"
  }
}
```

### 错误响应示例（500 - 服务器错误）
```json
{
  "code": 500,
  "message": "服务器内部错误",
  "error": {
    "reason": "数据库连接失败"
  }
}
```

### 告警子类编码
| 编码 | 说明 |
|------|------|
| 03001 | 挖矿攻击 |
| 03002 | 勒索攻击 |
| 03003 | 远控攻击 |
| 03004 | 爆破攻击 |
| 03005 | 后门攻击 |
| 03006 | 注入攻击 |
| 03007 | 横向移动攻击 |
| 03008 | 数据窃取攻击 |
| 03009 | 其它异常行为告警 |

---

## 通用响应码说明

| 响应码 | 说明 |
|--------|------|
| 200 | 请求成功 |
| 400 | 请求参数错误 |
| 401 | 未授权访问 |
| 403 | 权限不足 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |
| 503 | 服务不可用 |

## 错误响应格式

```json
{
  "code": 400,
  "message": "请求参数错误",
  "error": {
    "field": "alarm_ids",
    "reason": "告警ID列表不能为空"
  }
}
```

## 数据源编码说明

| 编码 | 说明 |
|------|------|
| 1 | 精控流量检测引擎 |
| 2 | 漏洞分析引擎 |
| 3 | 终端日志检测引擎 |
| 4 | 样本检测引擎 |
| 5 | D3包 |
| 6 | D7包 |
| 7 | D5包 |
| 8 | D6包 |
| 9 | TL一期 |
| 10 | D2包 |
| 11 | 其他 |

## 注意事项

1. 所有时间戳均为13位Unix时间戳（毫秒级）
2. alarm_ids为必填参数，至少需要提供一个告警ID
3. Token认证失败将返回401错误
4. 查询不存在的告警ID将返回404错误
5. 响应数据包含所有字段的完整信息
6. 空值字段会返回null或空字符串