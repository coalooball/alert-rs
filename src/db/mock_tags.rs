use anyhow::Result;
use sqlx::PgPool;

/// 插入标签模拟数据
/// 返回插入的记录数
pub async fn insert_mock_tags(pool: &PgPool) -> Result<usize> {
    let mut count = 0;

    // 安全事件类标签
    let tags = vec![
        // 安全事件类
        ("APT攻击", "安全事件", "#E74C3C", "高级持续性威胁攻击事件"),
        ("勒索软件", "安全事件", "#C0392B", "勒索软件感染和加密事件"),
        ("DDoS攻击", "安全事件", "#E67E22", "分布式拒绝服务攻击"),
        ("数据泄露", "安全事件", "#D35400", "敏感数据泄露或外传事件"),
        ("供应链攻击", "安全事件", "#8E44AD", "第三方供应链安全事件"),
        // 威胁等级类
        ("高危", "威胁等级", "#E74C3C", "高危威胁，需要立即处理"),
        ("中危", "威胁等级", "#F39C12", "中等威胁，需要关注"),
        ("低危", "威胁等级", "#3498DB", "低危威胁，常规处理"),
        ("信息", "威胁等级", "#95A5A6", "信息性事件，无需处理"),
        // 处理状态类
        ("已处理", "处理状态", "#27AE60", "事件已完成处理"),
        ("处理中", "处理状态", "#F39C12", "事件正在处理中"),
        ("待处理", "处理状态", "#E74C3C", "事件等待处理"),
        ("已忽略", "处理状态", "#95A5A6", "事件已忽略"),
        // 攻击类型类
        ("钓鱼攻击", "攻击类型", "#9B59B6", "钓鱼邮件、钓鱼网站等"),
        (
            "漏洞利用",
            "攻击类型",
            "#E67E22",
            "利用系统或应用漏洞的攻击",
        ),
        (
            "恶意软件",
            "攻击类型",
            "#C0392B",
            "病毒、木马、蠕虫等恶意软件",
        ),
        ("暴力破解", "攻击类型", "#D35400", "密码暴力破解攻击"),
        ("SQL注入", "攻击类型", "#8E44AD", "SQL注入攻击"),
        ("XSS攻击", "攻击类型", "#9B59B6", "跨站脚本攻击"),
        // 行业类
        ("金融行业", "行业", "#3498DB", "银行、证券、保险等金融机构"),
        (
            "能源行业",
            "行业",
            "#E74C3C",
            "电力、石油、天然气等能源企业",
        ),
        ("互联网", "行业", "#1ABC9C", "互联网和科技公司"),
        ("制造业", "行业", "#34495E", "制造和工业企业"),
        // 影响范围类
        ("单一主机", "影响范围", "#3498DB", "影响单个主机或设备"),
        ("局部网络", "影响范围", "#F39C12", "影响局部网络或部门"),
        ("全网范围", "影响范围", "#E74C3C", "影响整个企业网络"),
    ];

    for (name, category, color, description) in tags {
        // 使用 ON CONFLICT 避免重复插入
        sqlx::query(
            "INSERT INTO tags (name, category, color, description, usage_count)
             VALUES ($1, $2, $3, $4, 0)
             ON CONFLICT (name) DO NOTHING",
        )
        .bind(name)
        .bind(category)
        .bind(color)
        .bind(description)
        .execute(pool)
        .await?;

        count += 1;
    }

    Ok(count)
}

/// 清空所有标签数据（保留表结构）
#[allow(dead_code)]
pub async fn clear_all_tags(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM tags").execute(pool).await?;

    Ok(result.rows_affected())
}

/// 重置标签数据：先清空，再插入模拟数据
#[allow(dead_code)]
pub async fn reset_mock_tags(pool: &PgPool) -> Result<usize> {
    clear_all_tags(pool).await?;
    insert_mock_tags(pool).await
}
