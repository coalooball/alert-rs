use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// 标签记录 - 数据库模型
#[derive(Clone, Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct TagRecord {
    pub id: Uuid,
    pub name: String,
    pub category: String,
    pub color: String,
    pub description: Option<String>,
    pub usage_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// 标签输入 - 用于创建和更新
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagInput {
    pub name: String,
    pub category: String,
    pub color: String,
    pub description: Option<String>,
}

/// 创建标签表
pub async fn create_tag_table(pool: &PgPool) -> Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tags (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL UNIQUE,
            category TEXT NOT NULL,
            color TEXT NOT NULL,
            description TEXT,
            usage_count INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ DEFAULT now(),
            updated_at TIMESTAMPTZ DEFAULT now()
        )",
    )
    .execute(pool)
    .await?;

    // 创建索引以优化查询
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tags_category ON tags(category)")
        .execute(pool)
        .await?;

    sqlx::query("CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name)")
        .execute(pool)
        .await?;

    Ok(())
}

/// 删除标签表
pub async fn drop_tag_table(pool: &PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS tags CASCADE")
        .execute(pool)
        .await?;
    Ok(())
}

/// 创建标签
pub async fn create_tag(pool: &PgPool, input: &TagInput) -> Result<TagRecord> {
    let record = sqlx::query_as::<_, TagRecord>(
        "INSERT INTO tags (name, category, color, description)
         VALUES ($1, $2, $3, $4)
         RETURNING *",
    )
    .bind(&input.name)
    .bind(&input.category)
    .bind(&input.color)
    .bind(&input.description)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 更新标签
pub async fn update_tag(pool: &PgPool, id: Uuid, input: &TagInput) -> Result<TagRecord> {
    let record = sqlx::query_as::<_, TagRecord>(
        "UPDATE tags
         SET name = $2, category = $3, color = $4, description = $5, updated_at = now()
         WHERE id = $1
         RETURNING *",
    )
    .bind(id)
    .bind(&input.name)
    .bind(&input.category)
    .bind(&input.color)
    .bind(&input.description)
    .fetch_one(pool)
    .await?;

    Ok(record)
}

/// 删除标签
pub async fn delete_tag(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM tags WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 根据 ID 查询单个标签
pub async fn get_tag_by_id(pool: &PgPool, id: Uuid) -> Result<TagRecord> {
    let record = sqlx::query_as::<_, TagRecord>("SELECT * FROM tags WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await?;

    Ok(record)
}

/// 查询标签列表（支持分页和搜索）
pub async fn query_tags(
    pool: &PgPool,
    page: u64,
    page_size: u64,
    search: Option<String>,
    category: Option<String>,
) -> Result<(Vec<TagRecord>, u64)> {
    let offset = (page - 1) * page_size;

    let mut query = String::from("SELECT * FROM tags WHERE 1=1");
    let mut count_query = String::from("SELECT COUNT(*) FROM tags WHERE 1=1");

    // 构建搜索条件
    if let Some(ref s) = search {
        if !s.is_empty() {
            query.push_str(&format!(
                " AND (name ILIKE '%{}%' OR description ILIKE '%{}%')",
                s, s
            ));
            count_query.push_str(&format!(
                " AND (name ILIKE '%{}%' OR description ILIKE '%{}%')",
                s, s
            ));
        }
    }

    if let Some(ref c) = category {
        if !c.is_empty() {
            query.push_str(&format!(" AND category = '{}'", c));
            count_query.push_str(&format!(" AND category = '{}'", c));
        }
    }

    query.push_str(" ORDER BY created_at DESC LIMIT $1 OFFSET $2");

    // 执行查询
    let records = sqlx::query_as::<_, TagRecord>(&query)
        .bind(page_size as i64)
        .bind(offset as i64)
        .fetch_all(pool)
        .await?;

    let total: (i64,) = sqlx::query_as(&count_query).fetch_one(pool).await?;

    Ok((records, total.0 as u64))
}

/// 查询所有标签（不分页）
pub async fn get_all_tags(pool: &PgPool) -> Result<Vec<TagRecord>> {
    let records = sqlx::query_as::<_, TagRecord>("SELECT * FROM tags ORDER BY category, name")
        .fetch_all(pool)
        .await?;

    Ok(records)
}

/// 增加标签使用次数
#[allow(dead_code)]
pub async fn increment_tag_usage(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE tags SET usage_count = usage_count + 1, updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// 减少标签使用次数
#[allow(dead_code)]
pub async fn decrement_tag_usage(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query(
        "UPDATE tags SET usage_count = GREATEST(usage_count - 1, 0), updated_at = now() WHERE id = $1"
    )
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}

/// 根据名称查询标签
pub async fn get_tag_by_name(pool: &PgPool, name: &str) -> Result<Option<TagRecord>> {
    let record = sqlx::query_as::<_, TagRecord>("SELECT * FROM tags WHERE name = $1")
        .bind(name)
        .fetch_optional(pool)
        .await?;

    Ok(record)
}

/// 批量创建标签（如果不存在）
#[allow(dead_code)]
pub async fn create_tags_if_not_exist(pool: &PgPool, names: &[String]) -> Result<Vec<TagRecord>> {
    let mut records = Vec::new();

    for name in names {
        let record = sqlx::query_as::<_, TagRecord>(
            "INSERT INTO tags (name, category, color, description)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (name) DO UPDATE SET updated_at = now()
             RETURNING *",
        )
        .bind(name)
        .bind("其他")
        .bind("#409EFF")
        .bind(format!("自动创建的标签: {}", name))
        .fetch_one(pool)
        .await?;

        records.push(record);
    }

    Ok(records)
}
