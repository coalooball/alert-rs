use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConvergeRule {
    pub condition: Condition,
    pub group_by: Vec<String>,
    pub window: TimeWindow,
    pub threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelateRule {
    pub events: Vec<EventDefinition>,
    pub join_on: JoinCondition,
    pub window: TimeWindow,
    pub generate: GenerateBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventDefinition {
    pub alias: String,
    pub condition: Condition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub clauses: Vec<ConditionClause>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionClause {
    pub field: FieldRef,
    pub operator: ComparisonOp,
    pub value: Value,
    pub logical_op: Option<LogicalOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRef {
    pub event_alias: Option<String>,
    pub field_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComparisonOp {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Contains,
    Regex,
    In,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicalOp {
    And,
    Or,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Value {
    Number(i64),
    String(String),
    List(Vec<Value>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinCondition {
    pub clauses: Vec<JoinClause>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinClause {
    pub left: FieldRef,
    pub right: FieldRef,
    pub logical_op: Option<LogicalOp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeWindow {
    pub value: u32,
    pub unit: TimeUnit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimeUnit {
    Minutes,
    Hours,
    Days,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateBlock {
    pub severity: u8,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompileRequest {
    pub dsl_rule: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CompileResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl CompileResponse {
    pub fn success(message: String) -> Self {
        Self {
            success: true,
            message: Some(message),
            error: None,
        }
    }

    pub fn error(error: String) -> Self {
        Self {
            success: false,
            message: None,
            error: Some(error),
        }
    }
}

