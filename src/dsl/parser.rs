use pest::Parser;
use pest_derive::Parser;
use anyhow::{anyhow, Result};

use super::types::*;

#[derive(Parser)]
#[grammar = "dsl/grammar.pest"]
pub struct DslParser;

pub fn parse_converge_rule(input: &str) -> Result<ConvergeRule> {
    let pairs = DslParser::parse(Rule::converge_rule, input)
        .map_err(|e| anyhow!("解析错误: {}", e))?;

    let mut condition = None;
    let mut group_by = Vec::new();
    let mut window = None;
    let mut threshold = None;

    for pair in pairs {
        match pair.as_rule() {
            Rule::converge_rule => {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::converge_where => {
                            condition = Some(parse_condition(inner_pair)?);
                        }
                        Rule::converge_group_by => {
                            for field_pair in inner_pair.into_inner() {
                                if field_pair.as_rule() == Rule::identifier {
                                    group_by.push(field_pair.as_str().to_string());
                                }
                            }
                        }
                        Rule::converge_window => {
                            window = Some(parse_time_window(inner_pair)?);
                        }
                        Rule::converge_threshold => {
                            for num_pair in inner_pair.into_inner() {
                                if num_pair.as_rule() == Rule::number {
                                    threshold = Some(num_pair.as_str().parse()?);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    Ok(ConvergeRule {
        condition: condition.ok_or_else(|| anyhow!("缺少 WHERE 子句"))?,
        group_by,
        window: window.ok_or_else(|| anyhow!("缺少 WINDOW 子句"))?,
        threshold: threshold.ok_or_else(|| anyhow!("缺少 THRESHOLD 子句"))?,
    })
}

pub fn parse_correlate_rule(input: &str) -> Result<CorrelateRule> {
    let pairs = DslParser::parse(Rule::correlate_rule, input)
        .map_err(|e| anyhow!("解析错误: {}", e))?;

    let mut events = Vec::new();
    let mut join_on = None;
    let mut window = None;
    let mut generate = None;

    for pair in pairs {
        match pair.as_rule() {
            Rule::correlate_rule => {
                for inner_pair in pair.into_inner() {
                    match inner_pair.as_rule() {
                        Rule::event_def => {
                            events.push(parse_event_definition(inner_pair)?);
                        }
                        Rule::join_on => {
                            join_on = Some(parse_join_condition(inner_pair)?);
                        }
                        Rule::correlate_window => {
                            window = Some(parse_time_window(inner_pair)?);
                        }
                        Rule::generate_block => {
                            generate = Some(parse_generate_block(inner_pair)?);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    if events.len() < 2 {
        return Err(anyhow!("关联规则至少需要2个事件定义"));
    }

    Ok(CorrelateRule {
        events,
        join_on: join_on.ok_or_else(|| anyhow!("缺少 JOIN ON 子句"))?,
        window: window.ok_or_else(|| anyhow!("缺少 WINDOW 子句"))?,
        generate: generate.ok_or_else(|| anyhow!("缺少 GENERATE 块"))?,
    })
}

fn parse_condition(pair: pest::iterators::Pair<Rule>) -> Result<Condition> {
    let mut clauses = Vec::new();
    let mut current_logical_op = None;

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::condition => {
                return parse_condition(inner_pair);
            }
            Rule::simple_condition => {
                let clause = parse_simple_condition(inner_pair)?;
                let mut clause = clause;
                clause.logical_op = current_logical_op.take();
                clauses.push(clause);
            }
            Rule::and_op => {
                current_logical_op = Some(LogicalOp::And);
            }
            Rule::or_op => {
                current_logical_op = Some(LogicalOp::Or);
            }
            _ => {}
        }
    }

    Ok(Condition { clauses })
}

fn parse_simple_condition(pair: pest::iterators::Pair<Rule>) -> Result<ConditionClause> {
    let mut field = None;
    let mut operator = None;
    let mut value = None;

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::field_ref => {
                field = Some(parse_field_ref(inner_pair)?);
            }
            Rule::comparison_op => {
                operator = Some(parse_comparison_op(inner_pair)?);
            }
            Rule::value => {
                value = Some(parse_value(inner_pair)?);
            }
            Rule::value_list => {
                value = Some(parse_value_list(inner_pair)?);
            }
            _ => {}
        }
    }

    Ok(ConditionClause {
        field: field.ok_or_else(|| anyhow!("缺少字段"))?,
        operator: operator.ok_or_else(|| anyhow!("缺少操作符"))?,
        value: value.ok_or_else(|| anyhow!("缺少值"))?,
        logical_op: None,
    })
}

fn parse_field_ref(pair: pest::iterators::Pair<Rule>) -> Result<FieldRef> {
    let parts: Vec<_> = pair.into_inner().collect();
    
    if parts.len() == 2 {
        Ok(FieldRef {
            event_alias: Some(parts[0].as_str().to_string()),
            field_name: parts[1].as_str().to_string(),
        })
    } else if parts.len() == 1 {
        Ok(FieldRef {
            event_alias: None,
            field_name: parts[0].as_str().to_string(),
        })
    } else {
        Err(anyhow!("字段引用格式错误"))
    }
}

fn parse_comparison_op(pair: pest::iterators::Pair<Rule>) -> Result<ComparisonOp> {
    for inner_pair in pair.into_inner() {
        return Ok(match inner_pair.as_rule() {
            Rule::eq_op => ComparisonOp::Equal,
            Rule::ne_op => ComparisonOp::NotEqual,
            Rule::gt_op => {
                if inner_pair.as_str() == ">=" {
                    ComparisonOp::GreaterThanOrEqual
                } else {
                    ComparisonOp::GreaterThan
                }
            }
            Rule::lt_op => {
                if inner_pair.as_str() == "<=" {
                    ComparisonOp::LessThanOrEqual
                } else {
                    ComparisonOp::LessThan
                }
            }
            Rule::contains_op => ComparisonOp::Contains,
            Rule::regex_op => ComparisonOp::Regex,
            Rule::in_op => ComparisonOp::In,
            _ => return Err(anyhow!("未知的比较操作符")),
        });
    }
    Err(anyhow!("缺少操作符"))
}

fn parse_value(pair: pest::iterators::Pair<Rule>) -> Result<Value> {
    for inner_pair in pair.into_inner() {
        return Ok(match inner_pair.as_rule() {
            Rule::number => Value::Number(inner_pair.as_str().parse()?),
            Rule::string => {
                let s = inner_pair.into_inner().next()
                    .ok_or_else(|| anyhow!("字符串解析错误"))?
                    .as_str()
                    .to_string();
                Value::String(s)
            }
            Rule::identifier => Value::String(inner_pair.as_str().to_string()),
            _ => return Err(anyhow!("未知的值类型")),
        });
    }
    Err(anyhow!("缺少值"))
}

fn parse_value_list(pair: pest::iterators::Pair<Rule>) -> Result<Value> {
    let mut values = Vec::new();
    for inner_pair in pair.into_inner() {
        if inner_pair.as_rule() == Rule::value {
            values.push(parse_value(inner_pair)?);
        }
    }
    Ok(Value::List(values))
}

fn parse_time_window(pair: pest::iterators::Pair<Rule>) -> Result<TimeWindow> {
    let mut value = None;
    let mut unit = TimeUnit::Minutes; // 默认单位

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::number => {
                value = Some(inner_pair.as_str().parse()?);
            }
            _ => {
                unit = match inner_pair.as_str() {
                    "m" | "minutes" => TimeUnit::Minutes,
                    "h" | "hours" => TimeUnit::Hours,
                    "d" | "days" => TimeUnit::Days,
                    _ => TimeUnit::Minutes,
                };
            }
        }
    }

    Ok(TimeWindow {
        value: value.ok_or_else(|| anyhow!("缺少时间窗口值"))?,
        unit,
    })
}

fn parse_event_definition(pair: pest::iterators::Pair<Rule>) -> Result<EventDefinition> {
    let mut alias = None;
    let mut condition = None;

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identifier => {
                alias = Some(inner_pair.as_str().to_string());
            }
            Rule::condition => {
                condition = Some(parse_condition(inner_pair)?);
            }
            _ => {}
        }
    }

    Ok(EventDefinition {
        alias: alias.ok_or_else(|| anyhow!("缺少事件别名"))?,
        condition: condition.ok_or_else(|| anyhow!("缺少事件条件"))?,
    })
}

fn parse_join_condition(pair: pest::iterators::Pair<Rule>) -> Result<JoinCondition> {
    let mut clauses = Vec::new();
    let mut current_logical_op: Option<LogicalOp> = None;

    // 收集所有内部 pairs
    let mut inner_pairs: Vec<_> = pair.into_inner().collect();
    
    // 如果只有一个 inner pair 且它也是 join_condition，递归处理
    if inner_pairs.len() == 1 && inner_pairs[0].as_rule() == Rule::join_condition {
        inner_pairs = inner_pairs[0].clone().into_inner().collect();
    }
    
    let mut i = 0;
    while i < inner_pairs.len() {
        match inner_pairs[i].as_rule() {
            Rule::field_ref => {
                // 找到第一个字段引用
                if i + 2 < inner_pairs.len() {
                    let left = parse_field_ref(inner_pairs[i].clone())?;
                    
                    // 跳过 eq_op (i+1)
                    if inner_pairs[i + 1].as_rule() == Rule::eq_op {
                        // 获取右侧字段 (i+2)
                        if inner_pairs[i + 2].as_rule() == Rule::field_ref {
                            let right = parse_field_ref(inner_pairs[i + 2].clone())?;
                            
                            clauses.push(JoinClause {
                                left,
                                right,
                                logical_op: current_logical_op.clone(),
                            });
                            current_logical_op = None;
                            i += 3;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            Rule::and_op => {
                current_logical_op = Some(LogicalOp::And);
                i += 1;
            }
            Rule::or_op => {
                current_logical_op = Some(LogicalOp::Or);
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    if clauses.is_empty() {
        return Err(anyhow!("JOIN ON 子句解析失败：未找到有效的关联条件"));
    }

    Ok(JoinCondition { clauses })
}

fn parse_generate_block(pair: pest::iterators::Pair<Rule>) -> Result<GenerateBlock> {
    let mut severity = None;
    let mut name = None;
    let mut description = None;

    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::generate_severity => {
                for num_pair in inner_pair.into_inner() {
                    if num_pair.as_rule() == Rule::number {
                        severity = Some(num_pair.as_str().parse()?);
                    }
                }
            }
            Rule::generate_name => {
                for str_pair in inner_pair.into_inner() {
                    if str_pair.as_rule() == Rule::string {
                        name = Some(
                            str_pair
                                .into_inner()
                                .next()
                                .ok_or_else(|| anyhow!("名称解析错误"))?
                                .as_str()
                                .to_string(),
                        );
                    }
                }
            }
            Rule::generate_description => {
                for str_pair in inner_pair.into_inner() {
                    if str_pair.as_rule() == Rule::string {
                        description = Some(
                            str_pair
                                .into_inner()
                                .next()
                                .ok_or_else(|| anyhow!("描述解析错误"))?
                                .as_str()
                                .to_string(),
                        );
                    }
                }
            }
            _ => {}
        }
    }

    Ok(GenerateBlock {
        severity: severity.ok_or_else(|| anyhow!("缺少 SEVERITY"))?,
        name: name.ok_or_else(|| anyhow!("缺少 NAME"))?,
        description: description.ok_or_else(|| anyhow!("缺少 DESCRIPTION"))?,
    })
}

