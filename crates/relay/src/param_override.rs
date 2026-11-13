//! Go `internal/relay/common/apply_param_override.go` 的移植（2164 行）。
//!
//! 契约要点：
//! - `operations` 键存在且可解析 → 新操作模式；否则旧 map 逐顶层 key 字面覆盖。
//! - 操作模式全集：delete/set/move/copy/prepend/append/trim_prefix/trim_suffix/
//!   ensure_prefix/ensure_suffix/trim_space/to_lower/to_upper/replace/
//!   regex_replace/return_error/prune_objects/set_header/delete_header/
//!   copy_header/move_header/pass_headers/sync_fields。
//! - 条件：path/mode(full,prefix,suffix,contains,gt,gte,lt,lte)/value/invert/
//!   pass_missing_key，logic AND/OR（默认 OR）。
//! - 负数索引 `.(-\d+)`：按数组长度换算。
//! - header 操作作用于上下文的 `header_override` / `request_headers` 表，
//!   归一化为小写 TrimSpace。
//! - `return_error` 产出 [`ParamOverrideReturnError`]，由
//!   [`api_error_from_param_override`] 归一化为 OpenAI 错误信封。
//!
//! JSON 路径语义对齐 sjson/gjson 的字面 key 用法（`.*?\` 转义、数字下标、
//! 通配符在应用前展开为具体路径），未实现 gjson 的 `#`/查询/修饰符等高级语法
//! ——Go 侧本文件只用到了上述子集。

use std::collections::BTreeMap;

use serde_json::{Map, Value};

const CONTEXT_REQUEST_HEADERS: &str = "request_headers";
const CONTEXT_HEADER_OVERRIDE: &str = "header_override";
#[allow(dead_code)] // 与 Go 上下文键名对齐，供 dispatch 切片接线审计时复用
const CONTEXT_AUDIT_RECORDER: &str = "__param_override_audit_recorder";

/// Go `paramOverrideSensitivePathPrefixes`。
const SENSITIVE_PATH_PREFIXES: &[&str] = &[
    "model",
    "original_model",
    "upstream_model",
    "reasoning",
    "reasoning_effort",
    "output_config",
    "generationConfig.thinkingConfig",
    "generation_config.thinking_config",
    "service_tier",
    "inference_geo",
    "speed",
    "messages",
    "input",
    "instructions",
    "system",
    "contents",
    "systemInstruction",
    "system_instruction",
];

// ---------------------------------------------------------------------------
// 数据结构
// ---------------------------------------------------------------------------

/// Go `ConditionOperation`。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConditionOperation {
    pub path: String,
    pub mode: String,
    pub value: Value,
    pub invert: bool,
    pub pass_missing_key: bool,
}

/// Go `ParamOperation`。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParamOperation {
    pub path: String,
    pub mode: String,
    pub value: Value,
    pub keep_origin: bool,
    pub from: String,
    pub to: String,
    pub conditions: Vec<ConditionOperation>,
    pub logic: String,
}

/// Go `ParamOverrideReturnError`。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ParamOverrideReturnError {
    pub message: String,
    pub status_code: i32,
    pub code: String,
    pub error_type: String,
    pub skip_retry: bool,
}

/// 应用过程的错误：受控的 `return_error` 或普通失败。
#[derive(Clone, Debug, PartialEq)]
pub enum ParamOverrideError {
    Return(ParamOverrideReturnError),
    Message(String),
}

impl std::fmt::Display for ParamOverrideError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Return(e) => write!(f, "{}", go_display_message(e)),
            Self::Message(m) => write!(f, "{m}"),
        }
    }
}

/// Go `ParamOverrideReturnError.Error()` 的显示语义（含 nil 占位分支）。
fn go_display_message(e: &ParamOverrideReturnError) -> String {
    if e.message.is_empty() {
        "param override return error".to_owned()
    } else {
        e.message.clone()
    }
}

impl ParamOverrideError {
    /// Go `AsParamOverrideReturnError`。
    pub fn as_return_error(&self) -> Option<&ParamOverrideReturnError> {
        match self {
            Self::Return(e) => Some(e),
            Self::Message(_) => None,
        }
    }
}

/// 上下文：条件求值与 header 操作共享的可变表。
/// audit 开关与 Go 一致由调用方决定（记录器是否注入）。
#[derive(Debug, Default)]
pub struct ParamOverrideContext {
    pub map: Map<String, Value>,
    pub audit_lines: Vec<String>,
}

impl ParamOverrideContext {
    pub fn new(map: Map<String, Value>) -> Self {
        Self {
            map,
            audit_lines: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// 错误归一化
// ---------------------------------------------------------------------------

/// Go `NewAPIErrorFromParamOverride`：状态码越界回退 400，缺省 code/type/
/// message 补齐为 invalid_request / invalid_request_error / 默认文案。
pub fn api_error_from_param_override(
    err: Option<&ParamOverrideReturnError>,
) -> ParamOverrideReturnError {
    let Some(err) = err else {
        return ParamOverrideReturnError {
            message: "param override return error is nil".to_owned(),
            code: "channel_param_override_invalid".to_owned(),
            error_type: "invalid_request_error".to_owned(),
            skip_retry: true,
            ..Default::default()
        };
    };
    let mut status_code = err.status_code;
    if !(100..=511).contains(&status_code) {
        status_code = 400;
    }
    // 空 code 落 string(types.ErrorCodeInvalidRequest)，即 "invalid_request"。
    let code = if err.code.trim().is_empty() {
        "invalid_request".to_owned()
    } else {
        err.code.clone()
    };
    let error_type = if err.error_type.trim().is_empty() {
        "invalid_request_error".to_owned()
    } else {
        err.error_type.clone()
    };
    let message = if err.message.trim().is_empty() {
        "request blocked by param override".to_owned()
    } else {
        err.message.clone()
    };
    ParamOverrideReturnError {
        message,
        status_code,
        code,
        error_type,
        skip_retry: err.skip_retry,
    }
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// Go `ApplyParamOverride`。`param_override` 是渠道配置的 JSON 对象。
pub fn apply_param_override(
    json_data: Value,
    param_override: &Value,
    context: &mut ParamOverrideContext,
) -> Result<Value, ParamOverrideError> {
    let Some(override_map) = param_override.as_object() else {
        return Ok(json_data);
    };
    if override_map.is_empty() {
        return Ok(json_data);
    }
    if let Some(operations) = try_parse_operations(override_map)? {
        // 旧 key 与 operations 并存时先应用旧覆盖。
        let mut working = json_data;
        let legacy = build_legacy_param_override(override_map);
        if !legacy.is_empty() {
            working = apply_operations_legacy(working, &legacy, context)?;
        }
        apply_operations(working, &operations, context)
    } else {
        apply_operations_legacy(
            json_data,
            &build_legacy_param_override(override_map),
            context,
        )
    }
}

/// Go `buildLegacyParamOverride`：剔除 `operations` 键。
fn build_legacy_param_override(override_map: &Map<String, Value>) -> BTreeMap<String, Value> {
    override_map
        .iter()
        .filter(|(k, _)| !k.trim().eq_ignore_ascii_case("operations"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Go `applyOperationsLegacy`：每个顶层 key 视为字面 key 写入。
fn apply_operations_legacy(
    json_data: Value,
    param_override: &BTreeMap<String, Value>,
    context: &mut ParamOverrideContext,
) -> Result<Value, ParamOverrideError> {
    let mut result = json_data;
    for (key, value) in param_override {
        let escaped = escape_literal_key(key);
        result = set_path(result, &escaped, value.clone()).map_err(ParamOverrideError::Message)?;
        context.record_operation("set", key, "", "", value);
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// operations 解析
// ---------------------------------------------------------------------------

/// Go `tryParseOperations`：解析失败返回 Ok(None)（走旧路径）；mode 缺失或
/// conditions 非法同样视为"不是 operations 形状"。
fn try_parse_operations(
    override_map: &Map<String, Value>,
) -> Result<Option<Vec<ParamOperation>>, ParamOverrideError> {
    let Some(ops_value) = override_map.get("operations") else {
        return Ok(None);
    };
    let Some(ops) = ops_value.as_array() else {
        return Ok(None);
    };
    let mut operations = Vec::with_capacity(ops.len());
    for op in ops {
        let Some(op_map) = op.as_object() else {
            return Ok(None);
        };
        let Some(mode) = op_map.get("mode").and_then(|v| v.as_str()) else {
            return Ok(None);
        };
        let mut operation = ParamOperation {
            mode: mode.to_owned(),
            ..Default::default()
        };
        if let Some(path) = op_map.get("path").and_then(|v| v.as_str()) {
            operation.path = path.to_owned();
        }
        if let Some(value) = op_map.get("value") {
            operation.value = value.clone();
        }
        if let Some(keep) = op_map.get("keep_origin").and_then(|v| v.as_bool()) {
            operation.keep_origin = keep;
        }
        if let Some(from) = op_map.get("from").and_then(|v| v.as_str()) {
            operation.from = from.to_owned();
        }
        if let Some(to) = op_map.get("to").and_then(|v| v.as_str()) {
            operation.to = to.to_owned();
        }
        operation.logic = op_map
            .get("logic")
            .and_then(|v| v.as_str())
            .unwrap_or("OR")
            .to_owned();
        if let Some(conditions) = op_map.get("conditions") {
            match parse_condition_operations(conditions) {
                Ok(parsed) => operation.conditions = parsed,
                Err(_) => return Ok(None),
            }
        }
        operations.push(operation);
    }
    Ok(Some(operations))
}

/// Go `parseConditionOperations`：对象形状（每 key 一条 full 条件）或数组形状。
pub fn parse_condition_operations(raw: &Value) -> Result<Vec<ConditionOperation>, String> {
    match raw {
        Value::Object(map) => {
            let mut conditions = Vec::new();
            for (key, value) in map {
                let path = key.trim();
                if path.is_empty() {
                    continue;
                }
                conditions.push(ConditionOperation {
                    path: path.to_owned(),
                    mode: "full".to_owned(),
                    value: value.clone(),
                    invert: false,
                    pass_missing_key: false,
                });
            }
            if conditions.is_empty() {
                return Err("conditions object must contain at least one key".to_owned());
            }
            Ok(conditions)
        }
        Value::Array(items) => {
            let mut result = Vec::with_capacity(items.len());
            for item in items {
                let Some(item_map) = item.as_object() else {
                    return Err("condition must be object".to_owned());
                };
                let path = item_map.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let mode = item_map.get("mode").and_then(|v| v.as_str()).unwrap_or("");
                if path.trim().is_empty() || mode.trim().is_empty() {
                    return Err("condition path/mode is required".to_owned());
                }
                let condition = ConditionOperation {
                    path: path.to_owned(),
                    mode: mode.to_owned(),
                    value: item_map.get("value").cloned().unwrap_or(Value::Null),
                    invert: item_map
                        .get("invert")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    pass_missing_key: item_map
                        .get("pass_missing_key")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                };
                result.push(condition);
            }
            Ok(result)
        }
        _ => Err("conditions must be an array or object".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// 操作应用
// ---------------------------------------------------------------------------

/// Go `applyOperations`。
fn apply_operations(
    json_data: Value,
    operations: &[ParamOperation],
    context: &mut ParamOverrideContext,
) -> Result<Value, ParamOverrideError> {
    let context_json = context_map_json(&context.map).map_err(ParamOverrideError::Message)?;
    let mut result = json_data;
    for op in operations {
        let ok = check_conditions(&result, &context_json, &op.conditions, &op.logic)
            .map_err(ParamOverrideError::Message)?;
        if !ok {
            continue;
        }
        let op_path = process_negative_index(&result, &op.path);
        let op_paths: Vec<String> = if is_path_based_operation(&op.mode) {
            let paths = resolve_operation_paths(&result, &op_path);
            if paths.is_empty() {
                continue;
            }
            paths
        } else {
            Vec::new()
        };

        let outcome: Result<Value, String> = match op.mode.as_str() {
            "delete" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| delete_value(v, path));
                    context.record_operation("delete", path, "", "", &Value::Null);
                }
                r
            }
            "set" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    let exists = r
                        .as_ref()
                        .ok()
                        .and_then(|v| get_path(v, path).cloned())
                        .is_some();
                    if op.keep_origin && exists {
                        continue;
                    }
                    r = r.and_then(|v| set_path(v, path, op.value.clone()));
                    context.record_operation("set", path, "", "", &op.value);
                }
                r
            }
            "move" => {
                let op_from = process_negative_index(&result, &op.from);
                let op_to = process_negative_index(&result, &op.to);
                move_value(result, &op_from, &op_to).inspect(|v| {
                    context.record_operation("move", "", &op_from, &op_to, &Value::Null);
                    let _ = v;
                })
            }
            "copy" => {
                if op.from.is_empty() || op.to.is_empty() {
                    Err("copy from/to is required".to_owned())
                } else {
                    let op_from = process_negative_index(&result, &op.from);
                    let op_to = process_negative_index(&result, &op.to);
                    copy_value(result, &op_from, &op_to).inspect(|v| {
                        context.record_operation("copy", "", &op_from, &op_to, &Value::Null);
                        let _ = v;
                    })
                }
            }
            "prepend" | "append" => {
                let is_prepend = op.mode == "prepend";
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r
                        .and_then(|v| modify_value(v, path, &op.value, op.keep_origin, is_prepend));
                    context.record_operation(&op.mode.clone(), path, "", "", &op.value);
                }
                r
            }
            "trim_prefix" | "trim_suffix" => {
                let is_prefix = op.mode == "trim_prefix";
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| trim_string_value(v, path, &op.value, is_prefix));
                    context.record_operation(&op.mode.clone(), path, "", "", &op.value);
                }
                r
            }
            "ensure_prefix" | "ensure_suffix" => {
                let is_prefix = op.mode == "ensure_prefix";
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| ensure_string_affix(v, path, &op.value, is_prefix));
                    context.record_operation(&op.mode.clone(), path, "", "", &op.value);
                }
                r
            }
            "trim_space" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| transform_string_value(v, path, |s| s.trim().to_owned()));
                    context.record_operation("trim_space", path, "", "", &Value::Null);
                }
                r
            }
            "to_lower" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| transform_string_value(v, path, |s| s.to_lowercase()));
                    context.record_operation("to_lower", path, "", "", &Value::Null);
                }
                r
            }
            "to_upper" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| transform_string_value(v, path, |s| s.to_uppercase()));
                    context.record_operation("to_upper", path, "", "", &Value::Null);
                }
                r
            }
            "replace" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| replace_string_value(v, path, &op.from, &op.to));
                    context.record_operation("replace", path, &op.from, &op.to, &Value::Null);
                }
                r
            }
            "regex_replace" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| regex_replace_string_value(v, path, &op.from, &op.to));
                    context.record_operation("regex_replace", path, &op.from, &op.to, &Value::Null);
                }
                r
            }
            "return_error" => {
                context.record_operation("return_error", &op.path, "", "", &op.value);
                let return_err = parse_param_override_return_error(&op.value)
                    .map_err(ParamOverrideError::Message)?;
                return Err(ParamOverrideError::Return(return_err));
            }
            "prune_objects" => {
                let mut r = Ok(result);
                for path in &op_paths {
                    r = r.and_then(|v| prune_objects(v, path, &context_json, &op.value));
                }
                r
            }
            "set_header" => set_header_override_in_context(
                &mut context.map,
                &op.path,
                &op.value,
                op.keep_origin,
            )
            .map(|_| {
                context.record_operation("set_header", &op.path, "", "", &op.value);
                result
            }),
            "delete_header" => {
                delete_header_override_in_context(&mut context.map, &op.path).map(|_| {
                    context.record_operation("delete_header", &op.path, "", "", &Value::Null);
                    result
                })
            }
            "copy_header" | "move_header" => {
                let is_move = op.mode == "move_header";
                let mut source = op.from.trim().to_owned();
                if source.is_empty() {
                    source = op.path.trim().to_owned();
                }
                let mut target = op.to.trim().to_owned();
                if target.is_empty() {
                    target = op.path.trim().to_owned();
                }
                let apply = if is_move {
                    move_header_in_context(&mut context.map, &source, &target, op.keep_origin)
                } else {
                    copy_header_in_context(&mut context.map, &source, &target, op.keep_origin)
                };
                match apply {
                    Ok(()) => {
                        context.record_operation(
                            &op.mode.clone(),
                            "",
                            &source,
                            &target,
                            &Value::Null,
                        );
                        Ok(result)
                    }
                    Err(e) if e.starts_with(ERR_SOURCE_HEADER_NOT_FOUND) => Ok(result),
                    Err(e) => Err(e),
                }
            }
            "pass_headers" => {
                let header_names = parse_header_pass_through_names(&op.value)
                    .map_err(ParamOverrideError::Message)?;
                for name in &header_names {
                    match copy_header_in_context(&mut context.map, name, name, op.keep_origin) {
                        Ok(()) => {}
                        Err(e) if e.starts_with(ERR_SOURCE_HEADER_NOT_FOUND) => continue,
                        Err(e) => return Err(ParamOverrideError::Message(e)),
                    }
                }
                context.record_operation(
                    "pass_headers",
                    "",
                    "",
                    "",
                    &Value::Array(
                        header_names
                            .iter()
                            .map(|n| Value::String(n.clone()))
                            .collect(),
                    ),
                );
                Ok(result)
            }
            "sync_fields" => {
                sync_fields_between_targets(&mut result, &mut context.map, &op.from, &op.to)
                    .inspect(|v| {
                        context.record_operation("sync_fields", "", &op.from, &op.to, &Value::Null);
                        let _ = v;
                    })
            }
            other => Err(format!("unknown operation: {other}")),
        };
        let value = outcome.map_err(|e| {
            ParamOverrideError::Message(format!("operation {} failed: {}", op.mode, e))
        })?;
        result = value;
    }
    Ok(result)
}

const ERR_SOURCE_HEADER_NOT_FOUND: &str = "source header does not exist";

fn is_path_based_operation(mode: &str) -> bool {
    matches!(
        mode,
        "delete"
            | "set"
            | "prepend"
            | "append"
            | "trim_prefix"
            | "trim_suffix"
            | "ensure_prefix"
            | "ensure_suffix"
            | "trim_space"
            | "to_lower"
            | "to_upper"
            | "replace"
            | "regex_replace"
            | "prune_objects"
    )
}

/// Go `resolveOperationPaths`：无 `*` 直接返回；有则展开。
fn resolve_operation_paths(data: &Value, path: &str) -> Vec<String> {
    if !path.contains('*') {
        return vec![path.to_owned()];
    }
    expand_wildcard_paths(data, path)
}

/// Go `expandWildcardPaths` + `collectWildcardPaths`：按 JSON 实际形状展开
/// `*` 段（对象 keys 字典序 / 数组下标），其余段按字面下钻。
fn expand_wildcard_paths(data: &Value, path: &str) -> Vec<String> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut paths = Vec::new();
    collect_wildcard_paths(data, &segments, &mut Vec::new(), &mut paths);
    paths
}

fn collect_wildcard_paths(
    node: &Value,
    segments: &[&str],
    prefix: &mut Vec<String>,
    out: &mut Vec<String>,
) {
    if segments.is_empty() {
        out.push(prefix.join("."));
        return;
    }
    let segment = segments[0].trim();
    if segment.is_empty() {
        return;
    }
    let is_last = segments.len() == 1;
    if segment == "*" {
        match node {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for key in keys {
                    prefix.push(key.clone());
                    collect_wildcard_paths(&map[key], &segments[1..], prefix, out);
                    prefix.pop();
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    prefix.push(index.to_string());
                    collect_wildcard_paths(item, &segments[1..], prefix, out);
                    prefix.pop();
                }
            }
            _ => {}
        }
        return;
    }
    match node {
        Value::Object(map) => {
            if is_last {
                prefix.push(segment.to_owned());
                out.push(prefix.join("."));
                prefix.pop();
                return;
            }
            if let Some(next) = map.get(segment) {
                prefix.push(segment.to_owned());
                collect_wildcard_paths(next, &segments[1..], prefix, out);
                prefix.pop();
            }
        }
        Value::Array(items) => {
            let Ok(index) = segment.parse::<usize>() else {
                return;
            };
            if index >= items.len() {
                return;
            }
            if is_last {
                prefix.push(segment.to_owned());
                out.push(prefix.join("."));
                prefix.pop();
                return;
            }
            prefix.push(segment.to_owned());
            collect_wildcard_paths(&items[index], &segments[1..], prefix, out);
            prefix.pop();
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// 条件求值
// ---------------------------------------------------------------------------

/// Go `checkConditions`。
pub fn check_conditions(
    data: &Value,
    context_json: &str,
    conditions: &[ConditionOperation],
    logic: &str,
) -> Result<bool, String> {
    if conditions.is_empty() {
        return Ok(true);
    }
    let mut results = Vec::with_capacity(conditions.len());
    for condition in conditions {
        results.push(check_single_condition(data, context_json, condition)?);
    }
    if logic.to_uppercase() == "AND" {
        Ok(results.iter().all(|r| *r))
    } else {
        Ok(results.iter().any(|r| *r))
    }
}

fn check_single_condition(
    data: &Value,
    context_json: &str,
    condition: &ConditionOperation,
) -> Result<bool, String> {
    let path = process_negative_index(data, &condition.path);
    let mut value_owned: Option<Value> = get_path(data, &path).cloned();
    if value_owned.is_none()
        && !context_json.is_empty()
        && let Ok(parsed) = serde_json::from_str::<Value>(context_json)
    {
        value_owned = get_path(&parsed, &condition.path).cloned();
    }
    let Some(value) = value_owned else {
        if condition.pass_missing_key {
            return Ok(true);
        }
        return Ok(false);
    };
    let result = compare_values(
        &value,
        &condition.value,
        condition.mode.to_lowercase().as_str(),
    )
    .map_err(|e| format!("comparison failed for path {}: {}", condition.path, e))?;
    Ok(if condition.invert { !result } else { result })
}

/// Go `compareGjsonValues`。
fn compare_values(json_value: &Value, target_value: &Value, mode: &str) -> Result<bool, String> {
    match mode {
        "full" => compare_equal(json_value, target_value),
        "prefix" => Ok(value_string(json_value).starts_with(&value_string(target_value))),
        "suffix" => Ok(value_string(json_value).ends_with(&value_string(target_value))),
        "contains" => Ok(value_string(json_value).contains(&value_string(target_value))),
        "gt" => compare_numeric(json_value, target_value, "gt"),
        "gte" => compare_numeric(json_value, target_value, "gte"),
        "lt" => compare_numeric(json_value, target_value, "lt"),
        "lte" => compare_numeric(json_value, target_value, "lte"),
        other => Err(format!("unsupported comparison mode: {other}")),
    }
}

/// gjson `.String()` 对非字符串值输出原始 JSON 文本；字符串不加引号。
fn value_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn compare_equal(json_value: &Value, target_value: &Value) -> Result<bool, String> {
    use Value::*;
    match (json_value, target_value) {
        (Null, Null) => Ok(true),
        (Null, _) | (_, Null) => Ok(false),
        (Bool(a), Bool(b)) => Ok(a == b),
        (Number(a), Number(b)) => {
            let (fa, fb) = (a.as_f64(), b.as_f64());
            Ok(match (fa, fb) {
                (Some(x), Some(y)) => x == y,
                // NaN/整型越界等 as_f64 不可精确表达的情形：Number 实现了
                // 部分相等，gjson 的 Num 是 f64，这里与 Go 语义对齐取浮点。
                _ => false,
            })
        }
        (String(a), String(b)) => Ok(a == b),
        (a, b) => {
            if std::mem::discriminant(a) == std::mem::discriminant(b) {
                // 相同变体的 JSON 文本比较；String 变体已提前返回。
                #[allow(clippy::cmp_owned)]
                let equal = a.to_string() == b.to_string();
                Ok(equal)
            } else {
                Err(format!(
                    "compare for different types, got {} and {}",
                    type_name_of(a),
                    type_name_of(b)
                ))
            }
        }
    }
}

fn type_name_of(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn compare_numeric(
    json_value: &Value,
    target_value: &Value,
    operator: &str,
) -> Result<bool, String> {
    let (Some(a), Some(b)) = (json_value.as_f64(), target_value.as_f64()) else {
        return Err(format!(
            "numeric comparison requires both values to be numbers, got {} and {}",
            type_name_of(json_value),
            type_name_of(target_value)
        ));
    };
    Ok(match operator {
        "gt" => a > b,
        "gte" => a >= b,
        "lt" => a < b,
        "lte" => a <= b,
        other => return Err(format!("unsupported numeric operator: {other}")),
    })
}

/// Go `processNegativeIndex`：路径里 `.(-\d+)` 段按数组长度换算为正下标。
fn process_negative_index(data: &Value, path: &str) -> String {
    // 匹配 `.-<digits>` 的所有出现位置（等价 Go 的 negativeIndexRegexp）。
    let mut result_path = path.to_owned();
    let mut matches: Vec<(String, i64)> = Vec::new();
    let bytes = path.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'.' && bytes[i + 1] == b'-' {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end].is_ascii_digit() {
                end += 1;
            }
            if end > start {
                let token = &path[i + 1..end]; // "-12"
                if let Ok(index) = token.parse::<i64>() {
                    matches.push((format!(".{token}"), index));
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    if matches.is_empty() {
        return result_path;
    }
    for (token, index) in matches {
        // arrayPath = 首次出现 token 之前的部分（Go strings.Split(path, negIndex)[0]，
        // negIndex 含负号，如 "-1"）。
        let array_path_raw = result_path.split(&token).next().unwrap_or("");
        let mut array_path = array_path_raw.to_owned();
        if array_path.ends_with('.') {
            array_path.pop();
        }
        if let Some(Value::Array(items)) = get_path(data, &array_path) {
            let length = items.len() as i64;
            let actual = length + index;
            if actual >= 0 && actual < length {
                result_path = result_path.replacen(&token, &format!(".{actual}"), 1);
            }
        }
    }
    result_path
}

// ---------------------------------------------------------------------------
// JSON 路径读写（sjson 字面子集）
// ---------------------------------------------------------------------------

/// 把路径切成段：`.` 为分隔符，`\` 转义下一个字符；转义后的 `.` 属于字面段。
fn parse_path_segments(path: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = path.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            '.' => {
                segments.push(std::mem::take(&mut current));
            }
            _ => current.push(c),
        }
    }
    segments.push(current);
    segments
}

/// Go `escapeSjsonLiteralKey`：把可能被当作路径/通配符的字符转义，
/// 使单段字面 key 安全传入路径解析。
fn escape_literal_key(key: &str) -> String {
    if !key.contains(['.', '*', '?', '\\']) {
        return key.to_owned();
    }
    let mut out = String::with_capacity(key.len() + 4);
    for c in key.chars() {
        if matches!(c, '.' | '*' | '?' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// sjson 风格 `SetBytes`：按段导航，缺失的中间对象/数组自动创建。
pub fn set_path(root: Value, path: &str, value: Value) -> Result<Value, String> {
    let segments = parse_path_segments(path);
    if segments.is_empty() || (segments.len() == 1 && segments[0].is_empty()) {
        return Err("cannot set empty path".to_owned());
    }
    set_at(root, &segments, value)
}

fn set_at(node: Value, segments: &[String], value: Value) -> Result<Value, String> {
    let segment = &segments[0];
    if segments.len() == 1 {
        if let Ok(index) = segment.parse::<usize>() {
            let mut arr = node.as_array().cloned().unwrap_or_default();
            if index >= arr.len() {
                return Err(format!("array index out of bounds: {index}"));
            }
            arr[index] = value;
            return Ok(Value::Array(arr));
        }
        let mut obj = node.as_object().cloned().unwrap_or_else(Map::new);
        obj.insert(segment.clone(), value);
        return Ok(Value::Object(obj));
    }
    let next: &str = &segments[1];
    if next.parse::<usize>().is_ok() {
        // 目标是数组下标：下钻到子节点再定位（根是对象时取该 key 的数组值）。
        let child = match &node {
            Value::Object(map) => map.get(segment).cloned().unwrap_or(Value::Array(vec![])),
            Value::Array(_) | Value::Null => node.clone(),
            _other => return Err(format!("cannot index into non-array at {segment}")),
        };
        let arr = match child {
            Value::Array(arr) => arr,
            Value::Null => Vec::new(),
            _other => return Err(format!("cannot index into non-array at {segment}")),
        };
        let updated = set_array_at(arr, &segments[1..], value)?;
        let mut obj = node.as_object().cloned().unwrap_or_default();
        obj.insert(segment.clone(), Value::Array(updated));
        return Ok(Value::Object(obj));
    }
    let mut obj = node.as_object().cloned().unwrap_or_else(Map::new);
    let child = obj.remove(segment).unwrap_or(Value::Object(Map::new()));
    obj.insert(segment.clone(), set_at(child, segments, value)?);
    Ok(Value::Object(obj))
}

fn set_array_at(
    mut arr: Vec<Value>,
    segments: &[String],
    value: Value,
) -> Result<Vec<Value>, String> {
    let index: usize = segments[0]
        .parse()
        .map_err(|_| "invalid array index".to_owned())?;
    if segments.len() == 1 {
        if index >= arr.len() {
            return Err(format!("array index out of bounds: {index}"));
        }
        arr[index] = value;
        return Ok(arr);
    }
    if index >= arr.len() {
        return Err(format!("array index out of bounds: {index}"));
    }
    let child = arr.remove(index);
    arr.insert(index, set_at(child, &segments[1..], value)?);
    Ok(arr)
}

/// sjson 风格 `GetBytes`：按段导航读取。
pub fn get_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let segments = parse_path_segments(path);
    let mut node = root;
    for segment in &segments {
        if segment.is_empty() {
            continue;
        }
        if let Ok(index) = segment.parse::<usize>() {
            node = node.as_array()?.get(index)?;
        } else {
            node = node.as_object()?.get(segment)?;
        }
    }
    Some(node)
}

/// sjson 风格 `DeleteBytes`。
pub fn delete_value(root: Value, path: &str) -> Result<Value, String> {
    if path.trim().is_empty() {
        return Ok(root);
    }
    let segments = parse_path_segments(path);
    delete_at(root, &segments)
}

fn delete_at(node: Value, segments: &[String]) -> Result<Value, String> {
    if segments.len() == 1 {
        if let Ok(index) = segments[0].parse::<usize>() {
            let mut arr = match node {
                Value::Array(arr) => arr,
                _ => return Ok(node),
            };
            if index < arr.len() {
                arr.remove(index);
            }
            return Ok(Value::Array(arr));
        }
        if let Some(mut obj) = node.as_object().cloned() {
            obj.remove(&segments[0]);
            return Ok(Value::Object(obj));
        }
        return Ok(node);
    }
    let segment = &segments[0];
    if let Ok(index) = segment.parse::<usize>() {
        let mut arr = match node {
            Value::Array(arr) => arr,
            _ => return Ok(node),
        };
        if index < arr.len() {
            let child = arr.remove(index);
            arr.insert(index, delete_at(child, &segments[1..])?);
        }
        return Ok(Value::Array(arr));
    }
    if let Some(mut obj) = node.as_object().cloned() {
        if let Some(child) = obj.remove(segment) {
            obj.insert(segment.clone(), delete_at(child, &segments[1..])?);
        }
        return Ok(Value::Object(obj));
    }
    Ok(node)
}

/// Go `moveValue`：源不存在时保留原值并报错（Go 返回 data + err）。
fn move_value(data: Value, from_path: &str, to_path: &str) -> Result<Value, String> {
    let source = get_path(&data, from_path)
        .ok_or_else(|| format!("source path does not exist: {from_path}"))?
        .clone();
    let result = set_path(data, to_path, source)?;
    delete_value(result, from_path)
}

fn copy_value(data: Value, from_path: &str, to_path: &str) -> Result<Value, String> {
    let source = get_path(&data, from_path)
        .ok_or_else(|| format!("source path does not exist: {from_path}"))?
        .clone();
    set_path(data, to_path, source)
}

/// Go `modifyValue`：数组 → 前插/追加；字符串 → 拼接；对象 → 合并。
fn modify_value(
    data: Value,
    path: &str,
    value: &Value,
    keep_origin: bool,
    is_prepend: bool,
) -> Result<Value, String> {
    let current = get_path(&data, path).cloned();
    let Some(current) = current else {
        return Err("operation not supported for type: missing".to_owned());
    };
    if current.is_array() {
        return modify_array(data, path, value, is_prepend);
    }
    if current.is_string() {
        return modify_string(data, path, value, is_prepend);
    }
    if current.is_object() {
        return merge_objects(data, path, value, keep_origin);
    }
    Err(format!(
        "operation not supported for type: {}",
        type_name_of(&current)
    ))
}

fn modify_array(data: Value, path: &str, value: &Value, is_prepend: bool) -> Result<Value, String> {
    let current = get_path(&data, path)
        .cloned()
        .unwrap_or(Value::Array(vec![]));
    let mut new_array: Vec<Value> = Vec::new();
    let added: Vec<Value> = match value {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    };
    let original: Vec<Value> = current.as_array().cloned().unwrap_or_default();
    if is_prepend {
        new_array.extend(added.iter().cloned());
        new_array.extend(original);
    } else {
        new_array.extend(original);
        new_array.extend(added);
    }
    set_path(data, path, Value::Array(new_array))
}

fn modify_string(
    data: Value,
    path: &str,
    value: &Value,
    is_prepend: bool,
) -> Result<Value, String> {
    let current = get_path(&data, path)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    let value_str = format_value(value);
    let new_str = if is_prepend {
        format!("{value_str}{current}")
    } else {
        format!("{current}{value_str}")
    };
    set_path(data, path, Value::String(new_str))
}

fn trim_string_value(
    data: Value,
    path: &str,
    value: &Value,
    is_prefix: bool,
) -> Result<Value, String> {
    let current = get_path(&data, path).cloned();
    let Some(Value::String(current_str)) = current else {
        return Err(format!(
            "operation not supported for type: {}",
            current.as_ref().map(type_name_of).unwrap_or("missing")
        ));
    };
    let value_str = format_value(value);
    if value.is_null() {
        return Err("trim value is required".to_owned());
    }
    let new_str = if is_prefix {
        current_str
            .strip_prefix(&value_str)
            .map(str::to_owned)
            .unwrap_or(current_str)
    } else {
        current_str
            .strip_suffix(&value_str)
            .map(str::to_owned)
            .unwrap_or(current_str)
    };
    set_path(data, path, Value::String(new_str))
}

fn ensure_string_affix(
    data: Value,
    path: &str,
    value: &Value,
    is_prefix: bool,
) -> Result<Value, String> {
    let current = get_path(&data, path).cloned();
    let Some(Value::String(current_str)) = current else {
        return Err(format!(
            "operation not supported for type: {}",
            current.as_ref().map(type_name_of).unwrap_or("missing")
        ));
    };
    let value_str = format_value(value);
    if value.is_null() || value_str.is_empty() {
        return Err("ensure value is required".to_owned());
    }
    if is_prefix {
        if current_str.starts_with(&value_str) {
            return Ok(data);
        }
        set_path(
            data,
            path,
            Value::String(format!("{value_str}{current_str}")),
        )
    } else {
        if current_str.ends_with(&value_str) {
            return Ok(data);
        }
        set_path(
            data,
            path,
            Value::String(format!("{current_str}{value_str}")),
        )
    }
}

fn transform_string_value<F>(data: Value, path: &str, transform: F) -> Result<Value, String>
where
    F: Fn(&str) -> String,
{
    let current = get_path(&data, path).cloned();
    let Some(Value::String(current_str)) = current else {
        return Err(format!(
            "operation not supported for type: {}",
            current.as_ref().map(type_name_of).unwrap_or("missing")
        ));
    };
    set_path(data, path, Value::String(transform(&current_str)))
}

fn replace_string_value(data: Value, path: &str, from: &str, to: &str) -> Result<Value, String> {
    let current = get_path(&data, path).cloned();
    let Some(Value::String(current_str)) = current else {
        return Err(format!(
            "operation not supported for type: {}",
            current.as_ref().map(type_name_of).unwrap_or("missing")
        ));
    };
    if from.is_empty() {
        return Err("replace from is required".to_owned());
    }
    set_path(data, path, Value::String(current_str.replace(from, to)))
}

fn regex_replace_string_value(
    data: Value,
    path: &str,
    pattern: &str,
    replacement: &str,
) -> Result<Value, String> {
    let current = get_path(&data, path).cloned();
    let Some(Value::String(current_str)) = current else {
        return Err(format!(
            "operation not supported for type: {}",
            current.as_ref().map(type_name_of).unwrap_or("missing")
        ));
    };
    if pattern.is_empty() {
        return Err("regex pattern is required".to_owned());
    }
    let re = regex::Regex::new(pattern).map_err(|e| e.to_string())?;
    set_path(
        data,
        path,
        Value::String(re.replace_all(&current_str, replacement).to_string()),
    )
}

/// Go `mergeObjects`。
fn merge_objects(
    data: Value,
    path: &str,
    value: &Value,
    keep_origin: bool,
) -> Result<Value, String> {
    let current = get_path(&data, path).cloned();
    let Some(Value::Object(current_map)) = current else {
        return Err("merge target is not an object".to_owned());
    };
    let new_map = match value {
        Value::Object(map) => map.clone(),
        other => other.as_object().cloned().unwrap_or_else(|| {
            serde_json::from_value::<Map<String, Value>>(other.clone()).unwrap_or_default()
        }),
    };
    let mut result = current_map;
    for (k, v) in new_map {
        let absent_or_null = result.get(&k).map(|e| e.is_null()).unwrap_or(true);
        if !keep_origin || absent_or_null {
            result.insert(k, v);
        }
    }
    set_path(data, path, Value::Object(result))
}

// ---------------------------------------------------------------------------
// prune_objects
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct PruneObjectsOptions {
    conditions: Vec<ConditionOperation>,
    logic: String,
    recursive: bool,
}

/// Go `pruneObjects`。
fn prune_objects(
    data: Value,
    path: &str,
    context_json: &str,
    value: &Value,
) -> Result<Value, String> {
    let options = parse_prune_objects_options(value)?;
    if path.is_empty() {
        let (cleaned, _) = prune_objects_node(data, &options, context_json, true)?;
        return Ok(cleaned);
    }
    let target = get_path(&data, path).cloned();
    let Some(target) = target else {
        return Ok(data);
    };
    let (cleaned, _) = prune_objects_node(target, &options, context_json, true)?;
    set_path(data, path, cleaned)
}

fn parse_prune_objects_options(value: &Value) -> Result<PruneObjectsOptions, String> {
    let mut opts = PruneObjectsOptions {
        logic: "AND".to_owned(),
        recursive: true,
        conditions: Vec::new(),
    };
    match value {
        Value::Null => return Err("prune_objects value is required".to_owned()),
        Value::String(raw) => {
            let v = raw.trim();
            if v.is_empty() {
                return Err("prune_objects value is required".to_owned());
            }
            opts.conditions.push(ConditionOperation {
                path: "type".to_owned(),
                mode: "full".to_owned(),
                value: Value::String(v.to_owned()),
                invert: false,
                pass_missing_key: false,
            });
        }
        Value::Object(map) => {
            if let Some(logic) = map.get("logic").and_then(|v| v.as_str())
                && !logic.trim().is_empty()
            {
                opts.logic = logic.to_owned();
            }
            if let Some(recursive) = map.get("recursive").and_then(|v| v.as_bool()) {
                opts.recursive = recursive;
            }
            if let Some(cond_raw) = map.get("conditions") {
                opts.conditions
                    .extend(parse_condition_operations(cond_raw)?);
            }
            if let Some(Value::Object(where_map)) = map.get("where") {
                for (key, val) in where_map {
                    let key = key.trim();
                    if key.is_empty() {
                        continue;
                    }
                    opts.conditions.push(ConditionOperation {
                        path: key.to_owned(),
                        mode: "full".to_owned(),
                        value: val.clone(),
                        invert: false,
                        pass_missing_key: false,
                    });
                }
            }
            if let Some(match_type) = map.get("type") {
                opts.conditions.push(ConditionOperation {
                    path: "type".to_owned(),
                    mode: "full".to_owned(),
                    value: match_type.clone(),
                    invert: false,
                    pass_missing_key: false,
                });
            }
        }
        _ => return Err("prune_objects value must be string or object".to_owned()),
    }
    if opts.conditions.is_empty() {
        return Err("prune_objects conditions are required".to_owned());
    }
    Ok(opts)
}

fn prune_objects_node(
    node: Value,
    options: &PruneObjectsOptions,
    context_json: &str,
    is_root: bool,
) -> Result<(Value, bool), String> {
    match node {
        Value::Array(items) => {
            let mut result = Vec::with_capacity(items.len());
            for item in items {
                let (next, drop) = prune_objects_node(item, options, context_json, false)?;
                if drop {
                    continue;
                }
                result.push(next);
            }
            Ok((Value::Array(result), false))
        }
        Value::Object(map) => {
            let node_bytes = Value::Object(map.clone());
            let should_drop = check_conditions(
                &node_bytes,
                context_json,
                &options.conditions,
                &options.logic,
            )?;
            if should_drop && !is_root {
                return Ok((Value::Null, true));
            }
            if !options.recursive {
                return Ok((Value::Object(map), false));
            }
            let mut result = Map::new();
            for (key, child) in map {
                let (next, drop) = prune_objects_node(child, options, context_json, false)?;
                if drop {
                    continue;
                }
                result.insert(key, next);
            }
            Ok((Value::Object(result), false))
        }
        other => Ok((other, false)),
    }
}

// ---------------------------------------------------------------------------
// header 操作
// ---------------------------------------------------------------------------

/// Go `normalizeHeaderContextKey`。
fn normalize_header_context_key(key: &str) -> String {
    key.trim().to_lowercase()
}

/// Go `ensureMapKeyInContext`。
fn ensure_map_key_in_context<'a>(
    context: &'a mut Map<String, Value>,
    key: &str,
) -> &'a mut Map<String, Value> {
    let entry = context
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if !entry.is_object() {
        *entry = Value::Object(Map::new());
    }
    entry.as_object_mut().expect("just ensured object")
}

/// Go `getHeaderValueFromContext`：先 header_override 再 request_headers。
fn get_header_value_from_context(
    context: &Map<String, Value>,
    header_name: &str,
) -> Option<String> {
    let header_name = normalize_header_context_key(header_name);
    if header_name.is_empty() {
        return None;
    }
    for key in [CONTEXT_HEADER_OVERRIDE, CONTEXT_REQUEST_HEADERS] {
        let Some(Value::Object(source)) = context.get(key) else {
            continue;
        };
        if let Some(raw) = source.get(&header_name) {
            let value = format_value(raw);
            let value = value.trim().to_owned();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// Go `setHeaderOverrideInContext`。
fn set_header_override_in_context(
    context: &mut Map<String, Value>,
    header_name: &str,
    value: &Value,
    keep_origin: bool,
) -> Result<(), String> {
    let header_name = normalize_header_context_key(header_name);
    if header_name.is_empty() {
        return Err("header name is required".to_owned());
    }
    {
        let raw_headers = ensure_map_key_in_context(context, CONTEXT_HEADER_OVERRIDE);
        if keep_origin && let Some(existing) = raw_headers.get(&header_name) {
            let existing_value = format_value(existing).trim().to_owned();
            if !existing_value.is_empty() {
                return Ok(());
            }
        }
    }
    let resolved = resolve_header_override_value(context, &header_name, value)?;
    let raw_headers = ensure_map_key_in_context(context, CONTEXT_HEADER_OVERRIDE);
    match resolved {
        Some(header_value) => {
            raw_headers.insert(header_name, Value::String(header_value));
        }
        None => {
            raw_headers.remove(&header_name);
        }
    }
    Ok(())
}

/// Go `resolveHeaderOverrideValue`：None 表示"删除该 header"。
fn resolve_header_override_value(
    context: &Map<String, Value>,
    header_name: &str,
    value: &Value,
) -> Result<Option<String>, String> {
    if value.is_null() {
        return Err("header value is required".to_owned());
    }
    if let Some(mapping) = value.as_object() {
        return resolve_header_override_value_by_mapping(context, header_name, mapping);
    }
    let header_value = format_value(value).trim().to_owned();
    if header_value.is_empty() {
        return Ok(None);
    }
    Ok(Some(header_value))
}

/// Go `resolveHeaderOverrideValueByMapping`：token 替换/追加/白名单语义。
fn resolve_header_override_value_by_mapping(
    context: &Map<String, Value>,
    header_name: &str,
    mapping: &Map<String, Value>,
) -> Result<Option<String>, String> {
    if mapping.is_empty() {
        return Err("header value mapping cannot be empty".to_owned());
    }
    let append_tokens = parse_header_append_tokens(mapping)?;
    let keep_only_declared = mapping
        .get("$keep_only_declared")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let source_value = get_header_value_from_context(context, header_name);
    let source_tokens: Vec<String> = source_value
        .as_deref()
        .map(split_header_list_value)
        .unwrap_or_default();

    let wildcard = mapping.get("*").cloned();
    let mut result_tokens: Vec<String> =
        Vec::with_capacity(source_tokens.len() + append_tokens.len());
    for token in &source_tokens {
        let mut replacement = mapping.get(token).cloned();
        if replacement.is_none()
            && let Some(w) = &wildcard
            && !keep_only_declared
        {
            replacement = Some(w.clone());
        }
        let Some(replacement) = replacement else {
            if keep_only_declared {
                continue;
            }
            result_tokens.push(token.clone());
            continue;
        };
        result_tokens.extend(parse_header_replacement_tokens(&replacement)?);
    }
    result_tokens.extend(append_tokens);
    dedup_preserve_order(&mut result_tokens);
    if result_tokens.is_empty() {
        return Ok(None);
    }
    Ok(Some(result_tokens.join(",")))
}

fn parse_header_append_tokens(mapping: &Map<String, Value>) -> Result<Vec<String>, String> {
    match mapping.get("$append") {
        Some(raw) => parse_header_replacement_tokens(raw),
        None => Ok(Vec::new()),
    }
}

/// Go `parseHeaderReplacementTokens`。
fn parse_header_replacement_tokens(value: &Value) -> Result<Vec<String>, String> {
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(raw) => Ok(split_header_list_value(raw)),
        Value::Array(items) => {
            let mut tokens = Vec::new();
            for item in items {
                tokens.extend(parse_header_replacement_tokens(item)?);
            }
            dedup_preserve_order(&mut tokens);
            Ok(tokens)
        }
        Value::Object(_) => {
            Err("header replacement value must be string, array or null".to_owned())
        }
        other => {
            let token = format_value(other).trim().to_owned();
            if token.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![token])
            }
        }
    }
}

/// Go `splitHeaderListValue`：逗号分割 + TrimSpace + 去空。
fn split_header_list_value(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|item| item.trim().to_owned())
        .filter(|item| !item.is_empty())
        .collect()
}

fn dedup_preserve_order(tokens: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    tokens.retain(|t| seen.insert(t.clone()));
}

/// Go `copyHeaderInContext`。
fn copy_header_in_context(
    context: &mut Map<String, Value>,
    from_header: &str,
    to_header: &str,
    keep_origin: bool,
) -> Result<(), String> {
    let from = normalize_header_context_key(from_header);
    let to = normalize_header_context_key(to_header);
    if from.is_empty() || to.is_empty() {
        return Err("copy_header from/to is required".to_owned());
    }
    let value = get_header_value_from_context(context, &from)
        .ok_or_else(|| format!("{ERR_SOURCE_HEADER_NOT_FOUND}: {from}"))?;
    set_header_override_in_context(context, &to, &Value::String(value), keep_origin)
}

/// Go `moveHeaderInContext`。
fn move_header_in_context(
    context: &mut Map<String, Value>,
    from_header: &str,
    to_header: &str,
    keep_origin: bool,
) -> Result<(), String> {
    let from = normalize_header_context_key(from_header);
    let to = normalize_header_context_key(to_header);
    if from.is_empty() || to.is_empty() {
        return Err("move_header from/to is required".to_owned());
    }
    copy_header_in_context(context, &from, &to, keep_origin)?;
    if from.eq_ignore_ascii_case(&to) {
        return Ok(());
    }
    delete_header_override_in_context(context, &from)
}

/// Go `deleteHeaderOverrideInContext`。
fn delete_header_override_in_context(
    context: &mut Map<String, Value>,
    header_name: &str,
) -> Result<(), String> {
    let header_name = normalize_header_context_key(header_name);
    if header_name.is_empty() {
        return Err("header name is required".to_owned());
    }
    let raw_headers = ensure_map_key_in_context(context, CONTEXT_HEADER_OVERRIDE);
    raw_headers.remove(&header_name);
    Ok(())
}

/// Go `parseHeaderPassThroughNames`。
fn parse_header_pass_through_names(value: &Value) -> Result<Vec<String>, String> {
    let normalize = |items: Vec<String>| -> Vec<String> {
        let mut names: Vec<String> = items
            .into_iter()
            .map(|item| normalize_header_context_key(&item))
            .filter(|n| !n.is_empty())
            .collect();
        dedup_preserve_order(&mut names);
        names
    };
    match value {
        Value::Null => Err("pass_headers value is required".to_owned()),
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err("pass_headers value is required".to_owned());
            }
            if (trimmed.starts_with('[') || trimmed.starts_with('{'))
                && let Ok(parsed) = serde_json::from_str::<Value>(trimmed)
            {
                return parse_header_pass_through_names(&parsed);
            }
            let names = normalize(raw.split(',').map(str::to_owned).collect());
            if names.is_empty() {
                return Err("pass_headers value is invalid".to_owned());
            }
            Ok(names)
        }
        Value::Array(items) => {
            let names = normalize(items.iter().map(format_value).collect());
            if names.is_empty() {
                return Err("pass_headers value is invalid".to_owned());
            }
            Ok(names)
        }
        Value::Object(map) => {
            let mut candidates: Vec<String> = Vec::new();
            if let Some(headers) = map.get("headers")
                && let Ok(names) = parse_header_pass_through_names(headers)
            {
                candidates.extend(names);
            }
            if let Some(names_raw) = map.get("names")
                && let Ok(names) = parse_header_pass_through_names(names_raw)
            {
                candidates.extend(names);
            }
            if let Some(header) = map.get("header")
                && let Ok(names) = parse_header_pass_through_names(header)
            {
                candidates.extend(names);
            }
            let names = normalize(candidates);
            if names.is_empty() {
                return Err("pass_headers value is invalid".to_owned());
            }
            Ok(names)
        }
        _ => Err("pass_headers value must be string, array or object".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// sync_fields
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum SyncTarget {
    Json(String),
    Header(String),
}

fn parse_sync_target(spec: &str) -> Result<SyncTarget, String> {
    let raw = spec.trim();
    if raw.is_empty() {
        return Err("sync_fields target is required".to_owned());
    }
    let Some(idx) = raw.find(':') else {
        return Ok(SyncTarget::Json(raw.to_owned()));
    };
    let kind = raw[..idx].trim().to_lowercase();
    let key = raw[idx + 1..].trim().to_owned();
    if key.is_empty() {
        return Err(format!("sync_fields target key is required: {raw}"));
    }
    match kind.as_str() {
        "json" | "body" => Ok(SyncTarget::Json(key)),
        "header" => Ok(SyncTarget::Header(key)),
        _ => Err(format!("sync_fields target prefix is invalid: {raw}")),
    }
}

fn read_sync_target_value(
    data: &Value,
    context: &Map<String, Value>,
    target: &SyncTarget,
) -> Option<Value> {
    match target {
        SyncTarget::Json(key) => {
            let path = process_negative_index(data, key);
            let value = get_path(data, &path)?;
            if value.is_null() {
                return None;
            }
            if let Value::String(s) = value
                && s.trim().is_empty()
            {
                return None;
            }
            Some(value.clone())
        }
        SyncTarget::Header(key) => {
            let value = get_header_value_from_context(context, key)?;
            if value.trim().is_empty() {
                return None;
            }
            Some(Value::String(value))
        }
    }
}

fn write_sync_target_value(
    data: Value,
    context: &mut Map<String, Value>,
    target: &SyncTarget,
    value: Value,
) -> Result<Value, String> {
    match target {
        SyncTarget::Json(key) => {
            let path = process_negative_index(&data, key);
            set_path(data, &path, value)
        }
        SyncTarget::Header(key) => {
            set_header_override_in_context(context, key, &value, false)?;
            Ok(data)
        }
    }
}

/// Go `syncFieldsBetweenTargets`：一侧存在另一侧缺失时补齐缺失侧。
fn sync_fields_between_targets(
    data: &mut Value,
    context: &mut Map<String, Value>,
    from_spec: &str,
    to_spec: &str,
) -> Result<Value, String> {
    let from_target = parse_sync_target(from_spec)?;
    let to_target = parse_sync_target(to_spec)?;
    let from_value = read_sync_target_value(data, context, &from_target);
    let to_value = read_sync_target_value(data, context, &to_target);
    match (from_value, to_value) {
        (Some(from), None) => {
            return write_sync_target_value(data.clone(), context, &to_target, from);
        }
        (None, Some(to)) => {
            return write_sync_target_value(data.clone(), context, &from_target, to);
        }
        _ => {}
    }
    Ok(data.clone())
}

// ---------------------------------------------------------------------------
// return_error
// ---------------------------------------------------------------------------

/// Go `parseParamOverrideReturnError`。
fn parse_param_override_return_error(value: &Value) -> Result<ParamOverrideReturnError, String> {
    let mut result = ParamOverrideReturnError {
        status_code: 400,
        code: "invalid_request".to_owned(),
        error_type: "invalid_request_error".to_owned(),
        skip_retry: true,
        message: String::new(),
    };
    match value {
        Value::Null => return Err("return_error value is required".to_owned()),
        Value::String(raw) => {
            result.message = raw.trim().to_owned();
        }
        Value::Object(map) => {
            if let Some(message) = map.get("message").and_then(|v| v.as_str()) {
                result.message = message.trim().to_owned();
            }
            if result.message.is_empty()
                && let Some(msg) = map.get("msg").and_then(|v| v.as_str())
            {
                result.message = msg.trim().to_owned();
            }
            if let Some(code) = map.get("code") {
                let code_str = format_value(code).trim().to_owned();
                if !code_str.is_empty() {
                    result.code = code_str;
                }
            }
            if let Some(err_type) = map.get("type").and_then(|v| v.as_str()) {
                let err_type = err_type.trim();
                if !err_type.is_empty() {
                    result.error_type = err_type.to_owned();
                }
            }
            if let Some(skip) = map.get("skip_retry").and_then(|v| v.as_bool()) {
                result.skip_retry = skip;
            }
            if let Some(status) = map.get("status_code") {
                result.status_code = parse_override_int(status)
                    .ok_or("return_error status_code must be an integer")?;
            } else if let Some(status) = map.get("status") {
                result.status_code =
                    parse_override_int(status).ok_or("return_error status must be an integer")?;
            }
        }
        _ => return Err("return_error value must be string or object".to_owned()),
    }
    if result.message.is_empty() {
        return Err("return_error message is required".to_owned());
    }
    if !(100..=511).contains(&result.status_code) {
        return Err(format!(
            "return_error status code out of range: {}",
            result.status_code
        ));
    }
    Ok(result)
}

fn parse_override_int(value: &Value) -> Option<i32> {
    match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Some(i32::try_from(i).ok()?)
            } else {
                let f = n.as_f64()?;
                if f.fract() != 0.0 {
                    return None;
                }
                Some(f as i32)
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 审计
// ---------------------------------------------------------------------------

impl ParamOverrideContext {
    /// Go `paramOverrideAuditRecorder.recordOperation`。
    fn record_operation(&mut self, mode: &str, path: &str, from: &str, to: &str, value: &Value) {
        let line = build_audit_line(mode, path, from, to, value);
        if line.is_empty() || self.audit_lines.contains(&line) {
            return;
        }
        self.audit_lines.push(line);
    }
}

/// Go `shouldAuditParamPath`（Debug 关闭时的敏感前缀规则；Debug 开关由服务层
/// 在构建上下文前决定是否预置记录器）。
pub fn should_audit_param_path(path: &str) -> bool {
    let path = path.trim();
    if path.is_empty() {
        return false;
    }
    SENSITIVE_PATH_PREFIXES
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}.")))
}

fn should_audit_operation(mode: &str, path: &str, from: &str, to: &str) -> bool {
    let _ = mode;
    should_audit_param_path(path) || should_audit_param_path(from) || should_audit_param_path(to)
}

/// Go `formatParamOverrideAuditValue`。
fn format_audit_value(value: &Value) -> String {
    match value {
        Value::Null => "<empty>".to_owned(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Go `buildParamOverrideAuditLine`。
pub fn build_audit_line(mode: &str, path: &str, from: &str, to: &str, value: &Value) -> String {
    let mode = mode.trim();
    let path = path.trim();
    let from = from.trim();
    let to = to.trim();
    if !should_audit_operation(mode, path, from, to) {
        return String::new();
    }
    match mode {
        "set" if !path.is_empty() => format!("set {path} = {}", format_audit_value(value)),
        "delete" if !path.is_empty() => format!("delete {path}"),
        "copy" | "move" if !from.is_empty() && !to.is_empty() => {
            format!("{mode} {from} -> {to}")
        }
        "prepend" | "append" if !path.is_empty() => {
            format!("{mode} {path} with {}", format_audit_value(value))
        }
        "trim_prefix" | "trim_suffix" | "ensure_prefix" | "ensure_suffix" if !path.is_empty() => {
            format!("{mode} {path} with {}", format_audit_value(value))
        }
        "trim_space" | "to_lower" | "to_upper" if !path.is_empty() => format!("{mode} {path}"),
        "replace" | "regex_replace" if !path.is_empty() => {
            format!("{mode} {path} from {from} to {to}")
        }
        "set_header" if !path.is_empty() => {
            format!("set_header {path} = {}", format_audit_value(value))
        }
        "delete_header" if !path.is_empty() => format!("delete_header {path}"),
        "copy_header" | "move_header" if !from.is_empty() && !to.is_empty() => {
            format!("{mode} {from} -> {to}")
        }
        "pass_headers" => format!("pass_headers {}", format_audit_value(value)),
        "sync_fields" if !from.is_empty() && !to.is_empty() => {
            format!("sync_fields {from} -> {to}")
        }
        "return_error" => format!("return_error {}", format_audit_value(value)),
        _ if path.is_empty() => mode.to_owned(),
        _ => format!("{mode} {path}"),
    }
}

/// Go `shouldEnableParamOverrideAudit`（debug 关闭分支）。
pub fn should_enable_param_override_audit(param_override: &Value) -> bool {
    let Some(map) = param_override.as_object() else {
        return false;
    };
    if map.is_empty() {
        return false;
    }
    if let Some(operations) = try_parse_operations(map).ok().flatten() {
        for operation in &operations {
            if should_audit_param_path(operation.path.trim())
                || should_audit_param_path(operation.from.trim())
                || should_audit_param_path(operation.to.trim())
            {
                return true;
            }
        }
        for key in build_legacy_param_override(map).keys() {
            if should_audit_param_path(key.trim()) {
                return true;
            }
        }
        return false;
    }
    map.keys().any(|key| should_audit_param_path(key.trim()))
}

/// Go `marshalContextJSON`。
fn context_map_json(context: &Map<String, Value>) -> Result<String, String> {
    if context.is_empty() {
        return Ok(String::new());
    }
    serde_json::to_string(&Value::Object(context.clone())).map_err(|e| e.to_string())
}

/// Go `formatParamOverrideAuditValue` / `fmt.Sprintf("%v")` 的值格式化：
/// 字符串原样，其余取 JSON 文本。
pub fn format_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "<nil>".to_owned(),
        other => other.to_string(),
    }
}

/// Go `BuildParamOverrideContext`（apply_param_override.go 尾部）：条件与
/// header 操作可用的上下文表。
pub fn build_param_override_context(info: &crate::relay_info::RelayInfo) -> Map<String, Value> {
    let mut ctx = Map::new();
    ctx.insert("user_id".to_owned(), Value::from(info.user_id));
    ctx.insert(
        "user_group".to_owned(),
        Value::String(info.user_group.clone()),
    );
    ctx.insert(
        "token_group".to_owned(),
        Value::String(info.token_group.clone()),
    );
    ctx.insert(
        "using_group".to_owned(),
        Value::String(info.using_group.clone()),
    );
    if let Some(meta) = &info.channel_meta
        && !meta.upstream_model_name.is_empty()
    {
        ctx.insert(
            "model".to_owned(),
            Value::String(meta.upstream_model_name.clone()),
        );
        ctx.insert(
            "upstream_model".to_owned(),
            Value::String(meta.upstream_model_name.clone()),
        );
    }
    if !info.origin_model_name.is_empty() {
        ctx.insert(
            "original_model".to_owned(),
            Value::String(info.origin_model_name.clone()),
        );
        ctx.entry("model".to_owned())
            .or_insert_with(|| Value::String(info.origin_model_name.clone()));
    }
    if !info.request_url_path.is_empty() {
        ctx.insert(
            "request_path".to_owned(),
            Value::String(info.request_url_path.clone()),
        );
    }

    // Go buildRequestHeadersContext：小写化 + TrimSpace + 去空。
    let mut headers = Map::new();
    for (key, value) in &info.request_headers {
        let normalized = key.trim().to_lowercase();
        let value = value.trim();
        if normalized.is_empty() || value.is_empty() {
            continue;
        }
        headers.insert(normalized, Value::String(value.to_owned()));
    }

    ctx.insert(CONTEXT_REQUEST_HEADERS.to_owned(), Value::Object(headers));

    let override_map = info
        .channel_meta
        .as_ref()
        .map(|m| m.headers_override.clone())
        .unwrap_or(Value::Object(Map::new()));
    let effective = if info.use_runtime_headers_override {
        let mut runtime = Map::new();
        for (key, value) in &info.runtime_headers_override {
            runtime.insert(key.clone(), Value::String(value.clone()));
        }
        sanitize_header_override_map(&Value::Object(runtime))
    } else {
        sanitize_header_override_map(&override_map)
    };
    ctx.insert(CONTEXT_HEADER_OVERRIDE.to_owned(), effective);

    ctx.insert("retry_index".to_owned(), Value::from(info.retry_index));
    ctx.insert("is_retry".to_owned(), Value::Bool(info.retry_index > 0));
    ctx.insert(
        "retry".to_owned(),
        serde_json::json!({"index": info.retry_index, "is_retry": info.retry_index > 0}),
    );
    if let Some(last_error) = &info.last_error {
        let code = last_error.code.clone();
        let error_type = last_error.error_type.clone();
        ctx.insert(
            "last_error".to_owned(),
            serde_json::json!({
                "status_code": last_error.status_code,
                "message": last_error.message,
                "code": code,
                "error_code": code,
                "type": error_type,
                "error_type": error_type,
                "skip_retry": last_error.skip_retry,
            }),
        );
        ctx.insert(
            "last_error_status_code".to_owned(),
            Value::from(last_error.status_code),
        );
        ctx.insert(
            "last_error_message".to_owned(),
            Value::String(last_error.message.clone()),
        );
        ctx.insert(
            "last_error_code".to_owned(),
            Value::String(last_error.code.clone()),
        );
        ctx.insert(
            "last_error_type".to_owned(),
            Value::String(last_error.error_type.clone()),
        );
    }
    ctx.insert(
        "is_channel_test".to_owned(),
        Value::Bool(info.is_channel_test),
    );
    ctx
}

/// Go `sanitizeHeaderOverrideMap`：key 小写化、值 TrimSpace；空值仅对
/// 透传规则 key（`*` / `re:` / `regex:` 前缀）保留空串。
pub fn sanitize_header_override_map(source: &Value) -> Value {
    let Some(map) = source.as_object() else {
        return Value::Object(Map::new());
    };
    let mut target = Map::new();
    for (key, value) in map {
        let normalized = key.trim().to_lowercase();
        if normalized.is_empty() {
            continue;
        }
        let normalized_value = format_value(value).trim().to_owned();
        if normalized_value.is_empty() {
            if is_header_passthrough_rule_key(&normalized) {
                target.insert(normalized, Value::String(String::new()));
            }
            continue;
        }
        target.insert(normalized, Value::String(normalized_value));
    }
    Value::Object(target)
}

fn is_header_passthrough_rule_key(key: &str) -> bool {
    let key = key.trim().to_lowercase();
    if key.is_empty() {
        return false;
    }
    key == "*" || key.starts_with("re:") || key.starts_with("regex:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ParamOverrideContext {
        ParamOverrideContext::default()
    }

    #[test]
    fn legacy_set_semantics() {
        let body = json!({"model": "gpt-4", "nested": {"a": 1}});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"temperature": 0.5, "nested": {"b": 2}}),
            &mut context,
        )
        .unwrap();
        // 旧语义：顶层 key 字面覆盖，nested 整体替换。
        assert_eq!(result["temperature"], 0.5);
        assert_eq!(result["nested"]["b"], 2);
        assert!(result["nested"].get("a").is_none());
    }

    #[test]
    fn operations_set_delete() {
        let body = json!({"model": "gpt-4", "foo": {"bar": 1}});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "set", "path": "temperature", "value": 1},
                {"mode": "delete", "path": "foo.bar"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["temperature"], 1);
        assert!(result["foo"].get("bar").is_none());
    }

    #[test]
    fn set_keep_origin_skips_existing() {
        let body = json!({"model": "gpt-4"});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "set", "path": "model", "value": "other", "keep_origin": true},
                {"mode": "set", "path": "extra", "value": "x", "keep_origin": true}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["model"], "gpt-4");
        assert_eq!(result["extra"], "x");
    }

    #[test]
    fn move_and_copy() {
        let body = json!({"a": {"b": 1}});
        let mut context = ctx();
        let result = apply_param_override(
            body.clone(),
            &json!({"operations": [
                {"mode": "copy", "from": "a.b", "to": "c"},
                {"mode": "move", "from": "a.b", "to": "d"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["c"], 1);
        assert_eq!(result["d"], 1);
        assert!(result["a"].get("b").is_none());
        // copy 缺 from 报错。
        let err = apply_param_override(
            body,
            &json!({"operations": [{"mode": "copy", "to": "c"}]}),
            &mut ctx(),
        )
        .unwrap_err();
        assert!(matches!(err, ParamOverrideError::Message(_)));
    }

    #[test]
    fn prepend_append_array_and_string() {
        let body = json!({"messages": [1, 2], "name": "x"});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "prepend", "path": "messages", "value": 0},
                {"mode": "append", "path": "messages", "value": 3},
                {"mode": "prepend", "path": "name", "value": "hi-"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["messages"], json!([0, 1, 2, 3]));
        assert_eq!(result["name"], "hi-x");
    }

    #[test]
    fn trim_ensure_transform() {
        let body = json!({"s": "  padded  ", "u": "abc"});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "trim_space", "path": "s"},
                {"mode": "ensure_suffix", "path": "s", "value": "!"},
                {"mode": "to_upper", "path": "u"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["s"], "padded!");
        assert_eq!(result["u"], "ABC");
    }

    #[test]
    fn replace_and_regex_replace() {
        let body = json!({"m": "gpt-3.5-turbo"});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "regex_replace", "path": "m", "from": "3\\.5", "to": "4o"},
                {"mode": "replace", "path": "m", "from": "turbo", "to": "mini"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["m"], "gpt-4o-mini");
    }

    #[test]
    fn conditions_or_and_invert() {
        let body = json!({"model": "gpt-4", "n": 5});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "set", "path": "flag1", "value": true,
                 "conditions": [{"path": "model", "mode": "prefix", "value": "gpt"}]},
                {"mode": "set", "path": "flag2", "value": true,
                 "conditions": [{"path": "model", "mode": "prefix", "value": "claude"}]},
                {"mode": "set", "path": "flag3", "value": true, "logic": "AND",
                 "conditions": [
                    {"path": "n", "mode": "gte", "value": 5},
                    {"path": "model", "mode": "contains", "value": "gpt", "invert": true}
                 ]},
                {"mode": "set", "path": "flag4", "value": true,
                 "conditions": [{"path": "missing", "mode": "full", "value": 1, "pass_missing_key": true}]}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["flag1"], true);
        assert!(result.get("flag2").is_none());
        assert!(result.get("flag3").is_none()); // invert 使 AND 失败
        assert_eq!(result["flag4"], true);
    }

    #[test]
    fn return_error_operation() {
        let body = json!({"x": 1});
        let mut context = ctx();
        let err = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "return_error", "value": {"message": "blocked", "status_code": 403, "code": "forbidden", "type": "permission_error"}}
            ]}),
            &mut context,
        )
        .unwrap_err();
        let e = err.as_return_error().unwrap();
        assert_eq!(e.message, "blocked");
        assert_eq!(e.status_code, 403);
        assert_eq!(e.code, "forbidden");
        assert_eq!(e.error_type, "permission_error");
        assert!(e.skip_retry);
    }

    #[test]
    fn return_error_string_and_defaults() {
        let mut context = ctx();
        let err = apply_param_override(
            json!({}),
            &json!({"operations": [{"mode": "return_error", "value": "nope"}]}),
            &mut context,
        )
        .unwrap_err();
        let e = err.as_return_error().unwrap();
        assert_eq!(e.message, "nope");
        assert_eq!(e.status_code, 400);
        assert_eq!(e.error_type, "invalid_request_error");
    }

    #[test]
    fn header_operations() {
        let mut context = ParamOverrideContext::new(
            [
                (
                    CONTEXT_REQUEST_HEADERS.to_owned(),
                    json!({"x-trace": "t1", "authorization": "secret"}),
                ),
                (CONTEXT_HEADER_OVERRIDE.to_owned(), json!({})),
            ]
            .into_iter()
            .collect(),
        );
        let result = apply_param_override(
            json!({"m": 1}),
            &json!({"operations": [
                {"mode": "set_header", "path": "x-new", "value": "v1"},
                {"mode": "copy_header", "from": "x-trace", "to": "x-copied"},
                {"mode": "move_header", "from": "x-trace", "to": "x-moved"},
                {"mode": "pass_headers", "value": ["authorization", "x-missing"]}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["m"], 1);
        let headers = &context.map[CONTEXT_HEADER_OVERRIDE];
        assert_eq!(headers["x-new"], "v1");
        assert_eq!(headers["x-copied"], "t1");
        assert_eq!(headers["x-moved"], "t1");
        assert!(headers.get("x-trace").is_none());
        assert_eq!(headers["authorization"], "secret");
    }

    #[test]
    fn header_value_mapping_replacement() {
        let mut context = ParamOverrideContext::new(
            [
                (
                    CONTEXT_REQUEST_HEADERS.to_owned(),
                    json!({"anthropic-beta": "a,b,c"}),
                ),
                (CONTEXT_HEADER_OVERRIDE.to_owned(), json!({})),
            ]
            .into_iter()
            .collect(),
        );
        apply_param_override(
            json!({}),
            &json!({"operations": [
                {"mode": "set_header", "path": "anthropic-beta", "value": {
                    "a": "x", "$keep_only_declared": true, "$append": ["z", "x"]
                }}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(
            context.map[CONTEXT_HEADER_OVERRIDE]["anthropic-beta"],
            "x,z"
        );
    }

    #[test]
    fn wildcard_expansion_sorted() {
        let body = json!({"tools": [{"type": "a"}, {"type": "b"}], "extra": 1});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "delete", "path": "tools.*.type"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["tools"], json!([{}, {}]));
        assert_eq!(result["extra"], 1);
    }

    #[test]
    fn negative_index_resolution() {
        let body = json!({"messages": [{"role": "user"}, {"role": "assistant"}]});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "set", "path": "messages.-1.content", "value": "hi"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["messages"][1]["content"], "hi");
        assert_eq!(result["messages"][0]["role"], "user");
    }

    #[test]
    fn prune_objects_by_type() {
        let body = json!({"messages": [
            {"type": "tool_use", "id": 1},
            {"type": "text", "id": 2}
        ]});
        let mut context = ctx();
        let result = apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "prune_objects", "path": "messages", "value": "tool_use"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(result["messages"], json!([{"type": "text", "id": 2}]));
    }

    #[test]
    fn sync_fields_json_to_header() {
        let body = json!({"user_id": "42"});
        let mut context = ParamOverrideContext::new(
            [
                (CONTEXT_REQUEST_HEADERS.to_owned(), json!({})),
                (CONTEXT_HEADER_OVERRIDE.to_owned(), json!({})),
            ]
            .into_iter()
            .collect(),
        );
        apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "sync_fields", "from": "json:user_id", "to": "header:x-user-id"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(context.map[CONTEXT_HEADER_OVERRIDE]["x-user-id"], "42");
    }

    #[test]
    fn audit_lines_for_sensitive_paths() {
        let body = json!({"model": "gpt-4", "other": 1});
        let mut context = ctx();
        apply_param_override(
            body,
            &json!({"operations": [
                {"mode": "set", "path": "model", "value": "new"},
                {"mode": "set", "path": "other", "value": 2},
                {"mode": "delete", "path": "model"}
            ]}),
            &mut context,
        )
        .unwrap();
        assert_eq!(context.audit_lines, vec!["set model = new", "delete model"]);
    }

    #[test]
    fn unknown_operation_rejected() {
        let mut context = ctx();
        let err = apply_param_override(
            json!({}),
            &json!({"operations": [{"mode": "explode", "path": "x"}]}),
            &mut context,
        )
        .unwrap_err();
        assert!(err.to_string().contains("unknown operation: explode"));
    }

    #[test]
    fn escaped_literal_keys() {
        let body = json!({});
        let mut context = ctx();
        let result = apply_param_override(body, &json!({"a.b": 1}), &mut context).unwrap();
        // 旧路径：key 是字面量，不展开为嵌套。
        assert_eq!(result.get("a.b"), Some(&json!(1)));
    }

    #[test]
    fn api_error_defaults_match_go() {
        let e = api_error_from_param_override(Some(&ParamOverrideReturnError {
            status_code: 999,
            ..Default::default()
        }));
        assert_eq!(e.status_code, 400);
        assert_eq!(e.message, "request blocked by param override");
        assert_eq!(e.error_type, "invalid_request_error");
    }
}
