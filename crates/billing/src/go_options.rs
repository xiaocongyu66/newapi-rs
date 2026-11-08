//! Go `strconv.ParseBool` / `strconv.ParseInt` 的等价解析，服务于
//! `settings.UpdateOption` 的 `updateConfigFromMap` 反射应用路径
//! （`apps/api/internal/settings/config.go:163-271`）。
//!
//! 该路径对所有 `settings.GlobalConfig.Register` 注册的分片一致：bool 用
//! `ParseBool`，int 先 `ParseInt`、失败退回 `ParseFloat` 再截断，两者都失败即
//! `continue`——**保留当前值**（首次加载即结构体缺省值）。
//!
//! 注意与 `crates/catalog/src/auth_settings/store.rs` 的 `value == "true"`
//! 是两条不同的应用路径（那条走 `settings.go:372` 的旧式 switch，只认
//! "true"），不要混用。

/// Go `strconv.ParseBool` 的接受集合；集合外一律视为解析失败。
pub(crate) fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go `strconv.ParseInt(v, 10, 64)`，失败退回 `strconv.ParseFloat` 再
/// `int64()` 截断（`config.go:210-220`）。
///
/// 非有限的浮点文本（`NaN`/`Inf`）在 Go 的 `int64(float64)` 是未定义转换，
/// 这里按 Rust `as` 的饱和语义（NaN → 0）；真实配置行不会出现。
pub(crate) fn parse_int(value: &str) -> Option<i64> {
    value
        .parse::<i64>()
        .ok()
        .or_else(|| value.parse::<f64>().ok().map(|float| float as i64))
}
