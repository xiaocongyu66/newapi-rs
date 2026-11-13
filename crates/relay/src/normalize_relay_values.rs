//! Go `internal/relay/common/normalize_relay_values.go` 的纯函数部分：
//! 出站 URL 拼接、日志脱敏、API 版本回退。

use std::collections::BTreeMap;

/// Go `GetFullRequestURL`：Cloudflare AI Gateway 对 OpenAI/Azure 渠道有
/// 专门的路径前缀剥离规则。
pub fn get_full_request_url(base_url: &str, request_url: &str, channel_type: i32) -> String {
    let mut full = format!("{base_url}{request_url}");
    if base_url.starts_with("https://gateway.ai.cloudflare.com") {
        let trimmed = match channel_type {
            crate::adaptor::channel_type::OPENAI => request_url.strip_prefix("/v1"),
            crate::adaptor::channel_type::AZURE => request_url.strip_prefix("/openai/deployments"),
            _ => None,
        };
        if let Some(rest) = trimmed {
            full = format!("{base_url}{rest}");
        }
    }
    full
}

/// Go `isSensitiveURLQueryKey`（normalize_relay_values.go）。
fn is_sensitive_url_query_key(key: &str) -> bool {
    let normalized = key.trim().to_lowercase();
    match normalized.as_str() {
        "key"
        | "api_key"
        | "api-key"
        | "apikey"
        | "x-api-key"
        | "access_token"
        | "refresh_token"
        | "id_token"
        | "token"
        | "authorization"
        | "auth"
        | "client_secret"
        | "secret"
        | "password"
        | "passwd"
        | "signature"
        | "sig"
        | "awsaccesskeyid"
        | "x-amz-credential"
        | "x-amz-security-token"
        | "x-amz-signature" => return true,
        _ => {}
    }
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("signature")
}

/// Go `SanitizeURLForLog`：查询串里的敏感键替换为 `***masked***`。
/// 解析失败时原样返回（Go url.Parse 错误分支）。
pub fn sanitize_url_for_log(raw_url: &str) -> String {
    if raw_url.is_empty() {
        return raw_url.to_owned();
    }
    let Ok(parsed) = url::Url::parse(raw_url) else {
        return raw_url.to_owned();
    };
    if parsed.query().is_none() {
        return raw_url.to_owned();
    }
    let mut changed = false;
    let mut pairs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in parsed.query_pairs() {
        let key = key.into_owned();
        let value = value.into_owned();
        if is_sensitive_url_query_key(&key) {
            changed = true;
            pairs
                .entry(key)
                .or_default()
                .push("***masked***".to_owned());
        } else {
            pairs.entry(key).or_default().push(value);
        }
    }
    if !changed {
        return raw_url.to_owned();
    }
    let query: Vec<String> = pairs
        .into_iter()
        .flat_map(|(k, vs)| vs.into_iter().map(move |v| format!("{k}={v}")))
        .collect();
    let mut rebuilt = parsed.clone();
    rebuilt.set_query(Some(&query.join("&")));
    rebuilt.to_string()
}

/// Go `GetAPIVersion`：query `api-version` 优先，回退上下文 `api_version`。
pub fn get_api_version(query_api_version: &str, context_api_version: &str) -> String {
    if !query_api_version.is_empty() {
        return query_api_version.to_owned();
    }
    context_api_version.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_gateway_prefix_strip() {
        use crate::adaptor::channel_type as ct;
        let base = "https://gateway.ai.cloudflare.com/v1/acc/tag/openai";
        assert_eq!(
            get_full_request_url(base, "/v1/chat/completions", ct::OPENAI),
            format!("{base}/chat/completions")
        );
        assert_eq!(
            get_full_request_url(
                base,
                "/openai/deployments/gpt-4/chat/completions",
                ct::AZURE
            ),
            format!("{base}/gpt-4/chat/completions")
        );
        // 非 Cloudflare 原样拼接。
        assert_eq!(
            get_full_request_url("https://api.openai.com", "/v1/chat/completions", ct::OPENAI),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn sanitize_masks_sensitive_query() {
        let out = sanitize_url_for_log("https://h/p?token=abc&ok=1&x-amz-signature=zz");
        assert!(
            out.contains("token=%2A%2A%2Amasked%2A%2A%2A") || out.contains("token=***masked***"),
            "{out}"
        );
        assert!(out.contains("ok=1"));
        assert!(!out.contains("zz"));
    }

    #[test]
    fn sanitize_passthrough() {
        assert_eq!(sanitize_url_for_log(""), "");
        assert_eq!(sanitize_url_for_log("https://h/p?a=1"), "https://h/p?a=1");
        // 非 URL 原样返回。
        assert_eq!(sanitize_url_for_log("not a url"), "not a url");
    }

    #[test]
    fn api_version_fallback() {
        assert_eq!(get_api_version("2024-01-01", "v1"), "2024-01-01");
        assert_eq!(get_api_version("", "v1"), "v1");
    }
}
