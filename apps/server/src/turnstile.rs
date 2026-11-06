//! Pure Cloudflare Turnstile decision layer.
//!
//! This module deliberately performs no network I/O: the caller owns the
//! siteverify request and passes its outcome in. That keeps the Go contract
//! (disabled -> pass, empty token -> reject, verify failure -> reject) testable
//! without an HTTP client dependency.

/// Outcome for the request middleware to apply. Every string is an i18n key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Pass,
    Reject(&'static str),
    Unavailable(&'static str),
}

impl Decision {
    /// `None` 放行；否则返回要回给客户端的 i18n key。
    pub fn rejection_key(self) -> Option<&'static str> {
        match self {
            Self::Pass => None,
            Self::Reject(key) | Self::Unavailable(key) => Some(key),
        }
    }
}

/// Extract the first `turnstile` value from a raw URI query string.
///
/// `fasthttp`'s `Args.Peek` returns the first value for a repeated key, so
/// repeated parameters are not combined or overridden. Decoding follows
/// `application/x-www-form-urlencoded`: `+` is a space and `%XX` is a byte.
pub fn query_token(query: Option<&str>) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if decode_component(raw_key) == "turnstile" {
            let token = decode_component(raw_value);
            return (!token.is_empty()).then_some(token);
        }
    }
    None
}

/// Parse the siteverify response, requiring a top-level boolean `success`.
///
/// Unknown fields are skipped, matching Go's decoding of the two-field struct.
/// Missing fields, non-object bodies, wrong value types, and trailing garbage
/// all report `None`.
pub fn parse_verify_success(body: &str) -> Option<bool> {
    // Go 解码到 `struct{ Success bool }`：未知字段忽略；缺字段与 `null` 都不
    // 报错并保留零值 false；只有类型不符或非对象体才是解码失败。
    match serde_json::from_str::<serde_json::Value>(body).ok()? {
        serde_json::Value::Object(fields) => match fields.get("success") {
            Some(serde_json::Value::Bool(flag)) => Some(*flag),
            Some(serde_json::Value::Null) | None => Some(false),
            Some(_) => None,
        },
        // Go 的 `json.Unmarshal("null", &struct)` 不报错且保留零值。
        serde_json::Value::Null => Some(false),
        _ => None,
    }
}

/// Apply the switch, token, and verification outcome in the Go middleware order.
pub fn decide(enabled: bool, token: Option<&str>, verify: Option<Result<bool, ()>>) -> Decision {
    if !enabled {
        return Decision::Pass;
    }
    match token {
        None | Some("") => Decision::Reject("turnstile.token_empty"),
        Some(_) => match verify {
            None => Decision::Unavailable("turnstile.unavailable"),
            Some(Err(())) => Decision::Reject("turnstile.verify_error"),
            Some(Ok(true)) => Decision::Pass,
            Some(Ok(false)) => Decision::Reject("turnstile.verify_failed"),
        },
    }
}

fn decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_value);
                let low = bytes.get(index + 2).copied().and_then(hex_value);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        decoded.push((high << 4) | low);
                        index += 3;
                    }
                    // Match fasthttp: an incomplete or non-hex escape stays literal.
                    _ => {
                        decoded.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_check_passes_even_without_a_token() {
        assert_eq!(decide(false, None, None), Decision::Pass);
        assert_eq!(decide(false, Some(""), Some(Ok(false))), Decision::Pass);
    }

    #[test]
    fn missing_or_empty_token_rejects_before_verification() {
        assert_eq!(
            decide(true, None, None),
            Decision::Reject("turnstile.token_empty"),
        );
        assert_eq!(
            decide(true, Some(""), None),
            Decision::Reject("turnstile.token_empty"),
        );
        // A verification result cannot rescue an empty token.
        assert_eq!(
            decide(true, Some(""), Some(Ok(true))),
            Decision::Reject("turnstile.token_empty"),
        );
    }

    #[test]
    fn absent_verification_transport_is_unavailable() {
        assert_eq!(
            decide(true, Some("token"), None),
            Decision::Unavailable("turnstile.unavailable"),
        );
    }

    #[test]
    fn transport_and_decode_errors_are_rejections() {
        assert_eq!(
            decide(true, Some("token"), Some(Err(()))),
            Decision::Reject("turnstile.verify_error"),
        );
    }

    #[test]
    fn verification_outcome_controls_the_decision() {
        assert_eq!(decide(true, Some("token"), Some(Ok(true))), Decision::Pass);
        assert_eq!(
            decide(true, Some("token"), Some(Ok(false))),
            Decision::Reject("turnstile.verify_failed"),
        );
    }

    #[test]
    fn query_token_reads_the_first_value() {
        assert_eq!(query_token(None), None);
        assert_eq!(query_token(Some("")), None);
        assert_eq!(query_token(Some("turnstile=abc")), Some("abc".into()));
        assert_eq!(
            query_token(Some("a=1&turnstile=abc&b=2")),
            Some("abc".into()),
        );
        assert_eq!(
            query_token(Some("turnstile=first&turnstile=second")),
            Some("first".into()),
        );
        // The first occurrence wins even when it is empty.
        assert_eq!(query_token(Some("turnstile=&turnstile=second")), None);
        assert_eq!(query_token(Some("turnstile")), None);
        assert_eq!(query_token(Some("turnstile=")), None);
    }

    #[test]
    fn query_token_decodes_form_encoding() {
        assert_eq!(query_token(Some("turnstile=a+b")), Some("a b".into()));
        assert_eq!(query_token(Some("turnstile=a%20b")), Some("a b".into()));
        assert_eq!(query_token(Some("turnstile=%E4%B8%AD")), Some("中".into()));
        assert_eq!(query_token(Some("%74urnstile=ok")), Some("ok".into()));
        assert_eq!(query_token(Some("turnstile=a%3Db")), Some("a=b".into()));
    }

    #[test]
    fn query_token_survives_invalid_percent_escapes() {
        assert_eq!(query_token(Some("turnstile=%ZZ")), Some("%ZZ".into()));
        assert_eq!(query_token(Some("turnstile=%2")), Some("%2".into()));
        assert_eq!(query_token(Some("turnstile=%")), Some("%".into()));
    }

    #[test]
    fn parses_success_booleans() {
        assert_eq!(parse_verify_success(r#"{"success":true}"#), Some(true));
        assert_eq!(parse_verify_success(r#"{"success":false}"#), Some(false));
        assert_eq!(
            parse_verify_success(" \n { \"success\" : true } \t"),
            Some(true),
        );
        assert_eq!(
            parse_verify_success(r#"{"challenge_ts":"x","success":true,"error-codes":[]}"#),
            Some(true),
        );
        assert_eq!(
            parse_verify_success(r#"{"note":"\ud83d\ude00","success":false}"#),
            Some(false),
        );
    }

    #[test]
    fn rejects_malformed_or_unrelated_verify_bodies() {
        assert_eq!(parse_verify_success(""), None);
        assert_eq!(parse_verify_success("not json"), None);
        assert_eq!(parse_verify_success("[]"), None);
        assert_eq!(parse_verify_success(r#"{"success":"true"}"#), None);
        assert_eq!(parse_verify_success(r#"{"success":1}"#), None);
        assert_eq!(parse_verify_success(r#"{"success":true"#), None);
        assert_eq!(parse_verify_success(r#"{"success":true} trailing"#), None);
    }

    #[test]
    fn missing_or_null_success_decodes_as_false_like_go() {
        // Go 把缺字段与 null 都解码成零值 false，并不返回错误。
        assert_eq!(parse_verify_success("null"), Some(false));
        assert_eq!(parse_verify_success("{}"), Some(false));
        assert_eq!(parse_verify_success(r#"{"challenge_ts":"x"}"#), Some(false));
        assert_eq!(parse_verify_success(r#"{"success":null}"#), Some(false));
    }
}
