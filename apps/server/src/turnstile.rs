//! Cloudflare Turnstile decision layer and `siteverify` transport.
//!
//! [`decide`] keeps the Go middleware order: disabled -> pass, empty token ->
//! reject without any request, siteverify failure or transport/decode error ->
//! reject (Go aborts on both, so it never fails open). The network call lives
//! behind the [`Verifier`] port so tests can inject a fake; [`HttpVerifier`] is
//! the production implementation.

use std::{
    fmt::Write as _,
    future::Future,
    pin::Pin,
    sync::{Arc, Once, OnceLock},
    time::Duration,
};

/// Cloudflare siteverify endpoint, identical to Go's `http.PostForm` target.
pub const SITEVERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

/// Total per-request deadline. Go's `http.PostForm` uses `http.DefaultClient`
/// with no timeout; the policy contract requires Rust to add an explicit bound.
/// Ten seconds stays well inside the HTTP boundary's 30-second budget.
const SITEVERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// Upper bound on the siteverify response body. Cloudflare returns a small JSON
/// object; anything larger is treated as a transport failure (fail closed).
const SITEVERIFY_MAX_BODY: usize = 64 * 1024;

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

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

/// Failure classification for the siteverify call.
///
/// Deliberately payload-free: `Debug`, logs, and client-facing messages can
/// never carry the secret or the response token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    /// DNS, connect, TLS, HTTP, or response-body read failure.
    Transport,
    /// The response exceeded [`SITEVERIFY_MAX_BODY`].
    BodyTooLarge,
    /// The body was not the JSON object shape Go's decoder accepts.
    Decode,
}

/// Boxed future used by [`Verifier`] so the port stays dyn-compatible.
pub type VerifyFuture<'a> = Pin<Box<dyn Future<Output = Result<bool, VerifyError>> + Send + 'a>>;

/// Outbound siteverify port.
///
/// Implementations must not put the secret or token into error payloads or
/// logs; errors are represented only by [`VerifyError`].
pub trait Verifier: Send + Sync {
    fn verify<'a>(
        &'a self,
        secret: &'a str,
        token: &'a str,
        remote_ip: Option<&'a str>,
    ) -> VerifyFuture<'a>;
}

/// Request-extension seam used by tests (and embedders) to replace the real
/// transport. The login guard prefers it over [`HttpVerifier`].
#[derive(Clone)]
pub struct InjectedVerifier(pub Arc<dyn Verifier>);

/// Production verifier backed by a shared `reqwest` client.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpVerifier;

impl Verifier for HttpVerifier {
    fn verify<'a>(
        &'a self,
        secret: &'a str,
        token: &'a str,
        remote_ip: Option<&'a str>,
    ) -> VerifyFuture<'a> {
        Box::pin(async move {
            let client = siteverify_client().ok_or(VerifyError::Transport)?;
            // Go ignores the HTTP status and decodes whatever body it gets;
            // `send()` without `error_for_status` preserves that behaviour.
            let response = client
                .post(SITEVERIFY_URL)
                .header(reqwest::header::CONTENT_TYPE, FORM_CONTENT_TYPE)
                .body(siteverify_form(secret, token, remote_ip))
                .send()
                .await
                .map_err(|_| VerifyError::Transport)?;
            let body = read_body_bounded(response).await?;
            let body = String::from_utf8_lossy(&body);
            parse_verify_success(&body).ok_or(VerifyError::Decode)
        })
    }
}

/// Process-wide client so connections and the TLS provider are initialised at
/// most once (building a client per login would discard connection pooling).
fn siteverify_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            install_crypto_provider();
            reqwest::Client::builder()
                .timeout(SITEVERIFY_TIMEOUT)
                .build()
                .ok()
        })
        .as_ref()
}

/// reqwest's `rustls-tls-*-no-provider` features select no crypto backend and
/// panic in `Client::build` unless a process default is installed. sqlx already
/// compiles rustls with `aws_lc_rs`, so installing that same provider here keeps
/// a single backend and avoids rustls' "multiple providers" panic.
///
/// `pub(crate)`：`qqbot` 的 `reqwest` 客户端复用同一安装入口，避免两个模块
/// 各自 `install_default`（第二个会得到 `Err`，语义相同但不显式）。
pub(crate) fn install_crypto_provider() {
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        // `Err` means another caller already installed the process default.
        // Because only `aws_lc_rs` is compiled, that default is the same one.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Read at most [`SITEVERIFY_MAX_BODY`] bytes, rejecting oversized responses
/// without buffering them.
async fn read_body_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, VerifyError> {
    if response
        .content_length()
        .is_some_and(|length| length > SITEVERIFY_MAX_BODY as u64)
    {
        return Err(VerifyError::BodyTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| VerifyError::Transport)? {
        if body.len().saturating_add(chunk.len()) > SITEVERIFY_MAX_BODY {
            return Err(VerifyError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Build the form body in Go `url.Values.Encode` order: keys sorted, values
/// query-escaped (space as `+`, uppercase hex).
fn siteverify_form(secret: &str, token: &str, remote_ip: Option<&str>) -> String {
    let mut fields: Vec<(&str, &str)> = Vec::with_capacity(3);
    if let Some(remote_ip) = remote_ip {
        fields.push(("remoteip", remote_ip));
    }
    fields.push(("response", token));
    fields.push(("secret", secret));
    fields.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut form = String::new();
    for (index, (name, value)) in fields.iter().copied().enumerate() {
        if index > 0 {
            form.push('&');
        }
        form.push_str(name);
        form.push('=');
        form_encode_component(&mut form, value);
    }
    form
}

/// Equivalent to Go's `url.QueryEscape` / `url.Values.Encode` escaping.
///
/// `pub(crate)`：`qqbot::query_escape`（Go `ListPanels` 的 scope 转义）复用
/// 同一实现，避免两份 QueryEscape 漂移。
pub(crate) fn form_encode_component(output: &mut String, value: &str) {
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                output.push(char::from(byte));
            }
            b' ' => output.push('+'),
            _ => {
                let _ = write!(output, "%{byte:02X}");
            }
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
/// The Go transport uses `json.NewDecoder(...).Decode(&struct)`, which decodes
/// the first JSON value and ignores trailing bytes. A stream deserializer's
/// first item behaves the same way. Unknown fields are skipped; missing fields
/// and `null` leave the struct zero value (false) without error; wrong value
/// types and non-object roots are decode errors.
pub fn parse_verify_success(body: &str) -> Option<bool> {
    let value = serde_json::Deserializer::from_str(body)
        .into_iter::<serde_json::Value>()
        .next()?
        .ok()?;
    match value {
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
///
/// The verifier is consulted only when the check is enabled and a non-empty
/// token exists, so disabled deployments and empty-token requests never touch
/// the network.
pub async fn decide(
    enabled: bool,
    token: Option<&str>,
    secret: &str,
    remote_ip: Option<&str>,
    verifier: Option<&dyn Verifier>,
) -> Decision {
    if !enabled {
        return Decision::Pass;
    }
    let token = match token {
        Some(token) if !token.is_empty() => token,
        _ => return Decision::Reject("turnstile.token_empty"),
    };
    let Some(verifier) = verifier else {
        return Decision::Unavailable("turnstile.unavailable");
    };
    match verifier.verify(secret, token, remote_ip).await {
        Ok(true) => Decision::Pass,
        Ok(false) => Decision::Reject("turnstile.verify_failed"),
        Err(category) => {
            // Go logs the transport/decode error; log only a fixed category so
            // neither the secret nor the token can reach the log sink.
            tracing::warn!(
                event = "turnstile_verify_error",
                category = ?category,
                "turnstile siteverify request failed"
            );
            Decision::Reject("turnstile.verify_error")
        }
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Deterministic verifier: records call count, never performs I/O.
    struct FakeVerifier {
        result: Result<bool, VerifyError>,
        calls: AtomicUsize,
    }

    impl FakeVerifier {
        fn new(result: Result<bool, VerifyError>) -> Self {
            Self {
                result,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl Verifier for FakeVerifier {
        fn verify<'a>(
            &'a self,
            _secret: &'a str,
            _token: &'a str,
            _remote_ip: Option<&'a str>,
        ) -> VerifyFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.result;
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn disabled_check_passes_without_calling_the_verifier() {
        let fake = FakeVerifier::new(Ok(false));
        assert_eq!(
            decide(false, None, "secret", None, Some(&fake)).await,
            Decision::Pass,
        );
        assert_eq!(
            decide(false, Some(""), "secret", None, Some(&fake)).await,
            Decision::Pass,
        );
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn missing_or_empty_token_rejects_before_verification() {
        let fake = FakeVerifier::new(Ok(true));
        assert_eq!(
            decide(true, None, "secret", None, Some(&fake)).await,
            Decision::Reject("turnstile.token_empty"),
        );
        assert_eq!(
            decide(true, Some(""), "secret", None, Some(&fake)).await,
            Decision::Reject("turnstile.token_empty"),
        );
        assert_eq!(fake.calls(), 0);
    }

    #[tokio::test]
    async fn absent_verification_transport_is_unavailable() {
        assert_eq!(
            decide(true, Some("token"), "secret", None, None).await,
            Decision::Unavailable("turnstile.unavailable"),
        );
    }

    #[tokio::test]
    async fn transport_and_decode_errors_are_rejections() {
        for error in [
            VerifyError::Transport,
            VerifyError::BodyTooLarge,
            VerifyError::Decode,
        ] {
            let fake = FakeVerifier::new(Err(error));
            assert_eq!(
                decide(true, Some("token"), "secret", None, Some(&fake)).await,
                Decision::Reject("turnstile.verify_error"),
            );
            assert_eq!(fake.calls(), 1);
        }
    }

    #[tokio::test]
    async fn verification_outcome_controls_the_decision() {
        let accepted = FakeVerifier::new(Ok(true));
        assert_eq!(
            decide(true, Some("token"), "secret", None, Some(&accepted)).await,
            Decision::Pass,
        );
        let rejected = FakeVerifier::new(Ok(false));
        assert_eq!(
            decide(true, Some("token"), "secret", None, Some(&rejected)).await,
            Decision::Reject("turnstile.verify_failed"),
        );
    }

    #[test]
    fn siteverify_url_matches_the_go_endpoint() {
        assert_eq!(
            SITEVERIFY_URL,
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        );
    }

    #[test]
    fn form_encoding_matches_go_url_values_encode() {
        assert_eq!(
            siteverify_form("sec ret&=", "tok+en/中", Some("203.0.113.9")),
            "remoteip=203.0.113.9&response=tok%2Ben%2F%E4%B8%AD&secret=sec+ret%26%3D",
        );
        // Keys follow Go's alphabetical order; an absent IP omits the field.
        assert_eq!(siteverify_form("s", "t", None), "response=t&secret=s");
        let mut encoded = String::new();
        form_encode_component(&mut encoded, "a b+c~*!*'()");
        assert_eq!(encoded, "a+b%2Bc~%2A%21%2A%27%28%29");
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
    }

    #[test]
    fn trailing_bytes_are_ignored_like_go_json_decoder() {
        // Go's `json.NewDecoder(...).Decode` consumes one value and does not
        // reject trailing bytes (`DecodeJson`, not `json.Unmarshal`).
        assert_eq!(
            parse_verify_success(r#"{"success":true} trailing"#),
            Some(true),
        );
        assert_eq!(
            parse_verify_success(r#"{"success":false}{"success":true}"#),
            Some(false),
        );
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
