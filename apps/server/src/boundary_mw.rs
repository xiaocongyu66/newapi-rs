//! HTTP boundary middleware ported from the Go transport layer: response
//! cache suppression and the anonymous request-body size limit.
//!
//! Go references:
//! - `apps/api/internal/transport/middleware/disable_cache.go`
//! - `apps/api/internal/transport/middleware/limit_body_size.go`
//! - `apps/api/internal/common/request_body_limit.go`
//!
//! Both Go middlewares answer with bare status codes and headers only — no
//! JSON envelope — so these helpers deliberately bypass the P1 `failure`
//! envelope in `http.rs`.

use axum::{
    body::{Body, to_bytes},
    extract::Request,
    http::{HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

/// Verbatim Go value from `middleware.DisableCache` (`SetHeader`). Applied
/// per-route in Go (login, 2FA/passkey login, session refresh and logout,
/// universal verify); route wiring happens when those routes are ported.
const CACHE_CONTROL_NO_STORE: &str = "no-store, no-cache, must-revalidate, private, max-age=0";

/// Go default for `ANONYMOUS_REQUEST_BODY_LIMIT_KB`
/// (`common/request_body_limit.go`, `common/init.go`).
pub const DEFAULT_ANONYMOUS_BODY_LIMIT_KB: u64 = 512;

/// Mirrors Go `common.GetAnonymousRequestBodyLimitBytes`: a negative configured
/// KB value falls back to the 512KB default. A zero value is kept as zero,
/// which [`reject_oversized`] treats as "limit disabled", exactly like Go's
/// `maxBytes <= 0` bail-out.
pub fn anonymous_body_limit_bytes(limit_kb: i64) -> usize {
    let effective = if limit_kb < 0 {
        DEFAULT_ANONYMOUS_BODY_LIMIT_KB as i64
    } else {
        limit_kb
    };
    (effective as usize).saturating_mul(1024)
}

/// Adds the three no-cache response headers with `insert`, overwriting any
/// prior value the same way Go's `SetHeader` does.
pub fn disable_cache_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL_NO_STORE),
    );
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));
}

/// Pure decision core of the Go `AnonymousRequestBodyLimit` middleware.
///
/// Returns the bare status the Go middleware would abort with:
/// - `limit_bytes == 0` → `None`: a non-positive limit disables the middleware
///   (Go `maxBytes <= 0 || ...` bail);
/// - missing or zero `Content-Length` → `None`: Go passes through without
///   reading the body (`c.ContentLength() == 0`, and an unparseable header
///   parses to 0 in Go too);
/// - declared or actual body length above the limit → `Some(413)`
///   (`http.StatusRequestEntityTooLarge` via `c.AbortWithStatus`).
///
/// The actual-length arm covers a forged-small `Content-Length`: the declared
/// check alone would miss it, the buffered length catches it (Go reads
/// `maxBytes + 1` and compares). A mid-stream transport error yields 400 in
/// Go; that branch lives in the async adapter below, not in this pure check.
pub fn reject_oversized(
    content_length: Option<u64>,
    body_len: usize,
    limit_bytes: usize,
) -> Option<StatusCode> {
    if limit_bytes == 0 {
        return None;
    }
    let declared = match content_length {
        None | Some(0) => return None,
        Some(len) => len,
    };
    if declared > limit_bytes as u64 || body_len > limit_bytes {
        return Some(StatusCode::PAYLOAD_TOO_LARGE);
    }
    None
}

/// Reads the declared `Content-Length`. A value that is absent or not a plain
/// unsigned integer is `None`, which [`reject_oversized`] skips — matching Go,
/// where `strconv.ParseUint` failures leave the length at 0.
fn declared_length(request: &Request) -> Option<u64> {
    request
        .headers()
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

/// Async adapter matching the `middleware::from_fn` shape, so route wiring is
/// `middleware::from_fn(move |req, next| anonymous_body_limit(limit, req, next))`
/// (a closure: `usize` is not an extractor, so the limit must be captured).
///
/// Divergence from Go, kept deliberate: after the declared-length pre-check
/// passes, the body is buffered with a `limit + 1` byte budget (Go's
/// `io.LimitReader(body, maxBytes+1)`). Go answers 413 on overflow and 400 on
/// a mid-read transport error; hyper surfaces both as one opaque `to_bytes`
/// error, and the only way the buffer arm trips is a body provably above the
/// limit, so the error arm answers 413 like the overflow path. A request whose
/// declared length is missing or zero is handed to `next` untouched, as Go
/// skips reading in that case.
pub async fn anonymous_body_limit(limit_bytes: usize, request: Request, next: Next) -> Response {
    let declared = declared_length(&request);
    if let Some(status) = reject_oversized(declared, 0, limit_bytes) {
        return status.into_response();
    }
    if declared.is_none_or(|len| len == 0) {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let max_read = limit_bytes.saturating_add(1);
    let bytes = match to_bytes(body, max_read).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    if let Some(status) = reject_oversized(declared, bytes.len(), limit_bytes) {
        return status.into_response();
    }
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMIT: usize = 1024;

    #[test]
    fn zero_length_or_missing_header_passes_through() {
        assert_eq!(reject_oversized(None, 0, LIMIT), None);
        assert_eq!(reject_oversized(Some(0), 0, LIMIT), None);
        // Go skips reading whenever the declared length is zero, so an
        // undeclared body length never trips the pure check.
        assert_eq!(reject_oversized(Some(0), 8 * LIMIT, LIMIT), None);
        assert_eq!(reject_oversized(None, 8 * LIMIT, LIMIT), None);
    }

    #[test]
    fn exactly_the_limit_is_accepted() {
        assert_eq!(reject_oversized(Some(LIMIT as u64), 0, LIMIT), None);
        assert_eq!(reject_oversized(Some(LIMIT as u64), LIMIT, LIMIT), None);
        assert_eq!(reject_oversized(Some(8), LIMIT, LIMIT), None);
    }

    #[test]
    fn one_byte_over_the_limit_is_413() {
        assert_eq!(
            reject_oversized(Some(LIMIT as u64 + 1), 0, LIMIT),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
        assert_eq!(
            reject_oversized(Some(LIMIT as u64), LIMIT + 1, LIMIT),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
        // 413 is http.StatusRequestEntityTooLarge, matching Go.
        assert_eq!(StatusCode::PAYLOAD_TOO_LARGE.as_u16(), 413);
    }

    #[test]
    fn forged_small_content_length_is_caught_by_actual_length() {
        assert_eq!(
            reject_oversized(Some(8), 4096, LIMIT),
            Some(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    #[test]
    fn zero_limit_disables_the_check_like_go() {
        assert_eq!(reject_oversized(Some(64), 64, 0), None);
    }

    #[test]
    fn negative_limit_kb_falls_back_to_the_default() {
        assert_eq!(anonymous_body_limit_bytes(-1), 512 * 1024);
        assert_eq!(anonymous_body_limit_bytes(0), 0);
        assert_eq!(anonymous_body_limit_bytes(64), 64 * 1024);
        assert_eq!(
            DEFAULT_ANONYMOUS_BODY_LIMIT_KB as usize * 1024,
            anonymous_body_limit_bytes(-1)
        );
    }

    #[test]
    fn disable_cache_headers_match_go_verbatim_and_overwrite() {
        let mut response = StatusCode::OK.into_response();
        // insert must overwrite, mirroring Go SetHeader semantics.
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("max-age=600"),
        );
        disable_cache_headers(&mut response);
        let headers = &response.headers();
        assert_eq!(
            headers[header::CACHE_CONTROL],
            "no-store, no-cache, must-revalidate, private, max-age=0"
        );
        assert_eq!(headers[header::PRAGMA], "no-cache");
        assert_eq!(headers[header::EXPIRES], "0");
        assert_eq!(
            headers
                .get_all(header::CACHE_CONTROL)
                .iter()
                .collect::<Vec<_>>()
                .len(),
            1
        );
    }

    // `Next` has no public constructor, so the adapter is exercised through
    // the real wiring shape: `from_fn` + a tiny router (tower is a
    // dev-dependency for `oneshot`).
    fn app(limit: usize) -> axum::Router {
        axum::Router::new()
            .route(
                "/api/user/login",
                axum::routing::post(|| async { StatusCode::OK }),
            )
            .layer(axum::middleware::from_fn(
                move |request: Request, next: Next| anonymous_body_limit(limit, request, next),
            ))
    }

    async fn send(limit: usize, declared: Option<&str>, body: Vec<u8>) -> Response {
        use tower::ServiceExt;
        let mut builder = Request::builder()
            .method(axum::http::Method::POST)
            .uri("/api/user/login");
        if let Some(value) = declared {
            builder = builder.header(header::CONTENT_LENGTH, value);
        }
        app(limit)
            .oneshot(builder.body(Body::from(body)).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn adapter_answers_bare_413_without_body() {
        let response = send(LIMIT, Some("2048"), vec![b'x'; 2048]).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        // Go AbortWithStatus sends no body; neither may the port.
        let bytes = to_bytes(response.into_body(), 16).await.unwrap();
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn adapter_forwards_small_bodies_and_skips_zero_declared() {
        let response = send(LIMIT, None, b"{\"a\":1}".to_vec()).await;
        assert_eq!(response.status(), StatusCode::OK);

        // A declared-zero body is passed to next unread, as Go does.
        let response = send(LIMIT, Some("0"), Vec::new()).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn adapter_overflow_beyond_read_budget_is_still_413() {
        // Declared small, actual huge: exceeds the limit+1 read budget, so
        // to_bytes fails on buffer length and must still map to 413.
        let response = send(LIMIT, Some("8"), vec![b'y'; LIMIT * 4]).await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
