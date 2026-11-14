//! relay 主链的调度面：adaptor 调用链（Go `relayHandler` 分发表 →
//! `GetAdaptor` → ConvertRequest → DoRequest → DoResponse）与失败分类
//! （Go `transport/handler/relay_failover.go` + `middleware/status_code`
//! 重试状态码表）。
//!
//! 契约要点：
//! - [`RelayAttemptError`] 是 Go `*types.NewAPIError` 的调度面投影：
//!   状态码、错误码、skip-retry、`Retry-After` 毫秒提示。
//!   `IsChannelError` = 错误码以 `channel:` 前缀开头（error.go:385）。
//! - [`classify_attempt`] 是 mono 失败分类（relay_failover.go:43-80）：
//!   回答"这次失败对候选池意味着什么"，与"是否允许重试"（管理员状态码
//!   范围）相互独立，但 Fatal 类即使范围允许也终止换道。
//! - [`should_retry_by_status_code`] 是 Go `AutomaticRetryStatusCodeRanges`
//!   的默认表 + 504/524 永不重试。
//! - [`run_adaptor_dispatch`] 消费 [`crate::adaptor::Adaptor`] trait：
//!   按 relay_format 选 convert 方法（Go 分发表形状），调用点契约见
//!   [`AdaptorFactory`]——真实外呼实现由 channel-adapter 切片经工厂合流，
//!   测试注入替身工厂。

use crate::adaptor::{self, Adaptor};
use crate::relay_info::{RelayInfo, relay_format};

/// Go `types.ErrorCode*` 调度面复用。
pub mod error_code {
    pub const DO_REQUEST_FAILED: &str = "do_request_failed";
    pub const GET_CHANNEL_FAILED: &str = "get_channel_failed";
    pub const CONVERT_REQUEST_FAILED: &str = "convert_request_failed";
    pub const BAD_RESPONSE_STATUS_CODE: &str = "bad_response_status_code";
    pub const BAD_RESPONSE_BODY: &str = "bad_response_body";
    pub const CHANNEL_NO_AVAILABLE_KEY: &str = "channel:no_available_key";
    pub const RATE_LIMITED: &str = "rate_limited";
}

// ---------------------------------------------------------------------------
// 尝试错误（Go *types.NewAPIError 的调度面）
// ---------------------------------------------------------------------------

/// 一次 relay 尝试的失败描述。小结构体（clippy::result_large_err 友好）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayAttemptError {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub skip_retry: bool,
    /// 上游 Retry-After 提示（毫秒）；0 = 无提示。
    pub retry_after_ms: i64,
}

impl RelayAttemptError {
    pub fn new(status_code: u16, code: &str, message: impl Into<String>) -> Self {
        Self {
            status_code,
            code: code.to_owned(),
            message: message.into(),
            skip_retry: false,
            retry_after_ms: 0,
        }
    }

    pub fn with_skip_retry(mut self) -> Self {
        self.skip_retry = true;
        self
    }

    pub fn with_retry_after_ms(mut self, retry_after_ms: i64) -> Self {
        self.retry_after_ms = retry_after_ms;
        self
    }

    /// Go `types.IsChannelError`：错误码 `channel:` 前缀。
    pub fn is_channel_error(&self) -> bool {
        self.code.starts_with("channel:")
    }

    /// Go `types.IsSkipRetryError`。
    pub fn is_skip_retry(&self) -> bool {
        self.skip_retry
    }
}

impl std::fmt::Display for RelayAttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

// ---------------------------------------------------------------------------
// 失败分类（Go relay_failover.go）
// ---------------------------------------------------------------------------

/// Go `relayAttemptKind`：一次失败对候选池的含义（mono AttemptOutcome）。
/// 决定换道资格，与"是否允许重试"（状态码范围）相互独立。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayAttemptKind {
    /// 无失败（成功臂）。
    Done,
    /// 5xx/408/传输失败：该候选当前已死，换道。
    Retryable,
    /// 429：渠道忙而非坏——换候选，绝不在环内睡眠（退避是终态错误携带的
    /// Retry-After 提示）。
    Throttled,
    /// 渠道域 4xx（401/403/404）：该候选被上游拒绝，其它候选可能可服务；
    /// 暂存用于终态直通。
    FatalSwitchable,
    /// 调用方侧失败（400/413/422，取消的请求）：换道无济于事。
    Fatal,
}

/// Go `classifyAttempt`（relay_failover.go:43-80）。行为差量（忠实于 mono）：
/// 渠道域外 4xx（409/410/425 等）视为 Request 域——同一请求在每个候选上
/// 都会失败——终态直通给客户端。
pub fn classify_attempt(error: Option<&RelayAttemptError>) -> RelayAttemptKind {
    let Some(error) = error else {
        return RelayAttemptKind::Done;
    };
    // 渠道域失败（egress/传输故障，无可用上游状态）：候选即死，换道。
    if error.is_channel_error() {
        return RelayAttemptKind::Retryable;
    }
    let code = i32::from(error.status_code);
    match code {
        429 => RelayAttemptKind::Throttled,
        401 | 403 | 404 => RelayAttemptKind::FatalSwitchable,
        // 408 与 5xx：候选当前已死，换道。
        408 => RelayAttemptKind::Retryable,
        c if c >= 500 => RelayAttemptKind::Retryable,
        c if c >= 400 => RelayAttemptKind::Fatal,
        // 无状态（传输层）或 1xx/3xx：候选切换留在桌上。
        _ => RelayAttemptKind::Retryable,
    }
}

// ---------------------------------------------------------------------------
// 重试状态码表（Go middleware/status_code/status_code_ranges.go）
// ---------------------------------------------------------------------------

/// Go `alwaysSkipRetryStatusCodes`：504/524 永不重试。
const ALWAYS_SKIP_RETRY_STATUS_CODES: [u16; 2] = [504, 524];

/// Go `ShouldRetryByStatusCode`。
pub fn should_retry_by_status_code(code: u16) -> bool {
    if ALWAYS_SKIP_RETRY_STATUS_CODES.contains(&code) {
        return false;
    }
    should_match_status_code_ranges(code)
}

fn should_match_status_code_ranges(code: u16) -> bool {
    if !(100..=599).contains(&code) {
        return false;
    }
    let ranges: [(u16, u16); 7] = [
        (100, 199),
        (300, 399),
        (401, 407),
        (409, 499),
        (500, 503),
        (505, 523),
        (525, 599),
    ];
    for (start, end) in ranges {
        if code < start {
            return false;
        }
        if code <= end {
            return true;
        }
    }
    false
}

/// Go `shouldRetry`（handle_relay.go:658-688）的纯规则部分（上下文相关项
/// ——亲和跳过、specific channel——由调用方先行短路）。
pub fn should_retry(error: Option<&RelayAttemptError>, retry_times: i32) -> bool {
    let Some(error) = error else {
        return false;
    };
    if error.is_channel_error() {
        return true;
    }
    if error.is_skip_retry() {
        return false;
    }
    if retry_times <= 0 {
        return false;
    }
    let code = error.status_code;
    if (200..300).contains(&code) {
        return false;
    }
    if !(100..=599).contains(&code) {
        return true;
    }
    if error.code == error_code::BAD_RESPONSE_BODY {
        // Go IsAlwaysSkipRetryCode(ErrorCodeBadResponseBody)。
        return false;
    }
    should_retry_by_status_code(code)
}

// ---------------------------------------------------------------------------
// failover 终态错误（Go relay_failover.go:82-139）
// ---------------------------------------------------------------------------

/// Go `relayFailoverExhausted` 的终态决策：503（无单元冷却）或
/// 504 + Retry-After（池正在从冷却恢复）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailoverExhausted {
    /// > 0 时线上响应携带 `Retry-After` 头（秒）。
    pub retry_after_sec: u32,
}

impl FailoverExhausted {
    pub fn message(&self) -> String {
        if self.retry_after_sec > 0 {
            format!(
                "所有路由正在冷却恢复中，请在 {} 秒后重试",
                self.retry_after_sec
            )
        } else {
            "所有路由暂时不可用".to_owned()
        }
    }
}

/// Go `newFailoverTerminalError`：暂存的渠道域 4xx 原样直通；否则
/// 有冷却 → 504 + Retry-After（向上取整），无 → 503。
pub fn new_failover_terminal_error(
    stashed: Option<RelayAttemptError>,
    cooling_ms: i64,
) -> RelayAttemptError {
    if let Some(stashed) = stashed {
        return stashed;
    }
    if cooling_ms > 0 {
        let seconds = u32::try_from((cooling_ms + 999) / 1000).unwrap_or(u32::MAX);
        return RelayAttemptError::new(
            504,
            error_code::GET_CHANNEL_FAILED,
            FailoverExhausted {
                retry_after_sec: seconds,
            }
            .message(),
        )
        .with_skip_retry()
        .with_retry_after_ms(cooling_ms);
    }
    RelayAttemptError::new(
        503,
        error_code::GET_CHANNEL_FAILED,
        FailoverExhausted { retry_after_sec: 0 }.message(),
    )
    .with_skip_retry()
}

/// Go `newConcurrencySlotFullError`：并发槽满的本地 429——非 channel: 前缀，
/// 健康表与 autoban 路径绝不视其为上游失败。
pub fn new_concurrency_slot_full_error() -> RelayAttemptError {
    RelayAttemptError::new(429, error_code::RATE_LIMITED, "concurrency limit reached")
}

/// Go `terminalFailoverError`：池饱和时最后一条槽满 429 是终态权威；
/// 否则按暂存/冷却二分。
pub fn terminal_failover_error(
    slot_full: Option<RelayAttemptError>,
    stashed: Option<RelayAttemptError>,
    cooling_ms: i64,
) -> RelayAttemptError {
    if let Some(slot_full) = slot_full {
        return slot_full;
    }
    new_failover_terminal_error(stashed, cooling_ms)
}

// ---------------------------------------------------------------------------
// adaptor 调用链（Go relayHandler 分发表 + GetAdaptor 消费点）
// ---------------------------------------------------------------------------

/// 调度结果：`do_response` 解析产物 + 上游状态。流式响应的字节面由
/// channel-adapter 切片填充；骨架层只承载 JSON 主体。
#[derive(Clone, Debug, Default)]
pub struct AdaptorOutcome {
    pub status: u16,
    pub body: serde_json::Value,
    /// 上游响应头（响应回写面的头继承，如 upstream request id）。
    pub headers: Vec<(String, String)>,
}

/// Go `GetAdaptor(apiType)` 的工厂端口：调用点（dispatch 骨架）经此拿到
/// [`Adaptor`] trait 对象。真实工厂由 channel-adapter 切片提供（按 Kind
/// 构造具体适配器）；测试注入替身工厂。
pub trait AdaptorFactory: Send + Sync {
    fn create(&self, api_type: i32) -> Result<Box<dyn Adaptor>, RelayAttemptError>;
}

/// Go `ResolveAdaptor` 的默认工厂：只做注册表解析并返回"外呼归适配器
/// 切片"的占位实现（[`adaptor::Adaptor::do_request`] 默认分支）。
pub struct RegistryAdaptorFactory;

impl AdaptorFactory for RegistryAdaptorFactory {
    fn create(&self, api_type: i32) -> Result<Box<dyn Adaptor>, RelayAttemptError> {
        match adaptor::resolve_adaptor(api_type) {
            Some(_) => Ok(Box::new(PlaceholderAdaptor { api_type })),
            None => Err(RelayAttemptError::new(
                500,
                error_code::GET_CHANNEL_FAILED,
                format!("invalid api type {api_type}"),
            )
            .with_skip_retry()),
        }
    }
}

/// 占位适配器：接口契约存在，外呼在适配器切片合流前恒报未实现
/// （500 + channel:error 前缀的调用面错误 → Retryable）。
struct PlaceholderAdaptor {
    #[allow(dead_code)]
    api_type: i32,
}

fn adaptor_placeholder_message() -> String {
    "adaptor outbound dispatch is owned by the channel-adapter slice".to_owned()
}

/// 占位 convert 面：所有 Convert*Request 恒报未实现（trait 无默认实现的
/// 接口面必须逐一覆盖）。
macro_rules! placeholder_convert {
    ($name:ident) => {
        fn $name(
            &self,
            _info: &RelayInfo,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err(adaptor_placeholder_message())
        }
    };
}

impl Adaptor for PlaceholderAdaptor {
    fn init(&mut self, _info: &RelayInfo) {}
    fn get_request_url(&self, _info: &RelayInfo) -> Result<String, String> {
        Err(adaptor_placeholder_message())
    }
    fn setup_request_header(&self, _info: &RelayInfo) -> Vec<(String, String)> {
        Vec::new()
    }
    placeholder_convert!(convert_openai_request);
    placeholder_convert!(convert_claude_request);
    placeholder_convert!(convert_gemini_request);
    placeholder_convert!(convert_embedding_request);
    placeholder_convert!(convert_image_request);
    placeholder_convert!(convert_openai_responses_request);
    fn convert_rerank_request(
        &self,
        _relay_mode: i32,
        _request: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        Err(adaptor_placeholder_message())
    }
    fn do_response(
        &self,
        _info: &mut RelayInfo,
        _response: &[u8],
    ) -> Result<serde_json::Value, crate::relay_info::AdaptorError> {
        Err(crate::relay_info::AdaptorError {
            status_code: 500,
            message: adaptor_placeholder_message(),
            code: error_code::DO_REQUEST_FAILED.to_owned(),
            error_type: "new_api_error".to_owned(),
            skip_retry: false,
        })
    }
    fn get_model_list(&self) -> Vec<String> {
        Vec::new()
    }
    fn get_channel_name(&self) -> String {
        "placeholder".to_owned()
    }
}

/// Go 分发表的 convert 方法选择：按最终请求 relay 格式（GetFinalRequestRelayFormat）
/// 选 `Convert*Request`。请求载荷统一 `serde_json::Value`（Go `any` 转换产物）。
fn convert_request(
    request_adaptor: &dyn Adaptor,
    info: &RelayInfo,
    payload: &serde_json::Value,
) -> Result<Vec<u8>, RelayAttemptError> {
    let format = info.get_final_request_relay_format();
    let converted = if format == relay_format::CLAUDE {
        request_adaptor.convert_claude_request(info, payload)
    } else if format == relay_format::GEMINI {
        request_adaptor.convert_gemini_request(info, payload)
    } else if format == relay_format::RERANK {
        request_adaptor.convert_rerank_request(info.relay_mode, payload)
    } else if format == relay_format::EMBEDDING {
        request_adaptor.convert_embedding_request(info, payload)
    } else if format == relay_format::OPENAI_IMAGE {
        request_adaptor.convert_image_request(info, payload)
    } else if format == relay_format::OPENAI_RESPONSES
        || format == relay_format::OPENAI_RESPONSES_COMPACTION
        || format == relay_format::OPENAI_ALPHA_SEARCH
    {
        request_adaptor.convert_openai_responses_request(info, payload)
    } else {
        // openai / openai_audio / task / mjproxy 等 default 臂。
        request_adaptor.convert_openai_request(info, payload)
    };
    converted
        .map(|value| serde_json::to_vec(&value).unwrap_or_else(|_| Vec::new()))
        .map_err(|message| {
            RelayAttemptError::new(
                500,
                error_code::CONVERT_REQUEST_FAILED,
                format!("convert request failed: {message}"),
            )
            .with_skip_retry()
        })
}

/// Go relay 尝试的 adaptor 调用链（TextHelper 等 helper 的 adaptor 段投影）：
/// `Init` → `GetRequestURL` → `SetupRequestHeader` → `Convert*Request` →
/// `DoRequest` → `DoResponse`。任一步失败折算成 [`RelayAttemptError`]；
/// `DoResponse` 的 [`crate::relay_info::AdaptorError`] 按其 status_code /
/// code 透传（skip_retry 保留）。
pub fn run_adaptor_dispatch(
    factory: &dyn AdaptorFactory,
    info: &mut RelayInfo,
    payload: &serde_json::Value,
) -> Result<AdaptorOutcome, RelayAttemptError> {
    let Some(api_type) = info.channel_meta.as_ref().map(|meta| meta.api_type) else {
        return Err(
            RelayAttemptError::new(503, error_code::GET_CHANNEL_FAILED, "route is nil")
                .with_skip_retry(),
        );
    };
    let mut request_adaptor = factory.create(api_type)?;
    request_adaptor.init(info);
    let _url = request_adaptor.get_request_url(info).map_err(|message| {
        // 渠道域故障：URL 组装失败即该候选不可用（Go egress 的
        // channel: 前缀族）。
        RelayAttemptError::new(
            500,
            error_code::DO_REQUEST_FAILED,
            format!("channel: get request url failed: {message}"),
        )
    })?;
    let _headers = request_adaptor.setup_request_header(info);
    let request_body = convert_request(request_adaptor.as_ref(), info, payload)?;
    let response_bytes = request_adaptor
        .do_request(info, &request_body)
        .map_err(|message| {
            // Go DoRequest 失败 → ErrorCodeDoRequestFailed（channel: 前缀族由
            // 适配器层标注；此处传输面缺省 channel:do_request_failed）。
            RelayAttemptError::new(
                500,
                "channel:do_request_failed",
                format!("do request failed: {message}"),
            )
        })?;
    let outcome = request_adaptor
        .do_response(info, &response_bytes)
        .map_err(|adaptor_error| {
            let mut error = RelayAttemptError::new(
                u16::try_from(adaptor_error.status_code).unwrap_or(500),
                if adaptor_error.code.is_empty() {
                    error_code::BAD_RESPONSE_BODY
                } else {
                    adaptor_error.code.as_str()
                },
                adaptor_error.message,
            );
            error.skip_retry = adaptor_error.skip_retry;
            error
        })?;
    Ok(AdaptorOutcome {
        // 非错误路径：上游状态由 do_response 消费——非 2xx 在那里折算成
        // RelayAttemptError；这里只剩成功主体。
        status: 200,
        body: outcome,
        headers: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_info::{ChannelMetaSnapshot, RelayInfoInput};
    use serde_json::json;

    fn error(status: u16, code: &str) -> RelayAttemptError {
        RelayAttemptError::new(status, code, "boom")
    }

    // ── classify_attempt（relay_failover.go 契约）─────────────────────────

    #[test]
    fn classify_channel_prefixed_errors_as_retryable() {
        assert_eq!(
            classify_attempt(Some(&error(500, "channel:no_available_key"))),
            RelayAttemptKind::Retryable
        );
    }

    #[test]
    fn classify_status_families() {
        assert_eq!(
            classify_attempt(Some(&error(429, "bad_response_status_code"))),
            RelayAttemptKind::Throttled
        );
        for code in [401u16, 403, 404] {
            assert_eq!(
                classify_attempt(Some(&error(code, "bad_response_status_code"))),
                RelayAttemptKind::FatalSwitchable,
                "code {code}"
            );
        }
        assert_eq!(
            classify_attempt(Some(&error(408, "bad_response_status_code"))),
            RelayAttemptKind::Retryable
        );
        assert_eq!(
            classify_attempt(Some(&error(503, "bad_response_status_code"))),
            RelayAttemptKind::Retryable
        );
        // 渠道域外 4xx（mono 行为差量）：终态。
        assert_eq!(
            classify_attempt(Some(&error(409, "bad_response_status_code"))),
            RelayAttemptKind::Fatal
        );
        assert_eq!(
            classify_attempt(Some(&error(413, "bad_response_status_code"))),
            RelayAttemptKind::Fatal
        );
        // 无上游状态/1xx/3xx：换道留在桌上。
        assert_eq!(
            classify_attempt(Some(&error(302, "bad_response_status_code"))),
            RelayAttemptKind::Retryable
        );
        // 2xx 带错误体：直通。
        assert_eq!(
            classify_attempt(Some(&error(200, "bad_response_body"))),
            RelayAttemptKind::Fatal
        );
    }

    // ── should_retry / 状态码表（status_code_ranges.go 契约）──────────────

    #[test]
    fn automatic_retry_ranges_default_table() {
        assert!(should_retry_by_status_code(150));
        assert!(should_retry_by_status_code(302));
        assert!(should_retry_by_status_code(401));
        assert!(should_retry_by_status_code(407));
        assert!(should_retry_by_status_code(429));
        assert!(should_retry_by_status_code(500));
        assert!(should_retry_by_status_code(503));
        assert!(should_retry_by_status_code(520));
        assert!(should_retry_by_status_code(525));
        // 2xx / 缺口码 / 永不重试码。
        assert!(!should_retry_by_status_code(200));
        assert!(!should_retry_by_status_code(400));
        assert!(!should_retry_by_status_code(408));
        assert!(!should_retry_by_status_code(504));
        assert!(!should_retry_by_status_code(524));
        assert!(!should_retry_by_status_code(600));
        assert!(!should_retry_by_status_code(99));
    }

    #[test]
    fn should_retry_rules() {
        // channel: 前缀无权重于重试预算之外：恒重试。
        assert!(should_retry(Some(&error(500, "channel:invalid_key")), 0));
        // skip_retry 标志终止。
        assert!(!should_retry(Some(&error(500, "x").with_skip_retry()), 3));
        // RetryTimes=0 终止。
        assert!(!should_retry(Some(&error(500, "x")), 0));
        // 2xx 不重试；范围外（0/600）重试；504/524 永不重试。
        assert!(!should_retry(Some(&error(200, "x")), 3));
        assert!(should_retry(Some(&error(0, "x")), 3));
        assert!(should_retry(Some(&error(600, "x")), 3));
        assert!(!should_retry(Some(&error(504, "x")), 3));
        assert!(!should_retry(Some(&error(524, "x")), 3));
        assert!(!should_retry(None, 3));
    }

    // ── failover 终态错误 ─────────────────────────────────────────────────

    #[test]
    fn failover_terminal_error_semantics() {
        // 暂存的渠道域 4xx 直通。
        let stashed = error(401, "bad_response_status_code");
        let terminal = new_failover_terminal_error(Some(stashed.clone()), 5000);
        assert_eq!(terminal, stashed);
        // 冷却中 → 504 + Retry-After（向上取整）。
        let terminal = new_failover_terminal_error(None, 4500);
        assert_eq!(terminal.status_code, 504);
        assert!(terminal.message().contains("5 秒后重试"));
        assert!(terminal.is_skip_retry());
        // 无冷却 → 503。
        let terminal = new_failover_terminal_error(None, 0);
        assert_eq!(terminal.status_code, 503);
        assert_eq!(terminal.message(), "所有路由暂时不可用");
        // 池饱和：槽满 429 是权威。
        let slot_full = new_concurrency_slot_full_error();
        let terminal = terminal_failover_error(Some(slot_full.clone()), Some(stashed), 5000);
        assert_eq!(terminal, slot_full);
    }

    #[test]
    fn concurrency_slot_error_is_not_channel_scoped() {
        let error = new_concurrency_slot_full_error();
        assert_eq!(error.status_code, 429);
        assert!(!error.is_channel_error());
    }

    // ── adaptor 调用链 ─────────────────────────────────────────────────────

    fn test_input() -> RelayInfoInput {
        RelayInfoInput {
            path: "/v1/chat/completions".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            user_group: "default".to_owned(),
            ..RelayInfoInput::default()
        }
    }

    /// 替身工厂：外呼回可配置结果。
    struct StubFactory {
        succeed: bool,
    }

    impl StubFactory {
        fn new(succeed: bool) -> Self {
            Self { succeed }
        }
    }

    impl Adaptor for StubAdaptor {
        fn init(&mut self, _info: &RelayInfo) {}
        fn get_request_url(&self, _info: &RelayInfo) -> Result<String, String> {
            Ok("https://upstream/v1/chat/completions".to_owned())
        }
        fn setup_request_header(&self, _info: &RelayInfo) -> Vec<(String, String)> {
            vec![("authorization".to_owned(), "Bearer sk-stub".to_owned())]
        }
        fn convert_openai_request(
            &self,
            _info: &RelayInfo,
            request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            self.record(request);
            Ok(request.clone())
        }
        fn convert_claude_request(
            &self,
            _info: &RelayInfo,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("stub: claude convert not implemented".to_owned())
        }
        fn convert_gemini_request(
            &self,
            _info: &RelayInfo,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("stub: gemini convert not implemented".to_owned())
        }
        fn convert_rerank_request(
            &self,
            _relay_mode: i32,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("stub: rerank convert not implemented".to_owned())
        }
        fn convert_embedding_request(
            &self,
            _info: &RelayInfo,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("stub: embedding convert not implemented".to_owned())
        }
        fn convert_image_request(
            &self,
            _info: &RelayInfo,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("stub: image convert not implemented".to_owned())
        }
        fn convert_openai_responses_request(
            &self,
            _info: &RelayInfo,
            _request: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            Err("stub: responses convert not implemented".to_owned())
        }
        fn do_request(&self, _info: &RelayInfo, _body: &[u8]) -> Result<Vec<u8>, String> {
            if self.succeed {
                Ok(br#"{"id":"chatcmpl-1","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#.to_vec())
            } else {
                Err("upstream 503".to_owned())
            }
        }
        fn do_response(
            &self,
            _info: &mut RelayInfo,
            response: &[u8],
        ) -> Result<serde_json::Value, crate::relay_info::AdaptorError> {
            serde_json::from_slice(response).map_err(|e| crate::relay_info::AdaptorError {
                status_code: 500,
                message: e.to_string(),
                code: error_code::BAD_RESPONSE_BODY.to_owned(),
                error_type: "new_api_error".to_owned(),
                skip_retry: false,
            })
        }
        fn get_model_list(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_channel_name(&self) -> String {
            "stub".to_owned()
        }
    }

    struct StubAdaptor {
        succeed: bool,
    }

    impl StubAdaptor {
        fn record(&self, request: &serde_json::Value) {
            STUB_CONVERTS.lock().unwrap().push(
                request
                    .get("model")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned(),
            );
        }
    }

    static STUB_CONVERTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

    impl AdaptorFactory for StubFactory {
        fn create(&self, _api_type: i32) -> Result<Box<dyn Adaptor>, RelayAttemptError> {
            Ok(Box::new(StubAdaptor {
                succeed: self.succeed,
            }))
        }
    }

    fn info_with_channel() -> RelayInfo {
        let mut info = crate::relay_info::gen_relay_info_openai(&test_input());
        info.init_channel_meta(ChannelMetaSnapshot {
            channel_type: adaptor::channel_type::OPENAI,
            api_type: adaptor::api_type::OPENAI,
            api_version: String::new(),
            upstream_model_name: "gpt-4".to_owned(),
            param_override: json!({}),
            headers_override: json!({}),
            channel_setting: json!({}),
            channel_other_settings: json!({}),
            pass_through_request_enabled: false,
        });
        info
    }

    #[test]
    fn dispatch_without_channel_meta_is_terminal() {
        let mut info = crate::relay_info::gen_relay_info_openai(&test_input());
        let factory = StubFactory::new(true);
        let error = run_adaptor_dispatch(&factory, &mut info, &json!({})).unwrap_err();
        assert_eq!(error.status_code, 503);
        assert_eq!(error.code, error_code::GET_CHANNEL_FAILED);
        assert!(error.is_skip_retry());
    }

    #[test]
    fn dispatch_success_round_trip() {
        let mut info = info_with_channel();
        let factory = StubFactory::new(true);
        let outcome =
            run_adaptor_dispatch(&factory, &mut info, &json!({"model": "gpt-4"})).unwrap();
        assert_eq!(outcome.body["id"], "chatcmpl-1");
        assert_eq!(outcome.body["usage"]["total_tokens"], 15);
    }

    #[test]
    fn dispatch_failure_maps_do_request_error() {
        let mut info = info_with_channel();
        let factory = StubFactory::new(false);
        let error = run_adaptor_dispatch(&factory, &mut info, &json!({})).unwrap_err();
        assert!(error.is_channel_error());
        assert_eq!(error.code, "channel:do_request_failed");
        assert_eq!(classify_attempt(Some(&error)), RelayAttemptKind::Retryable);
    }

    #[test]
    fn dispatch_selects_convert_by_final_format() {
        // Claude 格式走 convert_claude_request（替身未实现 → 转换失败路径）。
        let mut info = info_with_channel();
        info.append_request_conversion(relay_format::CLAUDE);
        let factory = StubFactory::new(true);
        let error = run_adaptor_dispatch(&factory, &mut info, &json!({})).unwrap_err();
        assert_eq!(error.code, error_code::CONVERT_REQUEST_FAILED);
        assert!(error.is_skip_retry());
    }

    #[test]
    fn channel_meta_snapshot_supports_stream_options() {
        let info = info_with_channel();
        let meta = info.channel_meta.as_ref().unwrap();
        assert!(meta.support_stream_options);
    }
}
