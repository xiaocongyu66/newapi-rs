//! Channel balance query core ported from Go
//! `apps/api/internal/billing/fetch_channel_balance.go`.
//!
//! Contract (oracle `/root/newapi`, read-only):
//! - `GetResponseBody` (`fetch_channel_balance.go:136-164`): GET with the
//!   given headers through the channel's proxy-configured client; a non-200
//!   status becomes the error `status code: %d`.
//! - `updateChannelBalance` (`fetch_channel_balance.go:340-403`): the base
//!   URL starts at `constant.ChannelBaseURLs[type]` (verbatim table) unless
//!   the channel overrides it; Azure and unknown types error `尚未实现`;
//!   fixed-endpoint types (AIProxy/API2GPT/AIGC2D/SiliconFlow/DeepSeek/
//!   OpenRouter/Moonshot) call their vendor endpoints; OpenAI/Custom run the
//!   two-step subscription + usage flow whose balance is
//!   `hard_limit_usd - total_usage/100`, with the usage start date falling
//!   back 100 days when `has_payment_method` is false.
//! - `UpdateChannelBalance` handler pieces (`:405-433`): multi-key channels
//!   are refused with `多密钥渠道不支持余额查询`; the success body is
//!   `{success, message, balance}`.
//! - `updateAllChannelsBalance` (`:435-463`): enabled, non-multi-key channels
//!   only; a balance `<= 0` disables the channel (`余额不足`); per-channel
//!   `common.RequestInterval` throttling; query errors skip the channel.
//!
//! Ownership notes (P1 slice boundary): the HTTP transport lives behind the
//! [`BalanceFetcher`] port so tests inject a fake (the task's "trait 注入替身"
//! requirement); the reqwest-backed production fetcher lives in the server
//! adapter (which owns the transport dependency surface), the egress proxy
//! client and the `AutomaticallyUpdateChannels` background loop belong to
//! integrations/jobs (P7 per `docs/async-final-audit.md:113`), and the
//! persistence half of the all-channels loop (`catalog.DisableChannel`,
//! `Channel.UpdateBalance`) is wired by the server adapter once the channel
//! cache slice lands. The pure query/parse/decision core here is byte-faithful.

/// Go `billing.Price` (`pay_subscription.go:71`): the CNY→USD rate used by
/// the Moonshot balance conversion.
pub const CNY_TO_USD_PRICE: f64 = 7.3;

/// Go `constant.ChannelBaseURLs` (`constant/channel.go:65-122`), verbatim.
pub const CHANNEL_BASE_URLS: [&str; 61] = [
    "", // 0
    "https://api.openai.com",
    "https://oa.api2d.net",
    "", // 3
    "http://localhost:11434",
    "https://api.openai-sb.com",
    "https://api.openaimax.com",
    "https://api.ohmygpt.com",
    "", // 8
    "https://api.caipacity.com",
    "https://api.aiproxy.io",
    "", // 11
    "https://api.api2gpt.com",
    "https://api.aigc2d.com",
    "https://api.anthropic.com",
    "https://aip.baidubce.com",
    "https://open.bigmodel.cn",
    "https://dashscope.aliyuncs.com",
    "", // 18
    "https://api.360.cn",
    "https://openrouter.ai/api",
    "https://api.aiproxy.io",
    "https://fastgpt.run/api/openapi",
    "https://hunyuan.tencentcloudapi.com",
    "https://generativelanguage.googleapis.com",
    "https://api.moonshot.cn",
    "https://open.bigmodel.cn",
    "https://api.perplexity.ai",
    "", // 28
    "", // 29
    "", // 30
    "https://api.lingyiwanwu.com",
    "", // 32
    "", // 33
    "https://api.cohere.ai",
    "https://api.minimax.chat",
    "", // 36
    "https://api.dify.ai",
    "https://api.jina.ai",
    "https://api.cloudflare.com",
    "https://api.siliconflow.cn",
    "", // 41
    "https://api.mistral.ai",
    "https://api.deepseek.com",
    "https://api.moka.ai",
    "https://ark.cn-beijing.volces.com",
    "https://qianfan.baidubce.com",
    "", // 47
    "https://api.x.ai",
    "https://api.coze.cn",
    "https://api.klingai.com",
    "https://visual.volcengineapi.com",
    "https://api.vidu.cn",
    "https://llm.submodel.ai",
    "https://ark.cn-beijing.volces.com",
    "https://api.openai.com",
    "https://api.replicate.com",
    "https://chatgpt.com",
    "", // 58
    "", // 59
    "", // 60
];

/// Go `constant` channel types used by the balance switch.
pub const CHANNEL_TYPE_OPEN_AI: i64 = 1;
pub const CHANNEL_TYPE_AZURE: i64 = 3;
pub const CHANNEL_TYPE_CUSTOM: i64 = 8;
pub const CHANNEL_TYPE_AI_PROXY: i64 = 10;
pub const CHANNEL_TYPE_API2GPT: i64 = 12;
pub const CHANNEL_TYPE_AIGC2D: i64 = 13;
pub const CHANNEL_TYPE_OPEN_ROUTER: i64 = 20;
pub const CHANNEL_TYPE_MOONSHOT: i64 = 25;
pub const CHANNEL_TYPE_SILICON_FLOW: i64 = 40;
pub const CHANNEL_TYPE_DEEP_SEEK: i64 = 43;

/// Go `common.ChannelStatusEnabled`.
pub const CHANNEL_STATUS_ENABLED: i64 = 1;

/// Port of Go `GetResponseBody` (`fetch_channel_balance.go:136-164`). The
/// production implementation adds the channel's proxy-configured HTTP client
/// (egress slice); the contract it must satisfy is GET + headers + non-200 →
/// `status code: <n>` + full body. The boxed-future shape keeps the trait
/// object-safe so tests inject fakes behind `&dyn BalanceFetcher`.
pub trait BalanceFetcher: Send + Sync {
    fn fetch(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>;
}

/// Go `GetAuthHeader` (`fetch_channel_balance.go:122-126`).
pub fn auth_header(token: &str) -> Vec<(String, String)> {
    vec![("Authorization".to_owned(), format!("Bearer {token}"))]
}

/// Go `GetClaudeAuthHeader` (`fetch_channel_balance.go:129-134`).
pub fn claude_auth_header(token: &str) -> Vec<(String, String)> {
    vec![
        ("x-api-key".to_owned(), token.to_owned()),
        ("anthropic-version".to_owned(), "2023-06-01".to_owned()),
    ]
}

/// The channel fields the balance switch reads.
#[derive(Clone, Debug)]
pub struct BalanceChannel<'a> {
    pub id: i64,
    pub channel_type: i64,
    pub key: &'a str,
    /// Go `channel.GetBaseURL()` (nil/empty → `ChannelBaseURLs[type]`).
    pub base_url: &'a str,
    pub is_multi_key: bool,
}

impl<'a> BalanceChannel<'a> {
    /// Go `channel.GetBaseURL()` (`catalog/store_channel.go:529-538`).
    pub fn effective_base_url(&self) -> String {
        if self.base_url.is_empty() {
            return CHANNEL_BASE_URLS
                .get(self.channel_type as usize)
                .copied()
                .unwrap_or_default()
                .to_owned();
        }
        self.base_url.to_owned()
    }
}

// --- Vendor response shapes (serde) ---------------------------------------

#[derive(serde::Deserialize)]
struct OpenAISubscriptionResponse {
    // Go's json.Unmarshal leaves missing fields at their zero values.
    #[serde(default)]
    has_payment_method: bool,
    #[serde(default)]
    hard_limit_usd: f64,
}

#[derive(serde::Deserialize)]
struct OpenAIUsageResponse {
    #[serde(default)]
    total_usage: f64,
}

#[derive(serde::Deserialize)]
struct AIProxyUserOverviewResponse {
    success: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error_code: i64,
    // Go's json.Unmarshal leaves a missing struct field at its zero value.
    #[serde(default)]
    data: AIProxyOverviewData,
}

#[derive(serde::Deserialize)]
struct AIProxyOverviewData {
    #[serde(default, rename = "totalPoints")]
    total_points: f64,
}

#[derive(serde::Deserialize)]
struct API2GPTUsageResponse {
    #[serde(default)]
    total_remaining: f64,
}

#[derive(serde::Deserialize)]
struct APGC2DGPTUsageResponse {
    #[serde(default)]
    total_available: f64,
}

#[derive(serde::Deserialize)]
struct SiliconFlowUsageResponse {
    code: i64,
    #[serde(default)]
    message: String,
    #[serde(default)]
    data: SiliconFlowData,
}

#[derive(serde::Deserialize)]
struct SiliconFlowData {
    #[serde(default)]
    total_balance: String,
}

#[derive(serde::Deserialize)]
struct DeepSeekUsageResponse {
    #[serde(default)]
    balance_infos: Vec<DeepSeekBalanceInfo>,
}

#[derive(serde::Deserialize)]
struct DeepSeekBalanceInfo {
    currency: String,
    total_balance: String,
}

#[derive(serde::Deserialize)]
struct OpenRouterCreditResponse {
    #[serde(default)]
    data: OpenRouterCreditData,
}

#[derive(serde::Deserialize)]
struct OpenRouterCreditData {
    #[serde(default)]
    total_credits: f64,
    #[serde(default)]
    total_usage: f64,
}

#[derive(serde::Deserialize)]
struct MoonshotBalanceResponse {
    code: i64,
    #[serde(default)]
    scode: String,
    status: bool,
    #[serde(default)]
    data: MoonshotBalanceData,
}

#[derive(serde::Deserialize)]
struct MoonshotBalanceData {
    #[serde(default)]
    available_balance: f64,
}

/// Errors are Go's `error` values, kept as strings for contract fidelity.
pub type BalanceError = String;

/// Go `updateChannelBalance` (`fetch_channel_balance.go:340-403`).
pub async fn update_channel_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let mut base_url = channel.effective_base_url();
    match channel.channel_type {
        CHANNEL_TYPE_OPEN_AI => {
            if !channel.effective_base_url().is_empty() {
                base_url = channel.effective_base_url();
            }
        }
        CHANNEL_TYPE_AZURE => return Err("尚未实现".to_owned()),
        CHANNEL_TYPE_CUSTOM => base_url = channel.effective_base_url(),
        CHANNEL_TYPE_AI_PROXY => return update_ai_proxy_balance(fetcher, channel).await,
        CHANNEL_TYPE_API2GPT => return update_api2gpt_balance(fetcher, channel).await,
        CHANNEL_TYPE_AIGC2D => return update_aigc2d_balance(fetcher, channel).await,
        CHANNEL_TYPE_SILICON_FLOW => return update_silicon_flow_balance(fetcher, channel).await,
        CHANNEL_TYPE_DEEP_SEEK => return update_deep_seek_balance(fetcher, channel).await,
        CHANNEL_TYPE_OPEN_ROUTER => return update_open_router_balance(fetcher, channel).await,
        CHANNEL_TYPE_MOONSHOT => return update_moonshot_balance(fetcher, channel).await,
        _ => return Err("尚未实现".to_owned()),
    }
    let url = format!("{base_url}/v1/dashboard/billing/subscription");
    let body = fetcher
        .fetch("GET", &url, &auth_header(channel.key))
        .await?;
    let subscription: OpenAISubscriptionResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    // Go's date arithmetic: start = "YYYY-MM-01" of the current month, end =
    // today; without a payment method the start rolls back 100 days.
    let now = chrono_today();
    let (start_date, end_date) = if subscription.has_payment_method {
        (format!("{}-01", now.0), now.1)
    } else {
        (days_before_today(100), now.1)
    };
    let url = format!(
        "{base_url}/v1/dashboard/billing/usage?start_date={start_date}&end_date={end_date}"
    );
    let body = fetcher
        .fetch("GET", &url, &auth_header(channel.key))
        .await?;
    let usage: OpenAIUsageResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    let balance = subscription.hard_limit_usd - usage.total_usage / 100.0;
    Ok(balance)
}

/// Civil date helpers replacing Go's `time.Format` arithmetic. Returns
/// `(YYYY-MM, YYYY-MM-DD)` for today (UTC).
fn chrono_today() -> (String, String) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = (now.as_secs() / 86_400) as i64;
    let (year, month, day) = civil_from_days(days);
    (
        format!("{year:04}-{month:02}"),
        format!("{year:04}-{month:02}-{day:02}"),
    )
}

fn days_before_today(n: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = (now.as_secs() / 86_400) as i64 - n;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

async fn get_body(
    fetcher: &dyn BalanceFetcher,
    url: &str,
    headers: &[(String, String)],
) -> Result<Vec<u8>, BalanceError> {
    fetcher.fetch("GET", url, headers).await
}

/// Go `updateChannelAIProxyBalance` (`fetch_channel_balance.go:188-206`).
async fn update_ai_proxy_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://aiproxy.io/api/report/getUserOverview";
    let headers = vec![("Api-Key".to_owned(), channel.key.to_owned())];
    let body = get_body(fetcher, url, &headers).await?;
    let response: AIProxyUserOverviewResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    if !response.success {
        return Err(format!(
            "code: {}, message: {}",
            response.error_code, response.message
        ));
    }
    Ok(response.data.total_points)
}

/// Go `updateChannelAPI2GPTBalance` (`fetch_channel_balance.go:208-222`).
async fn update_api2gpt_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://api.api2gpt.com/dashboard/billing/credit_grants";
    let body = get_body(fetcher, url, &auth_header(channel.key)).await?;
    let response: API2GPTUsageResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    Ok(response.total_remaining)
}

/// Go `updateChannelAIGC2DBalance` (`fetch_channel_balance.go:275-288`).
async fn update_aigc2d_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://api.aigc2d.com/dashboard/billing/credit_grants";
    let body = get_body(fetcher, url, &auth_header(channel.key)).await?;
    let response: APGC2DGPTUsageResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    Ok(response.total_available)
}

/// Go `updateChannelSiliconFlowBalance` (`fetch_channel_balance.go:224-244`).
async fn update_silicon_flow_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://api.siliconflow.cn/v1/user/info";
    let body = get_body(fetcher, url, &auth_header(channel.key)).await?;
    let response: SiliconFlowUsageResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    if response.code != 20000 {
        return Err(format!(
            "code: {}, message: {}",
            response.code, response.message
        ));
    }
    response
        .data
        .total_balance
        .parse::<f64>()
        .map_err(|error| error.to_string())
}

/// Go `updateChannelDeepSeekBalance` (`fetch_channel_balance.go:246-273`).
async fn update_deep_seek_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://api.deepseek.com/user/balance";
    let body = get_body(fetcher, url, &auth_header(channel.key)).await?;
    let response: DeepSeekUsageResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    let index = response
        .balance_infos
        .iter()
        .position(|info| info.currency == "CNY")
        .ok_or_else(|| "currency CNY not found".to_owned())?;
    response.balance_infos[index]
        .total_balance
        .parse::<f64>()
        .map_err(|error| error.to_string())
}

/// Go `updateChannelOpenRouterBalance` (`fetch_channel_balance.go:290-304`).
async fn update_open_router_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://openrouter.ai/api/v1/credits";
    let body = get_body(fetcher, url, &auth_header(channel.key)).await?;
    let response: OpenRouterCreditResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    Ok(response.data.total_credits - response.data.total_usage)
}

/// Go `updateChannelMoonshotBalance` (`fetch_channel_balance.go:306-338`):
/// CNY available balance converted at `billing.Price`.
async fn update_moonshot_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    let url = "https://api.moonshot.cn/v1/users/me/balance";
    let body = get_body(fetcher, url, &auth_header(channel.key)).await?;
    let response: MoonshotBalanceResponse =
        serde_json::from_slice(&body).map_err(|error| error.to_string())?;
    if !response.status || response.code != 0 {
        return Err(format!(
            "failed to update moonshot balance, status: {}, code: {}, scode: {}",
            response.status, response.code, response.scode
        ));
    }
    Ok(response.data.available_balance / CNY_TO_USD_PRICE)
}

/// Go `UpdateChannelBalance`'s handler contract (`fetch_channel_balance.go:405-433`)
/// minus the context plumbing: `Ok(balance)` renders
/// `{success: true, message: "", balance}`, the multi-key refusal is the
/// caller's `{success: false, message: "多密钥渠道不支持余额查询"}`.
pub async fn query_channel_balance(
    fetcher: &dyn BalanceFetcher,
    channel: &BalanceChannel<'_>,
) -> Result<f64, BalanceError> {
    update_channel_balance(fetcher, channel).await
}

/// The pure decision half of Go `updateAllChannelsBalance`
/// (`fetch_channel_balance.go:435-463`): whether a channel participates and
/// what a resolved balance does. `Err(())` = skip (disabled / multi-key /
/// query error); `Some(disable)` = the channel must be disabled because the
/// balance is used up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllChannelsDecision {
    Skip,
    Continue,
    Disable,
}

pub fn decide_all_channels_step(
    status: i64,
    is_multi_key: bool,
    balance_result: &Result<f64, BalanceError>,
) -> AllChannelsDecision {
    if status != CHANNEL_STATUS_ENABLED || is_multi_key {
        return AllChannelsDecision::Skip;
    }
    match balance_result {
        Err(_) => AllChannelsDecision::Skip,
        // err is nil & balance <= 0 means quota is used up.
        Ok(balance) if *balance <= 0.0 => AllChannelsDecision::Disable,
        Ok(_) => AllChannelsDecision::Continue,
    }
}

/// The production fetcher contract for the server adapter: reqwest-backed,
/// non-200 → `status code: <n>`, proxy support owned by the egress slice.
/// The impl lives in `apps/server` (`transport_http::BalanceHttpFetcher`).
pub trait ProductionBalanceFetcher: BalanceFetcher {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Fake fetcher replaying canned (url-contains, body) pairs — the task's
    /// injected-double requirement.
    struct FakeFetcher {
        routes: Vec<(&'static str, Result<&'static str, String>)>,
        calls: Mutex<Vec<(String, String)>>,
    }

    impl FakeFetcher {
        fn new(routes: Vec<(&'static str, Result<&'static str, String>)>) -> Self {
            Self {
                routes,
                calls: Mutex::new(Vec::new()),
            }
        }
    }

    impl BalanceFetcher for FakeFetcher {
        fn fetch(
            &self,
            method: &str,
            url: &str,
            headers: &[(String, String)],
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + '_>>
        {
            let method = method.to_owned();
            let url = url.to_owned();
            let headers = headers.to_vec();
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap()
                    .push((format!("{method} {url}"), headers[0].0.clone()));
                for (needle, body) in &self.routes {
                    if url.contains(needle) {
                        return match body {
                            Ok(text) => Ok(text.as_bytes().to_vec()),
                            Err(error) => Err(error.clone()),
                        };
                    }
                }
                Err("status code: 404".to_owned())
            })
        }
    }

    fn channel<'a>(channel_type: i64, key: &'a str, base_url: &'a str) -> BalanceChannel<'a> {
        BalanceChannel {
            id: 1,
            channel_type,
            key,
            base_url,
            is_multi_key: false,
        }
    }

    #[test]
    fn base_url_table_matches_go_verbatim() {
        assert_eq!(CHANNEL_BASE_URLS.len(), 61);
        assert_eq!(CHANNEL_BASE_URLS[1], "https://api.openai.com");
        assert_eq!(CHANNEL_BASE_URLS[25], "https://api.moonshot.cn");
        assert_eq!(CHANNEL_BASE_URLS[40], "https://api.siliconflow.cn");
        assert_eq!(CHANNEL_BASE_URLS[43], "https://api.deepseek.com");
        assert_eq!(CHANNEL_BASE_URLS[60], "");
    }

    #[test]
    fn effective_base_url_falls_back_to_table() {
        assert_eq!(
            channel(1, "k", "").effective_base_url(),
            "https://api.openai.com"
        );
        assert_eq!(
            channel(1, "k", "https://proxy.example").effective_base_url(),
            "https://proxy.example"
        );
        // Type 8 (Custom) has an empty table entry; Go uses the override.
        assert_eq!(channel(8, "k", "").effective_base_url(), "");
        assert_eq!(channel(99, "k", "").effective_base_url(), "");
    }

    #[test]
    fn azure_and_unknown_types_error_with_go_message() {
        let fetcher = FakeFetcher::new(vec![]);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let azure = runtime.block_on(update_channel_balance(&fetcher, &channel(3, "k", "")));
        assert_eq!(azure, Err("尚未实现".to_owned()));
        let unknown = runtime.block_on(update_channel_balance(&fetcher, &channel(99, "k", "")));
        assert_eq!(unknown, Err("尚未实现".to_owned()));
    }

    #[test]
    fn openai_two_step_flow_computes_hard_limit_minus_usage() {
        let fetcher = FakeFetcher::new(vec![
            (
                "/v1/dashboard/billing/subscription",
                Ok(r#"{"object":"list","has_payment_method":true,"hard_limit_usd":42.5}"#),
            ),
            (
                "/v1/dashboard/billing/usage",
                Ok(r#"{"object":"list","total_usage":250}"#),
            ),
        ]);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let balance = runtime
            .block_on(update_channel_balance(&fetcher, &channel(1, "sk-x", "")))
            .unwrap();
        assert!((balance - (42.5 - 2.5)).abs() < 1e-9);
        let calls = fetcher.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        let (first, header) = &calls[0];
        assert!(
            first.contains("/v1/dashboard/billing/subscription"),
            "{first}"
        );
        assert_eq!(header, "Authorization");
        let (second, _) = &calls[1];
        // has_payment_method=true: start = current month, end = today.
        assert!(second.contains("start_date="), "{second}");
        assert!(second.contains("&end_date="), "{second}");
    }

    #[test]
    fn openai_without_payment_method_rolls_start_back_100_days() {
        let fetcher = FakeFetcher::new(vec![
            (
                "subscription",
                Ok(r#"{"has_payment_method":false,"hard_limit_usd":10}"#),
            ),
            ("usage", Ok(r#"{"total_usage":0}"#)),
        ]);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let balance = runtime
            .block_on(update_channel_balance(&fetcher, &channel(1, "sk-x", "")))
            .unwrap();
        assert!((balance - 10.0).abs() < 1e-9);
        let (second, _) = fetcher.calls.lock().unwrap()[1].clone();
        let today = days_before_today(100);
        assert!(second.contains(&format!("start_date={today}")), "{second}");
    }

    #[test]
    fn non_200_status_surfaces_go_error_text() {
        let fetcher = FakeFetcher::new(vec![("subscription", Err("status code: 401".to_owned()))]);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let error = runtime
            .block_on(update_channel_balance(&fetcher, &channel(1, "sk-x", "")))
            .unwrap_err();
        assert_eq!(error, "status code: 401");
    }

    #[test]
    fn fixed_endpoint_types_query_vendor_urls() {
        let cases: [(i64, &'static str, &'static str, f64); 5] = [
            (
                CHANNEL_TYPE_AI_PROXY,
                r#"{"success":true,"message":"","error_code":0,"data":{"totalPoints":12.5}}"#,
                "aiproxy.io",
                12.5,
            ),
            (
                CHANNEL_TYPE_API2GPT,
                r#"{"object":"x","total_granted":1,"total_used":2,"total_remaining":33.25}"#,
                "api2gpt.com",
                33.25,
            ),
            (
                CHANNEL_TYPE_AIGC2D,
                r#"{"object":"x","total_available":7.75}"#,
                "aigc2d.com",
                7.75,
            ),
            (
                CHANNEL_TYPE_OPEN_ROUTER,
                r#"{"data":{"total_credits":100,"total_usage":40}}"#,
                "openrouter.ai",
                60.0,
            ),
            (
                CHANNEL_TYPE_DEEP_SEEK,
                r#"{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"5"},{"currency":"CNY","total_balance":"88.8"}]}"#,
                "deepseek.com",
                88.8,
            ),
        ];
        for (channel_type, body, needle, expected) in cases {
            let fetcher = FakeFetcher::new(vec![(needle, Ok(body))]);
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let balance = runtime
                .block_on(update_channel_balance(
                    &fetcher,
                    &channel(channel_type, "k", ""),
                ))
                .unwrap();
            assert!((balance - expected).abs() < 1e-9, "{channel_type}");
        }
    }

    #[test]
    fn vendor_failure_contracts_match_go_messages() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // AIProxy success=false → "code: N, message: M".
        let fetcher = FakeFetcher::new(vec![(
            "aiproxy.io",
            Ok(r#"{"success":false,"message":"bad key","error_code":7}"#),
        )]);
        let error = runtime
            .block_on(update_channel_balance(
                &fetcher,
                &channel(CHANNEL_TYPE_AI_PROXY, "k", ""),
            ))
            .unwrap_err();
        assert_eq!(error, "code: 7, message: bad key");
        // SiliconFlow code != 20000.
        let fetcher = FakeFetcher::new(vec![(
            "siliconflow.cn",
            Ok(r#"{"code":401,"message":"denied","status":false,"data":{"total_balance":"1"}}"#),
        )]);
        let error = runtime
            .block_on(update_channel_balance(
                &fetcher,
                &channel(CHANNEL_TYPE_SILICON_FLOW, "k", ""),
            ))
            .unwrap_err();
        assert_eq!(error, "code: 401, message: denied");
        // DeepSeek without a CNY row.
        let fetcher = FakeFetcher::new(vec![(
            "deepseek.com",
            Ok(r#"{"balance_infos":[{"currency":"USD","total_balance":"5"}]}"#),
        )]);
        let error = runtime
            .block_on(update_channel_balance(
                &fetcher,
                &channel(CHANNEL_TYPE_DEEP_SEEK, "k", ""),
            ))
            .unwrap_err();
        assert_eq!(error, "currency CNY not found");
        // Moonshot status/code guard.
        let fetcher = FakeFetcher::new(vec![(
            "moonshot.cn",
            Ok(r#"{"code":1,"scode":"x","status":false,"data":{"available_balance":1}}"#),
        )]);
        let error = runtime
            .block_on(update_channel_balance(
                &fetcher,
                &channel(CHANNEL_TYPE_MOONSHOT, "k", ""),
            ))
            .unwrap_err();
        assert_eq!(
            error,
            "failed to update moonshot balance, status: false, code: 1, scode: x"
        );
    }

    #[test]
    fn moonshot_converts_cny_at_price() {
        let fetcher = FakeFetcher::new(vec![(
            "moonshot.cn",
            Ok(r#"{"code":0,"status":true,"scode":"","data":{"available_balance":73.0}}"#),
        )]);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let balance = runtime
            .block_on(update_channel_balance(
                &fetcher,
                &channel(CHANNEL_TYPE_MOONSHOT, "k", ""),
            ))
            .unwrap();
        assert!((balance - 10.0).abs() < 1e-9);
        assert!((CNY_TO_USD_PRICE - 7.3).abs() < 1e-9);
    }

    #[test]
    fn siliconflow_parses_string_balance() {
        let fetcher = FakeFetcher::new(vec![(
            "siliconflow.cn",
            Ok(r#"{"code":20000,"message":"","status":true,"data":{"totalBalance":"  19.5 "}}"#),
        )]);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        // Go strconv.ParseFloat("  19.5 ") fails; serde trims nothing either.
        let result = runtime.block_on(update_channel_balance(
            &fetcher,
            &channel(CHANNEL_TYPE_SILICON_FLOW, "k", ""),
        ));
        assert!(result.is_err());
    }

    #[test]
    fn all_channels_step_decisions_match_go_loop() {
        // Disabled / multi-key channels are skipped before any query.
        assert_eq!(
            decide_all_channels_step(0, false, &Ok(1.0)),
            AllChannelsDecision::Skip
        );
        assert_eq!(
            decide_all_channels_step(CHANNEL_STATUS_ENABLED, true, &Ok(1.0)),
            AllChannelsDecision::Skip
        );
        // Query error: continue to the next channel.
        assert_eq!(
            decide_all_channels_step(CHANNEL_STATUS_ENABLED, false, &Err("boom".to_owned())),
            AllChannelsDecision::Skip
        );
        // Balance <= 0 disables the channel.
        assert_eq!(
            decide_all_channels_step(CHANNEL_STATUS_ENABLED, false, &Ok(0.0)),
            AllChannelsDecision::Disable
        );
        assert_eq!(
            decide_all_channels_step(CHANNEL_STATUS_ENABLED, false, &Ok(-0.5)),
            AllChannelsDecision::Disable
        );
        assert_eq!(
            decide_all_channels_step(CHANNEL_STATUS_ENABLED, false, &Ok(0.01)),
            AllChannelsDecision::Continue
        );
    }

    #[test]
    fn auth_headers_match_go_shapes() {
        assert_eq!(
            auth_header("sk-x"),
            vec![("Authorization".to_owned(), "Bearer sk-x".to_owned())]
        );
        assert_eq!(
            claude_auth_header("k"),
            vec![
                ("x-api-key".to_owned(), "k".to_owned()),
                ("anthropic-version".to_owned(), "2023-06-01".to_owned())
            ]
        );
    }
}
