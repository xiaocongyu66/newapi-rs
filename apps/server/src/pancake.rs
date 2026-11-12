//! Waffo Pancake 管理端上游客户端：`fetchWaffoPancakeCatalog`、
//! `CreateWaffoPancakePrimaryPair`、`CreateWaffoPancakeProductForPlan`
//! 的 Rust 复刻。
//!
//! Go 参考（只读 `/root/newapi` 与 SDK 源）：
//! - `apps/api/internal/billing/call_waffo_pancake.go`
//!   （`fetchWaffoPancakeCatalog`、`CreateWaffoPancakePrimaryStore/Product/
//!   Pair`、`CreateWaffoPancakeProductForPlan`）
//! - SDK `waffo-pancake-sdk-go@v0.3.1`：`http_client.go`（签名 POST）、
//!   `internal/signing/signature.go`（`POST\npath\ntimestamp\nbodyHash`
//!   的 RSA-SHA256 PKCS#1v15 规范串）、`graphql.go`、`stores.go`、
//!   `onetime_products.go`、`internal/signing/pem.go`（私钥归一化）。
//!
//! 传输通过 [`PancakeTransport`] 注入（与 `turnstile::Verifier`、
//! `custom_oauth_http::DiscoveryTransport` 同一手法），测试注入假传输，
//! 生产走 [`HttpPancakeTransport`]（ring RSA 签名 + 共享 reqwest 客户端）。

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

/// 生产 API 基址（SDK `DefaultBaseURL`）。
pub const DEFAULT_BASE_URL: &str = "https://api.waffo.ai";

/// Go `defaultWaffoPancakeStoreName`。
pub const DEFAULT_STORE_NAME: &str = "new-api-store";

/// Go `defaultWaffoPancakeProductName`。
pub const DEFAULT_PRODUCT_NAME: &str = "new-api-charge-product";

// ---------------------------------------------------------------------------
// 数据形状
// ---------------------------------------------------------------------------

/// Go `billing.WaffoPancakeCatalogProduct`。
#[derive(Clone, Debug, Default, Deserialize, PartialEq, serde::Serialize)]
pub struct WaffoPancakeCatalogProduct {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
}

/// Go `billing.WaffoPancakeCatalogStore`。
#[derive(Clone, Debug, Default, Deserialize, PartialEq, serde::Serialize)]
pub struct WaffoPancakeCatalogStore {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, rename = "prodEnabled")]
    pub prod_enabled: bool,
    #[serde(default, rename = "onetimeProducts")]
    pub onetime_products: Vec<WaffoPancakeCatalogProduct>,
}

/// Go `billing.WaffoPancakeCatalog`。
#[derive(Clone, Debug, Default, Deserialize, PartialEq, serde::Serialize)]
pub struct WaffoPancakeCatalog {
    #[serde(default)]
    pub stores: Vec<WaffoPancakeCatalogStore>,
}

/// Go `billing.WaffoPancakePairResult`（成功形态）。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WaffoPancakePairResult {
    pub store_id: String,
    pub store_name: String,
    pub product_id: String,
    pub product_name: String,
}

/// Go `CreateWaffoPancakePrimaryPair` 的 `(result, err)` 二元组：
/// - `Complete`：`(result, nil)`
/// - `OrphanStore`：`(result{store 半成品}, err)` —— 建店成功、建品失败，
///   handler 保留 store 上下文供前端重试
/// - `Failed`：`(nil, err)` —— 建店即失败
#[derive(Clone, Debug, PartialEq)]
pub enum PairOutcome {
    Complete(WaffoPancakePairResult),
    OrphanStore {
        store_id: String,
        store_name: String,
        error: String,
    },
    Failed(String),
}

/// 上游调用失败；`message` 进入 `data.error`（pair 孤儿分支）或仅入日志。
#[derive(Clone, Debug, PartialEq)]
pub struct PancakeError(pub String);

pub type PancakeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, PancakeError>> + Send + 'a>>;

/// 三个管理端点实际使用的上游能力；签名与信封解析在实现内完成。
pub trait PancakeTransport: Send + Sync {
    /// Go `fetchWaffoPancakeCatalog`：GraphQL `stores(limit: 100)` 查询。
    fn catalog<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
    ) -> PancakeFuture<'a, WaffoPancakeCatalog>;

    /// Go `CreateWaffoPancakePrimaryPair`：建店 + 建品（含发布）。
    fn create_pair<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
        return_url: &'a str,
    ) -> PancakeFuture<'a, PairOutcome>;

    /// Go `CreateWaffoPancakeProductForPlan`：建品 + 发布，返回产品 ID。
    fn create_product<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
        store_id: &'a str,
        name: &'a str,
        amount: &'a str,
        return_url: &'a str,
    ) -> PancakeFuture<'a, String>;
}

/// 请求扩展缝：测试与嵌入方替换真实传输。
#[derive(Clone)]
pub struct InjectedPancakeTransport(pub Arc<dyn PancakeTransport>);

// ---------------------------------------------------------------------------
// 生产实现
// ---------------------------------------------------------------------------

/// 生产实现：每次调用解析 PEM 私钥、签名并经共享 reqwest 客户端发送。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpPancakeTransport;

/// Go `fetchWaffoPancakeCatalog` 的 GraphQL 查询原文（缩进保持一致，便于
/// 与上游抓包比对）。
const CATALOG_QUERY: &str = "query {
			stores(limit: 100) {
				id
				name
				status
				prodEnabled
				onetimeProducts {
					id
					name
					status
				}
			}
		}";

impl PancakeTransport for HttpPancakeTransport {
    fn catalog<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
    ) -> PancakeFuture<'a, WaffoPancakeCatalog> {
        Box::pin(async move {
            let body = serde_json::json!({ "query": CATALOG_QUERY }).to_string();
            let data = signed_post(merchant_id, private_key, "/v1/graphql", &body, false).await?;
            if !data.errors.is_empty() {
                return Err(PancakeError(data.errors[0].clone()));
            }
            let parsed: WaffoPancakeCatalog = match data.data {
                Some(value) if !value.is_null() => serde_json::from_value(value)
                    .map_err(|_| PancakeError("decode response data".to_owned()))?,
                _ => WaffoPancakeCatalog::default(),
            };
            Ok(parsed)
        })
    }

    fn create_pair<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
        return_url: &'a str,
    ) -> PancakeFuture<'a, PairOutcome> {
        Box::pin(async move {
            // Go：先建店，失败直接上抛（Failed）；建品失败返回孤儿店。
            let store_id = match create_store(merchant_id, private_key).await {
                Ok(store_id) => store_id,
                Err(error) => return Ok(PairOutcome::Failed(error.0)),
            };
            let product = create_product(
                merchant_id,
                private_key,
                &store_id,
                DEFAULT_PRODUCT_NAME,
                "1.00",
                return_url,
            )
            .await;
            match product {
                Ok(product_id) => Ok(PairOutcome::Complete(WaffoPancakePairResult {
                    store_id,
                    store_name: DEFAULT_STORE_NAME.to_owned(),
                    product_id,
                    product_name: DEFAULT_PRODUCT_NAME.to_owned(),
                })),
                Err(error) => {
                    let message = format!(
                        "store created at {store_id} but product creation failed: {}",
                        error.0
                    );
                    Ok(PairOutcome::OrphanStore {
                        store_id,
                        store_name: DEFAULT_STORE_NAME.to_owned(),
                        error: message,
                    })
                }
            }
        })
    }

    fn create_product<'a>(
        &'a self,
        merchant_id: &'a str,
        private_key: &'a str,
        store_id: &'a str,
        name: &'a str,
        amount: &'a str,
        return_url: &'a str,
    ) -> PancakeFuture<'a, String> {
        Box::pin(async move {
            create_product(merchant_id, private_key, store_id, name, amount, return_url).await
        })
    }
}

/// Go `CreateWaffoPancakePrimaryStore`：`POST /v1/actions/store/create-store`。
async fn create_store(merchant_id: &str, private_key: &str) -> Result<String, PancakeError> {
    let body = serde_json::json!({ "name": DEFAULT_STORE_NAME }).to_string();
    let data = signed_post(
        merchant_id,
        private_key,
        "/v1/actions/store/create-store",
        &body,
        true,
    )
    .await?;
    if !data.errors.is_empty() {
        return Err(PancakeError(data.errors[0].clone()));
    }
    let store_id = data.store_field("id").unwrap_or_default().to_owned();
    if store_id.is_empty() {
        return Err(PancakeError(
            "create Waffo Pancake store: empty store id".to_owned(),
        ));
    }
    Ok(store_id)
}

/// Go `CreateWaffoPancakePrimaryProduct` / `CreateWaffoPancakeProductForPlan`
/// 共享的建品 + 发布序列。
async fn create_product(
    merchant_id: &str,
    private_key: &str,
    store_id: &str,
    name: &str,
    amount: &str,
    return_url: &str,
) -> Result<String, PancakeError> {
    if store_id.trim().is_empty() {
        return Err(PancakeError(
            "store id is required to create a product".to_owned(),
        ));
    }
    let mut body = serde_json::json!({
        "storeId": store_id,
        "name": name,
        "prices": { "USD": { "amount": amount, "taxCategory": "saas" } },
    });
    let success_url = return_url.trim();
    if !success_url.is_empty() {
        body["successUrl"] = Value::String(success_url.to_owned());
    }
    let body_text = body.to_string();
    let data = signed_post(
        merchant_id,
        private_key,
        "/v1/actions/onetime-product/create-product",
        &body_text,
        true,
    )
    .await?;
    if !data.errors.is_empty() {
        return Err(PancakeError(data.errors[0].clone()));
    }
    let product_id = data.product_field("id").unwrap_or_default().to_owned();
    if product_id.is_empty() {
        return Err(PancakeError(
            "create Waffo Pancake product: empty product id".to_owned(),
        ));
    }
    // Go：发布失败报 "publish Waffo Pancake ... failed"。
    let publish_body = serde_json::json!({ "id": product_id }).to_string();
    let published = signed_post(
        merchant_id,
        private_key,
        "/v1/actions/onetime-product/publish-product",
        &publish_body,
        true,
    )
    .await;
    match published {
        Ok(data) if data.errors.is_empty() => Ok(product_id),
        Ok(data) => Err(PancakeError(format!(
            "publish Waffo Pancake product: {}",
            data.errors[0]
        ))),
        Err(error) => Err(PancakeError(format!(
            "publish Waffo Pancake product: {}",
            error.0
        ))),
    }
}

// ---------------------------------------------------------------------------
// 签名传输
// ---------------------------------------------------------------------------

/// SDK `envelope`：`{ data, errors?, warnings? }` 的解析结果。
struct Envelope {
    data: Option<Value>,
    errors: Vec<String>,
}

impl Envelope {
    /// `data.store.<field>`。
    fn store_field(&self, field: &str) -> Option<&str> {
        self.data
            .as_ref()
            .and_then(|data| data.get("store"))
            .and_then(|store| store.get(field))
            .and_then(Value::as_str)
    }

    /// `data.product.<field>`。
    fn product_field(&self, field: &str) -> Option<&str> {
        self.data
            .as_ref()
            .and_then(|data| data.get("product"))
            .and_then(|product| product.get(field))
            .and_then(Value::as_str)
    }
}

#[derive(Deserialize)]
struct WireEnvelope {
    #[serde(default)]
    data: Option<Value>,
    #[serde(default)]
    errors: Vec<WireNotice>,
}

#[derive(Deserialize)]
struct WireNotice {
    #[serde(default)]
    message: String,
}

/// Go `httpClient.post`（`http_client.go:88-148`）+ `unwrapEnvelope`：
/// 非 JSON 响应体、网络失败、>=400 的空体都是传输错误；信封 errors 非空
/// 时携带首条消息。
async fn signed_post(
    merchant_id: &str,
    private_key: &str,
    path: &str,
    body: &str,
    idempotency: bool,
) -> Result<Envelope, PancakeError> {
    let client =
        pancake_client().ok_or_else(|| PancakeError("transport unavailable".to_owned()))?;
    let key = parse_private_key(private_key).map_err(PancakeError)?;
    let timestamp = crate::http::now_seconds().to_string();
    let signature = sign_request("POST", path, &timestamp, body.as_bytes(), &key)
        .map_err(|_| PancakeError("sign request".to_owned()))?;

    let mut request = client
        .post(format!("{DEFAULT_BASE_URL}{path}"))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Merchant-Id", merchant_id)
        .header("X-Timestamp", &timestamp)
        .header("X-Signature", signature);
    if idempotency {
        // SDK `computeIdempotencyKey`：sha256(merchantID:path:body) hex。
        let mut input = Vec::with_capacity(merchant_id.len() + path.len() + body.len() + 2);
        input.extend_from_slice(merchant_id.as_bytes());
        input.push(b':');
        input.extend_from_slice(path.as_bytes());
        input.push(b':');
        input.extend_from_slice(body.as_bytes());
        request = request.header("X-Idempotency-Key", hex_encode(&sha256(&input)));
    }

    let response = request
        .body(body.to_owned())
        .send()
        .await
        .map_err(|_| PancakeError("transport failure".to_owned()))?;
    let status = response.status().as_u16();
    let raw = response
        .bytes()
        .await
        .map_err(|_| PancakeError("read response body".to_owned()))?;
    let trimmed = trim_ascii(&raw);
    if trimmed.is_empty() {
        if status >= 400 {
            return Err(PancakeError(format!(
                "waffo pancake error (status {status})"
            )));
        }
        return Ok(Envelope {
            data: None,
            errors: Vec::new(),
        });
    }
    let wire: WireEnvelope = serde_json::from_slice(trimmed)
        .map_err(|_| PancakeError(format!("Non-JSON response from {path}")))?;
    Ok(Envelope {
        data: wire.data,
        errors: wire
            .errors
            .into_iter()
            .map(|notice| {
                if notice.message.is_empty() {
                    format!("waffo pancake error (status {status})")
                } else {
                    notice.message
                }
            })
            .collect(),
    })
}

/// 共享的签名 POST（结账会话等外呼复用）：返回信封 `data` 字段（`null`
/// 或缺失折叠为 `None`）。
pub(crate) async fn signed_post_data(
    merchant_id: &str,
    private_key: &str,
    path: &str,
    body: &str,
) -> Result<Option<Value>, PancakeError> {
    let envelope = signed_post(merchant_id, private_key, path, body, true).await?;
    if !envelope.errors.is_empty() {
        return Err(PancakeError(envelope.errors[0].clone()));
    }
    Ok(envelope.data)
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map_or(start, |position| position + 1);
    &bytes[start..end]
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Go `signing.SignRequest`（`signature.go:465-475`）：
/// `canonical = method + "\n" + path + "\n" + timestamp + "\n" + base64(sha256(body))`，
/// RSA PKCS#1v15 + SHA-256 签名后 base64。ring 的 `sign` 自行计算摘要，
/// 输入即规范串原文。
fn sign_request(
    method: &str,
    path: &str,
    timestamp: &str,
    body: &[u8],
    key: &ring::signature::RsaKeyPair,
) -> Result<String, ring::error::Unspecified> {
    let body_hash = base64::engine::general_purpose::STANDARD.encode(sha256(body));
    let canonical = format!("{method}\n{path}\n{timestamp}\n{body_hash}");
    sign_pkcs1_sha256(key, canonical.as_bytes())
}

/// Waffo SDK `utils.Sign`：对原始数据（无规范串）做 RSA PKCS#1v15 SHA-256
/// 签名后 base64。
pub(crate) fn sign_pkcs1_sha256(
    key: &ring::signature::RsaKeyPair,
    data: &[u8],
) -> Result<String, ring::error::Unspecified> {
    let mut signature = vec![0u8; key.public().modulus_len()];
    let rng = ring::rand::SystemRandom::new();
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &rng,
        data,
        &mut signature,
    )?;
    Ok(base64::engine::general_purpose::STANDARD.encode(signature))
}

/// Go `signing.NormalizePrivateKey` + `ParsePrivateKey` 的合并复刻：接受
/// PEM（PKCS#8 `PRIVATE KEY` / PKCS#1 `RSA PRIVATE KEY`）、字面 `\n`、
/// CRLF 与裸 base64（按 PKCS#8 处理），解析为 ring 密钥。
pub(crate) fn parse_private_key(raw: &str) -> Result<ring::signature::RsaKeyPair, String> {
    if raw.trim().is_empty() {
        return Err("private key is empty; provide an RSA private key in PEM format".to_owned());
    }
    let normalized = raw.replace("\\n", "\n").replace("\r\n", "\n");
    let normalized = normalized.trim();
    const PKCS8_HEADER: &str = "-----BEGIN PRIVATE KEY-----";
    const PKCS8_FOOTER: &str = "-----END PRIVATE KEY-----";
    const PKCS1_HEADER: &str = "-----BEGIN RSA PRIVATE KEY-----";
    const PKCS1_FOOTER: &str = "-----END RSA PRIVATE KEY-----";
    let has_pkcs1 = normalized.contains(PKCS1_HEADER);
    let has_pkcs8 = normalized.contains(PKCS8_HEADER);
    let base64_body: String = if has_pkcs1 || has_pkcs8 {
        let stripped = normalized
            .replace(PKCS8_HEADER, "")
            .replace(PKCS8_FOOTER, "")
            .replace(PKCS1_HEADER, "")
            .replace(PKCS1_FOOTER, "");
        let body: String = stripped
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        if body.is_empty() {
            return Err("private key contains PEM headers but no key data".to_owned());
        }
        body
    } else {
        let body: String = normalized
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        // Go `^[A-Za-z0-9+/]+=*$`。
        let valid = !body.is_empty()
            && body.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/' || byte == b'='
            });
        if !valid {
            return Err(
                "private key is not valid PEM or base64; expected an RSA private key in PEM format or raw base64"
                    .to_owned(),
            );
        }
        body
    };
    let der = base64::engine::general_purpose::STANDARD
        .decode(base64_body.as_bytes())
        .map_err(|_| "private key could not be parsed".to_owned())?;
    if has_pkcs1 {
        // PKCS#1 `RSAPrivateKey` DER（无 PKCS#8 包装）。
        ring::signature::RsaKeyPair::from_der(&der)
            .map_err(|_| "private key could not be parsed".to_owned())
    } else {
        ring::signature::RsaKeyPair::from_pkcs8(&der)
            .map_err(|_| "private key could not be parsed".to_owned())
    }
}

/// 共享 reqwest 客户端（20 秒超时）；TLS provider 安装与 turnstile/qqbot
/// 共用同一入口。
fn pancake_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::turnstile::install_crypto_provider();
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()
                .ok()
        })
        .as_ref()
}
