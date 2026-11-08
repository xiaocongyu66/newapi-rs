//! QQ 开放平台客户端与指令面板同步：
//! Go `apps/api/internal/billing/qqbot_client.go`（tokenManager / apiClient /
//! `ListPanels` / `CreatePanel` / `DeletePanel`）与
//! `apps/api/internal/billing/qqbot_service.go:773-813`（`SyncCommandPanel`）。
//!
//! ## 与 Go 的差异（均不改变 HTTP 可观察行为）
//!
//! - **不缓存 AccessToken**：Go 的 `tokenManager` 按 AppID/Secret 缓存并在
//!   到期前 60 秒刷新。本端口每次同步重新取一次 token（admin 手动点击的
//!   低频操作），响应契约一致；这里不引入进程级缓存与该缓存的生命周期管理。
//! - **错误不回显远端响应体**：Go 把 `获取 AccessToken 失败 HTTP %d: %s`
//!   这类含远端响应体的 `err.Error()` 直接回给客户端。本端口遵循本仓库的
//!   固定分类约定（见 `lib.rs::database_error_class` 的同一立场），只回固定
//!   文案，日志也只记事件名。
//! - **面板列表失败不中断**：这一点与 Go 一致——`ListPanels` 与逐条
//!   `DeletePanel` 的失败在 Go 里只 `SysError` 后继续重建（幂等策略）。

use std::{
    fmt::Write as _,
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
};

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

/// Go `qqbot_client.go:17-19` 的两个端点常量。
pub const TOKEN_URL: &str = "https://bots.qq.com/app/getAppAccessToken";
pub const API_BASE: &str = "https://api.bot.qq.com";

/// Go `SyncCommandPanel` 固定的面板场景与目标类型。
const PANEL_SCOPE_GROUP: &str = "group";
const PANEL_TARGET_TYPE_ALL: &str = "all";

/// Go `SyncCommandPanel` 的指令面板内容（`qqbot_service.go:793-806`）。
const PANEL_ITEM_NAME: &str = "签到";
const PANEL_ITEM_DESC: &str = "领取每日额度";
const PANEL_ITEM_TYPE: &str = "command";
const PANEL_REMARK: &str = "站内签到指令面板";

/// 响应体上限：面板响应是小 JSON 对象，与 `turnstile::SITEVERIFY_MAX_BODY`
/// 同一量级。
const MAX_BODY_BYTES: usize = 64 * 1024;

/// 单次调用的总超时（Go 的 apiClient 是 20 秒、tokenManager 15 秒）。
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

const JSON_CONTENT_TYPE: &str = "application/json";

/// 出站调用的失败分类，不携带任何远端文本（日志与客户端都只看类别）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QQBotApiError {
    /// 连接、IO、超时等传输层失败。
    Transport,
    /// 响应体不是 Go 解码器能接受的结构（含 `access_token` 为空的响应）。
    Decode,
    /// HTTP 状态不在 Go 接受的状态集合内。
    Rejected,
}

/// Go `PanelItem`（`qqbot_client.go:447-454`）中本切片用到的三个字段；
/// `OnlyAdmin` / `Link` 恒为零值，不入 JSON（Go 的 omitempty 同结果）。
#[derive(Clone, Debug, Serialize)]
pub struct QQPanelItem {
    pub name: String,
    pub desc: String,
    #[serde(rename = "type")]
    pub kind: String,
}

/// Go `Panel`（`qqbot_client.go:456-461`）。
#[derive(Clone, Debug, Serialize)]
pub struct QQPanel {
    pub items: Vec<QQPanelItem>,
    pub remark: String,
}

/// Go `CreatePanelRequest`（`qqbot_client.go:463-470`）。
#[derive(Clone, Debug, Serialize)]
pub struct QQCreatePanelRequest {
    pub scope: String,
    pub target_type: String,
    pub panel: QQPanel,
}

/// Go `PanelBrief`（`qqbot_client.go:472-477`）中本切片读取的两列。
/// Go 的 `json.Unmarshal` 对缺字段落在零值上，因此两列都可空。
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq)]
pub struct QQPanelBrief {
    #[serde(default)]
    pub panel_id: String,
    #[serde(default)]
    pub scope: String,
}

/// Go `tokenResponse` / `CreatePanel` 响应的解码目标：顶层 `null` 与缺字段
/// 都落在零值上（Go 的 `json.Unmarshal` 对 null 是 no-op），类型不匹配才算
/// Decode 错误。
#[derive(Default, Deserialize)]
struct AccessTokenBody {
    #[serde(default)]
    access_token: String,
}

#[derive(Default, Deserialize)]
struct PanelIdBody {
    #[serde(default)]
    panel_id: String,
}

#[derive(Default, Deserialize)]
struct PanelListBody {
    #[serde(default)]
    list: Vec<QQPanelBrief>,
}

/// Boxed future，让端口保持 dyn 兼容（与 `turnstile::Verifier` 同一手法）。
pub type QQBotFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, QQBotApiError>> + Send + 'a>>;

/// QQ 开放平台出站端口。实现不得把 AppSecret、token 或远端响应体放进错误
/// 负载与日志。
pub trait QQBotApi: Send + Sync {
    /// Go `tokenManager.Token`：换取 AppAccessToken。
    fn app_access_token<'a>(
        &'a self,
        app_id: &'a str,
        app_secret: &'a str,
    ) -> QQBotFuture<'a, String>;

    /// Go `apiClient.ListPanels`：查询指定场景的面板列表。
    fn list_panels<'a>(
        &'a self,
        token: &'a str,
        scope: &'a str,
    ) -> QQBotFuture<'a, Vec<QQPanelBrief>>;

    /// Go `apiClient.DeletePanel`：删除单个面板。
    fn delete_panel<'a>(&'a self, token: &'a str, panel_id: &'a str) -> QQBotFuture<'a, ()>;

    /// Go `apiClient.CreatePanel`：创建面板，返回 panel_id。
    fn create_panel<'a>(
        &'a self,
        token: &'a str,
        request: &'a QQCreatePanelRequest,
    ) -> QQBotFuture<'a, String>;
}

/// 测试与嵌入方用来替换真实传输的请求扩展；与 `turnstile::InjectedVerifier`
/// 同一约定。
#[derive(Clone)]
pub struct InjectedQQBotApi(pub Arc<dyn QQBotApi>);

/// 生产实现：共享 `reqwest` 客户端（连接复用，TLS provider 只装一次）。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpQQBotApi;

impl QQBotApi for HttpQQBotApi {
    fn app_access_token<'a>(
        &'a self,
        app_id: &'a str,
        app_secret: &'a str,
    ) -> QQBotFuture<'a, String> {
        Box::pin(async move {
            let client = qq_client().ok_or(QQBotApiError::Transport)?;
            // Go 用 `map[string]string` 序列化，键按字典序：appId 先于
            // clientSecret；`json!` 的字段顺序与之相同。
            let payload = serde_json::json!({
                "appId": app_id,
                "clientSecret": app_secret,
            });
            let response = client
                .post(TOKEN_URL)
                .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .json(&payload)
                .send()
                .await
                .map_err(|_| QQBotApiError::Transport)?;
            let status = response_status(&response);
            // Go：非 200 即错误；`access_token` 为空同样错误。
            if status != StatusCode::OK {
                return Err(QQBotApiError::Rejected);
            }
            let body = read_body(response).await?;
            let token = decode::<Option<AccessTokenBody>>(&body)
                .ok_or(QQBotApiError::Decode)?
                .unwrap_or_default()
                .access_token;
            (!token.is_empty())
                .then_some(token)
                .ok_or(QQBotApiError::Decode)
        })
    }

    fn list_panels<'a>(
        &'a self,
        token: &'a str,
        scope: &'a str,
    ) -> QQBotFuture<'a, Vec<QQPanelBrief>> {
        Box::pin(async move {
            let client = qq_client().ok_or(QQBotApiError::Transport)?;
            // Go：`/v2/panels?scope=` + `url.QueryEscape(scope)`。
            let url = format!("{API_BASE}/v2/panels?scope={}", query_escape(scope));
            let response = client
                .get(&url)
                .header(reqwest::header::AUTHORIZATION, &authorization(token))
                .send()
                .await
                .map_err(|_| QQBotApiError::Transport)?;
            if response_status(&response) != StatusCode::OK {
                return Err(QQBotApiError::Rejected);
            }
            let body = read_body(response).await?;
            // 顶层 null 与缺 `list` 都落在空列表上（Go 的 Unmarshal 语义）。
            Ok(decode::<Option<PanelListBody>>(&body)
                .ok_or(QQBotApiError::Decode)?
                .map(|parsed| parsed.list)
                .unwrap_or_default())
        })
    }

    fn delete_panel<'a>(&'a self, token: &'a str, panel_id: &'a str) -> QQBotFuture<'a, ()> {
        Box::pin(async move {
            let client = qq_client().ok_or(QQBotApiError::Transport)?;
            // Go：`fmt.Sprintf("/v2/panels/%s", url.PathEscape(panelID))`。
            let url = format!("{API_BASE}/v2/panels/{}", path_escape(panel_id));
            let response = client
                .delete(&url)
                .header(reqwest::header::AUTHORIZATION, &authorization(token))
                .send()
                .await
                .map_err(|_| QQBotApiError::Transport)?;
            let status = response_status(&response);
            // Go 接受 200 与 204。
            if status != StatusCode::OK && status != StatusCode::NO_CONTENT {
                return Err(QQBotApiError::Rejected);
            }
            Ok(())
        })
    }

    fn create_panel<'a>(
        &'a self,
        token: &'a str,
        request: &'a QQCreatePanelRequest,
    ) -> QQBotFuture<'a, String> {
        Box::pin(async move {
            let client = qq_client().ok_or(QQBotApiError::Transport)?;
            let response = client
                .post(format!("{API_BASE}/v2/panels"))
                .header(reqwest::header::AUTHORIZATION, &authorization(token))
                .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
                .json(request)
                .send()
                .await
                .map_err(|_| QQBotApiError::Transport)?;
            let status = response_status(&response);
            // Go 接受 200 与 201。
            if status != StatusCode::OK && status != StatusCode::CREATED {
                return Err(QQBotApiError::Rejected);
            }
            let body = read_body(response).await?;
            Ok(decode::<Option<PanelIdBody>>(&body)
                .ok_or(QQBotApiError::Decode)?
                .unwrap_or_default()
                .panel_id)
        })
    }
}

/// `SyncCommandPanel` 的失败分类（`qqbot_service.go:773-779`）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPanelError {
    /// Go `getClient()`：未配置 AppID/AppSecret。
    NotConfigured,
    /// token 获取、面板创建失败。（列表与单条删除失败不中断同步。）
    ApiUnavailable,
}

/// Go `SyncCommandPanel`：先删已有的 group 面板再重建，幂等。
pub async fn sync_command_panel(
    api: &dyn QQBotApi,
    app_id: &str,
    app_secret: &str,
) -> Result<(), SyncPanelError> {
    // Go `getClient()` 在拿 token 之前就检查配置。
    if app_id.is_empty() || app_secret.is_empty() {
        return Err(SyncPanelError::NotConfigured);
    }
    let token = api
        .app_access_token(app_id, app_secret)
        .await
        .map_err(|_| SyncPanelError::ApiUnavailable)?;
    // 列表失败只告警：Go 记 `SysError` 后继续走重建分支。
    match api.list_panels(&token, PANEL_SCOPE_GROUP).await {
        Ok(panels) => {
            for panel in panels
                .iter()
                .filter(|panel| panel.scope == PANEL_SCOPE_GROUP)
            {
                if api.delete_panel(&token, &panel.panel_id).await.is_err() {
                    tracing::warn!(
                        event = "qq_panel_delete_failed",
                        "QQ panel delete failed; the rebuild continues"
                    );
                }
            }
        }
        Err(_) => {
            tracing::warn!(
                event = "qq_panel_list_failed",
                "QQ panel list failed; the rebuild continues"
            );
        }
    }
    let panel_id = api
        .create_panel(&token, &command_panel_request())
        .await
        .map_err(|_| SyncPanelError::ApiUnavailable)?;
    tracing::info!(
        event = "qq_command_panel_synced",
        panel_id = %panel_id,
        "QQ command panel synced"
    );
    Ok(())
}

/// Go `SyncCommandPanel` 的重建请求（`qqbot_service.go:793-806`）。
fn command_panel_request() -> QQCreatePanelRequest {
    QQCreatePanelRequest {
        scope: PANEL_SCOPE_GROUP.to_owned(),
        target_type: PANEL_TARGET_TYPE_ALL.to_owned(),
        panel: QQPanel {
            items: vec![QQPanelItem {
                name: PANEL_ITEM_NAME.to_owned(),
                desc: PANEL_ITEM_DESC.to_owned(),
                kind: PANEL_ITEM_TYPE.to_owned(),
            }],
            remark: PANEL_REMARK.to_owned(),
        },
    }
}

/// Go `req.Header.Set("Authorization", "QQBot "+token)`。以 `String` 返回：
/// reqwest 的 `.header()` 走 `TryFrom<&String>`，http 1.5 没有针对
/// `HeaderValue` 本身的 identity impl。
fn authorization(token: &str) -> String {
    format!("QQBot {token}")
}

/// Go `json.Unmarshal` 的等价解码：**顶层 `null` 与缺字段落零值**，类型不
/// 匹配才是 Decode 错误。调用点一律把 `T` 写成 `Option<结构体>`：`Some(None)`
/// 即 Go 的「null 是 no-op」，配合 `unwrap_or_default()` 得到零值结构体；
/// `decode` 自己返回 `None` 才表示解码失败。
///
/// 两点与 serde_json 的默认行为必须脱钩：
/// - `from_str::<Option<T>>().flatten()` 会把顶层 null 压平成 `None`，与解码
///   失败不可区分——`CreatePanel` 收到 `null` 体时 Go 返回空字符串且无错误
///   （`SyncQQPanel` 因此成功），本端口必须复刻这一点；
/// - serde_json 的 `deserialize_struct` 对顶层 `[` 走 struct-from-seq 回退，
///   配合字段上的 `#[serde(default)]` 会把 `[]` 当缺字段填而解码成功，而 Go
///   报 `cannot unmarshal array into Go value of type struct`。先按 `Value`
///   判形状（对象或 null），再交给具体类型校验字段。
fn decode<T: for<'de> Deserialize<'de>>(body: &str) -> Option<T> {
    let value = serde_json::from_str::<serde_json::Value>(body).ok()?;
    match value {
        serde_json::Value::Null | serde_json::Value::Object(_) => {
            serde_json::from_value::<T>(value).ok()
        }
        _ => None,
    }
}

/// Go 按状态集合分流；这里只取状态，读取与分类在调用处。
fn response_status(response: &reqwest::Response) -> StatusCode {
    response.status()
}

/// 有界读取，超大响应体按传输失败拒收（与 `turnstile::read_body_bounded`
/// 同一策略，只是错误类型不同）。
async fn read_body(mut response: reqwest::Response) -> Result<String, QQBotApiError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(QQBotApiError::Transport);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| QQBotApiError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_BODY_BYTES {
            return Err(QQBotApiError::Transport);
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|_| QQBotApiError::Decode)
}

/// 进程级共享客户端；`None` 表示构造失败（与 `turnstile::siteverify_client`
/// 同一处理：该失败按 Transport 归类）。
fn qq_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::turnstile::install_crypto_provider();
            reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .ok()
        })
        .as_ref()
}

/// Go `url.QueryEscape`：未保留字符原样，空格转 `+`，其余 `%XX` 大写。
/// 与 `turnstile::form_encode_component` 同一套转义。
fn query_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    crate::turnstile::form_encode_component(&mut out, value);
    out
}

/// Go `url.PathEscape`（`encodePathSegment`）：未保留字符原样，`/` `;` `,`
/// 与非 ASCII 转 `%XX` 大写；`$ & + : = ? @` 在路径段里不转。
fn path_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'$'
            | b'&'
            | b'+'
            | b':'
            | b'='
            | b'?'
            | b'@' => {
                out.push(char::from(byte));
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// 记录调用序列的假 API；永不触网。
    struct FakeApi {
        token: Result<String, QQBotApiError>,
        panels: Result<Vec<QQPanelBrief>, QQBotApiError>,
        delete: Result<(), QQBotApiError>,
        create: Result<String, QQBotApiError>,
        calls: Mutex<Vec<String>>,
        create_body: Mutex<Option<String>>,
    }

    impl FakeApi {
        fn new(
            panels: Result<Vec<QQPanelBrief>, QQBotApiError>,
            create: Result<String, QQBotApiError>,
        ) -> Self {
            Self {
                token: Ok("fake-token".to_owned()),
                panels,
                delete: Ok(()),
                create,
                calls: Mutex::new(Vec::new()),
                create_body: Mutex::new(None),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn create_body(&self) -> Option<String> {
            self.create_body
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }
    }

    impl QQBotApi for FakeApi {
        fn app_access_token<'a>(
            &'a self,
            _app_id: &'a str,
            _app_secret: &'a str,
        ) -> QQBotFuture<'a, String> {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push("token".to_owned());
            let token = self.token.clone();
            Box::pin(async move { token })
        }

        fn list_panels<'a>(
            &'a self,
            _token: &'a str,
            scope: &'a str,
        ) -> QQBotFuture<'a, Vec<QQPanelBrief>> {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("list:{scope}"));
            let panels = self.panels.clone();
            Box::pin(async move { panels })
        }

        fn delete_panel<'a>(&'a self, _token: &'a str, panel_id: &'a str) -> QQBotFuture<'a, ()> {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(format!("delete:{panel_id}"));
            let delete = self.delete;
            Box::pin(async move { delete })
        }

        fn create_panel<'a>(
            &'a self,
            _token: &'a str,
            request: &'a QQCreatePanelRequest,
        ) -> QQBotFuture<'a, String> {
            self.calls
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push("create".to_owned());
            *self
                .create_body
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                Some(serde_json::to_string(request).expect("serialize request"));
            let create = self.create.clone();
            Box::pin(async move { create })
        }
    }

    #[tokio::test]
    async fn unconfigured_credentials_never_touch_the_api() {
        let fake = FakeApi::new(Ok(Vec::new()), Ok("panel-1".to_owned()));
        assert_eq!(
            sync_command_panel(&fake, "", "").await,
            Err(SyncPanelError::NotConfigured)
        );
        assert_eq!(
            sync_command_panel(&fake, "app-1", "").await,
            Err(SyncPanelError::NotConfigured)
        );
        assert!(fake.calls().is_empty());
    }

    #[tokio::test]
    async fn sync_deletes_group_panels_then_rebuilds() {
        let fake = FakeApi::new(
            Ok(vec![
                QQPanelBrief {
                    panel_id: "panel-group-1".to_owned(),
                    scope: "group".to_owned(),
                },
                QQPanelBrief {
                    panel_id: "panel-c2c-1".to_owned(),
                    scope: "c2c".to_owned(),
                },
                QQPanelBrief {
                    panel_id: "panel-group-2".to_owned(),
                    scope: "group".to_owned(),
                },
            ]),
            Ok("panel-new".to_owned()),
        );
        assert_eq!(sync_command_panel(&fake, "app-1", "secret-1").await, Ok(()));
        // 只删 group 场景的面板（Go `qqbot_service.go:784-790` 的过滤）。
        assert_eq!(
            fake.calls(),
            vec![
                "token".to_owned(),
                "list:group".to_owned(),
                "delete:panel-group-1".to_owned(),
                "delete:panel-group-2".to_owned(),
                "create".to_owned(),
            ]
        );
        // 重建请求与 Go 的 CreatePanelRequest 逐字一致。
        assert_eq!(
            fake.create_body().as_deref(),
            Some(
                r#"{"scope":"group","target_type":"all","panel":{"items":[{"name":"签到","desc":"领取每日额度","type":"command"}],"remark":"站内签到指令面板"}}"#
            )
        );
    }

    #[tokio::test]
    async fn list_and_delete_failures_do_not_abort_the_sync() {
        let fake = FakeApi::new(Err(QQBotApiError::Rejected), Ok("panel-new".to_owned()));
        assert_eq!(sync_command_panel(&fake, "app-1", "secret-1").await, Ok(()));
        assert_eq!(
            fake.calls(),
            vec![
                "token".to_owned(),
                "list:group".to_owned(),
                "create".to_owned()
            ]
        );
    }

    #[tokio::test]
    async fn token_and_create_failures_surface_as_api_unavailable() {
        let mut fake = FakeApi::new(Ok(Vec::new()), Ok("panel-new".to_owned()));
        fake.token = Err(QQBotApiError::Transport);
        assert_eq!(
            sync_command_panel(&fake, "app-1", "secret-1").await,
            Err(SyncPanelError::ApiUnavailable)
        );

        let mut fake = FakeApi::new(Ok(Vec::new()), Err(QQBotApiError::Decode));
        fake.delete = Err(QQBotApiError::Rejected);
        assert_eq!(
            sync_command_panel(&fake, "app-1", "secret-1").await,
            Err(SyncPanelError::ApiUnavailable)
        );
        // 删除失败仍然尝试重建（Go 只 SysError）。
        assert_eq!(
            fake.calls(),
            vec![
                "token".to_owned(),
                "list:group".to_owned(),
                "create".to_owned()
            ]
        );
    }

    #[test]
    fn endpoints_match_the_go_constants() {
        assert_eq!(TOKEN_URL, "https://bots.qq.com/app/getAppAccessToken");
        assert_eq!(API_BASE, "https://api.bot.qq.com");
    }

    #[test]
    fn query_escape_matches_go_url_query_escape() {
        assert_eq!(query_escape("group"), "group");
        assert_eq!(query_escape("a b"), "a+b");
        assert_eq!(query_escape("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(query_escape("中"), "%E4%B8%AD");
        assert_eq!(query_escape("a-_.~"), "a-_.~");
    }

    #[test]
    fn path_escape_matches_go_url_path_escape() {
        assert_eq!(path_escape("abc123"), "abc123");
        assert_eq!(path_escape("a/b"), "a%2Fb");
        assert_eq!(path_escape("a;b"), "a%3Bb");
        assert_eq!(path_escape("a,b"), "a%2Cb");
        // 路径段里这些保留字符不转（Go `shouldEscape` 的 encodePathSegment 分支）。
        assert_eq!(path_escape("a$&+:=?@b"), "a$&+:=?@b");
        assert_eq!(path_escape("a b"), "a%20b");
        assert_eq!(path_escape("中"), "%E4%B8%AD");
        assert_eq!(path_escape("a-_.~"), "a-_.~");
    }

    #[test]
    fn decode_accepts_null_and_missing_fields_like_go_json_unmarshal() {
        // 顶层 null：Go 的 Unmarshal 是 no-op，落零值。
        assert_eq!(
            decode::<Option<PanelIdBody>>("null").map(|body| body.map(|b| b.panel_id)),
            Some(None)
        );
        assert_eq!(
            decode::<Option<PanelIdBody>>("{}").map(|body| body.map(|b| b.panel_id)),
            Some(Some(String::new()))
        );
        assert_eq!(
            decode::<Option<PanelIdBody>>(r#"{"panel_id":"p1"}"#)
                .map(|body| body.map(|b| b.panel_id)),
            Some(Some("p1".to_owned()))
        );
        // 缺字段与 null 字段都落在空列表上。
        assert_eq!(
            decode::<Option<PanelListBody>>("{}")
                .flatten()
                .map(|body| body.list),
            Some(Vec::new())
        );
        // 类型不匹配是 Decode 错误。
        assert!(decode::<Option<PanelIdBody>>(r#"{"panel_id":5}"#).is_none());
        assert!(decode::<Option<PanelListBody>>("[]").is_none());
        assert!(decode::<Option<AccessTokenBody>>("not json").is_none());
        // 未知字段被跳过（Go 同样忽略）。
        assert_eq!(
            decode::<Option<AccessTokenBody>>(r#"{"access_token":"t","expires_in":"7200"}"#)
                .map(|body| body.map(|b| b.access_token)),
            Some(Some("t".to_owned()))
        );
    }
}
