//! 自定义 OAuth 提供商管理端：Go `identity.GetCustomOAuthProviders` /
//! `GetCustomOAuthProvider` / `CreateCustomOAuthProvider` /
//! `UpdateCustomOAuthProvider` / `DeleteCustomOAuthProvider` /
//! `FetchCustomOAuthDiscovery`（`apps/api/internal/identity/bind_custom_oauth.go`）。
//!
//! ## 路由链（`register_api.go:342-352`）
//!
//! 六条路由统一挂在 `apiRouter.Group("/custom-oauth-provider")` 的
//! `security.AdminAuth()` + `security.RequirePermission(policy.SystemSettings)`
//! 之下，无 `DisableCache`、无限流：
//!
//! - `GET  /`、`GET /:id`：读方法，`beginAdminAudit` 不开捕获，不落审计；
//! - `POST /`、`PUT /:id`、`DELETE /:id`：写方法，落兜底审计（见下）；
//! - `POST /discovery`：写方法，审计 action 未登记，落 `generic`。
//!
//! 本端口把 `RequirePermission` 实现为路由级中间件 `require_system_settings`，
//! 叠在 `admin_auth` 之后（Axum 的 `route_layer` 后加先执行）。401/403 由
//! `admin_auth` 产生（带 `code`）；权限不足由本中间件产生：HTTP 403 +
//! `{"success": false, "message": <auth.insufficient_privilege>}`，**无** `code`
//! 字段（Go 的 `RequirePermission` 同样只写 success/message）。
//!
//! ## 审计（`security/audit_access.go`）
//!
//! Go 的兜底审计挂在 `AdminAuth` 内部：`beginAdminAudit` 在角色检查通过后
//! 开捕获，`finishAdminAudit` 在整个链路（含 `RequirePermission` 的 403）
//! 之后写库。因此：
//! - `admin_auth` 自己的 401/403 不进审计（`beginAdminAudit` 尚未开始）；
//! - `RequirePermission` 的 403 **照样落审计**（`success=false`、`status=403`）；
//! - 三个写路由的每个 handler 结果（含全部业务失败）都落审计；
//! - `POST /discovery` 的每个 handler 结果落 `generic` 审计；
//! - 两个 GET 永不落审计。
//!
//! 本端口把兜底审计内联进 handler 与权限中间件，`success` 直接取自分支
//! 结果（等价 Go 解析响应体的 `success` 字段；这些响应恒为 HTTP 200），
//! 落库在返回前 await（Go 丢进 `gopool.Go`）——可观察结果同为一行
//! `type=3` 的日志，失败仅告警。
//!
//! ## 响应契约（逐条对齐 Go 手写 `common.H`）
//!
//! - 两个 GET 成功：`{"success": true, "message": "", "data": ...}`，列表
//!   恒为数组（Go `make(..., 0, len)` 空集合也是 `[]`）；成员为
//!   `CustomOAuthProviderResponse` 投影，**不含 `client_secret`**；
//! - 创建/更新成功：`message` 分别为 `创建成功` / `更新成功`，`data` 为投影；
//! - 删除成功：`{"success": true, "message": "删除成功"}`，**无** `data` 键；
//! - discovery 成功：`data` 为 `{"well_known_url": <实际请求的 URL>,
//!   "discovery": <上游文档>}`，文档按 Go 的 `map[string]any` 语义以
//!   null 或键升序对象返回；
//! - 失败一律 HTTP 200 + `{"success": false, "message": ...}`（除权限层的
//!   403 与鉴权层的 401/403），无 `data`、无 `code`。
//!
//! 以下文案是 Go 的硬编码字面量（不走 i18n，前端按字面量比对），逐字返回：
//! `无效的 ID`、`未找到该 OAuth 提供商`、`该 Slug 已被使用`、
//! `该 Slug 与内置 OAuth 提供商冲突`、`创建成功`、`更新成功`、`删除成功`、
//! `检查用户绑定时发生错误，请稍后重试`、
//! `该 OAuth 提供商还有用户绑定，无法删除。请先解除所有用户绑定。`、
//! `请先填写 Discovery URL 或 Issuer URL`、`Discovery URL 无效，仅支持 http/https`、
//! `获取 Discovery 配置失败`、`解析 Discovery 配置失败`，以及
//! `validateCustomOAuthProvider` 的英文校验文案（由 identity 仓储枚举携带）。
//!
//! ## 与 Go 的有意分歧
//!
//! 1. Go 的 `c.BindJSON` 失败回显 gin 的校验文本（`无效的请求参数: <err>`）；
//!    本端口沿用 `login_http` / `token_http` 的既有约定，折叠为固定 i18n 键
//!    `common.invalid_params`，不把框架错误文本透给客户端。
//! 2. Go 的 `CtxApiError(err)` 原样回显 GORM 错误（含 SQL 文本与唯一索引
//!    冲突细节）；本端口折叠为 `common.database_error`，与其它切片一致。
//! 3. discovery 的传输/解码失败分支，Go 透传 `err.Error()`
//!    （含目标 URL 与拨号细节）；本端口只回固定文案
//!    `获取 Discovery 配置失败` / `解析 Discovery 配置失败`。上游服务工作
//!    分支仍按 Go 透传目标服务的响应体（至多 512 字节）或状态行。
//! 4. Go 的 slug 冲突检查在进程内 OAuth 注册表上判“内置提供商”
//!    （`IsProviderRegistered && !IsCustomProvider`），注册表由登录流程
//!    在启动时装载，其内容等价于“四个内置 slug +
//!    DB 中的全部自定义提供商”。后者已被 `IsSlugTaken`（DB 唯一约束）
//!    覆盖，本端口因此只比对四个内置 slug（`discord` / `github` /
//!    `linuxdo` / `oidc`，`security/oauth/{discord,github,linuxdo,oidc}.go`
//!    的 `Register` 调用）。进程内注册表的同步属于登录切片。
//! 5. Go 在创建/更新/删除后调用 `oauthRegistrar` 的内存注册表
//!    （`RegisterOrUpdateCustomProvider` / `UnregisterCustomProvider`）；
//!    登录流程尚未移植，本端口的六个管理端点只落库，不同步注册表。

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::{
    Json,
    body::to_bytes,
    extract::{ConnectInfo, Extension, Path, Request, State},
    http::{HeaderMap, Method, StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use newapi_identity::{
    audit::{AuditOperator, RouteAudit, record_route_audit},
    custom_oauth::{
        CustomOAuthProviderRecord, CustomOAuthProviderView, CustomOAuthRepository, validate,
    },
    policy::{CasbinRuleRepository, SYSTEM_SETTINGS, can},
    user_auth::{CredentialKind, UserAuthIdentity},
};
use newapi_storage::Database;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::AppState;
use crate::auth::AuthenticatedUser;

/// Go `bind_custom_oauth.go:95`：`strconv.Atoi` 失败（硬编码中文）。
const MSG_INVALID_ID: &str = "无效的 ID";
/// Go `bind_custom_oauth.go:101/306/411`：提供商不存在（硬编码中文）。
const MSG_PROVIDER_NOT_FOUND: &str = "未找到该 OAuth 提供商";
/// Go `bind_custom_oauth.go:221/315`：slug 已被占用（硬编码中文）。
const MSG_SLUG_TAKEN: &str = "该 Slug 已被使用";
/// Go `bind_custom_oauth.go:227/320`：slug 与内置提供商冲突（硬编码中文）。
const MSG_SLUG_BUILTIN_CONFLICT: &str = "该 Slug 与内置 OAuth 提供商冲突";
/// Go `bind_custom_oauth.go:262`：创建成功（硬编码中文）。
const MSG_CREATED: &str = "创建成功";
/// Go `bind_custom_oauth.go:395`：更新成功（硬编码中文）。
const MSG_UPDATED: &str = "更新成功";
/// Go `bind_custom_oauth.go:439`：删除成功（硬编码中文，无 data）。
const MSG_DELETED: &str = "删除成功";
/// Go `bind_custom_oauth.go:419`：绑定计数读取失败（硬编码中文）。
const MSG_BINDING_COUNT_FAILED: &str = "检查用户绑定时发生错误，请稍后重试";
/// Go `bind_custom_oauth.go:424`：仍有用户绑定（硬编码中文）。
const MSG_DELETE_HAS_BINDINGS: &str =
    "该 OAuth 提供商还有用户绑定，无法删除。请先解除所有用户绑定。";
/// Go `bind_custom_oauth.go:151`：两个 URL 都为空（硬编码中文）。
const MSG_DISCOVERY_EMPTY: &str = "请先填写 Discovery URL 或 Issuer URL";
/// Go `bind_custom_oauth.go:163`：scheme/host 非法（硬编码中文）。
const MSG_DISCOVERY_INVALID_URL: &str = "Discovery URL 无效，仅支持 http/https";
/// Go `bind_custom_oauth.go:180/191`：上游请求/状态失败的前缀（固定文案）。
const MSG_DISCOVERY_FETCH_FAILED: &str = "获取 Discovery 配置失败";
/// Go `bind_custom_oauth.go:196`：解析失败（固定文案）。
const MSG_DISCOVERY_PARSE_FAILED: &str = "解析 Discovery 配置失败";
/// Go `c.BindJSON` 失败分支：本端口折叠为固定 i18n 键。
const MSG_INVALID_PARAMS: &str = "common.invalid_params";
/// Go `CtxApiError(err)` 的存储错误：本端口折叠为固定 i18n 键。
const MSG_DATABASE_ERROR: &str = "common.database_error";
/// Go `RequirePermission` 的 403 文案：`i18n.MsgAuthInsufficientPrivilege`。
const MSG_INSUFFICIENT_PRIVILEGE: &str = "auth.insufficient_privilege";

/// `auditRouteActions`（`audit_access.go:29-31`）登记的三条 action。
const AUDIT_CREATE: &str = "custom_oauth.create";
const AUDIT_UPDATE: &str = "custom_oauth.update";
const AUDIT_DELETE: &str = "custom_oauth.delete";
/// discovery 未登记，Go 回退为 `generic`（`op.params` 带 method/route）。
const AUDIT_GENERIC: &str = "generic";
/// Go `c.FullPath()`：注册路由模板（冒号风格与 Go 一致，落库内容不变）。
const ROUTE_ROOT: &str = "/api/custom-oauth-provider/";
const ROUTE_DISCOVERY: &str = "/api/custom-oauth-provider/discovery";
const ROUTE_ID_PREFIX: &str = "/api/custom-oauth-provider/";
const ROUTE_ID: &str = "/api/custom-oauth-provider/:id";
/// Fiber 的尾斜线宽容（StrictRouting=false）使 `/api/custom-oauth-provider`
/// 同样命中根路由，审计的 `FullPath` 仍是带尾斜线的注册模板。
const ROUTE_ROOT_NO_SLASH: &str = "/api/custom-oauth-provider";

/// Go `security/oauth` 的四个内置提供商 slug（登录切片的注册表装载等价集）。
const BUILTIN_PROVIDER_SLUGS: [&str; 4] = ["discord", "github", "linuxdo", "oidc"];

/// Go 的两处 20 秒超时（`context.WithTimeout` 与 `http.Client.Timeout`）。
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(20);
/// 200 响应体的读取上限：Go 用 `json.NewDecoder` 只读到首个完整值，
/// 这里以 1 MiB 封顶防御恶意长流，超出按传输失败处理。
const DISCOVERY_MAX_BODY: usize = 1024 * 1024;
/// 非 200 响应体的读取上限：Go 的 `io.LimitReader(resp.Body, 512)`。
const DISCOVERY_ERROR_BODY_LIMIT: usize = 512;

// ---------------------------------------------------------------------------
// 鉴权中间件
// ---------------------------------------------------------------------------

/// Go `security.RequirePermission(policy.SystemSettings)`
/// （`authenticate.go:222-237`）：`admin_auth` 之后执行，判 `policy.Can`。
///
/// 拒绝时 HTTP 403 + `{"success": false, "message": <i18n>}`，无 `code`。
/// 策略读取失败按 Go 的“空 enforcer”同一姿态 fail-closed（Go `Can` 在
/// `currentEnforcer() == nil` 时返回 false）。写方法（POST/PUT/DELETE）
/// 在返回 403 前补一条兜底审计——Go 的 `finishAdminAudit` 位于
/// `AdminAuth` 内、`RequirePermission` 之外，403 也会落库。
pub async fn require_system_settings(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(user) = request.extensions().get::<AuthenticatedUser>().cloned() else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let allowed = match can(
        &CasbinRuleRepository::new(db.clone()),
        user.0.user_id,
        // Go 的系统角色与 Rust 策略求值同为小整数域（0/1/10/100）。
        user.0.role as i32,
        SYSTEM_SETTINGS,
    )
    .await
    {
        Ok(allowed) => allowed,
        Err(error) => {
            tracing::warn!(
                event = "custom_oauth_policy_read_failed",
                category = crate::database_error_class(&error),
                "custom oauth policy lookup failed"
            );
            // Go 的空 enforcer 同样拒绝，不把 DB 故障放行成越权。
            false
        }
    };
    if allowed {
        return next.run(request).await;
    }
    // 拒绝路径：先补写方法的兜底审计，再回 403。
    let (parts, _body) = request.into_parts();
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);
    let method = parts.method.clone();
    let path = parts.uri.path().to_owned();
    let headers = parts.headers;
    let client_ip = crate::http::request_ip(&state, &headers, peer);
    let now = crate::http::now_seconds();
    if let Some(audit) = route_audit(&method, &path) {
        record_route_audit(
            &db,
            RouteAudit {
                operator: &audit_operator(&user.0),
                action: audit.action,
                method: method.as_str(),
                route: audit.route,
                path: &path,
                status: StatusCode::FORBIDDEN.as_u16(),
                success: false,
                route_params: audit.route_params,
                ip: &client_ip,
                now,
            },
        )
        .await;
    }
    api_error(&headers, MSG_INSUFFICIENT_PRIVILEGE)
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

/// Go `GetCustomOAuthProviders`（`bind_custom_oauth.go:71-88`）。
pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match CustomOAuthRepository::new(db).list().await {
        Ok(providers) => {
            let data: Vec<CustomOAuthProviderView> = providers
                .iter()
                .map(CustomOAuthProviderView::from)
                .collect();
            Json(json!({
                "success": true,
                "message": "",
                "data": data,
            }))
            .into_response()
        }
        Err(error) => database_error(&headers, &error),
    }
}

/// Go `GetCustomOAuthProvider`（`bind_custom_oauth.go:91-110`）。
///
/// 顺序即契约：先 `strconv.Atoi`（非法 → `无效的 ID`），再查库
/// （不存在 → `未找到该 OAuth 提供商`）。
pub async fn get_one(
    State(state): State<AppState>,
    Path(id_text): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    // Go `strconv.Atoi`：可选符号加十进制数字；溢出与非法字符同一分支。
    let Ok(provider_id) = id_text.parse::<i64>() else {
        return api_error_literal(MSG_INVALID_ID);
    };
    match CustomOAuthRepository::new(db).by_id(provider_id).await {
        Ok(Some(provider)) => Json(json!({
            "success": true,
            "message": "",
            "data": CustomOAuthProviderView::from(&provider),
        }))
        .into_response(),
        Ok(None) => api_error_literal(MSG_PROVIDER_NOT_FOUND),
        Err(error) => database_error(&headers, &error),
    }
}

/// Go `CreateCustomOAuthProvider`（`bind_custom_oauth.go:212-265`）。
///
/// 顺序即契约：BindJSON（required 校验）→ `IsSlugTaken`（fail-closed）
/// → 内置 slug 冲突 → `createCustomOAuthProvider`（validate + 落库）。
pub async fn create(
    State(state): State<AppState>,
    Extension(operator): Extension<AuthenticatedUser>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let audit = WriteAudit::new(&db, &state, &operator.0, parts);
    let headers = audit.headers.clone();
    let bytes = match to_bytes(body, crate::MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let outcome = create_flow(&db, &bytes).await;
    let (response, success) = respond_create(&headers, outcome);
    audit.record(success).await;
    response
}

/// Go `UpdateCustomOAuthProvider`（`bind_custom_oauth.go:290-398`）。
///
/// 顺序即契约：`Atoi(id)` → BindJSON → 查库 → slug 冲突（仅当新 slug
/// 非空且与现值不同）→ 字段合并 → validate + 整行写回。
pub async fn update(
    State(state): State<AppState>,
    Extension(operator): Extension<AuthenticatedUser>,
    Path(id_text): Path<String>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let audit = WriteAudit::new(&db, &state, &operator.0, parts);
    let headers = audit.headers.clone();
    let bytes = match to_bytes(body, crate::MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let outcome = update_flow(&db, &id_text, &bytes).await;
    let (response, success) = respond_update(&headers, outcome);
    audit.record(success).await;
    response
}

/// Go `DeleteCustomOAuthProvider`（`bind_custom_oauth.go:401-440`）。
///
/// 顺序即契约：`Atoi(id)` → 查库 → 绑定计数（失败 → 固定中文，
/// Go 另记 SysError）→ 有绑定则拒绝 → 删绑定 + 删提供商。
pub async fn delete(
    State(state): State<AppState>,
    Extension(operator): Extension<AuthenticatedUser>,
    Path(id_text): Path<String>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, _body) = request.into_parts();
    let audit = WriteAudit::new(&db, &state, &operator.0, parts);
    let headers = audit.headers.clone();
    let outcome = delete_flow(&db, &id_text).await;
    let (response, success) = respond_delete(&headers, outcome);
    audit.record(success).await;
    response
}

/// Go `FetchCustomOAuthDiscovery`（`bind_custom_oauth.go:140-209`）。
///
/// 顺序即契约：BindJSON → 两 URL 都空 → 目标推导（well_known 优先，
/// 否则 issuer 去尾斜线 + `/.well-known/openid-configuration`）
/// → scheme/host 校验（只认 http/https）→ 上游 GET → 非 200 透传上游
/// 响应体（至多 512 字节）或状态行 → 解析首个 JSON 对象。
pub async fn discovery(
    State(state): State<AppState>,
    Extension(operator): Extension<AuthenticatedUser>,
    injected: Option<Extension<InjectedDiscoveryTransport>>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let audit = WriteAudit::new(&db, &state, &operator.0, parts);
    let headers = audit.headers.clone();
    let bytes = match to_bytes(body, crate::MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };
    let http = HttpDiscoveryTransport;
    // `Extension<InjectedDiscoveryTransport>` 的两层元组：外层是 Extension，
    // 内层才是 `Arc<dyn DiscoveryTransport>`；经 `as_ref` 借引用避免拥有值的
    // 临时 Arc 在 match 结束时被释放。
    let transport: &dyn DiscoveryTransport = match injected.as_ref() {
        Some(injected) => injected.0.0.as_ref(),
        None => &http,
    };
    let outcome = discovery_flow(&bytes, transport).await;
    let (response, success) = respond_discovery(&headers, outcome);
    audit.record(success).await;
    response
}

// ---------------------------------------------------------------------------
// 兜底审计
// ---------------------------------------------------------------------------

/// 写方法兜底审计的请求上下文；由 handler 从 `Request::into_parts` 构建。
struct WriteAudit<'a> {
    db: &'a Database,
    state: &'a AppState,
    operator: &'a UserAuthIdentity,
    method: Method,
    path: String,
    headers: HeaderMap,
    peer: Option<SocketAddr>,
}

impl<'a> WriteAudit<'a> {
    fn new(
        db: &'a Database,
        state: &'a AppState,
        operator: &'a UserAuthIdentity,
        parts: Parts,
    ) -> Self {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0);
        Self {
            db,
            state,
            operator,
            method: parts.method,
            path: parts.uri.path().to_owned(),
            headers: parts.headers,
            peer,
        }
    }

    /// 与 Go 的 `finishAdminAudit` 一样不论业务成败都落库；`success`
    /// 取自分支结果（Go 解析响应体的 `success`，这些响应恒为 HTTP 200）。
    async fn record(self, success: bool) {
        let WriteAudit {
            db,
            state,
            operator,
            method,
            path,
            headers,
            peer,
        } = self;
        let Some(audit) = route_audit(&method, &path) else {
            return;
        };
        let client_ip = crate::http::request_ip(state, &headers, peer);
        record_route_audit(
            db,
            RouteAudit {
                operator: &audit_operator(operator),
                action: audit.action,
                method: method.as_str(),
                route: audit.route,
                path: &path,
                status: StatusCode::OK.as_u16(),
                success,
                route_params: audit.route_params,
                ip: &client_ip,
                now: crate::http::now_seconds(),
            },
        )
        .await;
    }
}

/// Go `c.FullPath()` + `auditRouteActions` + `c.Params()`：`(route, action,
/// route_params)`。GET 与未登记组合返回 `None`（`beginAdminAudit` 对读
/// 方法返回 nil）。
fn route_audit(method: &Method, path: &str) -> Option<RouteAuditInfo> {
    if path == ROUTE_ROOT || path == ROUTE_ROOT_NO_SLASH {
        return match method.as_ref() {
            // PUT 未注册在根路由上（Go 的 PUT 只有 /:id），不落审计。
            "POST" => Some(RouteAuditInfo {
                route: ROUTE_ROOT,
                action: AUDIT_CREATE,
                route_params: Vec::new(),
            }),
            _ => None,
        };
    }
    if path == ROUTE_DISCOVERY {
        return match method.as_ref() {
            "POST" => Some(RouteAuditInfo {
                route: ROUTE_DISCOVERY,
                action: AUDIT_GENERIC,
                route_params: Vec::new(),
            }),
            _ => None,
        };
    }
    let tail = path.strip_prefix(ROUTE_ID_PREFIX)?;
    if tail.is_empty() || tail.contains('/') {
        return None;
    }
    match method.as_ref() {
        "PUT" => Some(RouteAuditInfo {
            route: ROUTE_ID,
            action: AUDIT_UPDATE,
            route_params: vec![("id", tail.to_owned())],
        }),
        "DELETE" => Some(RouteAuditInfo {
            route: ROUTE_ID,
            action: AUDIT_DELETE,
            route_params: vec![("id", tail.to_owned())],
        }),
        _ => None,
    }
}

struct RouteAuditInfo {
    route: &'static str,
    action: &'static str,
    route_params: Vec<(&'static str, String)>,
}

/// Go `auditAuthMethod`（`audit_access.go:143-148`）：PAT → `access_token`，
/// 会话 → `session`。
fn audit_operator(user: &UserAuthIdentity) -> AuditOperator<'_> {
    AuditOperator {
        user_id: user.user_id,
        username: &user.username,
        role: user.role,
        auth_method: match user.credential {
            CredentialKind::DashboardSession => "session",
            CredentialKind::PersonalAccessToken => "access_token",
        },
    }
}

// ---------------------------------------------------------------------------
// 创建
// ---------------------------------------------------------------------------

/// 创建分支的固定分类；`Created` 携带落库后的完整行（含回填的 id）。
enum CreateOutcome {
    InvalidParams,
    SlugTaken,
    SlugBuiltinConflict,
    Validation(String),
    Database,
    Created(Box<CustomOAuthProviderRecord>),
}

/// Go `CreateCustomOAuthProviderRequest`（`bind_custom_oauth.go:113-132`）：
/// 七个 `binding:"required"` 字段在 BindJSON 阶段就必须存在且非空（gin 的
/// required 对空字符串同样失败），其余字段缺省。Rust 侧先反序列化再补
/// 这层“非空”检查，`null` / 非对象顶层与 `[]` 一样视为无效请求体。
fn parse_create_request(body: &[u8]) -> Option<CreateRequest> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value {
        Value::Null => Some(CreateRequest::default()),
        Value::Object(_) => serde_json::from_value(value).ok(),
        _ => None,
    }
}

#[derive(Debug, Default, Deserialize)]
struct CreateRequest {
    name: String,
    slug: String,
    icon: String,
    enabled: bool,
    client_id: String,
    client_secret: String,
    authorization_endpoint: String,
    token_endpoint: String,
    user_info_endpoint: String,
    scopes: String,
    user_id_field: String,
    username_field: String,
    display_name_field: String,
    email_field: String,
    well_known: String,
    auth_style: i64,
    access_policy: String,
    access_denied_message: String,
}

async fn create_flow(db: &Database, body: &[u8]) -> CreateOutcome {
    // Go `c.BindJSON(&req)`：缺字段、空字符串（required）与类型不符都失败。
    let Some(request) = parse_create_request(body) else {
        return CreateOutcome::InvalidParams;
    };
    // gin 的 `binding:"required"`：七个必填字段缺省或空串都判 invalid params
    // （对应 Go 的“无效的请求参数”分支，本端口折叠为固定 i18n 键）。
    if [
        &request.name,
        &request.slug,
        &request.client_id,
        &request.client_secret,
        &request.authorization_endpoint,
        &request.token_endpoint,
        &request.user_info_endpoint,
    ]
    .into_iter()
    .any(|field| field.is_empty())
    {
        return CreateOutcome::InvalidParams;
    }
    let repository = CustomOAuthRepository::new(db.clone());
    // Go `IsSlugTaken` 的 fail-closed：DB 错误同样算“已占用”。
    let slug_taken = match repository.slug_taken(&request.slug, 0).await {
        Ok(taken) => taken,
        Err(error) => {
            tracing::warn!(
                event = "custom_oauth_slug_lookup_failed",
                category = crate::database_error_class(&error),
                "custom oauth slug lookup failed"
            );
            true
        }
    };
    if slug_taken {
        return CreateOutcome::SlugTaken;
    }
    if BUILTIN_PROVIDER_SLUGS.contains(&request.slug.as_str()) {
        return CreateOutcome::SlugBuiltinConflict;
    }
    let mut record = CustomOAuthProviderRecord {
        id: 0,
        name: request.name,
        slug: request.slug,
        icon: request.icon,
        enabled: request.enabled,
        client_id: request.client_id,
        client_secret: request.client_secret,
        authorization_endpoint: request.authorization_endpoint,
        token_endpoint: request.token_endpoint,
        user_info_endpoint: request.user_info_endpoint,
        scopes: request.scopes,
        user_id_field: request.user_id_field,
        username_field: request.username_field,
        display_name_field: request.display_name_field,
        email_field: request.email_field,
        well_known: request.well_known,
        auth_style: request.auth_style,
        access_policy: request.access_policy,
        access_denied_message: request.access_denied_message,
    };
    if let Err(issue) = validate(&mut record) {
        return CreateOutcome::Validation(issue.message());
    }
    match repository.insert(&record).await {
        Ok(id) => {
            record.id = id;
            CreateOutcome::Created(Box::new(record))
        }
        Err(error) => {
            tracing::warn!(
                event = "custom_oauth_create_failed",
                category = crate::database_error_class(&error),
                "custom oauth provider insert failed"
            );
            CreateOutcome::Database
        }
    }
}

fn respond_create(headers: &HeaderMap, outcome: CreateOutcome) -> (Response, bool) {
    match outcome {
        CreateOutcome::Created(record) => (
            Json(json!({
                "success": true,
                "message": MSG_CREATED,
                "data": CustomOAuthProviderView::from(&record),
            }))
            .into_response(),
            true,
        ),
        CreateOutcome::InvalidParams => (api_error(headers, MSG_INVALID_PARAMS), false),
        CreateOutcome::SlugTaken => (api_error_literal(MSG_SLUG_TAKEN), false),
        CreateOutcome::SlugBuiltinConflict => (api_error_literal(MSG_SLUG_BUILTIN_CONFLICT), false),
        CreateOutcome::Validation(message) => (api_error_literal(message), false),
        CreateOutcome::Database => (api_error(headers, MSG_DATABASE_ERROR), false),
    }
}

// ---------------------------------------------------------------------------
// 更新
// ---------------------------------------------------------------------------

/// 更新分支的固定分类；`Updated` 携带合并并校验后的完整行。
enum UpdateOutcome {
    InvalidId,
    InvalidParams,
    NotFound,
    Database,
    SlugTaken,
    SlugBuiltinConflict,
    Validation(String),
    Updated(Box<CustomOAuthProviderRecord>),
}

/// Go `UpdateCustomOAuthProviderRequest`（`bind_custom_oauth.go:268-287`）：
/// 指针字段（icon/enabled/well_known/auth_style/access_policy/
/// access_denied_message）`null` 或缺省表示保留原值，显式 `""`（含
/// `false`/`0`）表示写回零值；字符串字段只在非空时覆盖（Go 的
/// `if req.X != ""`），因此 `{"name": null}` 与 `{"name": ""}` 都保留原值。
#[derive(Debug, Default, Deserialize)]
struct UpdateRequest {
    name: Option<String>,
    slug: Option<String>,
    icon: Option<String>,
    enabled: Option<bool>,
    client_id: Option<String>,
    client_secret: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    user_info_endpoint: Option<String>,
    scopes: Option<String>,
    user_id_field: Option<String>,
    username_field: Option<String>,
    display_name_field: Option<String>,
    email_field: Option<String>,
    well_known: Option<String>,
    auth_style: Option<i64>,
    access_policy: Option<String>,
    access_denied_message: Option<String>,
}

fn parse_update_request(body: &[u8]) -> Option<UpdateRequest> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value {
        Value::Null => Some(UpdateRequest::default()),
        Value::Object(_) => serde_json::from_value(value).ok(),
        _ => None,
    }
}

async fn update_flow(db: &Database, id_text: &str, body: &[u8]) -> UpdateOutcome {
    let Ok(provider_id) = id_text.parse::<i64>() else {
        return UpdateOutcome::InvalidId;
    };
    let Some(request) = parse_update_request(body) else {
        return UpdateOutcome::InvalidParams;
    };
    let repository = CustomOAuthRepository::new(db.clone());
    let Some(mut record) = repository.by_id(provider_id).await.unwrap_or_else(|error| {
        tracing::warn!(
            event = "custom_oauth_lookup_failed",
            category = crate::database_error_class(&error),
            "custom oauth provider lookup failed"
        );
        None
    }) else {
        return UpdateOutcome::NotFound;
    };
    // 新 slug 非空且与现值不同时才查冲突（Go 的 `req.Slug != "" &&
    // req.Slug != provider.Slug`）。
    if let Some(slug) = request
        .slug
        .as_deref()
        .filter(|slug| !slug.is_empty() && *slug != record.slug)
    {
        let slug_taken = match repository.slug_taken(slug, provider_id).await {
            Ok(taken) => taken,
            Err(error) => {
                tracing::warn!(
                    event = "custom_oauth_slug_lookup_failed",
                    category = crate::database_error_class(&error),
                    "custom oauth slug lookup failed"
                );
                true
            }
        };
        if slug_taken {
            return UpdateOutcome::SlugTaken;
        }
        if BUILTIN_PROVIDER_SLUGS.contains(&slug) {
            return UpdateOutcome::SlugBuiltinConflict;
        }
    }
    merge_update(&mut record, &request);
    if let Err(issue) = validate(&mut record) {
        return UpdateOutcome::Validation(issue.message());
    }
    match repository.update(&record).await {
        Ok(_) => UpdateOutcome::Updated(Box::new(record)),
        Err(error) => {
            tracing::warn!(
                event = "custom_oauth_update_failed",
                category = crate::database_error_class(&error),
                "custom oauth provider update failed"
            );
            UpdateOutcome::Database
        }
    }
}

/// Go `bind_custom_oauth.go:327-380` 的字段合并：字符串字段非空才覆盖，
/// 指针字段有值即写回（显式空串也清空原值）。
fn merge_update(record: &mut CustomOAuthProviderRecord, request: &UpdateRequest) {
    if let Some(name) = request.name.as_deref().filter(|name| !name.is_empty()) {
        record.name = name.to_owned();
    }
    if let Some(slug) = request.slug.as_deref().filter(|slug| !slug.is_empty()) {
        record.slug = slug.to_owned();
    }
    if let Some(icon) = request.icon.as_deref() {
        record.icon = icon.to_owned();
    }
    if let Some(enabled) = request.enabled {
        record.enabled = enabled;
    }
    if let Some(client_id) = request
        .client_id
        .as_deref()
        .filter(|client_id| !client_id.is_empty())
    {
        record.client_id = client_id.to_owned();
    }
    if let Some(client_secret) = request
        .client_secret
        .as_deref()
        .filter(|client_secret| !client_secret.is_empty())
    {
        record.client_secret = client_secret.to_owned();
    }
    if let Some(endpoint) = request
        .authorization_endpoint
        .as_deref()
        .filter(|endpoint| !endpoint.is_empty())
    {
        record.authorization_endpoint = endpoint.to_owned();
    }
    if let Some(endpoint) = request
        .token_endpoint
        .as_deref()
        .filter(|endpoint| !endpoint.is_empty())
    {
        record.token_endpoint = endpoint.to_owned();
    }
    if let Some(endpoint) = request
        .user_info_endpoint
        .as_deref()
        .filter(|endpoint| !endpoint.is_empty())
    {
        record.user_info_endpoint = endpoint.to_owned();
    }
    if let Some(scopes) = request
        .scopes
        .as_deref()
        .filter(|scopes| !scopes.is_empty())
    {
        record.scopes = scopes.to_owned();
    }
    if let Some(field) = request
        .user_id_field
        .as_deref()
        .filter(|field| !field.is_empty())
    {
        record.user_id_field = field.to_owned();
    }
    if let Some(field) = request
        .username_field
        .as_deref()
        .filter(|field| !field.is_empty())
    {
        record.username_field = field.to_owned();
    }
    if let Some(field) = request
        .display_name_field
        .as_deref()
        .filter(|field| !field.is_empty())
    {
        record.display_name_field = field.to_owned();
    }
    if let Some(field) = request
        .email_field
        .as_deref()
        .filter(|field| !field.is_empty())
    {
        record.email_field = field.to_owned();
    }
    if let Some(well_known) = request.well_known.as_deref() {
        record.well_known = well_known.to_owned();
    }
    if let Some(auth_style) = request.auth_style {
        record.auth_style = auth_style;
    }
    if let Some(access_policy) = request.access_policy.as_deref() {
        record.access_policy = access_policy.to_owned();
    }
    if let Some(access_denied_message) = request.access_denied_message.as_deref() {
        record.access_denied_message = access_denied_message.to_owned();
    }
}

fn respond_update(headers: &HeaderMap, outcome: UpdateOutcome) -> (Response, bool) {
    match outcome {
        UpdateOutcome::Updated(record) => (
            Json(json!({
                "success": true,
                "message": MSG_UPDATED,
                "data": CustomOAuthProviderView::from(&record),
            }))
            .into_response(),
            true,
        ),
        UpdateOutcome::InvalidId => (api_error_literal(MSG_INVALID_ID), false),
        UpdateOutcome::InvalidParams => (api_error(headers, MSG_INVALID_PARAMS), false),
        UpdateOutcome::NotFound => (api_error_literal(MSG_PROVIDER_NOT_FOUND), false),
        UpdateOutcome::Database => (api_error(headers, MSG_DATABASE_ERROR), false),
        UpdateOutcome::SlugTaken => (api_error_literal(MSG_SLUG_TAKEN), false),
        UpdateOutcome::SlugBuiltinConflict => (api_error_literal(MSG_SLUG_BUILTIN_CONFLICT), false),
        UpdateOutcome::Validation(message) => (api_error_literal(message), false),
    }
}

// ---------------------------------------------------------------------------
// 删除
// ---------------------------------------------------------------------------

/// 删除分支的固定分类。
enum DeleteOutcome {
    InvalidId,
    NotFound,
    BindingCountFailed,
    HasBindings,
    Database,
    Deleted,
}

async fn delete_flow(db: &Database, id_text: &str) -> DeleteOutcome {
    let Ok(provider_id) = id_text.parse::<i64>() else {
        return DeleteOutcome::InvalidId;
    };
    let repository = CustomOAuthRepository::new(db.clone());
    // 先取提供商记录：Go 用它的 slug 反注册内存表，本端口用其存在性分支。
    if repository
        .by_id(provider_id)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(
                event = "custom_oauth_lookup_failed",
                category = crate::database_error_class(&error),
                "custom oauth provider lookup failed"
            );
            None
        })
        .is_none()
    {
        return DeleteOutcome::NotFound;
    }
    match repository.binding_count(provider_id).await {
        Ok(count) if count > 0 => return DeleteOutcome::HasBindings,
        Ok(_) => {}
        Err(error) => {
            // Go `common.SysError` + 固定文案：不转述 SQL 文本。
            tracing::warn!(
                event = "custom_oauth_binding_count_failed",
                category = crate::database_error_class(&error),
                provider_id,
                "custom oauth binding count failed"
            );
            return DeleteOutcome::BindingCountFailed;
        }
    }
    match repository.delete(provider_id).await {
        Ok(_) => DeleteOutcome::Deleted,
        Err(error) => {
            tracing::warn!(
                event = "custom_oauth_delete_failed",
                category = crate::database_error_class(&error),
                "custom oauth provider delete failed"
            );
            DeleteOutcome::Database
        }
    }
}

fn respond_delete(headers: &HeaderMap, outcome: DeleteOutcome) -> (Response, bool) {
    match outcome {
        DeleteOutcome::Deleted => (
            Json(json!({
                "success": true,
                "message": MSG_DELETED,
            }))
            .into_response(),
            true,
        ),
        DeleteOutcome::InvalidId => (api_error_literal(MSG_INVALID_ID), false),
        DeleteOutcome::NotFound => (api_error_literal(MSG_PROVIDER_NOT_FOUND), false),
        DeleteOutcome::BindingCountFailed => (api_error_literal(MSG_BINDING_COUNT_FAILED), false),
        DeleteOutcome::HasBindings => (api_error_literal(MSG_DELETE_HAS_BINDINGS), false),
        DeleteOutcome::Database => (api_error(headers, MSG_DATABASE_ERROR), false),
    }
}

// ---------------------------------------------------------------------------
// discovery
// ---------------------------------------------------------------------------

/// discovery 分支的固定分类；`Parsed` 携带推导出的目标 URL 与解析后的文档。
enum DiscoveryOutcome {
    InvalidParams,
    Empty,
    InvalidUrl,
    FetchFailed,
    /// 上游非 200：Go 透传上游响应体（至多 512 字节）或状态行。
    UpstreamError(String),
    ParseFailed,
    Parsed(String, Value),
}

/// Go `FetchCustomOAuthDiscoveryRequest`（`bind_custom_oauth.go:134-137`）：
/// 两个字段都无 required；`null` 与缺省同为空串。
#[derive(Debug, Default, Deserialize)]
struct DiscoveryRequest {
    well_known_url: Option<String>,
    issuer_url: Option<String>,
}

fn parse_discovery_request(body: &[u8]) -> Option<DiscoveryRequest> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match value {
        Value::Null => Some(DiscoveryRequest::default()),
        Value::Object(_) => serde_json::from_value(value).ok(),
        _ => None,
    }
}

async fn discovery_flow(body: &[u8], transport: &dyn DiscoveryTransport) -> DiscoveryOutcome {
    let Some(request) = parse_discovery_request(body) else {
        return DiscoveryOutcome::InvalidParams;
    };
    let well_known = request.well_known_url.as_deref().unwrap_or("").trim();
    let issuer = request.issuer_url.as_deref().unwrap_or("").trim();
    if well_known.is_empty() && issuer.is_empty() {
        return DiscoveryOutcome::Empty;
    }
    // well_known 优先；否则 issuer 去尾斜线补 discovery 后缀。
    let target = if well_known.is_empty() {
        format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        )
    } else {
        well_known.to_owned()
    };
    if !is_http_url(&target) {
        return DiscoveryOutcome::InvalidUrl;
    }
    let response = match transport.fetch(&target).await {
        Ok(response) => response,
        Err(DiscoveryError::Transport) => return DiscoveryOutcome::FetchFailed,
    };
    if response.status != StatusCode::OK.as_u16() {
        // Go：读至多 512 字节并 TrimSpace；为空则用 `resp.Status`（如 "404 Not Found"）。
        let message = String::from_utf8_lossy(&response.body).trim().to_owned();
        let message = if message.is_empty() {
            status_line(response.status)
        } else {
            message
        };
        return DiscoveryOutcome::UpstreamError(message);
    }
    match parse_discovery_document(&response.body) {
        Some(document) => DiscoveryOutcome::Parsed(target, document),
        None => DiscoveryOutcome::ParseFailed,
    }
}

/// Go `url.Parse` 后校验 `Host` 非空且 `Scheme` 为 http/https（scheme 被
/// `url.Parse` 小写化，因此 `HTTP://` 同样放行）。scheme 缺失（无 `://`）
/// 与空 host（如 `http:///path`）都拒绝。
fn is_http_url(target: &str) -> bool {
    let Some((scheme, rest)) = target.split_once("://") else {
        return false;
    };
    if scheme.is_empty() {
        return false;
    }
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    // authority 段到首个 / ? # 为止。
    rest.split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| !authority.is_empty())
}

/// Go 的 `json.NewDecoder(...).Decode(&discovery)`：只读首个完整 JSON 值，
/// 忽略尾随内容；目标必须是 JSON 对象（map[string]any），`null` 解码成
/// nil map（响应里的 `discovery` 即 JSON `null`）。其他类型与语法错误都失败。
fn parse_discovery_document(body: &[u8]) -> Option<Value> {
    let value = serde_json::Deserializer::from_slice(body)
        .into_iter::<Value>()
        .next()?
        .ok()?;
    match value {
        Value::Object(_) => Some(value),
        Value::Null => Some(Value::Null),
        _ => None,
    }
}

fn respond_discovery(headers: &HeaderMap, outcome: DiscoveryOutcome) -> (Response, bool) {
    match outcome {
        DiscoveryOutcome::Parsed(target, document) => (
            Json(json!({
                "success": true,
                "message": "",
                "data": {
                    "well_known_url": target,
                    "discovery": document,
                }
            }))
            .into_response(),
            true,
        ),
        DiscoveryOutcome::InvalidParams => (api_error(headers, MSG_INVALID_PARAMS), false),
        DiscoveryOutcome::Empty => (api_error_literal(MSG_DISCOVERY_EMPTY), false),
        DiscoveryOutcome::InvalidUrl => (api_error_literal(MSG_DISCOVERY_INVALID_URL), false),
        DiscoveryOutcome::FetchFailed => (api_error_literal(MSG_DISCOVERY_FETCH_FAILED), false),
        DiscoveryOutcome::UpstreamError(message) => (
            api_error_literal(format!("{MSG_DISCOVERY_FETCH_FAILED}: {message}")),
            false,
        ),
        DiscoveryOutcome::ParseFailed => (api_error_literal(MSG_DISCOVERY_PARSE_FAILED), false),
    }
}

// ---------------------------------------------------------------------------
// 响应助手
// ---------------------------------------------------------------------------

/// Go 的硬编码字面量分支：逐字返回，不经 i18n（前端按字面量比对）。
fn api_error_literal(message: impl Into<String>) -> Response {
    Json(json!({
        "success": false,
        "message": message.into(),
    }))
    .into_response()
}

/// Go `CtxApiErrorI18n` 风格的分类替代：按请求语言解析固定键。
fn api_error(headers: &HeaderMap, key: &str) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, key),
    }))
    .into_response()
}

fn database_error(headers: &HeaderMap, error: &sqlx::Error) -> Response {
    tracing::warn!(
        event = "custom_oauth_database_operation_failed",
        category = crate::database_error_class(error),
        "custom oauth provider database operation failed"
    );
    api_error(headers, MSG_DATABASE_ERROR)
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    let language = crate::request_lang::request_language(accept_language.as_deref());
    newapi_i18n::translate(&language, key, std::iter::empty::<(&str, &str)>())
}

/// Go `resp.Status`：`"<code> <reason>"`。
fn status_line(status: u16) -> String {
    StatusCode::from_u16(status)
        .ok()
        .and_then(|status| {
            status
                .canonical_reason()
                .map(|reason| format!("{status} {reason}"))
        })
        .unwrap_or_else(|| status.to_string())
}

// ---------------------------------------------------------------------------
// discovery 传输
// ---------------------------------------------------------------------------

/// 上游响应的最小投影：状态码与响应体（非 200 已截断到 512 字节）。
pub struct DiscoveryResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    /// DNS、连接、TLS、HTTP 或响应体读取失败（含超长 200 响应体）。
    Transport,
}

pub type DiscoveryFuture<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<DiscoveryResponse, DiscoveryError>> + Send + 'a>,
>;

/// discovery 的出站端口；实现不得把 URL 或响应文本塞进错误载荷。
pub trait DiscoveryTransport: Send + Sync {
    fn fetch<'a>(&'a self, url: &'a str) -> DiscoveryFuture<'a>;
}

/// 请求扩展缝：测试与嵌入方用来替换真实传输（与
/// `turnstile::InjectedVerifier` 同一手法）。
#[derive(Clone)]
pub struct InjectedDiscoveryTransport(pub Arc<dyn DiscoveryTransport>);

/// 生产实现：共享 reqwest 客户端，20 秒超时，`Accept: application/json`。
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpDiscoveryTransport;

impl DiscoveryTransport for HttpDiscoveryTransport {
    fn fetch<'a>(&'a self, url: &'a str) -> DiscoveryFuture<'a> {
        Box::pin(async move {
            let client = discovery_client().ok_or(DiscoveryError::Transport)?;
            let response = client
                .get(url)
                .header(reqwest::header::ACCEPT, "application/json")
                .send()
                .await
                .map_err(|_| DiscoveryError::Transport)?;
            let status = response.status().as_u16();
            if status != StatusCode::OK.as_u16() {
                let body = read_capped(response, DISCOVERY_ERROR_BODY_LIMIT, false).await?;
                return Ok(DiscoveryResponse { status, body });
            }
            let body = read_capped(response, DISCOVERY_MAX_BODY, true).await?;
            Ok(DiscoveryResponse { status, body })
        })
    }
}

async fn read_capped(
    mut response: reqwest::Response,
    cap: usize,
    overflow_is_error: bool,
) -> Result<Vec<u8>, DiscoveryError> {
    if overflow_is_error
        && response
            .content_length()
            .is_some_and(|length| length > cap as u64)
    {
        return Err(DiscoveryError::Transport);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| DiscoveryError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > cap {
            if overflow_is_error {
                return Err(DiscoveryError::Transport);
            }
            // 非 200 的错误体按 Go 的 LimitReader 语义只保留前 cap 字节。
            body.truncate(cap);
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// 进程级客户端：连接与 TLS 提供者最多初始化一次（复用 turnstile 的
/// aws_lc_rs 安装入口，避免第二个 `install_default`）。
fn discovery_client() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            crate::turnstile::install_crypto_provider();
            reqwest::Client::builder()
                .timeout(DISCOVERY_TIMEOUT)
                .build()
                .ok()
        })
        .as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_slugs_match_go_oauth_register_calls() {
        assert_eq!(
            BUILTIN_PROVIDER_SLUGS,
            ["discord", "github", "linuxdo", "oidc"]
        );
    }

    #[test]
    fn http_url_validation() {
        for url in [
            "http://example.com/.well-known/openid-configuration",
            "https://example.com",
            "HTTP://example.com",
            "https://user:pass@example.com:8443/oidc?x=1#frag",
        ] {
            assert!(is_http_url(url), "{url}");
        }
        for url in [
            "example.com/.well-known/openid-configuration", // 无 scheme
            "ftp://example.com",
            "http:///path", // 空 host
            "https://",     // 空 host
            "/.well-known/openid-configuration",
            "https:///oidc?x=1",
        ] {
            assert!(!is_http_url(url), "{url}");
        }
    }

    #[test]
    fn discovery_document_parses_first_json_object() {
        assert_eq!(
            parse_discovery_document(br#"{"a":1,"b":[1,2]} trailing"#).unwrap(),
            json!({"a": 1, "b": [1, 2]})
        );
        // Go 的 `null` → nil map，响应里 discovery 为 null。
        assert_eq!(parse_discovery_document(b"null").unwrap(), Value::Null);
        assert_eq!(parse_discovery_document(b"   {}  ").unwrap(), json!({}));
    }

    #[test]
    fn discovery_document_rejects_non_object_roots() {
        for body in [
            &b"[]"[..],
            &b"[1,2]"[..],
            b"\"str\"",
            b"123",
            b"true",
            b"not json",
            b"",
            b"{\"a\":1",
        ] {
            assert!(parse_discovery_document(body).is_none(), "{body:?}");
        }
    }

    #[test]
    fn status_line_matches_go_resp_status() {
        assert_eq!(status_line(404), "404 Not Found");
        assert_eq!(status_line(500), "500 Internal Server Error");
        assert_eq!(status_line(503), "503 Service Unavailable");
    }

    #[test]
    fn route_audit_only_covers_registered_write_routes() {
        // 根路由 POST（含 Fiber 尾斜线宽容形态）。
        assert_eq!(
            route_audit(&Method::POST, "/api/custom-oauth-provider/")
                .unwrap()
                .action,
            AUDIT_CREATE
        );
        assert_eq!(
            route_audit(&Method::POST, "/api/custom-oauth-provider")
                .unwrap()
                .action,
            AUDIT_CREATE
        );
        // discovery 未登记 action → generic。
        let discovery = route_audit(&Method::POST, "/api/custom-oauth-provider/discovery").unwrap();
        assert_eq!(discovery.action, AUDIT_GENERIC);
        assert_eq!(discovery.route, "/api/custom-oauth-provider/discovery");
        // :id 路由的两个写方法带 params。
        let update = route_audit(&Method::PUT, "/api/custom-oauth-provider/7").unwrap();
        assert_eq!(update.action, AUDIT_UPDATE);
        assert_eq!(update.route, ROUTE_ID);
        assert_eq!(update.route_params, vec![("id", "7".to_owned())]);
        let delete = route_audit(&Method::DELETE, "/api/custom-oauth-provider/7").unwrap();
        assert_eq!(delete.action, AUDIT_DELETE);
        assert_eq!(delete.route_params, vec![("id", "7".to_owned())]);
        // GET 与未登记组合不落审计（Go 的 beginAdminAudit 对读方法返回 nil）。
        assert!(route_audit(&Method::GET, "/api/custom-oauth-provider/").is_none());
        assert!(route_audit(&Method::GET, "/api/custom-oauth-provider/7").is_none());
        assert!(route_audit(&Method::PUT, "/api/custom-oauth-provider/").is_none());
        assert!(route_audit(&Method::POST, "/api/custom-oauth-provider/7").is_none());
        assert!(route_audit(&Method::PUT, "/api/custom-oauth-provider/7/").is_none());
        assert!(route_audit(&Method::DELETE, "/api/other/1").is_none());
    }
}
