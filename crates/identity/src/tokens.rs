//! JWT 编码与用途隔离；时间由调用方注入，禁止读取隐式系统时钟。
use base64::{Engine, alphabet, engine::general_purpose};
use hmac::Mac;
use newapi_storage::Database;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::crypto::{AuthKeys, HmacSha256, equal, mac, random_uuid};
use crate::self_user::{QuotaDisplayKind, QuotaDisplaySettings};
use crate::{AuthError, AuthIdentity, CredentialKind, SecretString};

pub const ACCESS_TTL: i64 = 900;
pub const PROOF_TTL: i64 = 300;
pub const LEEWAY: i64 = 5;
const ISSUER: &str = "new-api";
const AUDIENCE: &str = "new-api-dashboard";
// Go RawURLEncoding 默认允许未使用位非零，不允许 padding。
const URL_SAFE_NO_PAD: general_purpose::GeneralPurpose = general_purpose::GeneralPurpose::new(
    &alphabet::URL_SAFE,
    general_purpose::NO_PAD.with_decode_allow_trailing_bits(true),
);

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn matches(&self) -> bool {
        match self {
            Self::One(value) => value == AUDIENCE,
            Self::Many(values) => values.iter().any(|value| value == AUDIENCE),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Claims {
    token_use: String,
    sid: String,
    uv: i64,
    sv: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    method: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    scopes: Vec<String>,
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
    nbf: i64,
    iat: i64,
    jti: String,
}

impl Claims {
    fn identity(&self) -> Result<AuthIdentity, AuthError> {
        let identity = AuthIdentity {
            user_id: self.sub.parse().map_err(|_| AuthError::Invalid)?,
            sid: self.sid.clone(),
            user_auth_version: self.uv,
            session_version: self.sv,
        };
        identity.validate()?;
        Ok(identity)
    }
}

/// token 原文不实现 Debug/Serialize，由 HTTP 层显式投影公开 access 字段。
pub struct IssuedToken {
    pub token: SecretString,
    pub expires_at: i64,
}

/// internal 分支内的失败必须终止认证，不得降级到 PAT/API key。
pub enum DashboardAccess {
    Opaque,
    Internal(Result<AuthIdentity, AuthError>),
}

impl AuthKeys {
    pub fn issue_access(
        &self,
        identity: &AuthIdentity,
        now: i64,
    ) -> Result<IssuedToken, AuthError> {
        self.issue_access_with_jti(identity, now, &random_uuid()?)
    }

    /// 固定 jti 仅用于差分测试；生产入口使用 CSPRNG UUIDv4。
    pub fn issue_access_with_jti(
        &self,
        identity: &AuthIdentity,
        now: i64,
        jti: &str,
    ) -> Result<IssuedToken, AuthError> {
        self.issue(identity, now, jti, None)
    }

    pub fn issue_security_proof(
        &self,
        identity: &AuthIdentity,
        method: &str,
        scopes: &[String],
        now: i64,
    ) -> Result<IssuedToken, AuthError> {
        self.issue_security_proof_with_jti(identity, method, scopes, now, &random_uuid()?)
    }

    pub fn issue_security_proof_with_jti(
        &self,
        identity: &AuthIdentity,
        method: &str,
        scopes: &[String],
        now: i64,
        jti: &str,
    ) -> Result<IssuedToken, AuthError> {
        self.issue(identity, now, jti, Some((method, scopes)))
    }

    fn issue(
        &self,
        identity: &AuthIdentity,
        now: i64,
        jti: &str,
        proof: Option<(&str, &[String])>,
    ) -> Result<IssuedToken, AuthError> {
        identity.validate()?;
        if jti.is_empty() {
            return Err(AuthError::Invalid);
        }
        let (purpose, key, ttl, method, scopes) = match proof {
            None => ("access", &self.access, ACCESS_TTL, "", &[][..]),
            Some((method, scopes)) if !method.trim().is_empty() && !scopes.is_empty() => (
                "security_proof",
                &self.proof,
                PROOF_TTL,
                method.trim(),
                scopes,
            ),
            Some(_) => return Err(AuthError::Invalid),
        };
        let expires_at = now.checked_add(ttl).ok_or(AuthError::Invalid)?;
        let claims = Claims {
            token_use: purpose.to_owned(),
            sid: identity.sid.clone(),
            uv: identity.user_auth_version,
            sv: identity.session_version,
            method: method.to_owned(),
            scopes: scopes.to_vec(),
            iss: ISSUER.to_owned(),
            sub: identity.user_id.to_string(),
            aud: Audience::Many(vec![AUDIENCE.to_owned()]),
            exp: expires_at,
            nbf: now.checked_sub(5).ok_or(AuthError::Invalid)?,
            iat: now,
            jti: jti.to_owned(),
        };
        // 与 Go encoding/json 默认 HTML 及行分隔符转义保持字节一致。
        let payload = serde_json::to_string(&claims)
            .map_err(|_| AuthError::Internal)?
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload),
        );
        let signature = URL_SAFE_NO_PAD.encode(mac(key, input.as_bytes()));
        Ok(IssuedToken {
            token: SecretString::new(format!("{input}.{signature}")),
            expires_at,
        })
    }

    pub fn parse_access(&self, raw: &str, now: i64) -> Result<AuthIdentity, AuthError> {
        self.parse(raw, "access", &self.access, now)?.identity()
    }

    pub fn parse_dashboard_access(&self, raw: &str, now: i64) -> DashboardAccess {
        match classify_dashboard(raw) {
            CredentialKind::Opaque => DashboardAccess::Opaque,
            CredentialKind::InternalDashboard => {
                DashboardAccess::Internal(self.parse_access(raw, now))
            }
        }
    }

    pub fn verify_security_proof(
        &self,
        raw: &str,
        identity: &AuthIdentity,
        required_scope: &str,
        allowed_methods: &[String],
        now: i64,
    ) -> Result<String, AuthError> {
        identity.validate()?;
        let claims = self.parse(raw, "security_proof", &self.proof, now)?;
        let actual = claims.identity()?;
        let bound = equal(
            &actual.user_id.to_be_bytes(),
            &identity.user_id.to_be_bytes(),
        ) & equal(actual.sid.as_bytes(), identity.sid.as_bytes())
            & equal(
                &actual.user_auth_version.to_be_bytes(),
                &identity.user_auth_version.to_be_bytes(),
            )
            & equal(
                &actual.session_version.to_be_bytes(),
                &identity.session_version.to_be_bytes(),
            );
        if !bound || claims.method.is_empty() || claims.scopes.is_empty() {
            return Err(AuthError::Invalid);
        }
        let method_allowed = allowed_methods
            .iter()
            .fold(allowed_methods.is_empty(), |found, method| {
                found | equal(method.as_bytes(), claims.method.as_bytes())
            });
        if !method_allowed {
            return Err(AuthError::ProofMethod);
        }
        let scope_allowed = claims
            .scopes
            .iter()
            .fold(required_scope.is_empty(), |found, scope| {
                found | equal(scope.as_bytes(), required_scope.as_bytes())
            });
        if !scope_allowed {
            return Err(AuthError::ProofScope);
        }
        Ok(claims.method)
    }

    fn parse(&self, raw: &str, purpose: &str, key: &[u8], now: i64) -> Result<Claims, AuthError> {
        let (header, payload, signature, input) = segments(raw.trim()).ok_or(AuthError::Invalid)?;
        let header: serde_json::Value = decode_json(header)?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("HS256") {
            return Err(AuthError::Invalid);
        }
        let signature = decode_segment(signature)?;
        let mut verifier = HmacSha256::new_from_slice(key).map_err(|_| AuthError::Internal)?;
        verifier.update(input.as_bytes());
        verifier
            .verify_slice(&signature)
            .map_err(|_| AuthError::Invalid)?;
        // 必需字段缺失、null、类型不匹配或重复字段由强类型反序列化拒绝。
        let claims: Claims = decode_json(payload)?;
        if now as i128 >= claims.exp as i128 + LEEWAY as i128 {
            return Err(AuthError::Expired);
        }
        if claims.iss != ISSUER
            || !claims.aud.matches()
            || claims.token_use != purpose
            || claims.jti.is_empty()
            || claims.iat as i128 > now as i128 + LEEWAY as i128
            || claims.nbf as i128 > now as i128 + LEEWAY as i128
        {
            return Err(AuthError::Invalid);
        }
        claims.identity()?;
        Ok(claims)
    }
}

/// 分类不是认证；一旦识别内部标记，即使其他 claim 畸形也不降级。
pub fn classify_dashboard(raw: &str) -> CredentialKind {
    let Some((_, payload, _, _)) = segments(raw.trim()) else {
        return CredentialKind::Opaque;
    };
    let Ok(value) = decode_json::<serde_json::Value>(payload) else {
        return CredentialKind::Opaque;
    };
    let audience = value.get("aud");
    let matches_audience = audience.and_then(|v| v.as_str()) == Some(AUDIENCE)
        || audience
            .and_then(|v| v.as_array())
            .is_some_and(|values| values.iter().any(|v| v.as_str() == Some(AUDIENCE)));
    if value.get("iss").and_then(|v| v.as_str()) == Some(ISSUER)
        && matches_audience
        && matches!(
            value.get("token_use").and_then(|v| v.as_str()),
            Some("access" | "security_proof")
        )
    {
        CredentialKind::InternalDashboard
    } else {
        CredentialKind::Opaque
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(encoded: &str) -> Result<T, AuthError> {
    let bytes = decode_segment(encoded)?;
    serde_json::from_slice(&bytes).map_err(|_| AuthError::Invalid)
}

fn decode_segment(encoded: &str) -> Result<Vec<u8>, AuthError> {
    // Go base64 忽略 CR/LF；验签输入仍保留原文，不能替换已签名字节。
    let bytes: Vec<u8> = encoded
        .bytes()
        .filter(|b| !matches!(b, b'\r' | b'\n'))
        .collect();
    URL_SAFE_NO_PAD
        .decode(bytes)
        .map_err(|_| AuthError::Invalid)
}

fn segments(raw: &str) -> Option<(&str, &str, &str, &str)> {
    let (input, signature) = raw.rsplit_once('.')?;
    let (header, payload) = input.split_once('.')?;
    if payload.contains('.') {
        return None;
    }
    Some((header, payload, signature, input))
}

// ---------------------------------------------------------------------------
// Token records (Go `apps/api/internal/identity/token_store.go`).
//
// The dashboard token endpoints operate on the `tokens` table only. This
// repository keeps the Go column semantics (soft delete, `-1` never expires,
// integer quota) and scopes every read/write by `user_id` so a caller cannot
// reach another user's rows. The raw key is a credential: it is only ever
// returned by the explicit `/:id/key` handler and is redacted from `Debug`.
// ---------------------------------------------------------------------------

pub const TOKEN_STATUS_ENABLED: i64 = 1;
pub const TOKEN_STATUS_DISABLED: i64 = 2;
pub const TOKEN_STATUS_EXPIRED: i64 = 3;
pub const TOKEN_STATUS_EXHAUSTED: i64 = 4;

pub const TOKEN_KEY_LEN: usize = 48;
pub const DEFAULT_MAX_USER_TOKENS: i64 = 1000;
pub const DEFAULT_MAX_TOKEN_AUTO_GROUPS: i64 = 5;

// Go `keyChars`; `GenerateKey` draws 48 unbiased characters from this set.
const KEY_CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Go quota columns are 32-bit; `saturateQuota` clamps to this range.
const MAX_QUOTA: i64 = i32::MAX as i64;
const MIN_QUOTA: i64 = i32::MIN as i64;

/// Go `Token`, minus `DeletedAt`. Display-only fields (`*_display`) and the
/// parsed `auto_groups` list are assembled at the HTTP boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct TokenRecord {
    pub id: i64,
    pub user_id: i64,
    pub key: String,
    pub status: i64,
    pub name: String,
    pub created_time: i64,
    pub accessed_time: i64,
    pub expired_time: i64,
    pub remain_quota: i64,
    pub used_quota: i64,
    pub unlimited_quota: bool,
    pub model_limits_enabled: bool,
    pub model_limits: String,
    pub allow_ips: Option<String>,
    pub group: String,
    pub cross_group_retry: bool,
    /// Raw JSON array text; empty means "inherit the global Auto list".
    pub auto_groups: String,
}

impl TokenRecord {
    pub fn masked_key(&self) -> String {
        mask_token_key(&self.key)
    }
}

// The raw key is a credential; never let `{:?}` emit it.
impl std::fmt::Debug for TokenRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRecord")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("key", &"<redacted>")
            .field("status", &self.status)
            .field("name", &self.name)
            .field("expired_time", &self.expired_time)
            .field("remain_quota", &self.remain_quota)
            .field("unlimited_quota", &self.unlimited_quota)
            .field("group", &self.group)
            .field("cross_group_retry", &self.cross_group_retry)
            .finish_non_exhaustive()
    }
}

/// Fields Go `Token.Insert` persists for a freshly generated token.
pub struct NewToken {
    pub user_id: i64,
    pub key: String,
    pub name: String,
    pub created_time: i64,
    pub accessed_time: i64,
    pub expired_time: i64,
    pub remain_quota: i64,
    pub unlimited_quota: bool,
    pub model_limits_enabled: bool,
    pub model_limits: String,
    pub allow_ips: Option<String>,
    pub group: String,
    pub cross_group_retry: bool,
    pub auto_groups: String,
}

/// Fields Go `Token.Update` writes. `status` is intentionally absent: a full
/// update keeps the stored status, while `?status_only` changes only that
/// column (see [`TokenRepository::update_status_for_user`]).
pub struct TokenUpdate {
    pub name: String,
    pub expired_time: i64,
    pub remain_quota: i64,
    pub unlimited_quota: bool,
    pub model_limits_enabled: bool,
    pub model_limits: String,
    pub allow_ips: Option<String>,
    pub group: String,
    pub cross_group_retry: bool,
    pub auto_groups: String,
}

/// Inputs for `SearchUserTokens`; wildcard sanitization happens before this.
pub struct TokenSearch<'a> {
    pub keyword: &'a str,
    pub key: &'a str,
    pub offset: i64,
    pub limit: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRuntimeSettings {
    /// Go `AutoGroups`, in configuration order.
    pub auto_groups: Vec<String>,
    /// Go `MaxTokenAutoGroups`; always positive.
    pub max_token_auto_groups: i64,
    /// Go `token_setting.max_user_tokens`.
    pub max_user_tokens: i64,
}

impl Default for TokenRuntimeSettings {
    fn default() -> Self {
        Self {
            // Go seeds `AutoGroups` with `["default"]` and the limit with 5.
            auto_groups: vec!["default".to_owned()],
            max_token_auto_groups: DEFAULT_MAX_TOKEN_AUTO_GROUPS,
            max_user_tokens: DEFAULT_MAX_USER_TOKENS,
        }
    }
}

const RUNTIME_OPTION_KEYS: [&str; 3] = [
    "AutoGroups",
    "MaxTokenAutoGroups",
    "token_setting.max_user_tokens",
];

/// Go `MaskTokenKey`: byte-based prefix/suffix reveal, never the middle.
pub fn mask_token_key(key: &str) -> String {
    match key.len() {
        0 => String::new(),
        len @ 1..=4 => "*".repeat(len),
        len @ 5..=8 => format!(
            "{}{}{}",
            byte_slice(key, 0, 2),
            "****",
            byte_slice(key, len - 2, len)
        ),
        len => format!(
            "{}{}{}",
            byte_slice(key, 0, 4),
            "**********",
            byte_slice(key, len - 4, len)
        ),
    }
}

// Go slices by byte offset even for invalid UTF-8; keep that shape while
// returning a valid Rust string for JSON encoding (invalid bytes become U+FFFD).
fn byte_slice(value: &str, start: usize, end: usize) -> String {
    String::from_utf8_lossy(&value.as_bytes()[start..end]).into_owned()
}

/// Go `common.GenerateKey`: 48 characters from `keyChars`, uniformly drawn
/// with rejection sampling (equivalent to `crypto/rand.Int`).
pub fn generate_token_key() -> Option<String> {
    let mut rng = rand::rngs::OsRng;
    let alphabet_len = KEY_CHARS.len() as u32;
    let zone = u32::MAX - (u32::MAX % alphabet_len);
    let mut key = String::with_capacity(TOKEN_KEY_LEN);
    for _ in 0..TOKEN_KEY_LEN {
        loop {
            let value = rng.next_u32();
            if value < zone {
                key.push(KEY_CHARS[(value % alphabet_len) as usize] as char);
                break;
            }
        }
    }
    Some(key)
}

/// Go `saturateQuota`: truncate toward zero inside `[i32::MIN, i32::MAX]`,
/// with NaN mapping to 0.
fn saturate_quota(value: f64) -> i64 {
    if value.is_nan() {
        0
    } else if value >= MAX_QUOTA as f64 {
        MAX_QUOTA
    } else if value <= MIN_QUOTA as f64 {
        MIN_QUOTA
    } else {
        value.trunc() as i64
    }
}

/// Go `common.QuotaFromFloat`.
pub fn quota_from_float(value: f64) -> i64 {
    saturate_quota(value)
}

/// Go `common.QuotaRound` (half away from zero, then saturate).
pub fn quota_round(value: f64) -> i64 {
    saturate_quota(value.round())
}

/// Go `billing.QuotaFromDisplayAmount`, the inverse of
/// [`QuotaDisplaySettings::to_display`]. Non-finite input maps to 0.
pub fn quota_from_display(display_amount: f64, settings: QuotaDisplaySettings) -> i64 {
    if !display_amount.is_finite() {
        return 0;
    }
    match settings.kind {
        QuotaDisplayKind::Usd => quota_round(display_amount * settings.quota_per_unit),
        QuotaDisplayKind::Cny { usd_exchange_rate } => {
            quota_round(display_amount / usd_exchange_rate * settings.quota_per_unit)
        }
        QuotaDisplayKind::Custom { rate } => {
            let rate = if rate <= 0.0 { 1.0 } else { rate };
            quota_round(display_amount / rate * settings.quota_per_unit)
        }
        QuotaDisplayKind::Tokens => quota_round(display_amount),
    }
}

/// Go `AddToken` upper quota bound: `QuotaFromFloat(1e9 * QuotaPerUnit)`.
pub fn max_quota_value(quota_per_unit: f64) -> i64 {
    quota_from_float(1_000_000_000.0 * quota_per_unit)
}

/// Go `Token.GetAutoGroups`: empty text inherits; malformed JSON is treated
/// as an empty list by the HTTP layer (Go logs and returns nil).
pub fn parse_auto_groups(value: &str) -> Option<Vec<String>> {
    if value.is_empty() {
        return None;
    }
    serde_json::from_str(value).ok()
}

/// Go `Token.SetAutoGroups`: an empty list is stored as empty text.
pub fn serialize_auto_groups(groups: &[String]) -> String {
    if groups.is_empty() {
        String::new()
    } else {
        serde_json::to_string(groups).unwrap_or_default()
    }
}

/// Go `dbx.SanitizeLikePattern` plus `ValidateLikePattern`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LikePatternError {
    ConsecutiveWildcards,
    TooManyWildcards,
    KeywordTooShort,
}

impl LikePatternError {
    pub fn message_key(self) -> &'static str {
        match self {
            Self::ConsecutiveWildcards => "token.search_consecutive_wildcard",
            Self::TooManyWildcards => "token.search_wildcard_limit",
            Self::KeywordTooShort => "token.search_keyword_too_short",
        }
    }
}

/// Escape SQL LIKE metacharacters (`!` and `_`), keeping `%` as a wildcard.
/// Validation mirrors Go exactly (byte length for the minimum keyword size).
pub fn sanitize_like_pattern(input: &str) -> Result<String, LikePatternError> {
    let escaped = input.replace('!', "!!").replace('_', "!_");
    if escaped.contains("%%") {
        return Err(LikePatternError::ConsecutiveWildcards);
    }
    let wildcard_count = escaped.matches('%').count();
    if wildcard_count > 2 {
        return Err(LikePatternError::TooManyWildcards);
    }
    if wildcard_count > 0 {
        let stripped = escaped.replace('%', "");
        if stripped.len() < 2 {
            return Err(LikePatternError::KeywordTooShort);
        }
    }
    Ok(escaped)
}

macro_rules! token_select {
    ($suffix:literal) => {
        concat!(
            "SELECT CAST(id AS BIGINT) AS id, CAST(user_id AS BIGINT) AS user_id, ",
            "\"key\", CAST(status AS BIGINT) AS status, name, ",
            "CAST(created_time AS BIGINT) AS created_time, ",
            "CAST(accessed_time AS BIGINT) AS accessed_time, ",
            "CAST(expired_time AS BIGINT) AS expired_time, ",
            "CAST(remain_quota AS BIGINT) AS remain_quota, ",
            "CAST(used_quota AS BIGINT) AS used_quota, unlimited_quota, ",
            "model_limits_enabled, model_limits, allow_ips, \"group\", ",
            "cross_group_retry, auto_groups",
            $suffix
        )
    };
}

const LIST_SQL: &str = token_select!(
    " FROM tokens WHERE user_id=$1 AND deleted_at IS NULL \
     ORDER BY id DESC LIMIT $2 OFFSET $3"
);

const COUNT_SQL: &str = "SELECT COUNT(*) FROM tokens WHERE user_id=$1 AND deleted_at IS NULL";

const BY_ID_SQL: &str =
    token_select!(" FROM tokens WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL");

const BY_KEY_SQL: &str = token_select!(" FROM tokens WHERE \"key\"=$1 AND deleted_at IS NULL");

const INSERT_SQL: &str = concat!(
    "INSERT INTO tokens (user_id, \"key\", status, name, created_time, ",
    "accessed_time, expired_time, remain_quota, used_quota, unlimited_quota, ",
    "model_limits_enabled, model_limits, allow_ips, \"group\", ",
    "cross_group_retry, auto_groups) VALUES ",
    "($1,$2,1,$3,$4,$5,$6,$7,0,$8,$9,$10,$11,$12,$13,$14) RETURNING CAST(id AS BIGINT)"
);

const UPDATE_SQL: &str = concat!(
    "UPDATE tokens SET name=$1, expired_time=$2, remain_quota=$3, ",
    "unlimited_quota=$4, model_limits_enabled=$5, model_limits=$6, ",
    "allow_ips=$7, \"group\"=$8, cross_group_retry=$9, auto_groups=$10 ",
    "WHERE id=$11 AND user_id=$12 AND deleted_at IS NULL"
);

const UPDATE_STATUS_SQL: &str =
    "UPDATE tokens SET status=$1 WHERE id=$2 AND user_id=$3 AND deleted_at IS NULL";

const DELETE_SQL: &str = concat!(
    "UPDATE tokens SET deleted_at=CURRENT_TIMESTAMP ",
    "WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL"
);

const SEARCH_SQL: &str = token_select!(
    " FROM tokens WHERE user_id=$1 AND deleted_at IS NULL \
     AND ($2 = '' OR name LIKE $2 ESCAPE '!') \
     AND ($3 = '' OR \"key\" LIKE $3 ESCAPE '!') \
     ORDER BY id DESC LIMIT $4 OFFSET $5"
);

// Go `SearchUserTokens` calls `baseQuery.Limit(maxTokens).Count(&total)`, but
// GORM's `Count` keeps that LIMIT beside the aggregate row and aggregate rows
// ignore LIMIT, so Go's total is in fact uncapped; this matches that behavior.
const SEARCH_COUNT_SQL: &str = concat!(
    "SELECT COUNT(*) FROM tokens ",
    "WHERE user_id=$1 AND deleted_at IS NULL",
    " AND ($2 = '' OR name LIKE $2 ESCAPE '!')",
    " AND ($3 = '' OR \"key\" LIKE $3 ESCAPE '!')"
);

const USER_GROUP_SQL: &str = "SELECT \"group\" FROM users WHERE id=$1 AND deleted_at IS NULL";

macro_rules! decode_token {
    ($row:expr) => {{
        let row = $row;
        TokenRecord {
            id: row.try_get::<Option<i64>, _>("id")?.unwrap_or_default(),
            user_id: row
                .try_get::<Option<i64>, _>("user_id")?
                .unwrap_or_default(),
            key: row.try_get::<Option<String>, _>("key")?.unwrap_or_default(),
            status: row.try_get::<Option<i64>, _>("status")?.unwrap_or_default(),
            name: row
                .try_get::<Option<String>, _>("name")?
                .unwrap_or_default(),
            created_time: row
                .try_get::<Option<i64>, _>("created_time")?
                .unwrap_or_default(),
            accessed_time: row
                .try_get::<Option<i64>, _>("accessed_time")?
                .unwrap_or_default(),
            expired_time: row
                .try_get::<Option<i64>, _>("expired_time")?
                .unwrap_or_default(),
            remain_quota: row
                .try_get::<Option<i64>, _>("remain_quota")?
                .unwrap_or_default(),
            used_quota: row
                .try_get::<Option<i64>, _>("used_quota")?
                .unwrap_or_default(),
            unlimited_quota: row
                .try_get::<Option<bool>, _>("unlimited_quota")?
                .unwrap_or_default(),
            model_limits_enabled: row
                .try_get::<Option<bool>, _>("model_limits_enabled")?
                .unwrap_or_default(),
            model_limits: row
                .try_get::<Option<String>, _>("model_limits")?
                .unwrap_or_default(),
            allow_ips: row.try_get::<Option<String>, _>("allow_ips")?,
            group: row
                .try_get::<Option<String>, _>("group")?
                .unwrap_or_default(),
            cross_group_retry: row
                .try_get::<Option<bool>, _>("cross_group_retry")?
                .unwrap_or_default(),
            auto_groups: row
                .try_get::<Option<String>, _>("auto_groups")?
                .unwrap_or_default(),
        }
    }};
}

#[derive(Clone)]
pub struct TokenRepository {
    db: Database,
}

impl TokenRepository {
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Borrow the underlying pool for option/group snapshots that live with
    /// the token settings but outside the token table.
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Go `GetAllUserTokens`: newest first, scoped to the owner.
    pub async fn list_for_user(
        &self,
        user_id: i64,
        offset: i64,
        limit: i64,
    ) -> Result<Vec<TokenRecord>, sqlx::Error> {
        let tokens = match &self.db {
            Database::Sqlite(pool) => {
                let mut tokens = Vec::new();
                for row in sqlx::query(LIST_SQL)
                    .bind(user_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
                {
                    tokens.push(decode_token!(row));
                }
                tokens
            }
            Database::Postgres(pool) => {
                let mut tokens = Vec::new();
                for row in sqlx::query(LIST_SQL)
                    .bind(user_id)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
                {
                    tokens.push(decode_token!(row));
                }
                tokens
            }
        };
        Ok(tokens)
    }

    /// Go `CountUserTokens`.
    pub async fn count_for_user(&self, user_id: i64) -> Result<i64, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(COUNT_SQL)
                    .bind(user_id)
                    .fetch_one(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(COUNT_SQL)
                    .bind(user_id)
                    .fetch_one(pool)
                    .await
            }
        }
    }

    /// Go `GetTokenByIds`; another user's id yields `None`, never a row.
    pub async fn by_id_for_user(
        &self,
        user_id: i64,
        id: i64,
    ) -> Result<Option<TokenRecord>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                match sqlx::query(BY_ID_SQL)
                    .bind(id)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
                {
                    Some(row) => Ok(Some(decode_token!(row))),
                    None => Ok(None),
                }
            }
            Database::Postgres(pool) => {
                match sqlx::query(BY_ID_SQL)
                    .bind(id)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
                {
                    Some(row) => Ok(Some(decode_token!(row))),
                    None => Ok(None),
                }
            }
        }
    }

    /// Go `GetTokenByKey`; used by credential validation. Soft-deleted rows
    /// are invisible, exactly like GORM's default scope.
    pub async fn by_key(&self, key: &str) -> Result<Option<TokenRecord>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                match sqlx::query(BY_KEY_SQL)
                    .bind(key)
                    .fetch_optional(pool)
                    .await?
                {
                    Some(row) => Ok(Some(decode_token!(row))),
                    None => Ok(None),
                }
            }
            Database::Postgres(pool) => {
                match sqlx::query(BY_KEY_SQL)
                    .bind(key)
                    .fetch_optional(pool)
                    .await?
                {
                    Some(row) => Ok(Some(decode_token!(row))),
                    None => Ok(None),
                }
            }
        }
    }

    /// Go `Token.Insert`; returns the generated id.
    pub async fn insert(&self, token: &NewToken) -> Result<i64, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(INSERT_SQL)
                    .bind(token.user_id)
                    .bind(&token.key)
                    .bind(&token.name)
                    .bind(token.created_time)
                    .bind(token.accessed_time)
                    .bind(token.expired_time)
                    .bind(token.remain_quota)
                    .bind(token.unlimited_quota)
                    .bind(token.model_limits_enabled)
                    .bind(&token.model_limits)
                    .bind(token.allow_ips.as_deref().unwrap_or(""))
                    .bind(&token.group)
                    .bind(token.cross_group_retry)
                    .bind(&token.auto_groups)
                    .fetch_one(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(INSERT_SQL)
                    .bind(token.user_id)
                    .bind(&token.key)
                    .bind(&token.name)
                    .bind(token.created_time)
                    .bind(token.accessed_time)
                    .bind(token.expired_time)
                    .bind(token.remain_quota)
                    .bind(token.unlimited_quota)
                    .bind(token.model_limits_enabled)
                    .bind(&token.model_limits)
                    .bind(token.allow_ips.as_deref().unwrap_or(""))
                    .bind(&token.group)
                    .bind(token.cross_group_retry)
                    .bind(&token.auto_groups)
                    .fetch_one(pool)
                    .await
            }
        }
    }

    /// Go `Token.Update` (full form); the stored status is left untouched.
    pub async fn update_for_user(
        &self,
        user_id: i64,
        id: i64,
        update: &TokenUpdate,
    ) -> Result<bool, sqlx::Error> {
        let affected = match &self.db {
            Database::Sqlite(pool) => sqlx::query(UPDATE_SQL)
                .bind(&update.name)
                .bind(update.expired_time)
                .bind(update.remain_quota)
                .bind(update.unlimited_quota)
                .bind(update.model_limits_enabled)
                .bind(&update.model_limits)
                .bind(update.allow_ips.as_deref())
                .bind(&update.group)
                .bind(update.cross_group_retry)
                .bind(&update.auto_groups)
                .bind(id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(UPDATE_SQL)
                .bind(&update.name)
                .bind(update.expired_time)
                .bind(update.remain_quota)
                .bind(update.unlimited_quota)
                .bind(update.model_limits_enabled)
                .bind(&update.model_limits)
                .bind(update.allow_ips.as_deref())
                .bind(&update.group)
                .bind(update.cross_group_retry)
                .bind(&update.auto_groups)
                .bind(id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    /// Go `?status_only` branch: only the status column changes.
    pub async fn update_status_for_user(
        &self,
        user_id: i64,
        id: i64,
        status: i64,
    ) -> Result<bool, sqlx::Error> {
        let affected = match &self.db {
            Database::Sqlite(pool) => sqlx::query(UPDATE_STATUS_SQL)
                .bind(status)
                .bind(id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(UPDATE_STATUS_SQL)
                .bind(status)
                .bind(id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    /// Go `DeleteTokenById`: soft delete, scoped to the owner.
    pub async fn delete_for_user(&self, user_id: i64, id: i64) -> Result<bool, sqlx::Error> {
        let affected = match &self.db {
            Database::Sqlite(pool) => sqlx::query(DELETE_SQL)
                .bind(id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Database::Postgres(pool) => sqlx::query(DELETE_SQL)
                .bind(id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok(affected > 0)
    }

    /// Go `SearchUserTokens`; `keyword`/`key` are already sanitized and empty
    /// strings disable that filter.
    pub async fn search_for_user(
        &self,
        user_id: i64,
        search: &TokenSearch<'_>,
    ) -> Result<(Vec<TokenRecord>, i64), sqlx::Error> {
        let tokens = match &self.db {
            Database::Sqlite(pool) => {
                let mut tokens = Vec::new();
                for row in sqlx::query(SEARCH_SQL)
                    .bind(user_id)
                    .bind(search.keyword)
                    .bind(search.key)
                    .bind(search.limit)
                    .bind(search.offset)
                    .fetch_all(pool)
                    .await?
                {
                    tokens.push(decode_token!(row));
                }
                tokens
            }
            Database::Postgres(pool) => {
                let mut tokens = Vec::new();
                for row in sqlx::query(SEARCH_SQL)
                    .bind(user_id)
                    .bind(search.keyword)
                    .bind(search.key)
                    .bind(search.limit)
                    .bind(search.offset)
                    .fetch_all(pool)
                    .await?
                {
                    tokens.push(decode_token!(row));
                }
                tokens
            }
        };
        let total = match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(SEARCH_COUNT_SQL)
                    .bind(user_id)
                    .bind(search.keyword)
                    .bind(search.key)
                    .fetch_one(pool)
                    .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(SEARCH_COUNT_SQL)
                    .bind(user_id)
                    .bind(search.keyword)
                    .bind(search.key)
                    .fetch_one(pool)
                    .await?
            }
        };
        Ok((tokens, total))
    }

    /// Go `GetUserGroup(id, false)` fallback used by `getTokenRequestUserGroup`.
    pub async fn user_group(&self, user_id: i64) -> Result<Option<String>, sqlx::Error> {
        match &self.db {
            Database::Sqlite(pool) => {
                sqlx::query_scalar(USER_GROUP_SQL)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
            }
            Database::Postgres(pool) => {
                sqlx::query_scalar(USER_GROUP_SQL)
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await
            }
        }
    }
}

impl TokenRuntimeSettings {
    /// Read the three Go option keys that govern token limits. Missing rows
    /// keep the Go seed defaults; an unparseable persisted value also keeps
    /// the default (Go refuses invalid updates and retains its previous value).
    pub async fn load(db: &Database) -> Result<Self, sqlx::Error> {
        let rows: Vec<(String, Option<String>)> = match db {
            Database::Sqlite(pool) => {
                sqlx::query_as(
                    "SELECT \"key\", \"value\" FROM options \
                     WHERE \"key\" IN ($1, $2, $3)",
                )
                .bind(RUNTIME_OPTION_KEYS[0])
                .bind(RUNTIME_OPTION_KEYS[1])
                .bind(RUNTIME_OPTION_KEYS[2])
                .fetch_all(pool)
                .await?
            }
            Database::Postgres(pool) => {
                sqlx::query_as(
                    "SELECT \"key\", \"value\" FROM options \
                     WHERE \"key\" IN ($1, $2, $3)",
                )
                .bind(RUNTIME_OPTION_KEYS[0])
                .bind(RUNTIME_OPTION_KEYS[1])
                .bind(RUNTIME_OPTION_KEYS[2])
                .fetch_all(pool)
                .await?
            }
        };
        let mut settings = Self::default();
        for (key, value) in rows {
            let Some(value) = value else { continue };
            match key.as_str() {
                "AutoGroups" => {
                    if let Ok(groups) = serde_json::from_str::<Vec<String>>(&value) {
                        settings.auto_groups = groups;
                    }
                }
                "MaxTokenAutoGroups" => {
                    if let Some(limit) = value.parse::<i64>().ok().filter(|limit| *limit > 0) {
                        settings.max_token_auto_groups = limit;
                    }
                }
                "token_setting.max_user_tokens" => {
                    if let Some(limit) = value.parse::<i64>().ok().filter(|limit| *limit > 0) {
                        settings.max_user_tokens = limit;
                    }
                }
                _ => {}
            }
        }
        Ok(settings)
    }
}

#[cfg(test)]
mod token_repository_tests {
    use super::*;

    #[test]
    fn mask_matches_go_byte_rules() {
        assert_eq!(mask_token_key(""), "");
        assert_eq!(mask_token_key("ab"), "**");
        assert_eq!(mask_token_key("abcd"), "****");
        assert_eq!(mask_token_key("abcde"), "ab****de");
        assert_eq!(mask_token_key("abcdefgh"), "ab****gh");
        assert_eq!(mask_token_key("abcdefghi"), "abcd**********fghi");
        assert_eq!(mask_token_key("abcd1234efgh5678"), "abcd**********5678");
    }

    #[test]
    fn generated_keys_use_the_go_alphabet_and_length() {
        let key = generate_token_key().expect("OS randomness");
        assert_eq!(key.len(), TOKEN_KEY_LEN);
        assert!(key.bytes().all(|byte| KEY_CHARS.contains(&byte)));
    }

    #[test]
    fn quota_helpers_clamp_to_int32() {
        assert_eq!(quota_from_float(1.9), 1);
        assert_eq!(quota_from_float(-1.9), -1);
        assert_eq!(quota_from_float(1e30), MAX_QUOTA);
        assert_eq!(quota_from_float(-1e30), MIN_QUOTA);
        assert_eq!(quota_round(1.5), 2);
        assert_eq!(quota_round(-1.5), -2);
        let display = QuotaDisplaySettings {
            quota_per_unit: 500_000.0,
            kind: QuotaDisplayKind::Usd,
        };
        assert_eq!(quota_from_display(1.0, display), 500_000);
        assert_eq!(quota_from_display(f64::NAN, display), 0);
        assert_eq!(
            max_quota_value(500_000.0),
            MAX_QUOTA,
            "1e9 * QuotaPerUnit saturates to the int32 bound"
        );
    }

    #[test]
    fn like_pattern_validation_matches_go() {
        assert_eq!(sanitize_like_pattern("abc"), Ok("abc".to_owned()));
        assert_eq!(sanitize_like_pattern("a_b"), Ok("a!_b".to_owned()));
        assert_eq!(sanitize_like_pattern("a!b"), Ok("a!!b".to_owned()));
        assert_eq!(sanitize_like_pattern("a%b"), Ok("a%b".to_owned()));
        assert_eq!(
            sanitize_like_pattern("%%"),
            Err(LikePatternError::ConsecutiveWildcards)
        );
        assert_eq!(
            sanitize_like_pattern("a%b%c%d"),
            Err(LikePatternError::TooManyWildcards)
        );
        assert_eq!(
            sanitize_like_pattern("%a"),
            Err(LikePatternError::KeywordTooShort)
        );
    }
}
