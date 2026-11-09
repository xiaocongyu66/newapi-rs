//! Passkey/WebAuthn 切片：Go `identity/passkey_*.go` 的移植。
//!
//! 范围对应 Go 的九条路由：
//! - 用户自管理：`GET/DELETE /api/user/passkey`
//! - 注册：`POST /api/user/passkey/register/{begin,finish}`
//! - 匿名可发现登录：`POST /api/user/passkey/login/{begin,finish}`
//! - 登录后二次验证（Go 的 verify 流）：`POST /api/user/passkey/verify/{begin,finish}`
//! - 管理员重置：`DELETE /api/user/:id/reset_passkey`
//!
//! 三个流共享同一套状态语义（对齐 Go `passkey_session.go`）：仪式状态序列化
//! 为 JSON 存入 `auth_flows.payload`，TTL 固定 5 分钟，`finish` 时按
//! `AuthFlowRepository::consume` 的条件更新单次消费。RP（rp_id/origin）按
//! Go `passkey_webauthn.go` 从 PasskeySettings 与请求传输事实（Host、TLS）
//! 推导，转发头不参与（Go `passkey_webauthn_test.go` 是该边界的契约表）。
//!
//! 已知与 Go 的差异（webauthn-rs safe wrapper 的策略固化，非本切片可配置）：
//! - 注册 begin 的 `authenticatorSelection` 为 `{residentKey:"discouraged",
//!   userVerification:"required"}`，Go 为 `{residentKey:"required",
//!   requireResidentKey:true, userVerification:"<settings,默认 preferred>",
//!   authenticatorAttachment:"<settings>"}`；webauthn-rs 另会附加
//!   credProtect/uvm/credProps 扩展。
//! - 断言（login/verify finish）按 UV `required` 校验，Go 按 settings（默认
//!   `preferred`）校验。
//!
//! 其余字段保持一致：rp/rpId/challenge/timeout(120s)/exclude 或 allow
//! credentials 的结构与 base64url 编码均与 Go 相同。
//!
//! 另一个已知边界差异：`WebauthnBuilder` 要求首个 origin 的域名等于 `rp_id`
//! 或以其为父域（IP 字面量 origin 恒拒），Go 的 `BuildWebAuthn` 不做该校验；
//! 命中时按 `RpError::Configuration` 回固定文案。

pub mod ceremony;
pub mod cose;
pub mod credential;
pub mod flow;
pub mod rp;
pub mod settings;

pub use ceremony::{Ceremony, CeremonyError, CeremonyUser, RegisteredCredential};
pub use credential::{
    ASSERTION_STATE_COLUMNS_POSTGRES, ASSERTION_STATE_COLUMNS_SQLITE, AssertionOutcome,
    PasskeyCredential, PasskeyCredentialRepository, PasskeyStoreError, StoredCredential,
};
pub use flow::{SessionFlowError, create_session_data_flow, pop_session_data_flow};
pub use rp::{RpError, TransportFacts, build_ceremony};
pub use settings::{
    DEFAULT_RP_DISPLAY_NAME, DEFAULT_SERVER_ADDRESS, PasskeySettings, PasskeySettingsRepository,
    SettingsError,
};
/// 仪式状态类型（webauthn-rs prelude 再导出；`danger-allow-state-serialisation`
/// 开启后这些类型实现 Serialize/Deserialize，供 flow payload 序列化）。
pub use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

/// Go `passkeyFlowTTL`：仪式流程固定 5 分钟。
pub const FLOW_TTL_SECONDS: i64 = 300;

/// Go `AuthFlowPurposePasskeyLogin`。
pub const PURPOSE_PASSKEY_LOGIN: &str = "passkey_login";
/// Go `AuthFlowPurposePasskeyRegister`。
pub const PURPOSE_PASSKEY_REGISTER: &str = "passkey_register";
/// Go `AuthFlowPurposePasskeyStepUp`。
pub const PURPOSE_PASSKEY_STEP_UP: &str = "passkey_step_up";

/// Go `SecurityProofScopePasskeyRegister`。
pub const SCOPE_PASSKEY_REGISTER: &str = "passkey.register";
/// Go `SecurityProofScopePasskeyDelete`。
pub const SCOPE_PASSKEY_DELETE: &str = "passkey.delete";
/// Go `SecurityProofScopeChannelKeyRead`。
pub const SCOPE_CHANNEL_KEY_READ: &str = "channel.key.read";

/// 安全验证方式，对齐 Go `respond_errors.go` 的固定字面量。
pub const METHOD_TWO_FA: &str = "2fa";
pub const METHOD_PASSKEY: &str = "passkey";

/// Go `isAllowedSecurityProofScope`：仅这三项合法。
pub fn is_allowed_proof_scope(scope: &str) -> bool {
    matches!(
        scope,
        SCOPE_CHANNEL_KEY_READ | SCOPE_PASSKEY_REGISTER | SCOPE_PASSKEY_DELETE
    )
}

/// 从 SQLite/PostgreSQL 共享 DDL 派生的 fixture 表定义，供集成测试与未来
/// 的迁移器复用；列名、可空性与 Go GORM 模型（schema-inventory 的
/// passkey_credentials 行）逐项一致。
pub const PASSKEY_CREDENTIALS_SQLITE_DDL: &str = "CREATE TABLE passkey_credentials (\
    id INTEGER PRIMARY KEY AUTOINCREMENT,\
    user_id INTEGER NOT NULL UNIQUE,\
    credential_id VARCHAR(512) NOT NULL UNIQUE,\
    public_key TEXT NOT NULL,\
    attestation_type VARCHAR(255),\
    aaguid VARCHAR(512),\
    sign_count INTEGER NOT NULL DEFAULT 0,\
    clone_warning INTEGER NOT NULL DEFAULT 0,\
    user_present INTEGER NOT NULL DEFAULT 0,\
    user_verified INTEGER NOT NULL DEFAULT 0,\
    backup_eligible INTEGER NOT NULL DEFAULT 0,\
    backup_state INTEGER NOT NULL DEFAULT 0,\
    transports TEXT,\
    attachment VARCHAR(32),\
    last_used_at DATETIME,\
    created_at DATETIME NOT NULL,\
    updated_at DATETIME NOT NULL,\
    deleted_at DATETIME)";

pub const PASSKEY_CREDENTIALS_POSTGRES_DDL: &str = "CREATE TABLE passkey_credentials (\
    id BIGSERIAL PRIMARY KEY,\
    user_id BIGINT NOT NULL UNIQUE,\
    credential_id VARCHAR(512) NOT NULL UNIQUE,\
    public_key TEXT NOT NULL,\
    attestation_type VARCHAR(255),\
    aaguid VARCHAR(512),\
    sign_count BIGINT NOT NULL DEFAULT 0,\
    clone_warning BOOLEAN NOT NULL DEFAULT FALSE,\
    user_present BOOLEAN NOT NULL DEFAULT FALSE,\
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,\
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,\
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,\
    transports TEXT,\
    attachment VARCHAR(32),\
    last_used_at TIMESTAMPTZ,\
    created_at TIMESTAMPTZ NOT NULL,\
    updated_at TIMESTAMPTZ NOT NULL,\
    deleted_at TIMESTAMPTZ)";

/// Unix 秒 → UTC RFC3339（`Z` 结尾，零小数位），对齐 Go `time.Time` 的 JSON
/// 输出；仅用于 `last_used_at` 这类 Go 以 `*time.Time` 序列化的字段。
pub fn format_rfc3339(epoch_seconds: i64) -> String {
    let epoch = epoch_seconds.rem_euclid(86_400);
    let days = epoch_seconds.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (epoch / 3_600) as u32;
    let min = ((epoch % 3_600) / 60) as u32;
    let sec = (epoch % 60) as u32;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Howard Hinnant 的 civil_from_days（与 `http.rs::format_http_date` 同源）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_matches_go_time_marshalling() {
        // 2026-10-02T18:01:36Z（UTC，无小数位）。
        assert_eq!(format_rfc3339(1_790_964_096), "2026-10-02T18:01:36Z");
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn proof_scopes_match_go_allowlist() {
        assert!(is_allowed_proof_scope("channel.key.read"));
        assert!(is_allowed_proof_scope("passkey.register"));
        assert!(is_allowed_proof_scope("passkey.delete"));
        assert!(!is_allowed_proof_scope("passkey.step_up"));
        assert!(!is_allowed_proof_scope(""));
    }
}
