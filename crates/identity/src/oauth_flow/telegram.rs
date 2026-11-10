//! Telegram Login Widget 的签名校验与断言防重放：
//! Go `identity/bind_telegram.go:281-339` 的三个纯函数。
//!
//! 校验逐字对 Go `verifyTelegramAuthorization`：
//! - bot token 为空直接失败；
//! - 任一查询参数出现重复值即失败（Go 遍历 `url.Values` 判 `len != 1`）；
//! - `id` / `hash` / `auth_date` 必填；
//! - `auth_date` 必须落在 `[now-5min, now+2min]` 窗口；
//! - 除 `hash` 外的所有键值按 `key=value` 排序后以 `\n` 连接，
//!   以 `SHA256(bot token)` 为 HMAC key 做 HMAC-SHA256，与 `hash`
//!   十六进制解码后常数时间比较。
//!
//! 校验通过后返回 Telegram 数字 id（字符串，Go 原样存库）。

use std::collections::BTreeMap;

use crate::crypto;

/// Go `telegramAuthorizationMaxAge` / `telegramAuthorizationFutureSkew`
/// 的本地别名；常量在 [`super`] 公开。
use super::{TELEGRAM_AUTHORIZATION_FUTURE_SKEW, TELEGRAM_AUTHORIZATION_MAX_AGE};

/// 校验失败的固定分类；不携带参数值或签名。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TelegramVerifyError;

/// Go `verifyTelegramAuthorization`（`bind_telegram.go:297-339`）。
///
/// `params` 是解析后的查询参数（同键多值保留，供重复检测）。成功返回
/// Telegram id 字符串。
pub fn verify_telegram_authorization(
    params: &[(String, Vec<String>)],
    bot_token: &str,
    now: i64,
) -> Result<String, TelegramVerifyError> {
    if bot_token.is_empty() {
        return Err(TelegramVerifyError);
    }
    // Go：任一键出现多个值即拒绝，防止重复参数混淆签名输入。
    if params.iter().any(|(_, values)| values.len() != 1) {
        return Err(TelegramVerifyError);
    }
    let pairs: BTreeMap<&str, &str> = params
        .iter()
        .filter_map(|(key, values)| Some((key.as_str(), values.first()?.as_str())))
        .collect();
    let telegram_id = *pairs.get("id").ok_or(TelegramVerifyError)?;
    let hash = *pairs.get("hash").ok_or(TelegramVerifyError)?;
    let auth_date_text = *pairs.get("auth_date").ok_or(TelegramVerifyError)?;
    if telegram_id.is_empty() || hash.is_empty() || auth_date_text.is_empty() {
        return Err(TelegramVerifyError);
    }
    let Ok(auth_date) = auth_date_text.parse::<i64>() else {
        return Err(TelegramVerifyError);
    };
    if auth_date < now - TELEGRAM_AUTHORIZATION_MAX_AGE
        || auth_date > now + TELEGRAM_AUTHORIZATION_FUTURE_SKEW
    {
        return Err(TelegramVerifyError);
    }
    // Go：`hash` 之外的全部键值，`key=value` 形式按字节排序后 `\n` 连接。
    let joined = pairs
        .iter()
        .filter(|(key, _)| **key != "hash")
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    // Go：secret = SHA256(bot token)，再以其为 key 做 HMAC-SHA256。
    let secret = Sha256::digest(bot_token.as_bytes());
    let expected = crypto::mac(&secret, joined.as_bytes());
    let Some(provided) = hex_decode(hash) else {
        return Err(TelegramVerifyError);
    };
    if !crypto::equal(&provided, &expected) {
        return Err(TelegramVerifyError);
    }
    Ok(telegram_id.to_owned())
}

/// Go `telegramAuthorizationClaim`（`bind_telegram.go:281-295`）：校验已
/// 通过后提取防重放断言（`hash` 十六进制原样）与到期时间
/// (`auth_date + 5min`)。`auth_date` 非法或断言已过期即失败。
pub fn telegram_authorization_claim(
    params: &[(String, Vec<String>)],
    now: i64,
) -> Result<(String, i64), TelegramVerifyError> {
    let auth_date_text = params
        .iter()
        .find(|(key, _)| key == "auth_date")
        .and_then(|(_, values)| values.first())
        .ok_or(TelegramVerifyError)?;
    let Ok(auth_date) = auth_date_text.parse::<i64>() else {
        return Err(TelegramVerifyError);
    };
    let hash = params
        .iter()
        .find(|(key, _)| key == "hash")
        .and_then(|(_, values)| values.first())
        .ok_or(TelegramVerifyError)?;
    let expires_at = auth_date + TELEGRAM_AUTHORIZATION_MAX_AGE;
    if expires_at <= now {
        return Err(TelegramVerifyError);
    }
    Ok((hash.clone(), expires_at))
}

/// 测试夹具/嵌入方使用的合法签名重算（与 widget 同算法）：
/// 排序键值（不含 hash）→ `key=value` 以 `\n` 连接 →
/// HMAC-SHA256(key = SHA256(bot token))。生产校验不调用本函数。
pub fn widget_signature(bot_token: &str, params: &[(String, String)]) -> String {
    let mut pairs = params.to_vec();
    pairs.sort();
    let joined = pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("\n");
    let secret = Sha256::digest(bot_token.as_bytes());
    let digest = crypto::mac(&secret, joined.as_bytes());
    digest.iter().fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

/// Go `hex.DecodeString`：只接受偶数长度与十六进制字符；失败返回 `None`
/// （Go 返回 error，两个分支在调用点同归失败）。
fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push(high * 16 + low);
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

use sha2::{Digest, Sha256};

#[cfg(test)]
mod tests {
    use super::*;

    fn single(pairs: &[(&str, &str)]) -> Vec<(String, Vec<String>)> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), vec![(*value).to_owned()]))
            .collect()
    }

    /// 与 Go `verifyTelegramAuthorization` 的手工计算一致的端到端向量：
    /// secret = SHA256("bot-token")，签名由同一算法在测试内重算，验证
    /// 排序、拼接与比较的形状（key=value\n…、hash 除外）。
    #[test]
    fn accepts_a_well_signed_authorization() {
        let params = single(&[
            ("id", "9000000001"),
            ("first_name", "Zhang"),
            ("last_name", "San"),
            ("username", "zhangsan"),
            ("photo_url", "https://cdn.example.invalid/a.png"),
            ("auth_date", "1700000000"),
            ("hash", "placeholder"),
        ]);
        // 重算合法签名：排序键值（不含 hash）→ \n 连接 → HMAC(SHA256(token))。
        let joined = params
            .iter()
            .filter(|(key, _)| key != "hash")
            .map(|(key, values)| format!("{key}={}", values[0]))
            .collect::<Vec<_>>()
            .join("\n");
        let secret = Sha256::digest(b"bot-token");
        let expected = crate::crypto::mac(&secret, joined.as_bytes());
        let signature = expected.iter().fold(String::new(), |mut acc, byte| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{byte:02x}");
            acc
        });
        let mut signed = params;
        signed.retain(|(key, _)| key != "hash");
        signed.push(("hash".to_owned(), vec![signature]));

        let verified =
            verify_telegram_authorization(&signed, "bot-token", 1_700_000_100).expect("valid");
        assert_eq!(verified, "9000000001");
        let (assertion, expires_at) =
            telegram_authorization_claim(&signed, 1_700_000_100).expect("claim");
        assert_eq!(assertion, signature);
        assert_eq!(expires_at, 1_700_000_000 + TELEGRAM_AUTHORIZATION_MAX_AGE);
    }

    #[test]
    fn rejects_tampered_fields_and_bad_windows() {
        let params = single(&[("id", "1"), ("auth_date", "1700000000"), ("hash", "00")]);
        // bot token 为空。
        assert!(verify_telegram_authorization(&params, "", 1_700_000_000).is_err());
        // 缺 id。
        let missing = single(&[("auth_date", "1700000000"), ("hash", "00")]);
        assert!(verify_telegram_authorization(&missing, "bot-token", 1_700_000_000).is_err());
        // auth_date 太旧（>5min）。
        assert!(verify_telegram_authorization(&params, "bot-token", 1_700_000_000 + 301).is_err());
        // auth_date 超未来（>2min skew）。
        assert!(verify_telegram_authorization(&params, "bot-token", 1_700_000_000 - 121).is_err());
        // 非 int auth_date。
        let bad_date = single(&[("id", "1"), ("auth_date", "x"), ("hash", "00")]);
        assert!(verify_telegram_authorization(&bad_date, "bot-token", 1_700_000_000).is_err());
        // 重复参数。
        let duplicated = vec![
            ("id".to_owned(), vec!["1".to_owned(), "2".to_owned()]),
            ("auth_date".to_owned(), vec!["1700000000".to_owned()]),
            ("hash".to_owned(), vec!["00".to_owned()]),
        ];
        assert!(verify_telegram_authorization(&duplicated, "bot-token", 1_700_000_000).is_err());
        // 非十六进制 hash。
        let bad_hash = single(&[("id", "1"), ("auth_date", "1700000000"), ("hash", "zz")]);
        assert!(verify_telegram_authorization(&bad_hash, "bot-token", 1_700_000_000).is_err());
        // 奇数长度 hash。
        let odd_hash = single(&[("id", "1"), ("auth_date", "1700000000"), ("hash", "0")]);
        assert!(verify_telegram_authorization(&odd_hash, "bot-token", 1_700_000_000).is_err());
    }

    #[test]
    fn future_skew_boundary_is_inclusive() {
        // 恰好 +2min 仍接受（Go `>` 边界）。
        let params = single(&[("id", "1"), ("auth_date", "1700000000"), ("hash", "00")]);
        let verified = verify_telegram_authorization(&params, "bot-token", 1_700_000_000 - 120);
        assert!(verified.is_ok());
        // 恰好 -5min 仍接受。
        let verified = verify_telegram_authorization(&params, "bot-token", 1_700_000_000 + 300);
        assert!(verified.is_ok());
    }

    #[test]
    fn claim_rejects_expired_assertion() {
        let params = single(&[("id", "1"), ("auth_date", "1700000000"), ("hash", "ab")]);
        // 断言在 auth_date+300 后过期；now == 到期即失败。
        assert!(telegram_authorization_claim(&params, 1_700_000_300).is_err());
        let claim = telegram_authorization_claim(&params, 1_700_000_299).expect("still valid");
        assert_eq!(claim.1, 1_700_000_300);
        // 缺 auth_date / hash 同样失败。
        let no_hash = single(&[("id", "1"), ("auth_date", "1700000000")]);
        assert!(telegram_authorization_claim(&no_hash, 0).is_err());
    }

    #[test]
    fn hex_decode_matches_go_semantics() {
        assert_eq!(hex_decode("0a"), Some(vec![10]));
        assert_eq!(hex_decode("FF"), Some(vec![255]));
        assert_eq!(hex_decode(""), Some(vec![]));
        assert_eq!(hex_decode("0"), None);
        assert_eq!(hex_decode("0z"), None);
    }
}
