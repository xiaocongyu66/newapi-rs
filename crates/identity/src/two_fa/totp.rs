//! TOTP（RFC 6238）与备用码格式化。
//!
//! 参数与 Go 端 `pquerna/otp v1.5.0` 的 `totp.Validate` 默认值一致：
//! SHA1、6 位、30 秒周期、skew=1。密钥按 RFC 4648 base32 解码，不允许
//! padding，大小写不敏感，并像 Go `encoding/base32` 一样忽略 `\r`/`\n`。
//! 时间由调用方传入 Unix 秒，本模块不读取系统时钟。

use hmac::{Hmac, Mac};
use sha1::Sha1;

const PERIOD_SECONDS: i64 = 30;
const SKEW_STEPS: i64 = 1;
const CODE_MODULUS: u32 = 1_000_000;
const CODE_DIGITS: usize = 6;
const BACKUP_CODE_DIGITS: usize = 8;

/// Go `common.ValidateNumericCode` 的成功结果：移除所有 ASCII 空格后，
/// 必须正好是 6 个 ASCII 数字。不接受的输入不参与 TOTP 校验。
pub fn normalize_numeric_code(code: &str) -> Option<String> {
    let cleaned: String = code.chars().filter(|character| *character != ' ').collect();
    if cleaned.len() == CODE_DIGITS && cleaned.bytes().all(|byte| byte.is_ascii_digit()) {
        Some(cleaned)
    } else {
        None
    }
}

/// Go `common.NormalizeBackupCode` + `common.ValidateBackupCode`：
/// 去掉所有 `-` 后转大写，必须正好 8 位 `A-Z0-9`；成功时返回 `XXXX-XXXX`。
pub fn normalize_backup_code(code: &str) -> Option<String> {
    let mut cleaned = String::with_capacity(BACKUP_CODE_DIGITS);
    for character in code.chars() {
        if character == '-' {
            continue;
        }
        let upper = character.to_ascii_uppercase();
        if !(upper.is_ascii_uppercase() || upper.is_ascii_digit()) {
            return None;
        }
        cleaned.push(upper);
    }
    if cleaned.len() != BACKUP_CODE_DIGITS {
        return None;
    }
    Some(format!("{}-{}", &cleaned[..4], &cleaned[4..]))
}

/// 校验 6 位 TOTP：接受当前时间步以及前后各一步。
/// 输入格式非法、secret 非法或窗口外一律返回 false。
pub fn validate_totp_code(secret: &str, code: &str, now: i64) -> bool {
    let Some(code) = normalize_numeric_code(code) else {
        return false;
    };
    let Some(key) = decode_base32(secret) else {
        return false;
    };
    if now < 0 {
        return false;
    }
    let counter = now / PERIOD_SECONDS;
    for offset in -SKEW_STEPS..=SKEW_STEPS {
        let Some(step) = counter.checked_add(offset) else {
            continue;
        };
        if step < 0 {
            continue;
        }
        if totp_code(&key, step as u64) == code {
            return true;
        }
    }
    false
}

fn totp_code(key: &[u8], counter: u64) -> String {
    // HMAC 接受任意长度密钥，构造失败不可达。
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // RFC 4226 动态截断。
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", binary % CODE_MODULUS)
}

/// Go `time.Time.Format("2006-01-02 15:04:05")` 的 UTC 形式。
/// 仅用于锁定提示文案中的解锁时间，不参与比较。
pub fn format_go_time(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let seconds = epoch.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60
    )
}

// Howard Hinnant 的 days-from-civil 逆变换；只处理 UTC。
fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month, day)
}

/// RFC 4648 base32 解码，无 padding，大小写不敏感。
/// pquerna 在解码前执行 `strings.TrimSpace`；Go `encoding/base32` 忽略
/// `\r`、`\n`，并拒绝长度余数为 1、3、6 的输入；末尾不足一个字节的剩余
/// 比特被丢弃。存储格式本身不带 padding，因此 `=` 一律拒绝。
fn decode_base32(secret: &str) -> Option<Vec<u8>> {
    let secret = secret.trim();
    let mut output = Vec::with_capacity(secret.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut symbols: usize = 0;
    for byte in secret.bytes() {
        if byte == b'\r' || byte == b'\n' {
            continue;
        }
        let value = match byte.to_ascii_uppercase() {
            b'A'..=b'Z' => byte.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        symbols += 1;
        if bits >= 8 {
            bits -= 8;
            output.push((buffer >> bits) as u8);
            buffer &= (1u32 << bits) - 1;
        }
    }
    match symbols % 8 {
        1 | 3 | 6 => None,
        _ => Some(output),
    }
}
