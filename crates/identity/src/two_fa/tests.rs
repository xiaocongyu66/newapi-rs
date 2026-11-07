//! 纯 TOTP / 格式化的单元测试；数据库契约见 `tests/two_fa_login.rs`。

use super::totp::{normalize_backup_code, normalize_numeric_code, validate_totp_code};

// RFC 4226 Appendix D 的共享密钥（ASCII "12345678901234567890"）的 base32 编码。
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn rfc4226_hotp_vectors_match_at_their_step() {
    // 来源：RFC 4226 Appendix D（HOTP）；TOTP 的时间步等同于 HOTP counter。
    let vectors = [
        (0_u64, "755224"),
        (1, "287082"),
        (2, "359152"),
        (3, "969429"),
        (4, "338314"),
        (5, "254676"),
        (6, "287922"),
        (7, "162583"),
        (8, "399871"),
        (9, "520489"),
    ];
    for (counter, code) in vectors {
        assert!(
            validate_totp_code(RFC_SECRET, code, counter as i64 * 30),
            "RFC 4226 counter {counter} code {code} must be accepted"
        );
    }
}

#[test]
fn rfc6238_sha1_vectors_match_at_the_published_times() {
    // 来源：RFC 6238 Appendix B（SHA1，8 位）；TOTP 6 位即其末 6 位。
    let vectors = [
        (59_i64, "287082"),
        (1_111_111_109, "081804"),
        (1_111_111_111, "050471"),
        (1_234_567_890, "005924"),
        (2_000_000_000, "279037"),
        (20_000_000_000, "353130"),
    ];
    for (now, code) in vectors {
        assert!(
            validate_totp_code(RFC_SECRET, code, now),
            "RFC 6238 time {now} code {code} must be accepted"
        );
    }
}

#[test]
fn skew_accepts_current_and_adjacent_steps_only() {
    // t=59 落在 counter=1；skew=1 接受 counter 0/1/2，拒绝 3。
    assert!(validate_totp_code(RFC_SECRET, "755224", 59));
    assert!(validate_totp_code(RFC_SECRET, "287082", 59));
    assert!(validate_totp_code(RFC_SECRET, "359152", 59));
    assert!(!validate_totp_code(RFC_SECRET, "969429", 59));

    // t=29 落在 counter=0；只接受 counter 0/1，拒绝 2。
    assert!(validate_totp_code(RFC_SECRET, "755224", 29));
    assert!(validate_totp_code(RFC_SECRET, "287082", 29));
    assert!(!validate_totp_code(RFC_SECRET, "359152", 29));
}

#[test]
fn secret_is_base32_case_insensitive_without_padding() {
    let lower = RFC_SECRET.to_ascii_lowercase();
    assert!(validate_totp_code(&lower, "287082", 59));
    // pquerna 在解码前 TrimSpace。
    assert!(validate_totp_code(
        &format!("  {RFC_SECRET}\n"),
        "287082",
        59
    ));
    assert!(!validate_totp_code(&format!("{RFC_SECRET}="), "287082", 59));
    // 0、1、8、9 不在 RFC 4648 base32 字母表中。
    assert!(!validate_totp_code(
        "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJ1",
        "287082",
        59
    ));
}

#[test]
fn numeric_code_requires_exactly_six_ascii_digits() {
    assert_eq!(
        normalize_numeric_code(" 287 082 "),
        Some("287082".to_owned())
    );
    assert_eq!(normalize_numeric_code("287082"), Some("287082".to_owned()));
    assert_eq!(normalize_numeric_code("28708"), None);
    assert_eq!(normalize_numeric_code("2870821"), None);
    assert_eq!(normalize_numeric_code("28708a"), None);
    assert_eq!(normalize_numeric_code("+28708"), None);
    assert_eq!(normalize_numeric_code("１２３４５６"), None);

    // 空格在进入 HMAC 之前被移除。
    assert!(validate_totp_code(RFC_SECRET, "287 082", 59));
    assert!(!validate_totp_code(RFC_SECRET, "28708", 59));
}

#[test]
fn backup_code_normalization_matches_go() {
    assert_eq!(
        normalize_backup_code("abcd-efgh"),
        Some("ABCD-EFGH".to_owned())
    );
    assert_eq!(
        normalize_backup_code("ABCDEFGH"),
        Some("ABCD-EFGH".to_owned())
    );
    assert_eq!(
        normalize_backup_code("ab-cd-ef-gh"),
        Some("ABCD-EFGH".to_owned())
    );
    assert_eq!(normalize_backup_code("ABCD-EFG"), None);
    assert_eq!(normalize_backup_code("ABCD-EFGHI"), None);
    assert_eq!(normalize_backup_code("ABCD-EFG!"), None);
    assert_eq!(
        normalize_backup_code("ABCD-EFG0"),
        Some("ABCD-EFG0".to_owned())
    );
}

#[test]
fn admin_stats_rate_matches_go_percent_format() {
    // Go `fmt.Sprintf("%.1f%%", enabled/total*100)`：字面带 `%` 的字符串。
    // total == 0 时 Go 以 0.0 起步。
    let zero = super::repository::TwoFaAdminStats::new(0, 0);
    assert_eq!(zero.total_users, 0);
    assert_eq!(zero.enabled_users, 0);
    assert_eq!(zero.enabled_rate, "0.0%");
    let half = super::repository::TwoFaAdminStats::new(2, 1);
    assert_eq!(half.enabled_rate, "50.0%");
    let third = super::repository::TwoFaAdminStats::new(3, 1);
    assert_eq!(third.enabled_rate, "33.3%");
    let seventh = super::repository::TwoFaAdminStats::new(7, 3);
    assert_eq!(seventh.enabled_rate, "42.9%");
    // 启用用户数不会超过总数（每个用户最多一个因子）。
    let full = super::repository::TwoFaAdminStats::new(4, 4);
    assert_eq!(full.enabled_rate, "100.0%");
}

#[test]
fn can_manage_target_role_matches_go_matrix() {
    // Go `canManageTargetRole(myRole, targetRole)`（manage_users.go:374-376）：
    // root 一律放行；其他角色仅可管理严格更低角色，同级互斥。
    assert!(super::repository::can_manage_target_role(100, 100));
    assert!(super::repository::can_manage_target_role(100, 10));
    assert!(super::repository::can_manage_target_role(100, 1));
    assert!(super::repository::can_manage_target_role(10, 1));
    assert!(super::repository::can_manage_target_role(10, 0));
    assert!(!super::repository::can_manage_target_role(10, 10));
    assert!(!super::repository::can_manage_target_role(10, 100));
    assert!(!super::repository::can_manage_target_role(1, 1));
    assert!(!super::repository::can_manage_target_role(1, 10));
    assert!(!super::repository::can_manage_target_role(1, 100));
}
