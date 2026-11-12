//! Go `email_smtp_sender.go:86-121` 的原始报文组装。

use chrono::{DateTime, Local};
use rand::Rng;

/// Go `str.go:30-36` `GetRandomString`：字母数字随机串。
fn get_random_string(length: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

/// Go `email.go:106-113` `generateMessageID`：`<unixnano.random12@domain>`。
/// from 无 `@` 时报 Go 同文错误。
pub fn generate_message_id(from: &str, now: &DateTime<Local>) -> Result<String, String> {
    let domain = from.split('@').nth(1);
    let Some(domain) = domain else {
        return Err("invalid SMTP account".to_owned());
    };
    let nanos = now.timestamp_nanos_opt().unwrap_or_default();
    Ok(format!("<{}{}@{}>", nanos, get_random_string(12), domain))
}

/// Go `email.go:115-119` `shouldUseSMTPLoginAuth`：`SMTPForceAuthLogin`、
/// outlook 账号与登录服务器白名单都强制 LOGIN 机制。lettre 端该选择交给
/// 服务器通告协商（见 lib.rs 偏差说明），此函数保留给测试与诊断。
pub fn is_outlook_server(server: &str) -> bool {
    // Go email-outlook-auth.go：兼容多地区 outlook 与 ofb 邮箱。
    server.contains("outlook") || server.contains("onmicrosoft")
}

/// Go `email_smtp_sender.go:106-121` 的报文字节：头部顺序 To、From
/// `<SystemName> <from>`、Subject（UTF-8 Base64 词编码）、Date（RFC1123Z）、
/// Message-ID、Content-Type text/html; charset=UTF-8，正文以 CRLF 收尾。
pub fn build_message(
    system_name: &str,
    from: &str,
    subject: &str,
    receiver: &str,
    content: &str,
    now: &DateTime<Local>,
) -> Result<String, String> {
    let id = generate_message_id(from, now)?;
    // Go base64.StdEncoding.EncodeToString。
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(subject.as_bytes());
    let date = now.format("%a, %d %b %Y %H:%M:%S %z").to_string();
    Ok(format!(
        "To: {receiver}\r\n\
         From: {system_name} <{from}>\r\n\
         Subject: =?UTF-8?B?{encoded}?=\r\n\
         Date: {date}\r\n\
         Message-ID: {id}\r\n\
         Content-Type: text/html; charset=UTF-8\r\n\r\n{content}\r\n",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    #[test]
    fn message_id_requires_domain() {
        let now = Local::now();
        let error = generate_message_id("no-domain", &now).unwrap_err();
        assert_eq!(error, "invalid SMTP account");
    }

    #[test]
    fn message_id_shape() {
        let now = Local::now();
        let id = generate_message_id("a@example.com", &now).unwrap();
        let (local, domain) = id.trim_matches(|c| c != '<').split_once('@').unwrap();
        assert!(domain == "example.com");
        assert!(local.len() > 12, "nanos + random12");
    }

    #[test]
    fn headers_follow_the_go_layout() {
        let now = "2026-11-12T08:30:00+08:00"
            .parse::<DateTime<Local>>()
            .unwrap();
        let mail = build_message(
            "New API",
            "noreply@example.com",
            "主题 subject",
            "user@example.com",
            "<p>hi</p>",
            &now,
        )
        .unwrap();
        let lines: Vec<&str> = mail.split("\r\n").collect();
        assert_eq!(lines[0], "To: user@example.com");
        assert_eq!(lines[1], "From: New API <noreply@example.com>");
        let expected = base64::engine::general_purpose::STANDARD.encode("主题 subject".as_bytes());
        assert_eq!(lines[2], format!("Subject: =?UTF-8?B?{expected}?="));
        assert!(lines[3].starts_with("Date: "));
        assert!(lines[4].starts_with("Message-ID: <"));
        assert_eq!(lines[5], "Content-Type: text/html; charset=UTF-8");
        assert_eq!(lines[6], "");
        assert_eq!(lines[7], "<p>hi</p>");
        assert!(mail.ends_with("<p>hi</p>\r\n"));
    }

    #[test]
    fn outlook_detection_matches_go() {
        assert!(is_outlook_server("smtp.office365.com"));
        assert!(is_outlook_server("example.onmicrosoft.com"));
        assert!(!is_outlook_server("smtp.gmail.com"));
    }
}
