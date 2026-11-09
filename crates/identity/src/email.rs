//! 邮件发送端口。
//!
//! Go 参考：`apps/api/internal/common/email.go` 的 `SendEmail`（:163-173）。
//! 当 `SMTPAccountPool` 为空且 legacy 单账号（`SMTPServer`/`SMTPAccount`）
//! 都为空时，Go 直接返回固定错误 `"SMTP 服务器未配置"`，handler 经
//! `CtxApiError` 把该文案原样写进 200 响应的 `message`。
//!
//! SMTP 传输本身登记在 `docs/config-inventory.md` 的 `integrations.mail`
//! （P7）尚未落地；端口与默认实现 [`UnconfiguredEmailSender`] 的组合复刻了
//! “未配置 SMTP 的 Go 部署”的全部可观察行为：`send` 恒失败、文案逐字一致，
//! 调用方在发送前生成的验证码与已写入的副作用都不受影响。P7 接入真实传输
//! 时只需提供新的 `EmailSender` 实现，端口形状保持不变。

use std::future::Future;
use std::pin::Pin;

/// Go 固定的未配置错误文案（`email.go:168`）。逐字复刻，不做翻译。
pub const SMTP_NOT_CONFIGURED: &str = "SMTP 服务器未配置";

/// Go `OutgoingMessage`：一封待发送邮件的三个可见字段。
#[derive(Clone, Debug)]
pub struct OutgoingMessage<'a> {
    pub subject: &'a str,
    pub receiver: &'a str,
    pub content: &'a str,
}

/// Go `SendEmail` 的错误；`Display` 输出 `err.Error()` 原文，handler 按
/// `common.CtxApiError` 把它原样写进响应 message。 purposely 不派生 Debug，
/// 避免未来 SMTP 实现把传输细节通过 `{:?}` 泄漏到日志。
pub struct EmailError(pub String);

impl std::fmt::Display for EmailError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// 异步发送 future；沿用 `turnstile::Verifier` 的 boxed-future 形状，
/// 保持 trait 对象兼容，P7 的 SMTP 实现可直接替换。
pub type SendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), EmailError>> + Send + 'a>>;

/// 邮件发送端口。
pub trait EmailSender: Send + Sync {
    fn send<'a>(&'a self, message: &OutgoingMessage<'a>) -> SendFuture<'a>;
}

/// 未配置任何 SMTP 账号时的 Go `SendEmail` 行为：恒返回
/// [`SMTP_NOT_CONFIGURED`]。
#[derive(Clone, Copy, Debug, Default)]
pub struct UnconfiguredEmailSender;

impl EmailSender for UnconfiguredEmailSender {
    fn send<'a>(&'a self, _message: &OutgoingMessage<'a>) -> SendFuture<'a> {
        Box::pin(async move { Err(EmailError(SMTP_NOT_CONFIGURED.to_owned())) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unconfigured_sender_fails_with_the_go_verbatim_message() {
        let message = OutgoingMessage {
            subject: "New API邮箱验证邮件",
            receiver: "user@example.com",
            content: "<p>您好</p>",
        };
        let error = UnconfiguredEmailSender
            .send(&message)
            .await
            .expect_err("unconfigured SMTP always fails");
        assert_eq!(error.to_string(), "SMTP 服务器未配置");
    }
}
