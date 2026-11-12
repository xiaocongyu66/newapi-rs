//! 真实 SMTP 传输（Go `email_smtp_sender.go` + `email.go:121-160`）。
//!
//! 每次发送新建一条 SMTP 连接（与 Go `newSMTPClient` 一致），整体超时 60s
//! （Go `SMTPOperationTimeout`）。TLS 映射：
//! - `ssl_enabled` 或（端口 465 且未开 starttls）→ 隐式 TLS（`Tls::Wrapper`）；
//! - `starttls` → `Tls::Required`（服务器不支持即失败，对齐 Go 的
//!   "SMTP server does not support STARTTLS"）；
//! - 其余 → 明文（`Tls::None`）。
//!
//! 认证：账号与 token 均非空时附凭据，机制由 lettre 依服务器通告协商
//! （PLAIN/LOGIN）；NTLM 未实现（lib.rs 遗留说明）。Go 的 QUIT 短窗优雅
//! 收尾由 lettre 内部处理，失败不影响发送结果。

use std::time::Duration;

use chrono::Local;
use lettre::{
    AsyncTransport, Tokio1Executor,
    transport::smtp::{
        authentication::Credentials,
        client::{Tls, TlsParameters},
    },
};
use newapi_identity::email::{
    EmailError, EmailSender, OutgoingMessage, SMTP_NOT_CONFIGURED, SendFuture,
};

use crate::config::SmtpAccountConfig;
use crate::message::build_message;
use crate::pool::PoolSender;

/// Go `email.go:11-13` `SMTPOperationTimeout`。
pub const SMTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

enum TlsChoice {
    Wrapper,
    Required,
    None,
}

fn tls_parameters(server: &str) -> Result<TlsParameters, EmailError> {
    TlsParameters::builder(server.to_owned())
        .build_rustls()
        .map_err(|error| EmailError(error.to_string()))
}

/// 单账号 SMTP 发送器（Go `smtpSender`）。
pub struct LettreSmtpSender {
    config: SmtpAccountConfig,
    system_name: String,
}

impl LettreSmtpSender {
    pub fn new(config: SmtpAccountConfig, system_name: impl Into<String>) -> Self {
        Self {
            config,
            system_name: system_name.into(),
        }
    }

    /// Go `smtpSender.envelopeFrom`（email_smtp_sender.go:80-84）。
    pub fn envelope_from(&self) -> String {
        if !self.config.from.is_empty() {
            self.config.from.clone()
        } else {
            self.config.account.clone()
        }
    }

    /// Go `newSMTPClient`（email.go:136-162）：ssl 或（465 且未开 starttls）
    /// 为隐式 TLS；starttls 为必须升级；其余明文。
    fn tls_mode(&self) -> TlsChoice {
        let implicit =
            self.config.ssl_enabled || (self.config.port == 465 && !self.config.starttls);
        if implicit {
            TlsChoice::Wrapper
        } else if self.config.starttls {
            TlsChoice::Required
        } else {
            TlsChoice::None
        }
    }

    fn transport(&self) -> Result<lettre::AsyncSmtpTransport<Tokio1Executor>, EmailError> {
        let base = match self.tls_mode() {
            TlsChoice::Wrapper => {
                let params = tls_parameters(&self.config.server)?;
                lettre::AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.server)
                    .port(self.config.port as u16)
                    .tls(Tls::Wrapper(params))
            }
            TlsChoice::Required => {
                let params = tls_parameters(&self.config.server)?;
                lettre::AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.server)
                    .port(self.config.port as u16)
                    .tls(Tls::Required(params))
            }
            TlsChoice::None => {
                lettre::AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&self.config.server)
                    .port(self.config.port as u16)
                    .tls(Tls::None)
            }
        };
        let builder = base.timeout(Some(SMTP_OPERATION_TIMEOUT));
        let builder = if !self.config.account.is_empty() && !self.config.token.is_empty() {
            builder.credentials(Credentials::new(
                self.config.account.clone(),
                self.config.token.clone(),
            ))
        } else {
            builder
        };
        Ok(builder.build())
    }

    fn envelope(
        &self,
        receiver: &str,
        from: &str,
    ) -> Result<lettre::address::Envelope, EmailError> {
        let parse = |value: &str| -> Result<lettre::address::Address, EmailError> {
            value
                .trim()
                .parse::<lettre::address::Address>()
                .map_err(|error| EmailError(error.to_string()))
        };
        let receivers: Vec<lettre::address::Address> = receiver
            .split(';')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(parse)
            .collect::<Result<Vec<_>, EmailError>>()?;
        let reverse_path = Some(parse(from)?);
        lettre::address::Envelope::new(reverse_path, receivers)
            .map_err(|error| EmailError(error.to_string()))
    }

    /// Go `smtpSender.deliver`（email_smtp_sender.go:86-134）：组装 Go 形状
    /// 的原始报文，经 SMTP 会话 MAIL FROM/RCPT TO/DATA 投递。
    pub async fn deliver(&self, message: &OutgoingMessage<'_>) -> Result<(), EmailError> {
        let from = self.envelope_from();
        let now = Local::now();
        let mail = build_message(
            &self.system_name,
            &from,
            message.subject,
            message.receiver,
            message.content,
            &now,
        )
        .map_err(EmailError)?;
        let envelope = self.envelope(message.receiver, &from)?;
        self.transport()?
            .send_raw(&envelope, mail.as_bytes())
            .await
            .map(|_| ())
            .map_err(|error| EmailError(error.to_string()))
    }
}

impl EmailSender for LettreSmtpSender {
    fn send<'a>(&'a self, message: &OutgoingMessage<'a>) -> SendFuture<'a> {
        let subject = message.subject.to_owned();
        let receiver = message.receiver.to_owned();
        let content = message.content.to_owned();
        Box::pin(async move {
            self.deliver(&OutgoingMessage {
                subject: &subject,
                receiver: &receiver,
                content: &content,
            })
            .await
        })
    }
}

impl PoolSender for LettreSmtpSender {
    fn config(&self) -> &SmtpAccountConfig {
        &self.config
    }
}

/// Go `SendEmail`（email.go:163-173）的完整入口：池非空走池，否则走
/// legacy 单账号；legacy 双空报 Go 同文错误 `"SMTP 服务器未配置"`。
pub struct Mailer {
    system_name: String,
    pool: Option<crate::pool::SenderPool>,
    legacy: Option<SmtpAccountConfig>,
}

impl Mailer {
    /// `pool_configs` 为解析后的 SMTPAccountPool；为空时启用 legacy。
    /// `factory` 供测试注入替身（Go `newSMTPSender(config)` 的位置）。
    pub fn with_factory(
        system_name: impl Into<String>,
        pool_configs: Vec<SmtpAccountConfig>,
        legacy: Option<SmtpAccountConfig>,
        quota: std::sync::Arc<dyn crate::quota::QuotaStore>,
        factory: &dyn Fn(&SmtpAccountConfig) -> std::sync::Arc<dyn PoolSender>,
    ) -> Self {
        let pool = if pool_configs.is_empty() {
            None
        } else {
            Some(crate::pool::SenderPool::new(pool_configs, quota, factory))
        };
        Self {
            system_name: system_name.into(),
            pool,
            legacy,
        }
    }

    /// 生产构造：全部账号走 lettre 真实传输。
    pub fn new(
        system_name: impl Into<String>,
        pool_configs: Vec<SmtpAccountConfig>,
        legacy: SmtpAccountConfig,
        quota: std::sync::Arc<dyn crate::quota::QuotaStore>,
    ) -> Self {
        let system_name = system_name.into();
        Self::with_factory(
            system_name.clone(),
            pool_configs,
            Some(legacy),
            quota,
            &|config| {
                std::sync::Arc::new(LettreSmtpSender::new(config.clone(), system_name.clone()))
            },
        )
    }
}

impl EmailSender for Mailer {
    fn send<'a>(&'a self, message: &OutgoingMessage<'a>) -> SendFuture<'a> {
        let subject = message.subject.to_owned();
        let receiver = message.receiver.to_owned();
        let content = message.content.to_owned();
        Box::pin(async move {
            let owned = OutgoingMessage {
                subject: &subject,
                receiver: &receiver,
                content: &content,
            };
            if let Some(pool) = &self.pool {
                return pool.send(&owned).await;
            }
            let Some(legacy) = &self.legacy else {
                return Err(EmailError(SMTP_NOT_CONFIGURED.to_owned()));
            };
            if legacy.server.is_empty() && legacy.account.is_empty() {
                return Err(EmailError(SMTP_NOT_CONFIGURED.to_owned()));
            }
            LettreSmtpSender::new(legacy.clone(), self.system_name.clone())
                .deliver(&owned)
                .await
        })
    }
}
