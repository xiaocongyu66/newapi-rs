//! 邮件发送面（Go `internal/common/email*.go` + `internal/mailer/quota_store.go`）。
//!
//! 端口沿用 `newapi_identity::email::EmailSender`；本 crate 提供：
//! - [`config`]：`SMTPAccountPool` 选项解析（`email_pool.go:44-62`）。
//! - [`message`]：Go 原始报文组装（`email_smtp_sender.go:106-121`）。
//! - [`pool`]：多账号池——配额门、优先级分层、层内轮转、逐层回退
//!   （`email_pool.go`）。
//! - [`quota`]：按账号的当日发送计数，UTC+8 日历日（`quota_store.go`）。
//! - [`smtp`]：lettre 真实 SMTP 传输，`EmailSender` 实现（`email_smtp_sender.go`）。
//!
//! 有意偏差（登记为遗留）：
//! - NTLM 认证（`email_ntlm_auth.go`，go-ntlmssp）未实现：lettre 不支持
//!   NTLM 机制。PLAIN/LOGIN 由 lettre 依服务器通告协商；Go 的
//!   `AutoSMTPAuth` 在 NTLM-only 服务器上会失败，本端口同样失败（错误文案不同）。
//! - `SMTPForceAuthLogin`/`EmailLoginAuthServerList`/`isOutlookServer` 的
//!   LOGIN 强制分支未移植：Go 用它绕过 NTLM-only 协商，lettre 恒按服务器
//!   通告选机制，语义上被协商逻辑覆盖。
//! - `SMTPInsecureSkipVerify` 未接选项快照，恒 false。
//! - `SenderStatus`/`Statuses` 管理端读取面未移植（无对应 HTTP 端点切片）。

pub mod config;
pub mod message;
pub mod pool;
pub mod quota;
pub mod smtp;
