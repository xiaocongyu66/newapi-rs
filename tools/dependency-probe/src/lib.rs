//! 依赖解析探针：仅提供 Cargo 检查所需的最小 target。
//! 不是服务或业务实现，不启动运行时、不连接数据库，不代表 P1 验收。
//!
//! 本轮：为 passkey 切片的依赖决策（A: 引入 webauthn-rs vs B: 手写最小实现）
//! 做 CI 级预验证——webauthn-rs =0.6.2 在 Rust 1.99.1 / Edition 2024 下
//! 能否被独立解析与编译。不涉及任何 attestation/registration 业务逻辑。

use webauthn_rs::Webauthn;

/// 编译级 smoke：仅断言 `Webauthn` 类型存在于 webauthn-rs 0.6.2 的公开 API。
/// 不猜测构造器签名、不构造运行时实例、不做认证流程。
pub fn webauthn_type_is_reachable() {
    let _ = std::any::type_name::<Webauthn>();
}
