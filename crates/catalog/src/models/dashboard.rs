//! `GET /api/models`（Go `DashboardListModels`）的静态目录。
//!
//! Go 在 `handle_model.go` 的 `init()` 里遍历渠道类型，用每个 relay adaptor
//! 的 `GetModelList()` 组装 `channelId2Models`。这里的 JSON 是对 Go 构建结果
//! 的一次性导出（`go build` 小程序复刻同一 init 循环后序列化），字段级含义：
//! - 键是渠道类型 id（JSON 对象键为十进制字符串，`map[int][]string` 的
//!   序列化形态）；
//! - 未在 `common.ChannelType2APIType` 映射到 API 类型（或映射到被跳过的
//!   `APITypeAIProxyLibrary`）的类型不出现；
//! - Dify（类型 37）的 adaptor 返回 nil 切片，JSON 为 `null`；OpenRouter
//!   （20）/Sub2API（59）/NewAPI（60）返回空切片，JSON 为 `[]`。差异来自
//!   Go nil 与空切片的 marshal 区别，须原样保留。
//!
//! 维护约定：渠道 adaptor 目录变更时重新导出本文件，不手改。

/// 已解析的静态目录（进程内解析一次）。
pub fn dashboard_models() -> serde_json::Value {
    static DASHBOARD: std::sync::OnceLock<serde_json::Value> = std::sync::OnceLock::new();
    DASHBOARD
        .get_or_init(|| {
            serde_json::from_str(include_str!("dashboard.json"))
                .expect("bundled dashboard.json is valid JSON")
        })
        .clone()
}
