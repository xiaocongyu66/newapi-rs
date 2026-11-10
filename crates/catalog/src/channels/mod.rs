//! 渠道域：基础 CRUD（`channels` 行 + `abilities` 联动写入）。
//!
//! - [`store`]：仓储（列表/搜索/详情/创建/更新/删除/批量删除/标签聚合）与
//!   `abilities` 表的渠道维度写路径。`crate::abilities` 保持只读投影，两者
//!   不共享可变状态。
//! - [`validation`]：`validateChannel` / `ValidateSettings` / 密钥模式解析。
//!
//! 路由 HTTP 适配在 `apps/server/src/channel_http.rs`。

pub mod store;
pub mod validation;

pub use store::{
    CHANNEL_STATUS_AUTO_DISABLED, CHANNEL_STATUS_ENABLED, CHANNEL_STATUS_MANUALLY_DISABLED,
    CHANNEL_TYPE_NEW_API, CHANNEL_TYPE_VERTEX_AI, ChannelInfo, ChannelInput, ChannelListFilter,
    ChannelPatch, ChannelRepository, ChannelRow, ChannelSort, MASKED_CHANNEL_KEY, NewChannel,
    StatusFilter,
};
pub use validation::{AddChannelRequest, KeyParseError, ParsedKeys, ValidationError};
