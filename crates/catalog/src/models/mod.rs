//! 模型元数据域：`models` 表 CRUD、缺失模型与 `GET /api/models` 静态目录。
//!
//! Go 参考（`/root/newapi/apps/api/internal/catalog`）：
//! - [`store`]：`store_model_meta.go`（models 行 CRUD/搜索/重名/供应商计数/
//!   绑定渠道）、`store_missing_models.go`（缺失模型）、
//!   `store_vendor_meta.go` 的最小供应商路径（sync 上游补建用）
//! - [`dashboard`]：`transport/handler/handle_model.go` init() 组装的
//!   `channelId2Models` 静态目录（一次性导出为 JSON 资产）
//!
//! 与已有 `crate::abilities`（分组→模型只读投影）的分工：本模块拥有
//! `models`/`vendors` 两张表的全部读写路径；`abilities` 表仍保持只读，
//! 缺失模型的“已引用模型”全集通过 [`crate::abilities::enabled_models`]
//! 读取。
//!
//! 路由 HTTP 适配在 `apps/server/src/models_http.rs`。

pub mod dashboard;
pub mod store;

pub use store::{
    BoundChannel, ModelInput, ModelRepository, ModelRow, NAME_RULE_CONTAINS, NAME_RULE_EXACT,
    NAME_RULE_PREFIX, NAME_RULE_SUFFIX, NewModel, choose_status, contains_field,
    parse_status_filter, parse_sync_filter,
};
