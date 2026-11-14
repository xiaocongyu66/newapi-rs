//! 渠道选择器契约（Distribute 的选择面）：Go
//! `internal/catalog/select_channel.go`（86 行）、`select_channel_contract.go`
//!（44 行）、`selector_seam.go`（45 行）、`select_channel_cached.go`（95 行，
//! auto 分组游走）与 `exclude_channels.go`（排除集）的移植。
//!
//! 契约要点（逐字对齐）：
//! - 选择失败是三个不同哨兵：无可用渠道（运行时态，可重试/报 503）、
//!   选择器未配置（启动缺陷）、模型名缺失（调用方 bug）——见
//!   [`SelectError`]。查找回零/负渠道 ID 等价"无可用"，绝不能让网关拨号
//!   渠道 0（Go SelectChannel 注释）。
//! - [`Selector`] 只实现规则，不触库：查找经 [`ChannelLookup`] 注入
//!   （Go `LookupFunc`），生产查找在服务装配层（abilities 过滤 +
//!   route units），测试注入替身。
//! - [`SelectParams`] 是重试范围的输入：`Retry *int` 的空值/递增/
//!   `ResetRetryNextTry`（补位通过不消耗尝试槽）逐位复刻。
//! - auto 分组游走（[`cache_get_random_satisfied_channel`]）：每个分组用完
//!   全部优先级才切到下一个；`cross_group_retry` 且当前分组优先级耗尽时
//!   推进游走索引并重置重试（ResetRetryNextTry 吞掉下一次 Increase）。
//! - 排除集（[`ExclusionSet`]）：非正 ID 丢弃；`with` 拷贝而非原地改，
//!   防止重试环回溯更改进行中选择所观察到的状态（Go 注释）。

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

/// Go `types.ErrorCode*` 选择面复用：无可用渠道在 Distribute 错误信封里
/// 落 `model_not_found`（distribute_channel.go:176,180）。
pub const ERROR_CODE_MODEL_NOT_FOUND: &str = "model_not_found";
pub const ERROR_CODE_GET_CHANNEL_FAILED: &str = "get_channel_failed";

// ---------------------------------------------------------------------------
// 排除集（Go exclude_channels.go）
// ---------------------------------------------------------------------------

/// Go `ExclusionSet`：单请求内已尝试且失败的渠道集合。
///
/// 非 ID 丢弃：它们不能标识真实渠道，保留会让畸形重试态"看似排除了
/// 实际什么都没排除"。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExclusionSet {
    ids: HashSet<i64>,
}

impl ExclusionSet {
    /// Go `NewExclusionSet`：从渠道 ID 构建。空集 → None 语义（空结构体）。
    pub fn new(channel_ids: &[i64]) -> Self {
        Self {
            ids: channel_ids.iter().filter(|id| **id > 0).copied().collect(),
        }
    }

    /// Go `Excludes`。
    pub fn excludes(&self, channel_id: i64) -> bool {
        self.ids.contains(&channel_id)
    }

    /// Go `With`：返回追加排除的集合（拷贝语义，不改自身）。
    pub fn with(&self, channel_id: i64) -> Self {
        let mut extended = self.clone();
        if channel_id > 0 {
            extended.ids.insert(channel_id);
        }
        extended
    }

    /// Go `IDs`：被排除渠道 ID。Go 注明顺序不可依赖；这里升序输出使
    /// 日志与持久化查询确定。
    pub fn ids(&self) -> Vec<i64> {
        let mut ids: Vec<i64> = self.ids.iter().copied().collect();
        ids.sort_unstable();
        ids
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }
}

// ---------------------------------------------------------------------------
// 路由单元键与路由排除（Go health_unit_store.go RouteKey + ExcludeRoutes map）
// ---------------------------------------------------------------------------

/// Go `catalog.RouteKey`：可调度路由单元的 (channel, key, model) 三元组，
/// 选择器与健康状态机共用的键。
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct RouteKey {
    pub channel_id: i64,
    pub key_index: i64,
    pub model: String,
}

/// Go `map[RouteKey]bool`（SelectParams.ExcludeRoutes / 重试环的 tried 集）。
/// BTreeSet 使迭代序确定。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ExcludeRoutes {
    keys: BTreeSet<RouteKey>,
}

impl ExcludeRoutes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mark_tried(&mut self, key: RouteKey) {
        self.keys.insert(key);
    }

    pub fn contains(&self, key: &RouteKey) -> bool {
        self.keys.contains(key)
    }

    /// Go `failover.ResetTried`：冷却等待后重开被排除单元。
    pub fn clear(&mut self) {
        self.keys.clear();
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

// ---------------------------------------------------------------------------
// 选择契约（Go select_channel_contract.go）
// ---------------------------------------------------------------------------

/// Go `ChannelSelection`：选中的渠道 ID + 实际选中分组（auto 游走时
/// 可能与请求分组不同）。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ChannelSelection {
    pub channel_id: i64,
    pub selected_group: String,
}

/// Go `ChannelRequest`：网关需要渠道的描述。`exclude_channel_ids` 携带
/// 本请求已试败的渠道，重试不重选已知坏渠道；`attempt` 是零基重试计数，
/// 用于优先级层降（route-unit 模型下仅作 API 兼容保留）。
#[derive(Clone, Debug, Default)]
pub struct ChannelRequest {
    pub token_group: String,
    pub model_name: String,
    pub request_path: String,
    pub exclude_channel_ids: Vec<i64>,
    pub attempt: i32,
}

/// Go `Selector` 的查找端口（Go `LookupFunc`）：按 (group, model, attempt,
/// exclusion set) 解析渠道 ID 与选中分组。查找自身错误经
/// [`SelectError::Lookup`] 透传。
pub trait ChannelLookup: Send + Sync {
    fn lookup(
        &self,
        group: &str,
        model_name: &str,
        request_path: &str,
        attempt: i32,
        excluded: &ExclusionSet,
    ) -> Result<(i64, String), SelectError>;
}

impl<F> ChannelLookup for F
where
    F: Fn(&str, &str, &str, i32, &ExclusionSet) -> Result<(i64, String), SelectError> + Send + Sync,
{
    fn lookup(
        &self,
        group: &str,
        model_name: &str,
        request_path: &str,
        attempt: i32,
        excluded: &ExclusionSet,
    ) -> Result<(i64, String), SelectError> {
        self(group, model_name, request_path, attempt, excluded)
    }
}

// ---------------------------------------------------------------------------
// 选择错误（Go select_channel.go 哨兵）
// ---------------------------------------------------------------------------

/// Go 三个哨兵 + 透传错误。Display 文案逐字对齐 Go 错误串。
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectError {
    /// `ErrNoChannelAvailable`：无启用渠道满足请求（运行时条件，
    /// 可重试或报 503 model_not_found）。
    NoChannelAvailable,
    /// `ErrSelectorNotConfigured`：选择器没有查找实现（启动缺陷）。
    SelectorNotConfigured,
    /// `ErrModelNameRequired`：无模型名的选择请求（调用方 bug）。
    ModelNameRequired,
    /// 查找自身失败（DB 一致性等）：消息透传。
    Lookup(String),
}

impl SelectError {
    /// Go 哨兵的原文案（测试与日志对齐用）。
    pub fn message(&self) -> String {
        match self {
            Self::NoChannelAvailable => "no channel available for request".to_owned(),
            Self::SelectorNotConfigured => "channel selector is not configured".to_owned(),
            Self::ModelNameRequired => "model name is required to select a channel".to_owned(),
            Self::Lookup(message) => message.clone(),
        }
    }

    /// Go `ErrNoChannelAvailable` 分流：Distribute 把它翻成
    /// 503 + model_not_found，其余翻 400/503（错误信封层判断）。
    pub fn is_no_channel_available(&self) -> bool {
        matches!(self, Self::NoChannelAvailable)
    }
}

impl std::fmt::Display for SelectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for SelectError {}

// ---------------------------------------------------------------------------
// 选择器（Go select_channel.go Selector）
// ---------------------------------------------------------------------------

/// Go `ChannelSelector` 接口（消费侧端口）。
pub trait ChannelSelector: Send + Sync {
    fn select_channel(&self, request: &ChannelRequest) -> Result<ChannelSelection, SelectError>;
}

/// Go `Selector`：选择规则本体。拒绝未配置选择器与空模型而非委托查找
/// （否则都会表现为难懂的查找 miss）；非正渠道 ID 视为"无可用"；
/// 查找返回已排除渠道同样视为"无可用"。
pub struct Selector {
    lookup: Option<Arc<dyn ChannelLookup>>,
}

impl Selector {
    /// Go `NewSelector`。
    pub fn new(lookup: Arc<dyn ChannelLookup>) -> Self {
        Self {
            lookup: Some(lookup),
        }
    }

    /// Go `nil` Selector / `lookup == nil` 的形状：未配置。
    pub fn unconfigured() -> Self {
        Self { lookup: None }
    }
}

impl ChannelSelector for Selector {
    /// Go `SelectChannel`。
    fn select_channel(&self, request: &ChannelRequest) -> Result<ChannelSelection, SelectError> {
        let Some(lookup) = self.lookup.as_ref() else {
            return Err(SelectError::SelectorNotConfigured);
        };
        if request.model_name.is_empty() {
            return Err(SelectError::ModelNameRequired);
        }
        // Go 的 ctx.Err() 取消检查由异步调用方（relay 主链）在调用前执行；
        // 纯契约层不持有时钟与执行器。

        let excluded = ExclusionSet::new(&request.exclude_channel_ids);

        let (channel_id, selected_group) = lookup.lookup(
            &request.token_group,
            &request.model_name,
            &request.request_path,
            request.attempt,
            &excluded,
        )?;
        if channel_id <= 0 {
            return Err(SelectError::NoChannelAvailable);
        }
        if excluded.excludes(channel_id) {
            return Err(SelectError::Lookup(format!(
                "no channel available for request: lookup returned already-excluded channel {channel_id}"
            )));
        }
        let selected_group = if selected_group.is_empty() {
            request.token_group.clone()
        } else {
            selected_group
        };
        Ok(ChannelSelection {
            channel_id,
            selected_group,
        })
    }
}

// ---------------------------------------------------------------------------
// 重试态（Go selector_seam.go SelectParams）
// ---------------------------------------------------------------------------

/// Go `SelectParams`：一次 relay 请求的重试范围选择输入。Rust 侧
/// `Retry *int` 平铺为 `retry` 字段 + `reset_next_try` 标志。
#[derive(Clone, Debug, Default)]
pub struct SelectParams {
    pub token_group: String,
    pub model_name: String,
    pub request_path: String,
    pub exclude_routes: ExcludeRoutes,
    retry: i32,
    reset_next_try: bool,
}

impl SelectParams {
    /// Go 构造位（handle_relay.go:215-222）：全零重试起点。
    pub fn new(token_group: &str, model_name: &str, request_path: &str) -> Self {
        Self {
            token_group: token_group.to_owned(),
            model_name: model_name.to_owned(),
            request_path: request_path.to_owned(),
            exclude_routes: ExcludeRoutes::new(),
            retry: 0,
            reset_next_try: false,
        }
    }

    /// Go `GetRetry`。
    pub fn get_retry(&self) -> i32 {
        self.retry
    }

    /// Go `SetRetry`。
    pub fn set_retry(&mut self, retry: i32) {
        self.retry = retry;
        self.reset_next_try = false;
    }

    /// Go `IncreaseRetry`：`resetNextTry` 置位时吞掉一次递增
    /// （冷却等待/并发槽满的补位通过不消耗尝试槽）。
    pub fn increase_retry(&mut self) {
        if self.reset_next_try {
            self.reset_next_try = false;
            return;
        }
        self.retry += 1;
    }

    /// Go `ResetRetryNextTry`。
    pub fn reset_retry_next_try(&mut self) {
        self.reset_next_try = true;
    }
}

// ---------------------------------------------------------------------------
// 路由单元（Go select_route_unit.go SelectedRoute 的选择面投影）
// ---------------------------------------------------------------------------

/// Go `SelectedRoute` 的核心投影（无完整 Channel 对象：渠道快照由服务层
/// 在 SetupContextForSelectedChannel 绑定时另行持有）。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SelectedRoute {
    /// `channel_model_routes.id`。
    pub route_id: i64,
    pub group: String,
    /// 公开模型别名（== 请求模型名）。
    pub alias: String,
    pub channel_id: i64,
    pub key_index: i64,
    /// 选中的 API key 明文（多 key 按 key_index；单 key 渠道 key）。
    pub key: String,
    /// 映射后的上游模型名。
    pub upstream_model: String,
}

impl SelectedRoute {
    /// 本路由单元的 [`RouteKey`]（health 表键，按请求别名取模）。
    pub fn route_key(&self) -> RouteKey {
        RouteKey {
            channel_id: self.channel_id,
            key_index: self.key_index,
            model: self.alias.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// auto 分组游走（Go select_channel_cached.go CacheGetRandomSatisfiedChannel）
// ---------------------------------------------------------------------------

/// Go 上下文键 `ContextKeyAutoGroupIndex` / `ContextKeyAutoGroupRetryIndex`
/// 的承载：当前游走分组索引与进入该分组时的全局重试数。Go 挂在请求
/// 上下文上，Rust 由调用方（relay 主链的重试环）随请求持有。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AutoGroupState {
    pub group_index: usize,
    pub start_retry_index: i32,
}

/// auto 游走的配置快照（Go：`GetRequestAutoGroups` 结果 +
/// `ContextKeyTokenCrossGroupRetry` + `common.RetryTimes`）。
#[derive(Clone, Debug, Default)]
pub struct AutoGroupConfig {
    /// 解析后的有序 auto 分组（token auto groups 过滤版，无 fallback 语义
    /// 由服务层 [`crate`] 外完成）。
    pub auto_groups: Vec<String>,
    pub cross_group_retry: bool,
    /// Go `common.RetryTimes` 选项值。
    pub retry_times: i32,
}

/// 单分组查找端口：Go `GetRandomSatisfiedChannel(group, model, retry, path,
/// excludeRoutes)`。`Ok(None)` = 该 (group, model) 在当前重试约束下无候选
/// （Go 返回 nil 路由 + nil error）；`Err` 透传。异步查找（DB 路径）经
/// RPITIT 端口接入；同步替身用 [`SyncGroupLookup`] 包装。
pub trait GroupRouteLookup: Send {
    fn lookup_route(
        &mut self,
        group: &str,
        priority_retry: i32,
    ) -> impl std::future::Future<Output = Result<Option<SelectedRoute>, SelectError>> + Send;
}

/// 同步闭包的 [`GroupRouteLookup`] 适配（纯契约测试用）。
pub struct SyncGroupLookup<F>(pub F);

impl<F> GroupRouteLookup for SyncGroupLookup<F>
where
    F: FnMut(&str, i32) -> Result<Option<SelectedRoute>, SelectError> + Send,
{
    async fn lookup_route(
        &mut self,
        group: &str,
        priority_retry: i32,
    ) -> Result<Option<SelectedRoute>, SelectError> {
        (self.0)(group, priority_retry)
    }
}

/// Go `CacheGetRandomSatisfiedChannel`：auto 分组游走。
///
/// - 每个分组先用尽当前优先级（`priority_retry = params.retry`），无候选时
///   推进 `state.group_index` 并重置重试，再试下一分组（下一起点起
///   `priority_retry = 0`）。
/// - 命中候选：`select_group` 跟随命中分组；`cross_group_retry` 且
///   `priority_retry >= retry_times` 时推进游走索引、重置重试并吞下一次
///   递增（`reset_retry_next_try`），否则游走索引停在当前分组。
/// - 非 auto 分组直通单分组查找。
/// - 游走完仍无候选：`Ok((None, token_group))`——错误信封由调用方按
///   "无可用渠道" 输出（Go route==nil 分支）。
pub async fn cache_get_random_satisfied_channel<L: GroupRouteLookup>(
    state: &mut AutoGroupState,
    params: &mut SelectParams,
    config: &AutoGroupConfig,
    lookup: &mut L,
) -> Result<(Option<SelectedRoute>, String), SelectError> {
    let select_group_default = params.token_group.clone();
    if params.token_group == "auto" {
        if config.auto_groups.is_empty() {
            return Err(SelectError::Lookup("auto groups is not enabled".to_owned()));
        }
        let start_group_index = state.group_index.min(config.auto_groups.len());
        for (offset, i) in (start_group_index..config.auto_groups.len()).enumerate() {
            let auto_group = config.auto_groups[i].clone();
            let priority_retry = if offset == 0 { params.get_retry() } else { 0 };
            let route = lookup.lookup_route(&auto_group, priority_retry).await?;
            let Some(route) = route else {
                // 优先级用完 → 切到下一个分组（Go SetCtxKey(i+1) + SetRetry(0)）。
                state.group_index = i + 1;
                state.start_retry_index = 0;
                params.set_retry(0);
                continue;
            };
            if config.cross_group_retry && priority_retry >= config.retry_times {
                state.group_index = i + 1;
                params.set_retry(0);
                params.reset_retry_next_try();
            } else {
                state.group_index = i;
            }
            return Ok((Some(route), auto_group));
        }
        Ok((None, select_group_default))
    } else {
        let retry = params.get_retry();
        let route = lookup.lookup_route(&params.token_group, retry).await?;
        Ok((route, select_group_default))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_lookup(channel_id: i64, group: &str) -> impl ChannelLookup {
        move |_group: &str, _model: &str, _path: &str, _attempt: i32, _excluded: &ExclusionSet| {
            Ok((channel_id, group.to_owned()))
        }
    }

    fn request(group: &str, model: &str) -> ChannelRequest {
        ChannelRequest {
            token_group: group.to_owned(),
            model_name: model.to_owned(),
            request_path: "/v1/chat/completions".to_owned(),
            exclude_channel_ids: Vec::new(),
            attempt: 0,
        }
    }

    // ── Selector 契约（select_channel.go 语义）────────────────────────────

    #[test]
    fn selector_requires_configuration() {
        let selector = Selector::unconfigured();
        let error = selector
            .select_channel(&request("default", "gpt-4"))
            .unwrap_err();
        assert_eq!(error, SelectError::SelectorNotConfigured);
        assert_eq!(error.message(), "channel selector is not configured");
    }

    #[test]
    fn selector_requires_model_name() {
        let selector = Selector::new(Arc::new(ok_lookup(1, "default")));
        let error = selector
            .select_channel(&request("default", ""))
            .unwrap_err();
        assert_eq!(error, SelectError::ModelNameRequired);
        assert_eq!(
            error.message(),
            "model name is required to select a channel"
        );
    }

    #[test]
    fn selector_maps_non_positive_lookup_to_no_channel() {
        let selector = Selector::new(Arc::new(ok_lookup(0, "default")));
        let error = selector
            .select_channel(&request("default", "gpt-4"))
            .unwrap_err();
        assert_eq!(error, SelectError::NoChannelAvailable);
        assert_eq!(error.message(), "no channel available for request");
    }

    #[test]
    fn selector_rejects_lookup_returning_excluded_channel() {
        let lookup =
            |group: &str, _model: &str, _path: &str, _attempt: i32, excluded: &ExclusionSet| {
                // 模拟生产查找忽略排除集的缺陷路径：始终返回渠道 7。
                let _ = group;
                assert!(excluded.excludes(7));
                Ok((7i64, group.to_owned()))
            };
        let selector = Selector::new(Arc::new(lookup));
        let mut request = request("default", "gpt-4");
        request.exclude_channel_ids = vec![7];
        let error = selector.select_channel(&request).unwrap_err();
        assert!(
            error
                .message()
                .contains("lookup returned already-excluded channel 7")
        );
        assert!(
            error
                .message()
                .starts_with("no channel available for request")
        );
    }

    #[test]
    fn selector_defaults_group_to_token_group() {
        // 查找返回空分组 → 回退 token_group（Go SelectChannel 尾段）。
        let lookup = |_group: &str, _m: &str, _p: &str, _a: i32, _e: &ExclusionSet| {
            Ok((3i64, String::new()))
        };
        let selector = Selector::new(Arc::new(lookup));
        let selection = selector.select_channel(&request("vip", "gpt-4")).unwrap();
        assert_eq!(
            selection,
            ChannelSelection {
                channel_id: 3,
                selected_group: "vip".to_owned(),
            }
        );
    }

    #[test]
    #[test]
    fn selector_passes_attempt_and_exclusions_to_lookup() {
        // Arc 共享观测缓冲：dyn 强转要求 'static 借用（E0597 面）。
        let seen = Arc::new(std::sync::Mutex::new(Vec::<(String, i32, Vec<i64>)>::new()));
        let seen_for_lookup = Arc::clone(&seen);
        let lookup =
            move |group: &str, model: &str, path: &str, attempt: i32, excluded: &ExclusionSet| {
                seen_for_lookup.lock().unwrap().push((
                    format!("{group}|{model}|{path}"),
                    attempt,
                    excluded.ids(),
                ));
                Ok((9i64, group.to_owned()))
            };
        let selector = Selector::new(Arc::new(lookup));
        let mut request = request("auto", "gpt-4");
        request.attempt = 2;
        request.exclude_channel_ids = vec![1, -5, 2, 0];
        let selection = selector.select_channel(&request).unwrap();
        assert_eq!(selection.channel_id, 9);
        assert_eq!(selection.selected_group, "auto");
        let observed = seen.lock().unwrap().clone();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0, "auto|gpt-4|/v1/chat/completions");
        assert_eq!(observed[0].1, 2);
        // 非正 ID 被丢弃（Go NewExclusionSet）。
        assert_eq!(observed[0].2, vec![1, 2]);
    }

    // ── ExclusionSet（exclude_channels.go 语义）───────────────────────────

    #[test]
    fn exclusion_set_drops_non_positive_and_copies_on_with() {
        let set = ExclusionSet::new(&[1, -2, 3, 0]);
        assert_eq!(set.ids(), vec![1, 3]);
        assert!(set.excludes(1));
        assert!(!set.excludes(-2));
        let extended = set.with(9);
        assert_eq!(extended.ids(), vec![1, 3, 9]);
        // with 拷贝：原集合不变。
        assert_eq!(set.ids(), vec![1, 3]);
        assert!(!set.excludes(9));
        // 非正 ID 追加为 no-op。
        assert_eq!(set.with(0).ids(), vec![1, 3]);
    }

    // ── SelectParams 重试态（selector_seam.go 语义）───────────────────────

    #[test]
    fn select_params_retry_machine() {
        let mut params = SelectParams::new("default", "gpt-4", "/v1/chat/completions");
        assert_eq!(params.get_retry(), 0);
        params.increase_retry();
        assert_eq!(params.get_retry(), 1);
        // 补位通过：ResetRetryNextTry 吞掉下一次 Increase。
        params.reset_retry_next_try();
        params.increase_retry();
        assert_eq!(params.get_retry(), 1);
        // SetRetry 清除吞增标志。
        params.set_retry(3);
        params.increase_retry();
        assert_eq!(params.get_retry(), 4);
    }

    // ── auto 分组游走（select_channel_cached.go 语义）─────────────────────

    fn auto_config(groups: &[&str], cross_group_retry: bool, retry_times: i32) -> AutoGroupConfig {
        AutoGroupConfig {
            auto_groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            cross_group_retry,
            retry_times,
        }
    }

    fn route_for(group: &str, key_index: i64) -> SelectedRoute {
        SelectedRoute {
            route_id: 1,
            group: group.to_owned(),
            alias: "gpt-4".to_owned(),
            channel_id: 10,
            key_index,
            key: "sk-x".to_owned(),
            upstream_model: "gpt-4".to_owned(),
        }
    }

    /// 游走测试执行器：current-thread runtime（纯契约，无 IO）。
    fn block_walk(
        state: &mut AutoGroupState,
        params: &mut SelectParams,
        config: &AutoGroupConfig,
        lookup: &mut SyncGroupLookup<
            impl FnMut(&str, i32) -> Result<Option<SelectedRoute>, SelectError> + Send,
        >,
    ) -> Result<(Option<SelectedRoute>, String), SelectError> {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(cache_get_random_satisfied_channel(
                state, params, config, lookup,
            ))
    }

    #[test]
    fn auto_walk_requires_groups() {
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("auto", "gpt-4", "/p");
        let config = auto_config(&[], false, 0);
        let mut lookup = SyncGroupLookup(|_g: &str, _r: i32| Ok(None));
        let error = block_walk(&mut state, &mut params, &config, &mut lookup).unwrap_err();
        assert_eq!(error.message(), "auto groups is not enabled");
    }

    #[test]
    fn auto_walk_exhausts_priorities_before_next_group() {
        // 分组 A 在 retry 0/1 无候选，分组 B 在 retry 0 命中：
        // Go 注释示例（2 组各 2 优先级，RetryTimes=3）的 Retry=2 段。
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("auto", "gpt-4", "/p");
        params.set_retry(2);
        let config = auto_config(&["A", "B"], false, 3);
        let calls = std::sync::Mutex::new(Vec::<(String, i32)>::new());
        let mut lookup = SyncGroupLookup(|group: &str, retry: i32| {
            calls.lock().unwrap().push((group.to_owned(), retry));
            if group == "B" && retry == 0 {
                return Ok(Some(route_for("B", 0)));
            }
            Ok(None)
        });
        let (route, selected_group) =
            block_walk(&mut state, &mut params, &config, &mut lookup).unwrap();
        let route = route.expect("route from group B");
        assert_eq!(selected_group, "B");
        assert_eq!(route.group, "B");
        assert_eq!(state.group_index, 1);
        // A retry=2（miss）→ A retry=0（miss）→ B retry=0（hit）。
        assert_eq!(
            calls.into_inner().unwrap(),
            vec![
                ("A".to_owned(), 2),
                ("A".to_owned(), 0),
                ("B".to_owned(), 0)
            ]
        );
    }

    #[test]
    fn auto_walk_cross_group_retry_advances_and_swallows_increase() {
        // cross_group_retry 且 priority_retry >= RetryTimes：命中后推进索引、
        // 重置重试并吞下一次 Increase（Go Retry=0 段 + RetryTimes=0）。
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("auto", "gpt-4", "/p");
        let config = auto_config(&["A", "B"], true, 0);
        let mut lookup = SyncGroupLookup(|group: &str, _retry: i32| {
            if group == "A" {
                return Ok(Some(route_for("A", 0)));
            }
            Ok(None)
        });
        let (route, selected_group) =
            block_walk(&mut state, &mut params, &config, &mut lookup).unwrap();
        assert_eq!(selected_group, "A");
        assert_eq!(route.unwrap().group, "A");
        assert_eq!(state.group_index, 1);
        assert_eq!(params.get_retry(), 0);
        params.increase_retry(); // 被 reset_next_try 吞掉
        assert_eq!(params.get_retry(), 0);
    }

    #[test]
    fn auto_walk_without_cross_group_retry_stays_on_group() {
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("auto", "gpt-4", "/p");
        let config = auto_config(&["A", "B"], false, 3);
        let mut lookup = SyncGroupLookup(|group: &str, _retry: i32| {
            if group == "A" {
                return Ok(Some(route_for("A", 1)));
            }
            Ok(None)
        });
        let (route, selected_group) =
            block_walk(&mut state, &mut params, &config, &mut lookup).unwrap();
        assert_eq!(selected_group, "A");
        assert_eq!(route.unwrap().key_index, 1);
        assert_eq!(state.group_index, 0);
        // 未吞增：下一次 Increase 正常递增。
        params.increase_retry();
        assert_eq!(params.get_retry(), 1);
    }

    #[test]
    fn auto_walk_exhausted_returns_none_with_token_group() {
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("auto", "gpt-4", "/p");
        let config = auto_config(&["A"], false, 3);
        let mut lookup = SyncGroupLookup(|_group: &str, _retry: i32| Ok(None));
        let (route, selected_group) =
            block_walk(&mut state, &mut params, &config, &mut lookup).unwrap();
        assert!(route.is_none());
        assert_eq!(selected_group, "auto");
        assert_eq!(state.group_index, 1);
    }

    #[test]
    fn non_auto_group_passes_retry_through() {
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("vip", "gpt-4", "/p");
        params.set_retry(1);
        let config = auto_config(&[], false, 3);
        let calls = std::sync::Mutex::new(Vec::<(String, i32)>::new());
        let mut lookup = SyncGroupLookup(|group: &str, retry: i32| {
            calls.lock().unwrap().push((group.to_owned(), retry));
            Ok(Some(route_for(group, 0)))
        });
        let (route, selected_group) =
            block_walk(&mut state, &mut params, &config, &mut lookup).unwrap();
        assert_eq!(selected_group, "vip");
        assert_eq!(route.unwrap().group, "vip");
        assert_eq!(calls.into_inner().unwrap(), vec![("vip".to_owned(), 1)]);
    }

    #[test]
    fn lookup_error_propagates_with_group() {
        let mut state = AutoGroupState::default();
        let mut params = SelectParams::new("auto", "gpt-4", "/p");
        let config = auto_config(&["A", "B"], false, 3);
        let mut lookup = SyncGroupLookup(|group: &str, _retry: i32| {
            if group == "B" {
                return Err(SelectError::Lookup("db exploded".to_owned()));
            }
            Ok(None)
        });
        let error = block_walk(&mut state, &mut params, &config, &mut lookup).unwrap_err();
        assert_eq!(error.message(), "db exploded");
    }

    #[test]
    fn route_key_round_trip() {
        let route = route_for("default", 2);
        let key = route.route_key();
        assert_eq!(
            key,
            RouteKey {
                channel_id: 10,
                key_index: 2,
                model: "gpt-4".to_owned(),
            }
        );
        let mut excluded = ExcludeRoutes::new();
        excluded.mark_tried(key.clone());
        assert!(excluded.contains(&key));
        assert_eq!(excluded.len(), 1);
        excluded.clear();
        assert!(excluded.is_empty());
    }
}
