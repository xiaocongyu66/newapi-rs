//! Per-call tool billing counts. Port of the upstream Go
//! `internal/relay/common/count_tool_usage.go` (lines 1-194) plus the
//! `GetToolPriceForModel` lookup from `internal/billing/price_expression/
//! price_tools.go` (lines 189-233) that the builtin price gate needs.
//!
//! The tool price index mirrors Go `RebuildToolPriceIndex` (price_tools.go:
//! 159-186): hardcoded defaults seeded first, then operator overrides keyed
//! `tool` (default) or `tool:model_prefix*` (longest-prefix match), sorted by
//! descending prefix length.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

use crate::relay_info::BuiltInToolInfo;

/// Go dto BuildInTool* constants (relaykit/dto/openai_response.go:366-370).
pub mod build_in_tool {
    pub const WEB_SEARCH_PREVIEW: &str = "web_search_preview";
    pub const WEB_SEARCH: &str = "web_search";
    pub const FILE_SEARCH: &str = "file_search";
    pub const GOOGLE_SEARCH: &str = "google_search";
    pub const IMAGE_GENERATION: &str = "image_generation";
}

/// Go dto BuildInCall* constants (relaykit/dto/openai_response.go:374-377).
pub mod build_in_call {
    pub const WEB_SEARCH_CALL: &str = "web_search_call";
    pub const FILE_SEARCH_CALL: &str = "file_search_call";
    pub const FUNCTION_CALL: &str = "function_call";
    pub const TOOL_USE: &str = "tool_use";
}

/// Go dto MaxImageN (relaykit/dto/openai_image.go:15).
pub const MAX_IMAGE_N: i64 = 128;

/// Go dto ResponsesOutputTypeImageGenerationCall.
pub const RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL: &str = "image_generation_call";

// ---------------------------------------------------------------------------
// Tool price index (Go price_tools.go)
// ---------------------------------------------------------------------------

const DEFAULT_WEB_SEARCH_TOOL_PRICE: f64 = 10.0;
const DEFAULT_WEB_SEARCH_PREVIEW_TOOL_PRICE: f64 = 10.0;
const DEFAULT_FILE_SEARCH_TOOL_PRICE: f64 = 2.5;
const DEFAULT_GOOGLE_SEARCH_TOOL_PRICE: f64 = 14.0;
const DEFAULT_IMAGE_GENERATION_TOOL_PRICE: f64 = 150.0;
const DEFAULT_SEARCH_PREVIEW_MODEL_PRICE: f64 = 25.0;

/// Go `seedHardcodedToolPrices` (price_tools.go:50-62).
fn seed_hardcoded_tool_prices(prices: &mut HashMap<String, f64>) {
    prices.insert("web_search".to_owned(), DEFAULT_WEB_SEARCH_TOOL_PRICE);
    prices.insert(
        "web_search_preview".to_owned(),
        DEFAULT_WEB_SEARCH_PREVIEW_TOOL_PRICE,
    );
    prices.insert("file_search".to_owned(), DEFAULT_FILE_SEARCH_TOOL_PRICE);
    prices.insert("google_search".to_owned(), DEFAULT_GOOGLE_SEARCH_TOOL_PRICE);
    prices.insert(
        "image_generation".to_owned(),
        DEFAULT_IMAGE_GENERATION_TOOL_PRICE,
    );
    prices.insert(
        "web_search_preview:gpt-4o*".to_owned(),
        DEFAULT_SEARCH_PREVIEW_MODEL_PRICE,
    );
    prices.insert(
        "web_search_preview:gpt-4.1*".to_owned(),
        DEFAULT_SEARCH_PREVIEW_MODEL_PRICE,
    );
    prices.insert(
        "web_search_preview:gpt-4o-mini*".to_owned(),
        DEFAULT_SEARCH_PREVIEW_MODEL_PRICE,
    );
    prices.insert(
        "web_search_preview:gpt-4.1-mini*".to_owned(),
        DEFAULT_SEARCH_PREVIEW_MODEL_PRICE,
    );
}

fn is_valid_tool_price(price: f64) -> bool {
    price >= 0.0 && !price.is_nan() && !price.is_infinite()
}

#[derive(Clone, Debug)]
struct PrefixEntry {
    prefix: String,
    price: f64,
}

#[derive(Debug, Default)]
struct ToolPriceIndex {
    defaults: HashMap<String, f64>,
    prefixes: HashMap<String, Vec<PrefixEntry>>,
}

/// Operator override store + derived index, standing in for Go
/// `toolPriceSetting.Prices` + the atomic `currentIndex` (settings
/// registration rebuilds on every write; Go reads are lock-free).
struct PriceState {
    prices: HashMap<String, f64>,
    index: ToolPriceIndex,
}

fn price_state() -> &'static Mutex<PriceState> {
    static STATE: OnceLock<Mutex<PriceState>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(PriceState {
            prices: HashMap::new(),
            index: rebuild_tool_price_index_with(&HashMap::new()),
        })
    })
}

/// Go `RebuildToolPriceIndex` (price_tools.go:159-186): merge defaults with
/// operator overrides, split `tool:model_prefix*` keys, sort prefixes by
/// descending length (ties by lexicographic order, matching the Go
/// sort.Slice less function).
fn rebuild_tool_price_index_with(overrides: &HashMap<String, f64>) -> ToolPriceIndex {
    let mut merged = HashMap::with_capacity(9 + overrides.len());
    seed_hardcoded_tool_prices(&mut merged);
    for (key, value) in overrides {
        if !is_valid_tool_price(*value) {
            continue;
        }
        merged.insert(key.clone(), *value);
    }

    let mut index = ToolPriceIndex::default();
    for (key, price) in merged {
        match key.find(':') {
            None => {
                index.defaults.insert(key, price);
            }
            Some(colon) => {
                let tool_name = key[..colon].to_owned();
                let model_part = &key[colon + 1..];
                let prefix = model_part.strip_suffix('*').unwrap_or(model_part);
                index
                    .prefixes
                    .entry(tool_name)
                    .or_default()
                    .push(PrefixEntry {
                        prefix: prefix.to_owned(),
                        price,
                    });
            }
        }
    }

    for entries in index.prefixes.values_mut() {
        entries.sort_by(|a, b| {
            if a.prefix.len() == b.prefix.len() {
                a.prefix.cmp(&b.prefix)
            } else {
                b.prefix.len().cmp(&a.prefix.len())
            }
        });
    }
    index
}

/// Test hook mirroring Go `SetToolPriceForTest` (price_tools.go:221-229):
/// injects a tool price and rebuilds the lookup index.
pub fn set_tool_price_for_test(name: &str, price: f64) {
    let mut state = price_state().lock().unwrap_or_else(|p| p.into_inner());
    state.prices.insert(name.to_owned(), price);
    state.index = rebuild_tool_price_index_with(&state.prices);
}

/// Test hook mirroring Go `DeleteToolPriceForTest`.
pub fn delete_tool_price_for_test(name: &str) {
    let mut state = price_state().lock().unwrap_or_else(|p| p.into_inner());
    state.prices.remove(name);
    state.index = rebuild_tool_price_index_with(&state.prices);
}

/// Clears all operator overrides (test isolation).
#[cfg(test)]
pub fn clear_tool_prices_for_test() {
    let mut state = price_state().lock().unwrap_or_else(|p| p.into_inner());
    state.prices.clear();
    state.index = rebuild_tool_price_index_with(&state.prices);
}

/// Go `GetToolPriceForModel` (price_tools.go:191-215): longest model prefix
/// match → tool default → 0.
pub fn get_tool_price_for_model(tool_name: &str, model_name: &str) -> f64 {
    let state = price_state().lock().unwrap_or_else(|p| p.into_inner());
    let index = &state.index;

    if !model_name.is_empty()
        && let Some(entries) = index.prefixes.get(tool_name)
    {
        for entry in entries {
            if model_name.starts_with(&entry.prefix) {
                return entry.price;
            }
        }
    }

    index.defaults.get(tool_name).copied().unwrap_or(0.0)
}

// ---------------------------------------------------------------------------
// CountBillableToolCall (count_tool_usage.go:14-75)
// ---------------------------------------------------------------------------

fn reserved_billable_tool_names(name: &str) -> bool {
    matches!(
        name,
        build_in_tool::WEB_SEARCH_PREVIEW
            | build_in_tool::WEB_SEARCH
            | build_in_tool::FILE_SEARCH
            | build_in_tool::GOOGLE_SEARCH
            | build_in_tool::IMAGE_GENERATION
    )
}

/// Go `resolveWebSearchToolName` (count_tool_usage.go:56-64): prefer an
/// already-present `web_search` entry over `web_search_preview`.
fn resolve_web_search_tool_name(tools: &[BuiltInToolInfo]) -> &'static str {
    if tools
        .iter()
        .any(|t| t.tool_name == build_in_tool::WEB_SEARCH)
    {
        return build_in_tool::WEB_SEARCH;
    }
    build_in_tool::WEB_SEARCH_PREVIEW
}

/// Increment the builtin tool counter for `name`, updating an existing entry
/// in place (Go `incrementBillableToolCall`, count_tool_usage.go:66-75).
/// `built_in_tools` is the RelayInfo.ResponsesUsageInfo.BuiltInTools store.
pub fn increment_billable_tool_call(built_in_tools: &mut Vec<BuiltInToolInfo>, name: &str) {
    for existing in built_in_tools.iter_mut() {
        if existing.tool_name == name {
            existing.call_count += 1;
            return;
        }
    }
    built_in_tools.push(BuiltInToolInfo {
        tool_name: name.to_owned(),
        call_count: 1,
        ..Default::default()
    });
}

/// Inputs for [`count_billable_tool_call`]: the builtin tool store (Go
/// `info.ResponsesUsageInfo.BuiltInTools`) plus the origin model name.
pub struct BillableToolContext<'a> {
    pub built_in_tools: &'a mut Vec<BuiltInToolInfo>,
    pub origin_model_name: &'a str,
}

/// Go `(*RelayInfo).CountBillableToolCall` (count_tool_usage.go:24-54).
/// Built-in call types always count; custom function/tool_use names only
/// count when priced.
pub fn count_billable_tool_call(
    ctx: &mut BillableToolContext<'_>,
    item_type: &str,
    function_name: &str,
) {
    match item_type {
        build_in_call::WEB_SEARCH_CALL => {
            let name = resolve_web_search_tool_name(ctx.built_in_tools);
            increment_billable_tool_call(ctx.built_in_tools, name);
        }
        build_in_call::FILE_SEARCH_CALL => {
            increment_billable_tool_call(ctx.built_in_tools, build_in_tool::FILE_SEARCH);
        }
        build_in_call::FUNCTION_CALL | build_in_call::TOOL_USE => {
            if function_name.is_empty() {
                return;
            }
            if reserved_billable_tool_names(function_name) {
                return;
            }
            if get_tool_price_for_model(function_name, ctx.origin_model_name) <= 0.0 {
                return;
            }
            increment_billable_tool_call(ctx.built_in_tools, function_name);
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// ImageGenerationCallCounter (count_tool_usage.go:77-176)
// ---------------------------------------------------------------------------

/// Counts completed Responses image_generation_call outputs with stream-safe
/// identity deduplication.
#[derive(Debug, Default)]
pub struct ImageGenerationCallCounter {
    seen: std::collections::HashSet<String>,
    count: i64,
}

/// Inputs mirroring Go `dto.ResponsesOutput` fields used by `Observe`.
#[derive(Clone, Debug, Default)]
pub struct ResponsesOutputInput {
    pub item_type: String,
    pub id: String,
    pub call_id: String,
    pub status: String,
    pub result: String,
}

impl ImageGenerationCallCounter {
    /// Go `(*ImageGenerationCallCounter).Observe` (count_tool_usage.go:86-126):
    /// records one completed final image output when billable. `output_index`
    /// participates in dedup when set and non-negative.
    pub fn observe(&mut self, item: &ResponsesOutputInput, output_index: Option<i64>) {
        if item.item_type != RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL {
            return;
        }
        if item.result.trim().is_empty() {
            return;
        }
        match item.status.trim().to_lowercase().as_str() {
            "failed" | "cancelled" | "canceled" | "incomplete" | "partial" => return,
            _ => {}
        }

        let mut aliases: Vec<String> = Vec::with_capacity(4);
        if !item.id.is_empty() {
            aliases.push(format!("id:{}", item.id));
        }
        // Go Observe reads item.CallId; ResponsesOutputInput keeps the same
        // wire field under `id` handling here via the call field below.
        if !item.call_id.is_empty() {
            aliases.push(format!("call:{}", item.call_id));
        }
        if let Some(index) = output_index
            && index >= 0
        {
            aliases.push(format!("index:{index}"));
        }
        let mut hasher = Sha256::new();
        hasher.update(item.result.as_bytes());
        aliases.push(format!("result:{}", hex::encode(hasher.finalize())));

        for alias in &aliases {
            if self.seen.contains(alias) {
                return;
            }
        }
        for alias in aliases {
            self.seen.insert(alias);
        }
        self.count += 1;
    }

    /// Go `Reset` (count_tool_usage.go:129-135): clears pending observations.
    pub fn reset(&mut self) {
        self.seen.clear();
        self.count = 0;
    }

    /// Go `Count` (count_tool_usage.go:138-143): deduplicated completed
    /// output count before commit capping.
    pub fn count(&self) -> i64 {
        self.count
    }

    /// Go `Commit` (count_tool_usage.go:147-176): writes the capped
    /// completed-output count into the builtin tool store once. Request tool
    /// declarations alone must not become billable calls.
    pub fn commit(&self, built_in_tools: &mut Vec<BuiltInToolInfo>) {
        let count = self.count.min(MAX_IMAGE_N);
        if let Some(existing) = built_in_tools
            .iter_mut()
            .find(|t| t.tool_name == build_in_tool::IMAGE_GENERATION)
        {
            existing.call_count = count;
            return;
        }
        built_in_tools.push(BuiltInToolInfo {
            tool_name: build_in_tool::IMAGE_GENERATION.to_owned(),
            call_count: count,
            ..Default::default()
        });
    }
}

// ---------------------------------------------------------------------------
// IsNonBillableResponsesStatus (count_tool_usage.go:180-194)
// ---------------------------------------------------------------------------

/// Reports terminal response statuses that must not bill pending
/// image_generation observations. `status` is the raw JSON value the Go code
/// unmarshals as a string.
pub fn is_non_billable_responses_status(status: Option<&str>) -> bool {
    let Some(status) = status else {
        return false;
    };
    matches!(
        status.trim().to_lowercase().as_str(),
        "failed" | "cancelled" | "canceled" | "incomplete"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(tools: &'a mut Vec<BuiltInToolInfo>, model: &'a str) -> BillableToolContext<'a> {
        BillableToolContext {
            built_in_tools: tools,
            origin_model_name: model,
        }
    }

    fn call_count(tools: &[BuiltInToolInfo], name: &str) -> Option<i64> {
        tools
            .iter()
            .find(|t| t.tool_name == name)
            .map(|t| t.call_count)
    }

    /// Go count_tool_usage_test.go:13-27.
    #[test]
    fn web_search_prefers_declared_web_search() {
        let mut tools = vec![BuiltInToolInfo {
            tool_name: build_in_tool::WEB_SEARCH.to_owned(),
            call_count: 0,
            ..Default::default()
        }];
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::WEB_SEARCH_CALL,
            "",
        );
        assert_eq!(call_count(&tools, build_in_tool::WEB_SEARCH), Some(1));
        assert_eq!(call_count(&tools, build_in_tool::WEB_SEARCH_PREVIEW), None);
    }

    /// Go count_tool_usage_test.go:29-36.
    #[test]
    fn web_search_defaults_to_preview() {
        let mut tools = Vec::new();
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::WEB_SEARCH_CALL,
            "",
        );
        assert_eq!(
            call_count(&tools, build_in_tool::WEB_SEARCH_PREVIEW),
            Some(1)
        );
    }

    /// Go count_tool_usage_test.go:38-51: priced functions count, unpriced
    /// ones do not.
    #[test]
    fn function_call_requires_price() {
        clear_tool_prices_for_test();
        set_tool_price_for_test("my_priced_fn", 5.0);
        let mut tools = Vec::new();
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::FUNCTION_CALL,
            "my_priced_fn",
        );
        assert_eq!(call_count(&tools, "my_priced_fn"), Some(1));

        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::FUNCTION_CALL,
            "unpriced_fn",
        );
        assert_eq!(call_count(&tools, "unpriced_fn"), None);
        clear_tool_prices_for_test();
    }

    /// Go count_tool_usage_test.go:53-67: reserved builtin names are skipped.
    #[test]
    fn function_call_skips_reserved_names() {
        let mut tools = Vec::new();
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::FUNCTION_CALL,
            build_in_tool::WEB_SEARCH_PREVIEW,
        );
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::FUNCTION_CALL,
            build_in_tool::FILE_SEARCH,
        );
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::FUNCTION_CALL,
            build_in_tool::GOOGLE_SEARCH,
        );
        count_billable_tool_call(
            &mut ctx(&mut tools, "gpt-5.1"),
            build_in_call::FUNCTION_CALL,
            build_in_tool::IMAGE_GENERATION,
        );
        assert!(tools.is_empty());
    }

    /// Go count_tool_usage_test.go:69-300 — the observe matrix.
    #[test]
    fn image_generation_counter_matrix() {
        struct Case {
            name: &'static str,
            observe: fn(&mut ImageGenerationCallCounter),
            want: i64,
        }
        fn item(
            id: &str,
            call_id: &str,
            status: &str,
            result: &str,
            item_type: &str,
        ) -> ResponsesOutputInput {
            ResponsesOutputInput {
                item_type: item_type.to_owned(),
                id: id.to_owned(),
                call_id: call_id.to_owned(),
                status: status.to_owned(),
                result: result.to_owned(),
            }
        }
        let cases = vec![
            Case {
                name: "one final result",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "completed",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 1,
            },
            Case {
                name: "two distinct finals",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                    c.observe(
                        &item(
                            "img_2",
                            "",
                            "",
                            "base64-b",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(1),
                    );
                },
                want: 2,
            },
            Case {
                name: "empty result",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "",
                            "   ",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "failed status",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "failed",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "incomplete status",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "incomplete",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "cancelled status",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "cancelled",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "canceled status",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "canceled",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "partial status",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "partial",
                            "partial-bytes",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "id dedup",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "call_a",
                            "",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                    c.observe(
                        &item(
                            "img_1",
                            "call_b",
                            "",
                            "base64-b",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(1),
                    );
                },
                want: 1,
            },
            Case {
                name: "index dedup",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                    c.observe(
                        &item(
                            "img_2",
                            "",
                            "",
                            "base64-b",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 1,
            },
            Case {
                name: "result hash dedup",
                observe: |c| {
                    c.observe(
                        &item(
                            "",
                            "",
                            "",
                            "same-bytes",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                    c.observe(
                        &item(
                            "",
                            "",
                            "",
                            "same-bytes",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(1),
                    );
                },
                want: 1,
            },
            Case {
                name: "output_item.done plus completed dedup",
                observe: |c| {
                    let same = item(
                        "img_1",
                        "call_1",
                        "completed",
                        "base64-a",
                        RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                    );
                    c.observe(&same, Some(0));
                    c.observe(&same, Some(0));
                },
                want: 1,
            },
            Case {
                name: "partial event equals zero",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "",
                            "partial-bytes",
                            "image_generation_call.partial_image",
                        ),
                        Some(0),
                    );
                },
                want: 0,
            },
            Case {
                name: "in_progress with final result counts",
                observe: |c| {
                    c.observe(
                        &item(
                            "img_1",
                            "",
                            "in_progress",
                            "base64-a",
                            RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
                        ),
                        Some(0),
                    );
                },
                want: 1,
            },
        ];
        for case in cases {
            let mut counter = ImageGenerationCallCounter::default();
            (case.observe)(&mut counter);
            assert_eq!(counter.count(), case.want, "case {}", case.name);
        }

        // Reset clears pending observations (Go test case "…plus incomplete
        // equals zero").
        let mut counter = ImageGenerationCallCounter::default();
        counter.observe(
            &item(
                "img_1",
                "",
                "completed",
                "base64-a",
                RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL,
            ),
            Some(0),
        );
        counter.reset();
        assert_eq!(counter.count(), 0);
    }

    /// Go count_tool_usage_test.go:302-320 — commit caps at MaxImageN.
    #[test]
    fn commit_caps_at_max_image_n() {
        let mut counter = ImageGenerationCallCounter::default();
        for i in 0..(MAX_IMAGE_N + 3) {
            counter.observe(
                &ResponsesOutputInput {
                    item_type: RESPONSES_OUTPUT_TYPE_IMAGE_GENERATION_CALL.to_owned(),
                    id: format!("img_{}", "a".repeat((i + 1) as usize)),
                    call_id: String::new(),
                    status: String::new(),
                    result: format!("result-{}", "b".repeat((i + 1) as usize)),
                },
                Some(i),
            );
        }
        assert_eq!(counter.count(), MAX_IMAGE_N + 3);

        let mut tools = Vec::new();
        counter.commit(&mut tools);
        assert_eq!(
            call_count(&tools, build_in_tool::IMAGE_GENERATION),
            Some(MAX_IMAGE_N)
        );
    }

    /// Go count_tool_usage_test.go:322-337 — declarations alone do not bill.
    #[test]
    fn commit_does_not_bill_declarations_alone() {
        let mut tools = vec![BuiltInToolInfo {
            tool_name: build_in_tool::IMAGE_GENERATION.to_owned(),
            call_count: 0,
            ..Default::default()
        }];
        ImageGenerationCallCounter::default().commit(&mut tools);
        assert_eq!(call_count(&tools, build_in_tool::IMAGE_GENERATION), Some(0));
    }

    /// Go count_tool_usage_test.go:339-348.
    #[test]
    fn non_billable_status_table() {
        assert!(is_non_billable_responses_status(Some("failed")));
        assert!(is_non_billable_responses_status(Some("incomplete")));
        assert!(is_non_billable_responses_status(Some("cancelled")));
        assert!(is_non_billable_responses_status(Some("canceled")));
        assert!(!is_non_billable_responses_status(Some("completed")));
        assert!(!is_non_billable_responses_status(None));
    }

    /// Go price_tools_test.go:28-45 — hardcoded fallbacks survive an empty
    /// operator config.
    #[test]
    fn tool_price_builtin_defaults_and_overrides() {
        clear_tool_prices_for_test();
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4o-2024-11-20"),
            25.0
        );
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4.1-mini"),
            25.0
        );
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4o"),
            25.0
        );
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4o-mini"),
            25.0
        );
        assert_eq!(get_tool_price_for_model("web_search_preview", "o1"), 10.0);
        assert_eq!(get_tool_price_for_model("file_search", "claude-3"), 2.5);
        assert_eq!(get_tool_price_for_model("google_search", "any"), 14.0);
        assert_eq!(get_tool_price_for_model("image_generation", "any"), 150.0);
        assert_eq!(get_tool_price_for_model("web_search", "any"), 10.0);
        assert_eq!(get_tool_price_for_model("unknown_tool", "any"), 0.0);
    }

    /// Go price_tools_test.go:48-69 — operator override precedence and
    /// explicit zero.
    #[test]
    fn tool_price_operator_override_precedence() {
        clear_tool_prices_for_test();
        set_tool_price_for_test("image_generation", 0.0);
        set_tool_price_for_test("web_search", 12.0);
        set_tool_price_for_test("web_search_preview", 0.0);
        set_tool_price_for_test("web_search_preview:gpt-4o*", 30.0);
        set_tool_price_for_test("web_search_preview:gpt-4o-mini*", 0.0);
        set_tool_price_for_test("web_search_preview:custom-model*", 7.0);

        assert_eq!(get_tool_price_for_model("image_generation", "any"), 0.0);
        assert_eq!(get_tool_price_for_model("web_search", "any"), 12.0);
        assert_eq!(get_tool_price_for_model("web_search_preview", "o1"), 0.0);
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4o"),
            30.0
        );
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4o-mini"),
            0.0
        );
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4.1"),
            25.0
        );
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "custom-model-v2"),
            7.0
        );

        delete_tool_price_for_test("web_search_preview:gpt-4o*");
        assert_eq!(
            get_tool_price_for_model("web_search_preview", "gpt-4o"),
            25.0
        );
        delete_tool_price_for_test("web_search");
        assert_eq!(get_tool_price_for_model("web_search", "any"), 10.0);
        clear_tool_prices_for_test();
    }

    /// Go price_tools_test.go:72-83 — custom functions have no hardcoded
    /// fallback.
    #[test]
    fn tool_price_custom_function_no_fallback() {
        clear_tool_prices_for_test();
        assert_eq!(get_tool_price_for_model("lookup_customer", ""), 0.0);
        set_tool_price_for_test("lookup_customer", 5.0);
        assert_eq!(get_tool_price_for_model("lookup_customer", ""), 5.0);
        set_tool_price_for_test("lookup_customer", 0.0);
        assert_eq!(get_tool_price_for_model("lookup_customer", ""), 0.0);
        clear_tool_prices_for_test();
    }
}
