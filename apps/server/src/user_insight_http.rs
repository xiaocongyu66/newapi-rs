//! `/api/user-insight/*` 管理端 HTTP 适配器（用户画像洞察 + 客户端封禁）。
//!
//! Go references:
//! - `apps/api/internal/usage/manage_user_insight.go`：`HandleGetUserInsights`、
//!   `HandleGetUserInsightDetail`、`HandlePurgeUserInsight`、
//!   `HandleGetUserInsightSummary`
//! - `apps/api/internal/usage/manage_client_ban.go`：`HandleGetClientCatalog`、
//!   `HandleSetGlobalClientBan`、`HandleToggleUserClientBan`
//! - `apps/api/internal/usage/user_insight.go`：画像聚合表 `user_insight_profiles`
//!   的读取与清除、`AggregateClientUsage`、`GetInsightUsersByIds`
//! - `apps/api/internal/usage/user_insight_client_ban.go`：`user_insight_client_bans`
//!   的读写、`SanitizeClientID`、`SetGlobalClientBan`
//! - `apps/api/internal/usage/user_insight_log.go`：派生字段
//!   `Ratios` / `PrimaryCategory` / `PrimaryStack` / `GuessedGender` / `RiskLevel`
//! - `apps/api/internal/usage/insight/client.go`：内置客户端识别规则目录
//! - `apps/api/internal/usage/insight/discover.go`：`DiscoveredClientName`
//! - `apps/api/internal/transport/compose/register_api.go:227-241`：路由组
//!   `apiRouter.Group("/user-insight")`，组级只挂 `security.AdminAuth()`。
//!
//! 契约要点（Go 是 oracle）：
//! - 所有业务结果一律 HTTP 200 + `{success,message,data}` 信封；401/403 只来自
//!   鉴权链。参数非法走 `common.ApiErrorI18n(common.invalid_params)`；数据库
//!   错误走 `common.CtxApiError`（200 + 失败信封）。
//! - 列表的筛选（类别/风险/仅中转/关键词）依赖派生结论，在内存里做：无筛选时
//!   SQL 分页（快路径），有筛选时全量扫描（上限 20000 行）、内存筛选后手工切片，
//!   `total` 用筛选后的真实条数。
//! - `keyword` 只匹配画像行的 username 与 user_id（display_name 在分页切片之后
//!   才由 users 表补齐，Go 因此明确不参与搜索）。
//! - DELETE `/:id` 清除画像：删 `user_insight_profiles` 行 + 删
//!   `user_insight_samples` 证据样本，回显删除计数。Go 还会清内存增量缓存
//!   `insightCache` 与自动封禁标记 `autoBanOnce`（进程内存，Rust 侧暂无对应
//!   组件，见交付说明的遗留项）。
//! - summary 是站点级聚合：对每行画像按派生字段归类计数，`clients` 是全部
//!   行 `clients_json` 的累计（Go JSON 序列化 map 按键排序）。
//! - client-ban 分两级：全局档写 option `user_insight_setting.blocked_clients`
//!   （JSON 数组，去重保序，上限 200）；单用户档写 `user_insight_client_bans`
//!   表（(user_id, client) 主键，幂等）。两级都只在画像配置总开关
//!   `client_ban_enabled` 打开时由 relay 中间件执行——那是 relay 切片的事，
//!   本切片只有管理端读写。副作用仅限存储写入：不踢会话、不禁 token。
//! - 请求体解析走 Go `c.RawBody()` + `common.Unmarshal`：只接受 JSON，
//!   空体/非 JSON 是参数错误（与 `BindJSON` 的宽容语义不同）。

use std::collections::BTreeMap;

use axum::{
    Json,
    body::to_bytes,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use sqlx::Row;

use crate::AppState;

const MSG_INVALID_PARAMS: &str = "common.invalid_params";
const MSG_DATABASE_ERROR: &str = "common.database_error";

/// Go `maxInsightProfileScan`：全量扫描的行数上限。
const MAX_PROFILE_SCAN: i64 = 20000;
/// Go `maxClientIDLength`：客户端标识列宽。
const MAX_CLIENT_ID_LENGTH: usize = 64;
/// Go `maxBlockedClients`：全局封禁列表长度上限。
const MAX_BLOCKED_CLIENTS: usize = 200;
/// Go `DiscoveredClientID`：自动发现客户端标识的前缀。
const DISCOVERED_CLIENT_ID: &str = "ua:";
/// Go `dbinfra.UpdateOption("user_insight_setting.blocked_clients", ...)`。
const BLOCKED_CLIENTS_OPTION: &str = "user_insight_setting.blocked_clients";

// Go `insight` 包常量（types.go:126-157 / 106-119）。
const CATEGORY_CODE: &str = "code";
const CATEGORY_ROLEPLAY: &str = "roleplay";
const CATEGORY_QA: &str = "qa";
const CATEGORY_TRANSLATE: &str = "translate";
const CATEGORY_EMBEDDING: &str = "embedding";
const CATEGORY_OTHER: &str = "other";

const STACK_FRONTEND: &str = "frontend";
const STACK_BACKEND: &str = "backend";
const STACK_FULL: &str = "fullstack";
const STACK_INFRA: &str = "infra";
const STACK_MOBILE: &str = "mobile";
const STACK_DATA: &str = "data";
const STACK_UNKNOWN: &str = "unknown";

const GENDER_FEMALE: &str = "female";
const GENDER_MALE: &str = "male";
const GENDER_UNKNOWN: &str = "unknown";
const GENDER_BASIS_SELF_REPORT: &str = "self_report";
const GENDER_BASIS_PREFERENCE: &str = "preference";
const GENDER_BASIS_INVERSE: &str = "inverse";

const JAILBREAK_NONE: &str = "none";
const JAILBREAK_SUSPECT: &str = "suspect";
const JAILBREAK_LIKELY: &str = "likely";
const JAILBREAK_CONFIRMED: &str = "confirmed";

// Go `insight` 包 kind 常量（types.go:106-119）。
const KIND_AGENT_CLI: &str = "agent_cli";
const KIND_IDE: &str = "ide";
const KIND_CHAT_UI: &str = "chat_ui";
const KIND_MOBILE: &str = "mobile";
const KIND_BROWSER: &str = "browser";
const KIND_SDK: &str = "sdk";
const KIND_HTTP_TOOL: &str = "http_tool";
const KIND_DISCOVERED: &str = "discovered";

/// Go `insight.ClientCatalog()`：内置识别规则目录，顺序与 `clientRules`
/// 一致（client.go:38-495）。封禁选择器以它为唯一内置数据源。
const CLIENT_CATALOG: &[(&str, &str, &str)] = &[
    ("claude_code", "Claude Code", KIND_AGENT_CLI),
    ("codex_cli", "Codex CLI", KIND_AGENT_CLI),
    ("opencode", "OpenCode", KIND_AGENT_CLI),
    ("zcode", "ZCode", KIND_AGENT_CLI),
    ("gemini_cli", "Gemini CLI", KIND_AGENT_CLI),
    ("cline", "Cline", KIND_IDE),
    ("roo_code", "Roo Code", KIND_IDE),
    ("kilo_code", "Kilo Code", KIND_IDE),
    ("cursor", "Cursor", KIND_IDE),
    ("windsurf", "Windsurf", KIND_IDE),
    ("copilot", "GitHub Copilot", KIND_IDE),
    ("continue", "Continue", KIND_IDE),
    ("aider", "Aider", KIND_AGENT_CLI),
    ("crush", "Crush", KIND_AGENT_CLI),
    ("droid", "Factory Droid", KIND_AGENT_CLI),
    ("pi", "Pi", KIND_AGENT_CLI),
    ("oh_my_pi", "Oh My Pi", KIND_AGENT_CLI),
    ("qwen_code", "QwenCode", KIND_AGENT_CLI),
    ("sillytavern", "SillyTavern", KIND_CHAT_UI),
    ("rikkahub", "RikkaHub", KIND_MOBILE),
    ("tavo", "Tavo", KIND_MOBILE),
    ("kelivo", "Kelivo", KIND_MOBILE),
    ("vercel_ai_sdk", "Vercel AI SDK", KIND_SDK),
    ("cherry_studio", "Cherry Studio", KIND_CHAT_UI),
    ("chatbox", "Chatbox", KIND_CHAT_UI),
    ("lobechat", "LobeChat", KIND_CHAT_UI),
    ("openwebui", "Open WebUI", KIND_CHAT_UI),
    ("nextchat", "NextChat", KIND_CHAT_UI),
    ("immersive_translate", "Immersive Translate", KIND_SDK),
    ("openai_sdk", "OpenAI SDK", KIND_SDK),
    ("anthropic_sdk", "Anthropic SDK", KIND_SDK),
    ("langchain", "LangChain", KIND_SDK),
    ("curl", "curl", KIND_HTTP_TOOL),
    ("python_requests", "Python requests", KIND_HTTP_TOOL),
    ("httpx", "httpx", KIND_HTTP_TOOL),
    ("aiohttp", "aiohttp", KIND_HTTP_TOOL),
    ("okhttp", "OkHttp", KIND_HTTP_TOOL),
    ("axios", "axios", KIND_HTTP_TOOL),
    ("node_fetch", "node-fetch", KIND_HTTP_TOOL),
    ("go_http", "Go http", KIND_HTTP_TOOL),
    ("deno", "Deno", KIND_HTTP_TOOL),
    ("postman", "Postman", KIND_HTTP_TOOL),
    ("generic_http", "Other HTTP Client", KIND_HTTP_TOOL),
    ("browser", "Web Browser", KIND_BROWSER),
];

/// Go `UserInsightProfile`（user_insight.go:19-78）的一行；数值列统一
/// CAST 成 BIGINT 后读取，兼容 SQLite/PostgreSQL 的整数宽度差异。
#[derive(Debug, Default)]
struct ProfileRow {
    user_id: i64,
    username: String,
    first_seen_at: i64,
    last_seen_at: i64,
    total_requests: i64,
    code_requests: i64,
    roleplay_requests: i64,
    qa_requests: i64,
    translate_requests: i64,
    embedding_requests: i64,
    other_requests: i64,
    frontend_score_sum: i64,
    backend_score_sum: i64,
    infra_requests: i64,
    mobile_requests: i64,
    data_requests: i64,
    male_guess_requests: i64,
    female_guess_requests: i64,
    male_self_report_requests: i64,
    female_self_report_requests: i64,
    male_preference_requests: i64,
    female_preference_requests: i64,
    ai_female_requests: i64,
    ai_male_requests: i64,
    jailbreak_suspect: i64,
    jailbreak_likely: i64,
    jailbreak_confirmed: i64,
    jailbreak_max_score: i64,
    last_jailbreak_at: i64,
    relay_requests: i64,
    clients_json: String,
    relay_vendors_json: String,
    jailbreak_tags_json: String,
    languages_json: String,
}

macro_rules! profile_select {
    ($suffix:literal) => {
        concat!(
            "SELECT user_id, username, ",
            "CAST(first_seen_at AS BIGINT) AS first_seen_at, ",
            "CAST(last_seen_at AS BIGINT) AS last_seen_at, ",
            "CAST(total_requests AS BIGINT) AS total_requests, ",
            "CAST(code_requests AS BIGINT) AS code_requests, ",
            "CAST(roleplay_requests AS BIGINT) AS roleplay_requests, ",
            "CAST(qa_requests AS BIGINT) AS qa_requests, ",
            "CAST(translate_requests AS BIGINT) AS translate_requests, ",
            "CAST(embedding_requests AS BIGINT) AS embedding_requests, ",
            "CAST(other_requests AS BIGINT) AS other_requests, ",
            "CAST(frontend_score_sum AS BIGINT) AS frontend_score_sum, ",
            "CAST(backend_score_sum AS BIGINT) AS backend_score_sum, ",
            "CAST(infra_requests AS BIGINT) AS infra_requests, ",
            "CAST(mobile_requests AS BIGINT) AS mobile_requests, ",
            "CAST(data_requests AS BIGINT) AS data_requests, ",
            "CAST(male_guess_requests AS BIGINT) AS male_guess_requests, ",
            "CAST(female_guess_requests AS BIGINT) AS female_guess_requests, ",
            "CAST(male_self_report_requests AS BIGINT) AS male_self_report_requests, ",
            "CAST(female_self_report_requests AS BIGINT) AS female_self_report_requests, ",
            "CAST(male_preference_requests AS BIGINT) AS male_preference_requests, ",
            "CAST(female_preference_requests AS BIGINT) AS female_preference_requests, ",
            "CAST(ai_female_requests AS BIGINT) AS ai_female_requests, ",
            "CAST(ai_male_requests AS BIGINT) AS ai_male_requests, ",
            "CAST(jailbreak_suspect AS BIGINT) AS jailbreak_suspect, ",
            "CAST(jailbreak_likely AS BIGINT) AS jailbreak_likely, ",
            "CAST(jailbreak_confirmed AS BIGINT) AS jailbreak_confirmed, ",
            "CAST(jailbreak_max_score AS BIGINT) AS jailbreak_max_score, ",
            "CAST(last_jailbreak_at AS BIGINT) AS last_jailbreak_at, ",
            "CAST(relay_requests AS BIGINT) AS relay_requests, ",
            "COALESCE(clients_json, '') AS clients_json, ",
            "COALESCE(relay_vendors_json, '') AS relay_vendors_json, ",
            "COALESCE(jailbreak_tags_json, '') AS jailbreak_tags_json, ",
            "COALESCE(languages_json, '') AS languages_json",
            $suffix
        )
    };
}

const PROFILES_PAGE_SQL: &str =
    profile_select!(" FROM user_insight_profiles ORDER BY last_seen_at DESC LIMIT $1 OFFSET $2");
const PROFILES_PAGE_COUNT_SQL: &str = "SELECT COUNT(*) FROM user_insight_profiles";
const PROFILES_ALL_SQL: &str =
    profile_select!(" FROM user_insight_profiles ORDER BY last_seen_at DESC LIMIT $1");
const PROFILES_COUNT_SQL: &str = "SELECT COUNT(*) FROM user_insight_profiles";
const PROFILES_BY_USER_SQL: &str =
    profile_select!(" FROM user_insight_profiles WHERE user_id = $1");
const PROFILES_CLIENTS_SQL: &str =
    "SELECT COALESCE(clients_json, '') AS clients_json FROM user_insight_profiles LIMIT $1";
const PROFILE_DELETE_SQL: &str = "DELETE FROM user_insight_profiles WHERE user_id = $1";
const SAMPLES_DELETE_SQL: &str = "DELETE FROM user_insight_samples WHERE user_id = $1";
const USERS_BY_IDS_PREFIX: &str = concat!(
    "SELECT CAST(id AS BIGINT) AS id, COALESCE(username, '') AS username, ",
    "COALESCE(display_name, '') AS display_name, ",
    "CAST(status AS BIGINT) AS status, CAST(role AS BIGINT) AS role, ",
    "COALESCE(\"group\", '') AS \"group\" FROM users WHERE id IN "
);
const BANS_BY_USERS_SQL: &str = "SELECT CAST(user_id AS BIGINT) AS user_id, client FROM user_insight_client_bans WHERE user_id IN ";
const BANS_BY_USER_SQL: &str = "SELECT client FROM user_insight_client_bans WHERE user_id = $1";
const BAN_EXISTS_SQL: &str =
    "SELECT COUNT(*) FROM user_insight_client_bans WHERE user_id = $1 AND client = $2";
const BAN_INSERT_SQL: &str =
    "INSERT INTO user_insight_client_bans (user_id, client, created_at) VALUES ($1, $2, $3)";
const BAN_DELETE_SQL: &str =
    "DELETE FROM user_insight_client_bans WHERE user_id = $1 AND client = $2";
const OPTION_GET_SQL: &str = "SELECT value FROM options WHERE \"key\" = $1";
const OPTION_UPSERT_SQL: &str = concat!(
    "INSERT INTO options (\"key\", \"value\") VALUES ($1, $2) ",
    "ON CONFLICT (\"key\") DO UPDATE SET value = $2"
);

/// 复刻 Go `DecodeClientUsage`（user_insight.go:376-385）：解析失败返回
/// 空列表，保证看板在历史脏数据下仍可渲染。成功行的无效项丢弃。
fn decode_client_usage(raw: &str) -> Vec<(String, i64, String)> {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let client = object.get("client")?.as_str()?.to_owned();
            let count = object.get("count").and_then(Value::as_i64)?;
            let version = object
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            Some((client, count, version))
        })
        .collect()
}

/// 复刻 Go `DecodeCounter`：解析计数型 JSON 字段，失败返回空 map。
fn decode_counter(raw: &str) -> BTreeMap<String, i64> {
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(raw) else {
        return BTreeMap::new();
    };
    map.into_iter()
        .filter_map(|(key, value)| value.as_i64().map(|count| (key, count)))
        .collect()
}

/// Go `InsightRatios`（user_insight_log.go:85-107）。分母为 0 时返回 0。
fn profile_ratios(row: &ProfileRow) -> Value {
    let total = row.total_requests as f64;
    let (code, roleplay, qa, translate, other) = if total > 0.0 {
        (
            row.code_requests as f64 / total,
            row.roleplay_requests as f64 / total,
            row.qa_requests as f64 / total,
            row.translate_requests as f64 / total,
            (row.other_requests + row.embedding_requests) as f64 / total,
        )
    } else {
        (0.0, 0.0, 0.0, 0.0, 0.0)
    };
    let stack_total = row.frontend_score_sum + row.backend_score_sum;
    let (frontend, backend) = if stack_total > 0 {
        (
            row.frontend_score_sum as f64 / stack_total as f64,
            row.backend_score_sum as f64 / stack_total as f64,
        )
    } else {
        (0.0, 0.0)
    };
    let gender_total = row.male_guess_requests + row.female_guess_requests;
    let (male, female) = if gender_total > 0 {
        (
            row.male_guess_requests as f64 / gender_total as f64,
            row.female_guess_requests as f64 / gender_total as f64,
        )
    } else {
        (0.0, 0.0)
    };
    json!({
        "code_ratio": go_f64(code),
        "roleplay_ratio": go_f64(roleplay),
        "qa_ratio": go_f64(qa),
        "translate_ratio": go_f64(translate),
        "other_ratio": go_f64(other),
        "frontend_ratio": go_f64(frontend),
        "backend_ratio": go_f64(backend),
        "male_ratio": go_f64(male),
        "female_ratio": go_f64(female),
    })
}

/// Go 的 JSON 数字序列化：整数值的 float64 输出为整数（`1.0` → `1`）。
fn go_f64(value: f64) -> Value {
    if value.is_finite() && value.fract() == 0.0 {
        Value::from(value as i64)
    } else {
        Value::Number(
            serde_json::Number::from_f64(value).unwrap_or(serde_json::Number::from(0_i64)),
        )
    }
}

/// Go `PrimaryCategory`（user_insight_log.go:110-130）：请求量最大的用途
/// 类别；并列时按 code/roleplay/qa/translate/embedding 的枚举顺序取先者。
fn primary_category(row: &ProfileRow) -> &'static str {
    if row.total_requests == 0 {
        return CATEGORY_OTHER;
    }
    let mut best = CATEGORY_OTHER;
    let mut best_count = 0;
    for (name, count) in [
        (CATEGORY_CODE, row.code_requests),
        (CATEGORY_ROLEPLAY, row.roleplay_requests),
        (CATEGORY_QA, row.qa_requests),
        (CATEGORY_TRANSLATE, row.translate_requests),
        (CATEGORY_EMBEDDING, row.embedding_requests),
    ] {
        if count > best_count {
            best = name;
            best_count = count;
        }
    }
    best
}

/// Go `PrimaryStack`（user_infra_log.go:133-160）：专项方向占比过半优先，
/// 否则回到前后端对比，双方都不低于 35% 视为全栈。
fn primary_stack(row: &ProfileRow) -> &'static str {
    if row.code_requests == 0 {
        return STACK_UNKNOWN;
    }
    let half = row.code_requests / 2;
    if row.infra_requests > half {
        return STACK_INFRA;
    }
    if row.mobile_requests > half {
        return STACK_MOBILE;
    }
    if row.data_requests > half {
        return STACK_DATA;
    }
    let front = row.frontend_score_sum;
    let back = row.backend_score_sum;
    if front == 0 && back == 0 {
        return STACK_UNKNOWN;
    }
    let total = front + back;
    if front * 100 >= total * 35 && back * 100 >= total * 35 {
        return STACK_FULL;
    }
    if front > back {
        STACK_FRONTEND
    } else {
        STACK_BACKEND
    }
}

/// Go `GuessedGender`（user_insight_log.go:178-232）与 `pickGender`
/// （248-268）：三档证据按优先级短路——自述（上限 0.9）、内容偏好
/// （折扣 0.7、上限 0.7）、纯反推（折扣 0.4、上限 0.45、样本至少 3 次）。
/// 一致率低于 60% 视为无结论。返回 `(gender, confidence, basis)`，
/// `basis` 为空表示没有结论（Go 的空串由 omitempty 折叠）。
fn guessed_gender(row: &ProfileRow) -> (&'static str, f64, &'static str) {
    // 第一档：自述。
    let self_total = row.male_self_report_requests + row.female_self_report_requests;
    if self_total > 0 {
        let (gender, confidence) = pick_gender(
            row.male_self_report_requests,
            row.female_self_report_requests,
            self_total,
            1.0,
        );
        if gender == GENDER_UNKNOWN {
            return (gender, confidence, "");
        }
        return (gender, confidence.min(0.9), GENDER_BASIS_SELF_REPORT);
    }
    // 第二档：内容偏好。
    let pref_total = row.male_preference_requests + row.female_preference_requests;
    if pref_total > 0 {
        let (gender, confidence) = pick_gender(
            row.male_preference_requests,
            row.female_preference_requests,
            pref_total,
            0.7,
        );
        if gender == GENDER_UNKNOWN {
            return (gender, confidence, "");
        }
        return (gender, confidence.min(0.7), GENDER_BASIS_PREFERENCE);
    }
    // 第三档：纯反向推断。
    let inverse_male =
        (row.male_guess_requests - row.male_self_report_requests - row.male_preference_requests)
            .max(0);
    let inverse_female = (row.female_guess_requests
        - row.female_self_report_requests
        - row.female_preference_requests)
        .max(0);
    let total = inverse_male + inverse_female;
    if total < 3 {
        return (GENDER_UNKNOWN, 0.0, "");
    }
    let (gender, confidence) = pick_gender(inverse_male, inverse_female, total, 0.4);
    if gender == GENDER_UNKNOWN {
        return (gender, confidence, "");
    }
    (gender, confidence.min(0.45), GENDER_BASIS_INVERSE)
}

/// Go `pickGender`：多数方一致率低于 60% 视为无结论。
fn pick_gender(male: i64, female: i64, total: i64, prior: f64) -> (&'static str, f64) {
    if total <= 0 {
        return (GENDER_UNKNOWN, 0.0);
    }
    if male > female {
        let ratio = male as f64 / total as f64;
        if ratio < 0.6 {
            return (GENDER_UNKNOWN, ratio * prior);
        }
        return (GENDER_MALE, ratio * prior);
    }
    if female > male {
        let ratio = female as f64 / total as f64;
        if ratio < 0.6 {
            return (GENDER_UNKNOWN, ratio * prior);
        }
        return (GENDER_FEMALE, ratio * prior);
    }
    (GENDER_UNKNOWN, 0.5 * prior)
}

/// Go `RiskLevel`（user_insight_log.go:271-285）。
fn risk_level(row: &ProfileRow) -> &'static str {
    if row.jailbreak_confirmed >= 3 || row.jailbreak_max_score >= 85 {
        return JAILBREAK_CONFIRMED;
    }
    if row.jailbreak_confirmed > 0 || row.jailbreak_likely >= 3 {
        return JAILBREAK_LIKELY;
    }
    if row.jailbreak_likely > 0 || row.jailbreak_suspect >= 5 {
        return JAILBREAK_SUSPECT;
    }
    JAILBREAK_NONE
}

/// Go `buildInsightView`（manage_user_insight.go:315-356）。
fn profile_view(row: &ProfileRow) -> Value {
    let (gender, confidence, basis) = guessed_gender(row);
    let mut view = json!({
        "user_id": row.user_id,
        "username": row.username,
        "status": 0,
        "role": 0,
        "first_seen_at": row.first_seen_at,
        "last_seen_at": row.last_seen_at,
        "total_requests": row.total_requests,
        "code_requests": row.code_requests,
        "roleplay_requests": row.roleplay_requests,
        "qa_requests": row.qa_requests,
        "translate_requests": row.translate_requests,
        "embedding_requests": row.embedding_requests,
        "other_requests": row.other_requests,
        "primary_category": primary_category(row),
        "primary_stack": primary_stack(row),
        "ratios": profile_ratios(row),
        "guessed_gender": gender,
        "gender_confidence": go_f64(confidence),
        "ai_female_requests": row.ai_female_requests,
        "ai_male_requests": row.ai_male_requests,
        "risk_level": risk_level(row),
        "jailbreak_suspect": row.jailbreak_suspect,
        "jailbreak_likely": row.jailbreak_likely,
        "jailbreak_confirmed": row.jailbreak_confirmed,
        "jailbreak_max_score": row.jailbreak_max_score,
        "last_jailbreak_at": row.last_jailbreak_at,
        "relay_requests": row.relay_requests,
    });
    let object = view.as_object_mut().expect("view object");
    // omitempty 字段：无值时不出现。
    if !basis.is_empty() {
        object.insert("gender_basis".into(), Value::from(basis));
    }
    let tags = decode_counter(&row.jailbreak_tags_json);
    if !tags.is_empty() {
        object.insert("jailbreak_tags".into(), json!(tags));
    }
    let vendors = decode_counter(&row.relay_vendors_json);
    if !vendors.is_empty() {
        object.insert("relay_vendors".into(), json!(vendors));
    }
    let languages = decode_counter(&row.languages_json);
    if !languages.is_empty() {
        object.insert("languages".into(), json!(languages));
    }
    let clients = decode_client_usage(&row.clients_json);
    if !clients.is_empty() {
        let items: Vec<Value> = clients
            .into_iter()
            .map(|(client, count, version)| {
                let mut item = json!({"client": client, "count": count});
                if !version.is_empty() {
                    item["version"] = Value::from(version);
                }
                item
            })
            .collect();
        object.insert("clients".into(), Value::Array(items));
    }
    view
}

/// Go `enrichWithUserStatus`（manage_user_insight.go:359-388）：批量补齐
/// 用户当前状态、角色、分组与显示名；查询失败时静默跳过。
fn enrich_with_user_status(views: &mut [Value], users: &BTreeMap<i64, Value>) {
    for view in views.iter_mut() {
        let user_id = view["user_id"].as_i64().unwrap_or(0);
        let Some(user) = users.get(&user_id) else {
            continue;
        };
        view["status"] = user["status"].clone();
        view["role"] = user["role"].clone();
        if !user["group"].as_str().unwrap_or_default().is_empty() {
            view["group"] = user["group"].clone();
        }
        if !user["display_name"].as_str().unwrap_or_default().is_empty() {
            view["display_name"] = user["display_name"].clone();
        }
        if view["username"].as_str().unwrap_or_default().is_empty() {
            view["username"] = user["username"].clone();
        }
    }
}

/// Go `enrichWithUserClientBans`（manage_user_insight.go:393-410）：补齐
/// 每个用户被"单用户档"封禁的客户端列表；无记录的用户字段不出现。
fn enrich_with_user_client_bans(views: &mut [Value], bans: &BTreeMap<i64, Vec<String>>) {
    for view in views.iter_mut() {
        let user_id = view["user_id"].as_i64().unwrap_or(0);
        if let Some(clients) = bans.get(&user_id) {
            view["disabled_clients"] = json!(clients);
        }
    }
}

/// Go `insightViewMatchesKeyword`（manage_user_insight.go:177-185）：
/// 只匹配画像行的 username 与 user_id。
fn view_matches_keyword(view: &Value, keyword: &str) -> bool {
    if keyword.is_empty() {
        return true;
    }
    let username = view["username"].as_str().unwrap_or_default().to_lowercase();
    if username.contains(keyword) {
        return true;
    }
    view["user_id"]
        .as_i64()
        .unwrap_or(0)
        .to_string()
        .contains(keyword)
}

/// Go `sortInsightViews`（manage_user_insight.go:412-435）：稳定排序。
fn sort_views(views: &mut [Value], sort_by: &str) {
    views.sort_by(|left, right| {
        let key = |view: &Value, field: &str| view[field].as_i64().unwrap_or(0);
        let ordering = match sort_by {
            "requests" => key(right, "total_requests").cmp(&key(left, "total_requests")),
            "risk" => key(right, "jailbreak_max_score").cmp(&key(left, "jailbreak_max_score")),
            "roleplay" => key(right, "roleplay_requests").cmp(&key(left, "roleplay_requests")),
            "code" => key(right, "code_requests").cmp(&key(left, "code_requests")),
            _ => key(right, "last_seen_at").cmp(&key(left, "last_seen_at")),
        };
        ordering
    });
}

// ---- 存储访问（双方言） ------------------------------------------------

fn decode_profile(row: &sqlx::postgres::PgRow) -> ProfileRow {
    let get_i64 = |column: &str| -> i64 {
        row.try_get::<Option<i64>, _>(column)
            .unwrap_or_default()
            .unwrap_or(0)
    };
    let get_text = |column: &str| -> String {
        row.try_get::<Option<String>, _>(column)
            .unwrap_or_default()
            .unwrap_or_default()
    };
    ProfileRow {
        user_id: get_i64("user_id"),
        username: get_text("username"),
        first_seen_at: get_i64("first_seen_at"),
        last_seen_at: get_i64("last_seen_at"),
        total_requests: get_i64("total_requests"),
        code_requests: get_i64("code_requests"),
        roleplay_requests: get_i64("roleplay_requests"),
        qa_requests: get_i64("qa_requests"),
        translate_requests: get_i64("translate_requests"),
        embedding_requests: get_i64("embedding_requests"),
        other_requests: get_i64("other_requests"),
        frontend_score_sum: get_i64("frontend_score_sum"),
        backend_score_sum: get_i64("backend_score_sum"),
        infra_requests: get_i64("infra_requests"),
        mobile_requests: get_i64("mobile_requests"),
        data_requests: get_i64("data_requests"),
        male_guess_requests: get_i64("male_guess_requests"),
        female_guess_requests: get_i64("female_guess_requests"),
        male_self_report_requests: get_i64("male_self_report_requests"),
        female_self_report_requests: get_i64("female_self_report_requests"),
        male_preference_requests: get_i64("male_preference_requests"),
        female_preference_requests: get_i64("female_preference_requests"),
        ai_female_requests: get_i64("ai_female_requests"),
        ai_male_requests: get_i64("ai_male_requests"),
        jailbreak_suspect: get_i64("jailbreak_suspect"),
        jailbreak_likely: get_i64("jailbreak_likely"),
        jailbreak_confirmed: get_i64("jailbreak_confirmed"),
        jailbreak_max_score: get_i64("jailbreak_max_score"),
        last_jailbreak_at: get_i64("last_jailbreak_at"),
        relay_requests: get_i64("relay_requests"),
        clients_json: get_text("clients_json"),
        relay_vendors_json: get_text("relay_vendors_json"),
        jailbreak_tags_json: get_text("jailbreak_tags_json"),
        languages_json: get_text("languages_json"),
    }
}

/// Go `GetUserInsightProfiles`：总数 + 按 last_seen_at 倒序分页。
async fn fetch_profiles_page(
    db: &newapi_storage::Database,
    offset: i64,
    limit: i64,
) -> Result<(Vec<ProfileRow>, i64), sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let total: i64 = sqlx::query_scalar(PROFILES_PAGE_COUNT_SQL)
                .fetch_one(pool)
                .await?;
            let rows = sqlx::query(PROFILES_PAGE_SQL)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;
            Ok((rows.iter().map(decode_sqlite_profile).collect(), total))
        }
        newapi_storage::Database::Postgres(pool) => {
            let total: i64 = sqlx::query_scalar(PROFILES_PAGE_COUNT_SQL)
                .fetch_one(pool)
                .await?;
            let rows = sqlx::query(PROFILES_PAGE_SQL)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await?;
            Ok((rows.iter().map(decode_profile).collect(), total))
        }
    }
}

fn decode_sqlite_profile(row: &sqlx::sqlite::SqliteRow) -> ProfileRow {
    let get_i64 = |column: &str| -> i64 {
        row.try_get::<Option<i64>, _>(column)
            .unwrap_or_default()
            .unwrap_or(0)
    };
    let get_text = |column: &str| -> String {
        row.try_get::<Option<String>, _>(column)
            .unwrap_or_default()
            .unwrap_or_default()
    };
    ProfileRow {
        user_id: get_i64("user_id"),
        username: get_text("username"),
        first_seen_at: get_i64("first_seen_at"),
        last_seen_at: get_i64("last_seen_at"),
        total_requests: get_i64("total_requests"),
        code_requests: get_i64("code_requests"),
        roleplay_requests: get_i64("roleplay_requests"),
        qa_requests: get_i64("qa_requests"),
        translate_requests: get_i64("translate_requests"),
        embedding_requests: get_i64("embedding_requests"),
        other_requests: get_i64("other_requests"),
        frontend_score_sum: get_i64("frontend_score_sum"),
        backend_score_sum: get_i64("backend_score_sum"),
        infra_requests: get_i64("infra_requests"),
        mobile_requests: get_i64("mobile_requests"),
        data_requests: get_i64("data_requests"),
        male_guess_requests: get_i64("male_guess_requests"),
        female_guess_requests: get_i64("female_guess_requests"),
        male_self_report_requests: get_i64("male_self_report_requests"),
        female_self_report_requests: get_i64("female_self_report_requests"),
        male_preference_requests: get_i64("male_preference_requests"),
        female_preference_requests: get_i64("female_preference_requests"),
        ai_female_requests: get_i64("ai_female_requests"),
        ai_male_requests: get_i64("ai_male_requests"),
        jailbreak_suspect: get_i64("jailbreak_suspect"),
        jailbreak_likely: get_i64("jailbreak_likely"),
        jailbreak_confirmed: get_i64("jailbreak_confirmed"),
        jailbreak_max_score: get_i64("jailbreak_max_score"),
        last_jailbreak_at: get_i64("last_jailbreak_at"),
        relay_requests: get_i64("relay_requests"),
        clients_json: get_text("clients_json"),
        relay_vendors_json: get_text("relay_vendors_json"),
        jailbreak_tags_json: get_text("jailbreak_tags_json"),
        languages_json: get_text("languages_json"),
    }
}

/// Go `GetAllUserInsightProfiles`：全量扫描（行数上限 20000）+ 真实总数。
async fn fetch_all_profiles(
    db: &newapi_storage::Database,
) -> Result<(Vec<ProfileRow>, i64), sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let total: i64 = sqlx::query_scalar(PROFILES_COUNT_SQL)
                .fetch_one(pool)
                .await?;
            let rows = sqlx::query(PROFILES_ALL_SQL)
                .bind(MAX_PROFILE_SCAN)
                .fetch_all(pool)
                .await?;
            Ok((rows.iter().map(decode_sqlite_profile).collect(), total))
        }
        newapi_storage::Database::Postgres(pool) => {
            let total: i64 = sqlx::query_scalar(PROFILES_COUNT_SQL)
                .fetch_one(pool)
                .await?;
            let rows = sqlx::query(PROFILES_ALL_SQL)
                .bind(MAX_PROFILE_SCAN)
                .fetch_all(pool)
                .await?;
            Ok((rows.iter().map(decode_profile).collect(), total))
        }
    }
}

/// Go `GetUserInsightProfile`：单行；不存在时 `None`。
async fn fetch_profile(
    db: &newapi_storage::Database,
    user_id: i64,
) -> Result<Option<ProfileRow>, sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let row = sqlx::query(PROFILES_BY_USER_SQL)
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
            Ok(row.map(|row| decode_sqlite_profile(&row)))
        }
        newapi_storage::Database::Postgres(pool) => {
            let row = sqlx::query(PROFILES_BY_USER_SQL)
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
            Ok(row.map(|row| decode_profile(&row)))
        }
    }
}

/// Go `AggregateClientUsage`（user_insight.go:524-552）：内存聚合全部画像
/// 行的客户端计数，按请求量降序、同量按 ID 升序返回。
async fn aggregate_client_usage(
    db: &newapi_storage::Database,
) -> Result<Vec<(String, i64, i64)>, sqlx::Error> {
    let mut requests: BTreeMap<String, i64> = BTreeMap::new();
    let mut users: BTreeMap<String, i64> = BTreeMap::new();
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let rows = sqlx::query(PROFILES_CLIENTS_SQL)
                .bind(MAX_PROFILE_SCAN)
                .fetch_all(pool)
                .await?;
            for row in &rows {
                let raw: String = row
                    .try_get::<Option<String>, _>("clients_json")
                    .unwrap_or_default()
                    .unwrap_or_default();
                for (client, count, _) in decode_client_usage(&raw) {
                    if client.is_empty() {
                        continue;
                    }
                    *requests.entry(client.clone()).or_insert(0) += count;
                    *users.entry(client).or_insert(0) += 1;
                }
            }
        }
        newapi_storage::Database::Postgres(pool) => {
            let rows = sqlx::query(PROFILES_CLIENTS_SQL)
                .bind(MAX_PROFILE_SCAN)
                .fetch_all(pool)
                .await?;
            for row in &rows {
                let raw: String = row
                    .try_get::<Option<String>, _>("clients_json")
                    .unwrap_or_default()
                    .unwrap_or_default();
                for (client, count, _) in decode_client_usage(&raw) {
                    if client.is_empty() {
                        continue;
                    }
                    *requests.entry(client.clone()).or_insert(0) += count;
                    *users.entry(client).or_insert(0) += 1;
                }
            }
        }
    }
    let mut stats: Vec<(String, i64, i64)> = requests
        .into_iter()
        .map(|(client, count)| {
            let users_count = users.get(&client).copied().unwrap_or(0);
            (client, count, users_count)
        })
        .collect();
    stats.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    Ok(stats)
}

/// Go `GetInsightUsersByIds`：批量读取展示字段；列为空时返回空 map。
async fn fetch_users_by_ids(
    db: &newapi_storage::Database,
    ids: &[i64],
) -> Result<BTreeMap<i64, Value>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let placeholders: Vec<String> = (1..=ids.len()).map(|index| format!("${index}")).collect();
    let sql = format!("{}({})", USERS_BY_IDS_PREFIX, placeholders.join(", "));
    let mut users = BTreeMap::new();
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
            for id in ids {
                query = query.bind(*id);
            }
            for row in query.fetch_all(pool).await? {
                users.insert(
                    row.try_get::<Option<i64>, _>("id")?.unwrap_or(0),
                    user_value_sqlite(&row),
                );
            }
        }
        newapi_storage::Database::Postgres(pool) => {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
            for id in ids {
                query = query.bind(*id);
            }
            for row in query.fetch_all(pool).await? {
                users.insert(
                    row.try_get::<Option<i64>, _>("id")?.unwrap_or(0),
                    user_value(&row),
                );
            }
        }
    }
    Ok(users)
}

fn user_value(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "username": row.try_get::<Option<String>, _>("username").unwrap_or_default().unwrap_or_default(),
        "display_name": row.try_get::<Option<String>, _>("display_name").unwrap_or_default().unwrap_or_default(),
        "status": row.try_get::<Option<i64>, _>("status").unwrap_or_default().unwrap_or(0),
        "role": row.try_get::<Option<i64>, _>("role").unwrap_or_default().unwrap_or(0),
        "group": row.try_get::<Option<String>, _>("group").unwrap_or_default().unwrap_or_default(),
    })
}

fn user_value_sqlite(row: &sqlx::sqlite::SqliteRow) -> Value {
    json!({
        "username": row.try_get::<Option<String>, _>("username").unwrap_or_default().unwrap_or_default(),
        "display_name": row.try_get::<Option<String>, _>("display_name").unwrap_or_default().unwrap_or_default(),
        "status": row.try_get::<Option<i64>, _>("status").unwrap_or_default().unwrap_or(0),
        "role": row.try_get::<Option<i64>, _>("role").unwrap_or_default().unwrap_or(0),
        "group": row.try_get::<Option<String>, _>("group").unwrap_or_default().unwrap_or_default(),
    })
}

/// Go `GetUserClientBansByUsers`：批量返回单用户封禁列表；无记录的用户
/// 不出现在结果里。列表元素按库内返回顺序追加（与 Go 一致无显式排序）。
async fn fetch_client_bans_by_users(
    db: &newapi_storage::Database,
    ids: &[i64],
) -> Result<BTreeMap<i64, Vec<String>>, sqlx::Error> {
    let mut bans: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    if ids.is_empty() {
        return Ok(bans);
    }
    let placeholders: Vec<String> = (1..=ids.len()).map(|index| format!("${index}")).collect();
    let sql = format!("{}({})", BANS_BY_USERS_SQL, placeholders.join(", "));
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
            for id in ids {
                query = query.bind(*id);
            }
            for row in query.fetch_all(pool).await? {
                let user_id = row.try_get::<Option<i64>, _>("user_id")?.unwrap_or(0);
                let client: String = row
                    .try_get::<Option<String>, _>("client")?
                    .unwrap_or_default();
                bans.entry(user_id).or_default().push(client);
            }
        }
        newapi_storage::Database::Postgres(pool) => {
            let mut query = sqlx::query(sqlx::AssertSqlSafe(sql.clone()));
            for id in ids {
                query = query.bind(*id);
            }
            for row in query.fetch_all(pool).await? {
                let user_id = row.try_get::<Option<i64>, _>("user_id")?.unwrap_or(0);
                let client: String = row
                    .try_get::<Option<String>, _>("client")?
                    .unwrap_or_default();
                bans.entry(user_id).or_default().push(client);
            }
        }
    }
    Ok(bans)
}

/// Go `GetUserClientBansByUsers(...)[userId]`：单用户封禁列表；无记录为
/// `None`（JSON `null`）。
async fn fetch_client_bans_by_user(
    db: &newapi_storage::Database,
    user_id: i64,
) -> Result<Option<Vec<String>>, sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let rows = sqlx::query(BANS_BY_USER_SQL)
                .bind(user_id)
                .fetch_all(pool)
                .await?;
            Ok(rows_option_list(rows))
        }
        newapi_storage::Database::Postgres(pool) => {
            let rows = sqlx::query(BANS_BY_USER_SQL)
                .bind(user_id)
                .fetch_all(pool)
                .await?;
            Ok(rows_option_list_pg(rows))
        }
    }
}

fn rows_option_list(rows: Vec<sqlx::sqlite::SqliteRow>) -> Option<Vec<String>> {
    if rows.is_empty() {
        return None;
    }
    let mut list = Vec::with_capacity(rows.len());
    for row in &rows {
        list.push(
            row.try_get::<Option<String>, _>("client")
                .unwrap_or_default()
                .unwrap_or_default(),
        );
    }
    Some(list)
}

fn rows_option_list_pg(rows: Vec<sqlx::postgres::PgRow>) -> Option<Vec<String>> {
    if rows.is_empty() {
        return None;
    }
    let mut list = Vec::with_capacity(rows.len());
    for row in &rows {
        list.push(
            row.try_get::<Option<String>, _>("client")
                .unwrap_or_default()
                .unwrap_or_default(),
        );
    }
    Some(list)
}

/// Go `ToggleUserClientBan`（user_insight_client_ban.go:139-162）：
/// ban 为真时 FirstOrCreate（幂等），为假时删除；存在性先查后写，
/// 并发重复按成功处理。
async fn toggle_user_client_ban(
    db: &newapi_storage::Database,
    user_id: i64,
    client: &str,
    ban: bool,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            if ban {
                let exists: i64 = sqlx::query_scalar(BAN_EXISTS_SQL)
                    .bind(user_id)
                    .bind(client)
                    .fetch_one(pool)
                    .await?;
                if exists == 0 {
                    sqlx::query(BAN_INSERT_SQL)
                        .bind(user_id)
                        .bind(client)
                        .bind(created_at)
                        .execute(pool)
                        .await?;
                }
            } else {
                sqlx::query(BAN_DELETE_SQL)
                    .bind(user_id)
                    .bind(client)
                    .execute(pool)
                    .await?;
            }
        }
        newapi_storage::Database::Postgres(pool) => {
            if ban {
                let exists: i64 = sqlx::query_scalar(BAN_EXISTS_SQL)
                    .bind(user_id)
                    .bind(client)
                    .fetch_one(pool)
                    .await?;
                if exists == 0 {
                    sqlx::query(BAN_INSERT_SQL)
                        .bind(user_id)
                        .bind(client)
                        .bind(created_at)
                        .execute(pool)
                        .await?;
                }
            } else {
                sqlx::query(BAN_DELETE_SQL)
                    .bind(user_id)
                    .bind(client)
                    .execute(pool)
                    .await?;
            }
        }
    }
    Ok(())
}

/// Go `PurgeUserInsight` 的库内部分（user_insight.go:483-509）：删除画像行
/// 与证据样本，回显删除计数。内存缓存与自动封禁标记不在 Rust 侧组件内。
async fn purge_user_insight(
    db: &newapi_storage::Database,
    user_id: i64,
) -> Result<(bool, i64), sqlx::Error> {
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            let profile = sqlx::query(PROFILE_DELETE_SQL)
                .bind(user_id)
                .execute(pool)
                .await?;
            let samples = sqlx::query(SAMPLES_DELETE_SQL)
                .bind(user_id)
                .execute(pool)
                .await?;
            Ok((profile.rows_affected() > 0, samples.rows_affected() as i64))
        }
        newapi_storage::Database::Postgres(pool) => {
            let profile = sqlx::query(PROFILE_DELETE_SQL)
                .bind(user_id)
                .execute(pool)
                .await?;
            let samples = sqlx::query(SAMPLES_DELETE_SQL)
                .bind(user_id)
                .execute(pool)
                .await?;
            Ok((profile.rows_affected() > 0, samples.rows_affected() as i64))
        }
    }
}

/// Go `GetBlockedClientList` 的库内读取路径：option
/// `user_insight_setting.blocked_clients` 的 JSON 数组；缺失或解析失败按
/// 空列表处理（与 Go 启动时反射应用失败的回落一致）。
async fn load_blocked_clients(db: &newapi_storage::Database) -> Result<Vec<String>, sqlx::Error> {
    let raw: Option<String> = match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query_scalar(OPTION_GET_SQL)
                .bind(BLOCKED_CLIENTS_OPTION)
                .fetch_optional(pool)
                .await?
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query_scalar(OPTION_GET_SQL)
                .bind(BLOCKED_CLIENTS_OPTION)
                .fetch_optional(pool)
                .await?
        }
    };
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    Ok(serde_json::from_str::<Vec<String>>(&raw).unwrap_or_default())
}

/// Go `SetGlobalClientBan`（user_insight_client_ban.go:80-112）：
/// 去重保序地重建列表；ban 为真且未触顶时追加，为假时移除。写库成功后
/// 内存由 Go 的 ApplyOption 钩子收敛——Rust 侧无内存镜像，读方每请求
/// 读库，语义一致。
async fn save_blocked_clients(
    db: &newapi_storage::Database,
    list: &[String],
) -> Result<(), sqlx::Error> {
    let value = serde_json::to_string(&list).unwrap_or_else(|_| "[]".to_owned());
    match db {
        newapi_storage::Database::Sqlite(pool) => {
            sqlx::query(OPTION_UPSERT_SQL)
                .bind(BLOCKED_CLIENTS_OPTION)
                .bind(value)
                .execute(pool)
                .await?;
        }
        newapi_storage::Database::Postgres(pool) => {
            sqlx::query(OPTION_UPSERT_SQL)
                .bind(BLOCKED_CLIENTS_OPTION)
                .bind(value)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

// ---- HTTP 层 -----------------------------------------------------------

/// Go `strconv.Atoi`：可选符号加十进制数字，无空白。
fn parse_i64(value: Option<&str>) -> Option<i64> {
    value.and_then(|value| value.parse::<i64>().ok())
}

/// 查询串解析：Go `DefaultQuery` / `Query` 的语义——同名键取第一个，
/// 无 axum query feature，手工解码（`+` 为空格、`%XX` 解一字节）。
fn query_value(uri: &Uri, key: &str) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(name) == key {
            return Some(percent_decode(value));
        }
    }
    None
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                match (hex_value(bytes[index + 1]), hex_value(bytes[index + 2])) {
                    (Some(high), Some(low)) => {
                        out.push(high * 16 + low);
                        index += 3;
                    }
                    _ => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn request_language(headers: &HeaderMap) -> String {
    let accept_language = crate::request_lang::accept_language_header(headers);
    crate::request_lang::request_language(accept_language.as_deref())
}

fn translate(headers: &HeaderMap, key: &str) -> String {
    newapi_i18n::translate(
        &request_language(headers),
        key,
        std::iter::empty::<(&str, &str)>(),
    )
}

/// Go `common.ApiErrorI18n`：HTTP 200 + 失败信封，message 走 i18n。
fn invalid_params(headers: &HeaderMap) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, MSG_INVALID_PARAMS),
    }))
    .into_response()
}

/// Go `common.CtxApiError`：HTTP 200 + 失败信封；错误文本不透传数据库内容，
/// 固定用 database_error 键翻译。
fn database_error(headers: &HeaderMap) -> Response {
    Json(json!({
        "success": false,
        "message": translate(headers, MSG_DATABASE_ERROR),
    }))
    .into_response()
}

fn success(data: Option<Value>) -> Response {
    let mut envelope = json!({"success": true, "message": ""});
    envelope["data"] = data.unwrap_or(Value::Null);
    Json(envelope).into_response()
}

/// Go `SanitizeClientID`（user_insight_client_ban.go:51-60）：去首尾空白，
/// 拒绝空串与超长值（长度按字节，与 Go `len` 一致）。
fn sanitize_client_id(client: &str) -> Option<String> {
    let client = client.trim();
    if client.is_empty() || client.len() > MAX_CLIENT_ID_LENGTH {
        return None;
    }
    Some(client.to_owned())
}

/// Go `decodeClientBanRequest`：请求体必须是 JSON 对象
/// （`c.RawBody` + `Unmarshal`，没有 BindJSON 的表单/空体宽容），client
/// 归一化后非空才合法。
#[derive(serde::Deserialize, Default)]
#[serde(default)]
struct ClientBanRequest {
    client: String,
    ban: bool,
}

fn decode_client_ban_request(body: &[u8]) -> Option<ClientBanRequest> {
    if body.is_empty() {
        return None;
    }
    let request = serde_json::from_slice::<ClientBanRequest>(body).ok()?;
    let client = sanitize_client_id(&request.client)?;
    Some(ClientBanRequest {
        client,
        ban: request.ban,
    })
}

/// Go `DiscoveredClientName`（discover.go:236-245）：自动发现项去前缀并把
/// 联合标识写成易读形式；其它 ID 原样返回。
fn discovered_client_name(id: &str) -> String {
    let Some(token) = id.strip_prefix(DISCOVERED_CLIENT_ID) else {
        return id.to_owned();
    };
    match token.split_once('+') {
        Some((ua, vendor_header)) => format!("{ua} ({vendor_header})"),
        None => token.to_owned(),
    }
}

fn now_seconds() -> i64 {
    crate::http::now_seconds()
}

/// `GET /api/user-insight` → Go `usage.HandleGetUserInsights`。
pub async fn list_user_insights(
    State(state): State<AppState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let mut page = parse_i64(query_value(&uri, "p").as_deref()).unwrap_or(1);
    if page < 1 {
        page = 1;
    }
    let mut page_size = parse_i64(query_value(&uri, "page_size").as_deref()).unwrap_or(20);
    if !(1..=100).contains(&page_size) {
        page_size = 20;
    }
    let category = query_value(&uri, "category")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let risk = query_value(&uri, "risk")
        .unwrap_or_default()
        .trim()
        .to_owned();
    let relay_only = query_value(&uri, "relay_only").as_deref() == Some("true");
    let sort_by = query_value(&uri, "sort").unwrap_or_else(|| "last_seen".to_owned());
    let keyword = query_value(&uri, "keyword")
        .unwrap_or_default()
        .trim()
        .to_lowercase();

    let filtered = !category.is_empty() || !risk.is_empty() || relay_only || !keyword.is_empty();

    // 快路径：无筛选时 SQL 分页；有筛选时全量扫描 + 内存筛选，total 用
    // 筛选后的真实条数（Go manage_user_insight.go:82-154）。
    let result = if !filtered {
        fetch_profiles_page(&db, (page - 1) * page_size, page_size).await
    } else {
        fetch_all_profiles(&db).await
    };
    let (rows, total) = match result {
        Ok(result) => result,
        Err(_) => return database_error(&headers),
    };

    let mut views: Vec<Value> = rows.iter().map(profile_view).collect();
    let response_total;
    if filtered {
        views.retain(|view| {
            if !category.is_empty() && view["primary_category"].as_str() != Some(category.as_str())
            {
                return false;
            }
            if !risk.is_empty() && view["risk_level"].as_str() != Some(risk.as_str()) {
                return false;
            }
            if relay_only && view["relay_requests"].as_i64().unwrap_or(0) == 0 {
                return false;
            }
            view_matches_keyword(view, &keyword)
        });
        // 先排序再切片：total 是筛选后的真实条数（Go 切片前保存）。
        sort_views(&mut views, &sort_by);
        response_total = views.len() as i64;
        let real_total = views.len() as i64;
        let start = ((page - 1) * page_size).min(real_total);
        let end = (start + page_size).min(real_total);
        views = views[start as usize..end as usize].to_vec();
    } else {
        sort_views(&mut views, &sort_by);
        response_total = total;
    }

    // enrichWithUserStatus + enrichWithUserClientBans：状态查询失败时封禁
    // 标记仍要展示（Go 各自吞错）。
    let ids: Vec<i64> = views
        .iter()
        .filter_map(|view| view["user_id"].as_i64())
        .collect();
    if let Ok(users) = fetch_users_by_ids(&db, &ids).await {
        enrich_with_user_status(&mut views, &users);
    }
    if let Ok(bans) = fetch_client_bans_by_users(&db, &ids).await {
        enrich_with_user_client_bans(&mut views, &bans);
    }

    Json(json!({
        "success": true,
        "message": "",
        "data": {
            "items": views,
            "total": response_total,
            "page": page,
            "size": page_size,
        },
    }))
    .into_response()
}

/// `GET /api/user-insight/:id` → Go `usage.HandleGetUserInsightDetail`。
/// 画像不存在时 `data` 为 `null`。
pub async fn get_user_insight_detail(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(user_id) = user_id.parse::<i64>() else {
        return invalid_params(&headers);
    };
    if user_id <= 0 {
        return invalid_params(&headers);
    }
    let row = match fetch_profile(&db, user_id).await {
        Ok(row) => row,
        Err(_) => return database_error(&headers),
    };
    let Some(row) = row else {
        return success(None);
    };
    let mut views = vec![profile_view(&row)];
    let ids = [user_id];
    if let Ok(users) = fetch_users_by_ids(&db, &ids).await {
        enrich_with_user_status(&mut views, &users);
    }
    if let Ok(bans) = fetch_client_bans_by_users(&db, &ids).await {
        enrich_with_user_client_bans(&mut views, &bans);
    }
    success(Some(views.remove(0)))
}

/// `DELETE /api/user-insight/:id` → Go `usage.HandlePurgeUserInsight`：
/// 清除画像行与证据样本；操作经 tracing 记录（Go `common.SysLog`）。
pub async fn purge_user_insight_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let headers = request.headers().clone();
    let Ok(user_id) = user_id.parse::<i64>() else {
        return invalid_params(&headers);
    };
    if user_id <= 0 {
        return invalid_params(&headers);
    }
    let (profile_deleted, samples_deleted) = match purge_user_insight(&db, user_id).await {
        Ok(result) => result,
        Err(_) => return database_error(&headers),
    };
    tracing::info!(
        target: "newapi::insight",
        event = "insight purged",
        user_id,
        profile_deleted,
        samples_deleted
    );
    success(Some(json!({
        "profile_deleted": profile_deleted,
        "samples_deleted": samples_deleted,
    })))
}

/// `GET /api/user-insight/summary` → Go `usage.HandleGetUserInsightSummary`：
/// 站点级聚合，派生字段在内存归类；`clients` 是全部行 `clients_json` 的累计。
pub async fn get_user_insight_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (rows, total) = match fetch_all_profiles(&db).await {
        Ok(result) => result,
        Err(_) => return database_error(&headers),
    };
    let mut summary = json!({
        "total_users": total,
        "coders": 0,
        "roleplayers": 0,
        "qa_users": 0,
        "frontend_leaning": 0,
        "backend_leaning": 0,
        "male_leaning": 0,
        "female_leaning": 0,
        "male_self_report": 0,
        "female_self_report": 0,
        "relay_users": 0,
        "risky_users": 0,
    });
    let mut client_totals: BTreeMap<String, i64> = BTreeMap::new();
    let bump = |summary: &mut Value, key: &str| {
        summary[key] = json!(summary[key].as_i64().unwrap_or(0) + 1);
    };
    for row in &rows {
        match primary_category(row) {
            CATEGORY_CODE => bump(&mut summary, "coders"),
            CATEGORY_ROLEPLAY => bump(&mut summary, "roleplayers"),
            CATEGORY_QA => bump(&mut summary, "qa_users"),
            _ => {}
        }
        match primary_stack(row) {
            STACK_FRONTEND => bump(&mut summary, "frontend_leaning"),
            STACK_BACKEND => bump(&mut summary, "backend_leaning"),
            _ => {}
        }
        let (gender, _, basis) = guessed_gender(row);
        match gender {
            GENDER_MALE => {
                bump(&mut summary, "male_leaning");
                if basis == GENDER_BASIS_SELF_REPORT {
                    bump(&mut summary, "male_self_report");
                }
            }
            GENDER_FEMALE => {
                bump(&mut summary, "female_leaning");
                if basis == GENDER_BASIS_SELF_REPORT {
                    bump(&mut summary, "female_self_report");
                }
            }
            _ => {}
        }
        if row.relay_requests > 0 {
            bump(&mut summary, "relay_users");
        }
        if risk_level(row) != JAILBREAK_NONE {
            bump(&mut summary, "risky_users");
        }
        for (client, count, _) in decode_client_usage(&row.clients_json) {
            *client_totals.entry(client).or_insert(0) += count;
        }
    }
    summary["clients"] = json!(client_totals);
    success(Some(summary))
}

/// `GET /api/user-insight/client-catalog` → Go `usage.HandleGetClientCatalog`：
/// 内置规则目录在前（顺序同 Go clientRules），观测数据并入对应项；
/// 目录里没有的观测 ID 以 discovered 形态追加。
pub async fn get_client_catalog(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let observed = match aggregate_client_usage(&db).await {
        Ok(stats) => stats,
        Err(_) => return database_error(&headers),
    };
    let mut views: Vec<Value> = CLIENT_CATALOG
        .iter()
        .map(|(id, name, kind)| {
            json!({
                "id": id,
                "name": name,
                "kind": kind,
                "built_in": true,
                "requests": 0,
                "users": 0,
            })
        })
        .collect();
    let mut indexes: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, (id, _, _)) in CLIENT_CATALOG.iter().enumerate() {
        indexes.insert(id, index);
    }
    for (client, requests, users) in observed {
        if let Some(index) = indexes.get(client.as_str()) {
            views[*index]["requests"] = json!(requests);
            views[*index]["users"] = json!(users);
            continue;
        }
        // 画像里出现过但目录里没有：自动发现或规则遗留，仍可勾选封禁。
        views.push(json!({
            "id": client,
            "name": discovered_client_name(&client),
            "kind": KIND_DISCOVERED,
            "built_in": false,
            "requests": requests,
            "users": users,
        }));
    }
    success(Some(Value::Array(views)))
}

/// `POST /api/user-insight/client-ban` → Go `usage.HandleSetGlobalClientBan`：
/// 全站封禁/解封一个客户端，写 option `user_insight_setting.blocked_clients`。
pub async fn set_global_client_ban(State(state): State<AppState>, request: Request) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers.clone();
    let bytes = match to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return invalid_params(&headers),
    };
    let Some(payload) = decode_client_ban_request(&bytes) else {
        return invalid_params(&headers);
    };
    let mut list = match load_blocked_clients(&db).await {
        Ok(list) => list,
        Err(_) => return database_error(&headers),
    };
    // Go：去重保序重建；ban 时未触顶才追加，unban 时移除。
    let target = payload.client.clone();
    list.retain(|existing| existing != &target);
    if payload.ban && list.len() < MAX_BLOCKED_CLIENTS {
        list.push(target.clone());
    }
    if save_blocked_clients(&db, &list).await.is_err() {
        return database_error(&headers);
    }
    tracing::info!(
        target: "newapi::insight",
        event = "insight global client ban",
        client = %target,
        ban = payload.ban
    );
    success(Some(json!({
        "client": target,
        "ban": payload.ban,
        "blocked_clients": list,
    })))
}

/// `POST /api/user-insight/:id/client-ban` → Go
/// `usage.HandleToggleUserClientBan`：单用户档封禁/解封，写
/// `user_insight_client_bans`；不影响该用户的其它客户端，也不踢会话。
pub async fn toggle_user_client_ban_handler(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
    request: Request,
) -> Response {
    let Some(db) = state.db() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let (parts, body) = request.into_parts();
    let headers = parts.headers.clone();
    let Ok(user_id) = user_id.parse::<i64>() else {
        return invalid_params(&headers);
    };
    if user_id <= 0 {
        return invalid_params(&headers);
    }
    let bytes = match to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return invalid_params(&headers),
    };
    let Some(payload) = decode_client_ban_request(&bytes) else {
        return invalid_params(&headers);
    };
    if toggle_user_client_ban(&db, user_id, &payload.client, payload.ban, now_seconds())
        .await
        .is_err()
    {
        return database_error(&headers);
    }
    tracing::info!(
        target: "newapi::insight",
        event = "insight user client ban",
        user_id,
        client = %payload.client,
        ban = payload.ban
    );
    let disabled = match fetch_client_bans_by_user(&db, user_id).await {
        Ok(disabled) => disabled,
        Err(_) => return database_error(&headers),
    };
    success(Some(json!({
        "user_id": user_id,
        "client": payload.client,
        "ban": payload.ban,
        "disabled_clients": disabled,
    })))
}
