//! 定价缓存与 ratio 设置面的双后端契约（SQLite 内存 + pg_temp PostgreSQL）。
//!
//! PG 变体在 `TEST_POSTGRES_DSN` 缺失时跳过（P1 CI 注入）。断言对齐 Go
//! `catalog/store_pricing.go` / `store_pricing_default.go` /
//! `store_model_extra.go` / `configure_ratio/*` 的可观察行为：
//!
//! - ratio 纯函数：模型名折叠、compact 回退、补全倍率级联（locked）、
//!   audio/image/cache 缺省、`GetModelRatio` 未命中回 37.5。
//! - `RatioSettings::apply_option`：整体替换 + 非法 JSON 保留旧 map。
//! - 定价缓存重建：abilities → 端点推断、分组并集、quota_type 按
//!   ModelPrice 命中选择、禁用模型（status != 1）跳过、规则模型匹配
//!   （prefix/suffix/contains）、`enable_groups`/`quota_types` 快照映射、
//!   默认供应商补建（不存在于 meta 的模型按规则落库 vendors 行）、
//!   pricing_version 挂首个条目。
//! - 缓存失效：`invalidate_pricing_cache` 后下次读取重建；
//!   `refresh_pricing` 绕过 TTL。
//!
//! 注意：全局缓存进程内共享 → 所有子测试串行执行（单一 `contract` 函数
//! 顺序断言，与 `catalog::affinity` 缓存测试同一约定）。

use std::time::Instant;

use newapi_catalog::group_settings::GroupSettings;
use newapi_catalog::pricing::{
    self, PricingSnapshot, default_endpoint_info, get_endpoint_types_by_channel_type,
    is_image_generation_model, is_openai_response_only_model,
};
use newapi_catalog::ratio_settings::RatioSettings;
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::PgPoolOptions,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};

async fn execute(db: &Database, statement: &'static str) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(statement).execute(pool).await.unwrap();
        }
    }
}

async fn create_schema(db: &Database) {
    execute(
        db,
        "CREATE TEMP TABLE models (\
             id BIGINT PRIMARY KEY, \
             model_name TEXT NOT NULL, \
             description TEXT, \
             icon TEXT, \
             tags TEXT, \
             vendor_id BIGINT, \
             endpoints TEXT, \
             status BIGINT DEFAULT 1, \
             sync_official BIGINT DEFAULT 1, \
             created_time BIGINT, \
             updated_time BIGINT, \
             deleted_at TIMESTAMP, \
             name_rule BIGINT DEFAULT 0)",
    )
    .await;
    // SQLite 要 rowid 别名（INTEGER PRIMARY KEY AUTOINCREMENT）才能在
    // RETURNING id 上拿到自增值；PG 用 BIGSERIAL。
    match db {
        Database::Sqlite(_) => {
            execute(
                db,
                "CREATE TEMP TABLE vendors (\
                     id INTEGER PRIMARY KEY AUTOINCREMENT, \
                     name TEXT NOT NULL, \
                     description TEXT, \
                     icon TEXT, \
                     status BIGINT DEFAULT 1, \
                     created_time BIGINT, \
                     updated_time BIGINT, \
                     deleted_at TIMESTAMP)",
            )
            .await;
        }
        Database::Postgres(_) => {
            execute(
                db,
                "CREATE TEMP TABLE vendors (\
                     id BIGSERIAL PRIMARY KEY, \
                     name TEXT NOT NULL, \
                     description TEXT, \
                     icon TEXT, \
                     status BIGINT DEFAULT 1, \
                     created_time BIGINT, \
                     updated_time BIGINT, \
                     deleted_at TIMESTAMP)",
            )
            .await;
        }
    }
    execute(
        db,
        "CREATE TEMP TABLE channels (\
             id BIGINT PRIMARY KEY, \
             name TEXT NOT NULL, \
             \"type\" BIGINT NOT NULL DEFAULT 0, \
             status BIGINT NOT NULL DEFAULT 1, \
             other TEXT)",
    )
    .await;
    execute(
        db,
        "CREATE TEMP TABLE abilities (\
             \"group\" TEXT NOT NULL, \
             model TEXT NOT NULL, \
             channel_id BIGINT NOT NULL, \
             enabled BOOLEAN NOT NULL, \
             tag TEXT, \
             PRIMARY KEY (\"group\", model, channel_id))",
    )
    .await;
    execute(
        db,
        "CREATE TEMP TABLE options (\"key\" TEXT PRIMARY KEY, \"value\" TEXT)",
    )
    .await;
    execute(
        db,
        "CREATE TEMP TABLE gateway_config_revisions (\
             id BIGINT PRIMARY KEY, routing_revision BIGINT NOT NULL)",
    )
    .await;
    execute(
        db,
        "CREATE TEMP TABLE gateway_config_outboxes (\
             id BIGINT PRIMARY KEY, \
             routing_revision BIGINT NOT NULL UNIQUE, \
             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, \
             published_at TIMESTAMP, \
             publish_attempts INTEGER NOT NULL DEFAULT 0, \
             last_publish_error_class VARCHAR(64))",
    )
    .await;
    pricing::invalidate_pricing_cache();
    // 供应商补建（get_or_create_vendor）经 mutate_routing! 推进修订号，
    // 水位单例行必须存在。
    newapi_catalog::gateway_revision::initialize_gateway_config_revision(db)
        .await
        .unwrap();
}

async fn reset(db: &Database) {
    for statement in [
        "DELETE FROM abilities",
        "DELETE FROM channels",
        "DELETE FROM vendors",
        "DELETE FROM models",
        "DELETE FROM options",
    ] {
        execute(db, statement).await;
    }
}

async fn insert_ability(db: &Database, group: &str, model: &str, channel_id: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO abilities (\"group\", model, channel_id, enabled) VALUES (?, ?, ?, ?)",
            )
            .bind(group)
            .bind(model)
            .bind(channel_id)
            .bind(true)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO abilities (\"group\", model, channel_id, enabled) VALUES ($1, $2, $3, $4)")
                .bind(group)
                .bind(model)
                .bind(channel_id)
                .bind(true)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn insert_channel(db: &Database, id: i64, name: &str, channel_type: i64) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO channels (id, name, \"type\") VALUES (?, ?, ?)")
                .bind(id)
                .bind(name)
                .bind(channel_type)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO channels (id, name, \"type\") VALUES ($1, $2, $3)")
                .bind(id)
                .bind(name)
                .bind(channel_type)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

async fn insert_model(
    db: &Database,
    id: i64,
    name: &str,
    status: i64,
    name_rule: i64,
    vendor_id: i64,
) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query(
                "INSERT INTO models (id, model_name, status, name_rule, vendor_id, updated_time) \
                 VALUES (?, ?, ?, ?, ?, 0)",
            )
            .bind(id)
            .bind(name)
            .bind(status)
            .bind(name_rule)
            .bind(vendor_id)
            .execute(pool)
            .await
            .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query(
                "INSERT INTO models (id, model_name, status, name_rule, vendor_id, updated_time) \
                 VALUES ($1, $2, $3, $4, $5, 0)",
            )
            .bind(id)
            .bind(name)
            .bind(status)
            .bind(name_rule)
            .bind(vendor_id)
            .execute(pool)
            .await
            .unwrap();
        }
    }
}

async fn insert_option(db: &Database, key: &str, value: Option<&str>) {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .unwrap();
        }
        Database::Postgres(pool) => {
            sqlx::query("INSERT INTO options (\"key\", \"value\") VALUES ($1, $2)")
                .bind(key)
                .bind(value)
                .execute(pool)
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn sqlite_pricing_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .connect_with(SqliteConnectOptions::new().in_memory(true))
        .await
        .unwrap();
    contract(&Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_pricing_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: sqlx::postgres::PgConnectOptions = dsn.parse().unwrap();
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .idle_timeout(None)
        .max_lifetime(None)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET search_path TO pg_temp")
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options.disable_statement_logging())
        .await
        .unwrap_or_else(|_| panic!("PostgreSQL test connection failed"));
    contract(&Database::Postgres(pool)).await;
}

fn find_pricing<'a>(
    snapshot: &'a PricingSnapshot,
    model: &str,
) -> &'a newapi_catalog::pricing::Pricing {
    snapshot
        .pricing
        .iter()
        .find(|item| item.model_name == model)
        .unwrap_or_else(|| panic!("pricing entry for {model} missing"))
}

/// 全局缓存串行契约：所有子场景按顺序在一个函数里跑（全局缓存共享，
/// 必须串行化）。
async fn contract(db: &Database) {
    create_schema(db).await;
    ratio_pure_contract();
    ratio_option_contract();
    pricing_rebuild_contract(db).await;
    pricing_cache_invalidation_contract(db).await;
}

// ---------------------------------------------------------------------------
// ratio 纯函数（无 DB）
// ---------------------------------------------------------------------------

fn ratio_pure_contract() {
    let ratios = RatioSettings::defaults();

    // Go `GetModelPrice`：命中与 compact 回退。
    assert_eq!(ratios.get_model_price("dall-e-3"), Some(0.04));
    assert_eq!(ratios.get_model_price("unknown-model"), None);
    assert_eq!(
        ratios.get_model_price("glm-4v-openai-compact"),
        None,
        "无通配键时 compact 未命中"
    );

    // Go `GetModelRatio`：命中/未命中 37.5、thinking 折叠。
    assert_eq!(
        ratios.get_model_ratio("gpt-4o"),
        (1.25, true, "gpt-4o".into())
    );
    assert_eq!(
        ratios.get_model_ratio("gpt-4o-2024-05-13"),
        (2.5, true, "gpt-4o-2024-05-13".into())
    );
    let (ratio, found, _) = ratios.get_model_ratio("totally-unknown");
    assert_eq!(ratio, 37.5);
    assert!(!found, "SelfUseModeEnabled 缺省 false");
    assert_eq!(
        ratios
            .get_model_ratio("gemini-2.5-flash-abc-thinking-1024")
            .0,
        0.075,
        "thinking 预算折叠到通配键"
    );
    assert_eq!(ratios.get_model_ratio("gpt-4-gizmo-xyz").0, 15.0);

    // Go `GetCompletionRatio` 级联：locked 硬编码优先于覆盖层。
    assert_eq!(ratios.get_completion_ratio("gpt-4o-2024-05-13"), 3.0);
    assert_eq!(ratios.get_completion_ratio("unknown-model"), 1.0);
    assert_eq!(
        ratios.get_completion_ratio("gemini-2.5-flash-preview-x"),
        3.5 / 0.15
    );

    // 缺省语义。
    assert_eq!(ratios.get_cache_ratio("gpt-4o"), Some(0.5));
    assert_eq!(ratios.get_cache_ratio("unknown"), None);
    assert_eq!(ratios.get_create_cache_ratio("claude-opus-4-8"), Some(1.25));
    assert_eq!(ratios.get_create_cache_ratio("unknown"), None);
    assert_eq!(ratios.get_image_ratio("gpt-image-1"), Some(2.0));
    assert_eq!(ratios.get_image_ratio("unknown"), None);
    assert!(ratios.contains_audio_ratio("gpt-4o-audio-preview"));
    assert_eq!(ratios.get_audio_ratio("gpt-4o-audio-preview"), 16.0);
    assert!(!ratios.contains_audio_ratio("gpt-4o"));
    assert_eq!(ratios.get_audio_ratio("gpt-4o"), 1.0);
    assert!(ratios.contains_audio_completion_ratio("tts-1"));
    assert_eq!(ratios.get_audio_completion_ratio("tts-1"), 0.0);

    // 端点推断（Go `GetEndpointTypesByChannelType`）。
    assert_eq!(
        get_endpoint_types_by_channel_type(14, "claude-3"),
        vec!["anthropic", "openai"]
    );
    assert_eq!(
        get_endpoint_types_by_channel_type(24, "gemini-x"),
        vec!["gemini", "openai"]
    );
    assert_eq!(
        get_endpoint_types_by_channel_type(38, "rerank"),
        vec!["jina-rerank"]
    );
    assert_eq!(
        get_endpoint_types_by_channel_type(0, "o3-pro"),
        vec!["openai-response"]
    );
    assert_eq!(
        get_endpoint_types_by_channel_type(0, "dall-e-3"),
        vec!["image-generation", "openai"]
    );
    assert!(is_openai_response_only_model("openai/o3-pro"));
    assert!(!is_openai_response_only_model("gpt-4o"));
    assert!(is_image_generation_model("flux.1-schnell"));
    assert!(is_image_generation_model("imagen-3.0-generate-002"));

    // 默认端点信息。
    let info = default_endpoint_info("openai").unwrap();
    assert_eq!(info.path, "/v1/chat/completions");
    assert_eq!(info.method, "POST");
    assert!(default_endpoint_info("midjourney").is_none());
}

fn ratio_option_contract() {
    let mut ratios = RatioSettings::defaults();
    // 整体替换（Go `LoadFromJsonString`）。
    assert!(ratios.apply_option("ModelRatio", r#"{"custom-model":2.5}"#));
    assert_eq!(ratios.get_model_ratio("custom-model").0, 2.5);
    assert_eq!(
        ratios.get_model_ratio("gpt-4o").0,
        37.5,
        "替换后默认键不再存在"
    );
    // 非法 JSON 保留旧 map。
    assert!(!ratios.apply_option("ModelRatio", "{bad json"));
    assert_eq!(ratios.get_model_ratio("custom-model").0, 2.5);
    // 非数值条目整体拒绝。
    assert!(!ratios.apply_option("ModelRatio", r#"{"x":"NaN"}"#));
    // 不认识的键 no-op。
    assert!(ratios.apply_option("UnknownKey", r#"{"a":1}"#));
    assert_eq!(ratios.get_model_ratio("custom-model").0, 2.5);
}

// ---------------------------------------------------------------------------
// 定价缓存重建
// ---------------------------------------------------------------------------

async fn pricing_rebuild_contract(db: &Database) {
    reset(db).await;
    // abilities：模型 m-open（渠道 1，OpenAI 类型 0）、m-anthropic（渠道 2，
    // 类型 14）、m-image（渠道 3，dall-e-3 走 image-generation）。
    insert_channel(db, 1, "openai-ch", 0).await;
    insert_channel(db, 2, "anthropic-ch", 14).await;
    insert_channel(db, 3, "image-ch", 0).await;
    insert_ability(db, "default", "m-open", 1).await;
    insert_ability(db, "vip", "m-open", 1).await;
    insert_ability(db, "default", "claude-x-test", 2).await;
    insert_ability(db, "default", "dall-e-3", 3).await;
    // 模型元数据：m-open 有 meta（status 1）、m-anthropic 无 meta（走默认
    // 供应商补建 → Anthropic）、dall-e-3 有 meta 且禁用（status 0 → 跳过）。
    insert_model(db, 10, "m-open", 1, 0, 0).await;
    insert_model(db, 11, "dall-e-3", 0, 0, 0).await;
    // 规则模型：prefix 规则命中 m-rule-1。
    insert_model(db, 12, "m-rule-", 1, 1, 0).await;
    insert_ability(db, "default", "m-rule-1", 1).await;
    // TopupGroupRatio 覆盖（audit 键集读取）。
    insert_option(db, "TopupGroupRatio", Some(r#"{"default":1,"vip":2}"#)).await;

    let ratios = RatioSettings::defaults();
    let groups = GroupSettings::default();
    let snapshot = pricing::refresh_pricing(db, &ratios, &groups)
        .await
        .unwrap();

    // pricing 列表按 model_name 字典序；禁用模型被跳过。
    let names: Vec<&str> = snapshot
        .pricing
        .iter()
        .map(|item| item.model_name.as_str())
        .collect();
    assert_eq!(names, vec!["claude-x-test", "m-open", "m-rule-1"]);

    // m-open：quota_type 0（无 ModelPrice 命中）、completion ratio 来自
    // 硬编码、enable_groups 去重排序、端点 openai。
    let item = find_pricing(&snapshot, "m-open");
    assert_eq!(item.quota_type, 0);
    assert_eq!(item.model_ratio, 37.5);
    assert_eq!(item.enable_groups, vec!["default", "vip"]);
    assert_eq!(item.supported_endpoint_types, vec!["openai"]);
    assert_eq!(item.model_price, 0.0);

    // claude-x-test：无 meta → 默认供应商补建（Anthropic 图标 Claude.Color）。
    let item = find_pricing(&snapshot, "claude-x-test");
    assert_ne!(item.vendor_id, 0);
    assert_eq!(
        snapshot
            .vendors
            .iter()
            .find(|v| v.id == item.vendor_id)
            .unwrap()
            .name,
        "Anthropic"
    );
    assert_eq!(item.supported_endpoint_types, vec!["anthropic", "openai"]);

    // dall-e-3：meta status 0 → 不出 pricing 条目，但端点映射保留
    // （Go modelSupportEndpointTypes 在跳过之前构建）。
    assert_eq!(
        snapshot
            .model_support_endpoint_types
            .get("dall-e-3")
            .unwrap(),
        &vec!["image-generation".to_owned(), "openai".to_owned()]
    );
    assert!(!snapshot.model_enable_groups.contains_key("dall-e-3"));

    // 规则模型：m-rule-1 被 prefix 规则 m-rule- 命中（Go 用规则 meta 覆盖）。
    let item = find_pricing(&snapshot, "m-rule-1");
    assert_eq!(item.quota_type, 0);

    // quota_type 1 路径：ModelPrice 选项命中。
    insert_option(db, "ModelPrice", Some(r#"{"m-open":0.5}"#)).await;
    let mut ratios_with_price = RatioSettings::defaults();
    assert!(ratios_with_price.apply_option("ModelPrice", r#"{"m-open":0.5}"#));
    pricing::invalidate_pricing_cache();
    let snapshot = pricing::refresh_pricing(db, &ratios_with_price, &groups)
        .await
        .unwrap();
    let item = find_pricing(&snapshot, "m-open");
    assert_eq!(item.quota_type, 1);
    assert_eq!(item.model_price, 0.5);

    // 快照映射（Go GetModelEnableGroups/GetModelQuotaTypes）。
    assert_eq!(
        snapshot.model_enable_groups("m-open"),
        vec!["default", "vip"]
    );
    assert_eq!(snapshot.model_quota_types("m-open"), vec![1]);
    assert_eq!(snapshot.model_quota_types("missing"), Vec::<i64>::new());
    assert_eq!(snapshot.model_enable_groups(""), Vec::<String>::new());
    assert_eq!(
        snapshot.model_support_endpoint_types(""),
        Vec::<String>::new()
    );

    // 供应商补建落库（id 回读）。
    let vendor_count: i64 = match db {
        Database::Sqlite(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM vendors")
            .fetch_one(pool)
            .await
            .unwrap(),
        Database::Postgres(pool) => sqlx::query_scalar("SELECT COUNT(*) FROM vendors")
            .fetch_one(pool)
            .await
            .unwrap(),
    };
    assert!(vendor_count >= 1, "Anthropic vendor row persisted");

    // supported_endpoint_map：默认 + 自定义覆盖。
    let info = snapshot
        .supported_endpoint_map
        .get("anthropic")
        .expect("anthropic endpoint info");
    assert_eq!(info.path, "/v1/messages");
    assert_eq!(info.method, "POST");

    // pricing_version 挂在第一个条目（字典序首个 = dall-e-3）。
    assert!(!snapshot.pricing.first().unwrap().pricing_version.is_empty());
    assert_eq!(
        find_pricing(&snapshot, "m-open").pricing_version,
        "",
        "只有首个条目携带版本"
    );

    // 清理：自定义 endpoints 覆盖 supported_endpoint_map。
    reset(db).await;
}

async fn pricing_cache_invalidation_contract(db: &Database) {
    reset(db).await;
    insert_channel(db, 1, "openai-ch", 0).await;
    insert_ability(db, "default", "m-cache", 1).await;
    let ratios = RatioSettings::defaults();
    let groups = GroupSettings::default();
    pricing::invalidate_pricing_cache();
    let first = pricing::get_pricing(db, &ratios, &groups).await.unwrap();
    assert_eq!(first.pricing.len(), 1);

    // TTL 内重复读取命中缓存（同一 Arc）。
    let cached = pricing::get_pricing(db, &ratios, &groups).await.unwrap();
    assert!(std::sync::Arc::ptr_eq(&first, &cached));

    // 新增模型 + 强制刷新 → 立即可见（RefreshPricing 绕过 TTL）。
    insert_ability(db, "default", "m-cache-2", 1).await;
    let refreshed = pricing::refresh_pricing(db, &ratios, &groups)
        .await
        .unwrap();
    assert_eq!(refreshed.pricing.len(), 2);

    // invalidate 后 get_pricing 重建。
    pricing::invalidate_pricing_cache();
    let rebuilt = pricing::get_pricing(db, &ratios, &groups).await.unwrap();
    assert_eq!(rebuilt.pricing.len(), 2);
    let _ = Instant::now();

    reset(db).await;
    pricing::invalidate_pricing_cache();
}
