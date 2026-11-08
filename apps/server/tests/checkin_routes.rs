//! HTTP contracts for `GET /api/user/checkin`.
//!
//! Runs only in remote CI. Every scenario uses an isolated synthetic fixture
//! (in-memory SQLite or an isolated PostgreSQL schema); no service is started.
//! The PostgreSQL test is skipped when `TEST_POSTGRES_DSN` is absent.
//!
//! Fixture shape follows `topup_routes.rs`. Seeded dates are derived from the
//! run-time clock (the handler computes today itself), and the expected month
//! window is recomputed with the same Go string-range rule
//! (`month + "-01"` .. `month + "-31"`) instead of being hardcoded.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    middleware,
    response::Response,
    routing::get,
};
use newapi_billing::checkin::today;
use newapi_server::{AppState, auth::user_auth, checkin_http};
use newapi_storage::Database;
use serde_json::{Value, json};
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::SqlitePoolOptions,
};
use tower::ServiceExt;

static NEXT: AtomicU64 = AtomicU64::new(0);

const SECRET: &str = "checkin-routes-fixture-secret";

const USERS: &str = r#"CREATE TABLE users (
    id BIGINT PRIMARY KEY, username TEXT, display_name TEXT,
    role BIGINT, status INTEGER, email TEXT, github_id TEXT, discord_id TEXT,
    oidc_id TEXT, wechat_id TEXT, telegram_id TEXT, "group" TEXT,
    quota BIGINT, used_quota BIGINT, request_count BIGINT, aff_code TEXT,
    aff_count BIGINT, aff_quota BIGINT, aff_history BIGINT, inviter_id INTEGER,
    linux_do_id TEXT, setting TEXT, stripe_customer TEXT, auth_version BIGINT,
    access_token TEXT, deleted_at TIMESTAMP
)"#;

const OPTIONS: &str = r#"CREATE TABLE options ("key" TEXT PRIMARY KEY, "value" TEXT)"#;

// Go `store_checkin.go:18-24` / `qq_checkin.go:18-26`：两张表都没有
// `deleted_at`，因此 fixture 的 DDL 也不建该列。
// `id` 是 Go 的 `gorm:"primaryKey;autoIncrement"`：SQLite 的
// `INTEGER PRIMARY KEY` 自动成为 rowid 别名，PostgreSQL 则需要显式 serial。
const CHECKINS_SQLITE: &str = r#"CREATE TABLE checkins (
    id INTEGER PRIMARY KEY,
    user_id BIGINT NOT NULL,
    checkin_date VARCHAR(10) NOT NULL,
    quota_awarded BIGINT NOT NULL,
    created_at BIGINT
)"#;

const CHECKINS_POSTGRES: &str = r#"CREATE TABLE checkins (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    checkin_date VARCHAR(10) NOT NULL,
    quota_awarded BIGINT NOT NULL,
    created_at BIGINT
)"#;

const QQ_CHECKINS: &str = r#"CREATE TABLE qq_checkins (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    checkin_date VARCHAR(10) NOT NULL,
    quota_awarded BIGINT NOT NULL,
    open_id VARCHAR(128),
    group_open_id VARCHAR(128),
    created_at BIGINT
)"#;

/// Go `identity/qq_binding.go:16-23`。POST 只在 `require_qq_bound` 开启时读它
/// （`IsQQBoundByUserId` 取一行的 `open_id`）。
const QQ_BINDINGS: &str = r#"CREATE TABLE qq_bindings (
    id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    open_id VARCHAR(128) NOT NULL,
    union_open_id VARCHAR(128),
    username VARCHAR(64),
    created_at BIGINT
)"#;

/// Go `do_checkin.go:79-86` 的成功消息：POST 是手写 `common.H`（与
/// `CtxApiSuccessI18n` 同形、但非同一 helper），因此与 GET 不同，**带** message。
const MSG_CHECKED_IN: &str = "签到成功";
/// Go `do_checkin.go:18` / `:50` `common.CtxApiErrorMsg(c, "签到功能未启用")`。
const MSG_DISABLED: &str = "签到功能未启用";
/// Go `store_checkin.go:108` / `:186`。
const MSG_ALREADY_CHECKED_TODAY: &str = "今日已签到";
/// Go `do_checkin.go:63-66`：带 `code` 的拒绝体。
const MSG_QQ_NOT_BOUND: &str = "请先绑定 QQ 账号后再签到";

/// 默认额度展示快照（USD，`QuotaPerUnit` 500000）：`AppState::default()` 不加载
/// 数据库选项，展示值即 `quota / 500000`。
const QUOTA_PER_UNIT: f64 = 500_000.0;

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

/// `checkins.id` 才是 Go `autoIncrement` 的那一列（`qq_checkins.id` 只由 seed
/// 显式给定，无需序列）。
async fn create_checkins(db: &Database) {
    let ddl = match db {
        Database::Sqlite(_) => CHECKINS_SQLITE,
        Database::Postgres(_) => CHECKINS_POSTGRES,
    };
    exec(db, ddl).await;
}

fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/user/checkin",
            get(checkin_http::checkin_status).post(checkin_http::do_checkin),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), user_auth))
        .with_state(state)
}

fn state(db: &Database) -> AppState {
    // PAT authentication and the handler read only the database.
    AppState::default().bind_runtime(db.clone(), SECRET)
}

async fn exec(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        sqlx::query(statement)
            .execute(pool)
            .await
            .expect("fixture ddl");
    });
}

async fn seed_user(db: &Database, id: i64, token: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",auth_version,access_token)
                VALUES ($1,'fixture','Fixture',1,1,'default',1,$2)"#,
        )
        .bind(id)
        .bind(token)
        .execute(pool)
        .await
        .expect("seed user");
    });
}

/// Upsert: the parse-failure scenarios rewrite the same keys.
async fn set_option(db: &Database, key: &str, value: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO options ("key", "value") VALUES ($1, $2)
               ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value""#,
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("seed option");
    });
}

/// POST 场景专用：显式给出 `quota`，因为 `quota + award` 在 NULL 上得 NULL，
/// 而 Go 的用户行同样非空。
async fn seed_checkin_user(db: &Database, id: i64, token: &str, quota: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO users
                (id,username,display_name,role,status,"group",quota,
                 auth_version,access_token)
                VALUES ($1,'fixture','Fixture',1,1,'default',$2,1,$3)"#,
        )
        .bind(id)
        .bind(quota)
        .bind(token)
        .execute(pool)
        .await
        .expect("seed checkin user");
    });
}

async fn seed_checkin(db: &Database, id: i64, user_id: i64, date: &str, quota: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO checkins (id,user_id,checkin_date,quota_awarded,created_at)
               VALUES ($1,$2,$3,$4,0)"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(date)
        .bind(quota)
        .execute(pool)
        .await
        .expect("seed checkin");
    });
}

async fn seed_qq_checkin(db: &Database, id: i64, user_id: i64, date: &str, quota: i64) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO qq_checkins
                   (id,user_id,checkin_date,quota_awarded,open_id,group_open_id,created_at)
               VALUES ($1,$2,$3,$4,'','',0)"#,
        )
        .bind(id)
        .bind(user_id)
        .bind(date)
        .bind(quota)
        .execute(pool)
        .await
        .expect("seed qq checkin");
    });
}

async fn send(state: &AppState, uri: &str, authorization: Option<&str>) -> Response {
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// POST `?turnstile=`：Go 的 `TurnstileCheck` 从查询串取 token。
async fn send_post(state: &AppState, query: &str, authorization: Option<&str>) -> Response {
    let uri = if query.is_empty() {
        "/api/user/checkin".to_owned()
    } else {
        format!("/api/user/checkin?{query}")
    };
    let mut builder = Request::builder().method("POST").uri(uri);
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    router(state.clone())
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

/// `users.quota`，用于验证发放是否落在同一表上。
async fn stored_quota(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT quota FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("stored quota")
    })
}

/// `checkins` 里 `user_id` 的今日行数，用于验证插入与重复拦截。
async fn checkin_count(db: &Database, user_id: i64) -> i64 {
    backend!(db, pool, {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM checkins WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await
            .expect("checkin count")
    })
}

/// 今日已发放的额度，确认发放值就是响应里的 `quota_awarded`。
async fn today_award(db: &Database, user_id: i64, today: &str) -> Option<i64> {
    backend!(db, pool, {
        sqlx::query_scalar::<_, Option<i64>>(
            "SELECT quota_awarded FROM checkins WHERE user_id = $1 AND checkin_date = $2",
        )
        .bind(user_id)
        .bind(today)
        .fetch_optional(pool)
        .await
        .expect("today award")
        .flatten()
    })
}

async fn bind_qq(db: &Database, user_id: i64, open_id: &str) {
    backend!(db, pool, {
        sqlx::query(
            r#"INSERT INTO qq_bindings (id,user_id,open_id,created_at)
               VALUES ($1,$2,$3,$4)"#,
        )
        .bind(user_id)
        .bind(user_id)
        .bind(open_id)
        .bind(now())
        .execute(pool)
        .await
        .expect("seed qq binding");
    });
}

async fn body_json(response: Response) -> Value {
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body");
    serde_json::from_slice(&bytes).expect("response JSON")
}

/// Go 的成功信封没有 `message` 字段（`do_checkin.go:34-44` 手写 `common.H`）。
async fn assert_success(response: Response) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert!(body.get("message").is_none(), "unexpected message: {body}");
    body
}

/// Go 的失败信封没有 `data` 字段（`common.CtxApiErrorMsg`）。
async fn assert_failure(response: Response, message: &str) -> Value {
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(false), "{body}");
    assert_eq!(body["message"], json!(message), "{body}");
    assert!(body.get("data").is_none(), "unexpected data: {body}");
    body
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// 与生产 `newapi_billing::checkin::datetime` 同一条日界偏移规则（测试独立
/// 复算，复刻 `tz_offset_minutes`）：`CHECKIN_TZ_OFFSET_MINUTES` 显式优先并
/// 钳到 ±720/840 分钟，其次按 Go 部署清单登记过的 `TZ` 名取值，其余（含
/// 缺省）回退 +480 分钟。播种日期与期望月份都必须按这条偏移算：CI 不设这
/// 两个环境变量，服务端日界即 UTC+8——UTC 16:00 之后服务端“今天”比 UTC 的
/// “今天”晚一天，用 UTC 播种会让 `checked_in_today` 与整个统计窗口错位。
fn tz_offset_seconds() -> i64 {
    if let Ok(raw) = std::env::var("CHECKIN_TZ_OFFSET_MINUTES")
        && let Ok(minutes) = raw.trim().parse::<i64>()
    {
        return minutes.clamp(-720, 840) * 60;
    }
    let offset = match std::env::var("TZ").as_deref().map(str::trim) {
        Ok("Asia/Shanghai" | "Asia/Chongqing" | "Asia/Taipei") => 480,
        Ok("" | "UTC" | "Etc/UTC" | "Universal" | "Zulu") => 0,
        _ => 480,
    };
    offset * 60
}

/// Howard Hinnant 逆运算（测试独立复算，与生产 `checkin::datetime` 同算法）。
fn date_string(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = year + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn month_string(epoch: i64) -> String {
    date_string(epoch)[..7].to_owned()
}

fn display(quota: i64) -> f64 {
    quota as f64 / QUOTA_PER_UNIT
}

/// Go 的月份窗口：`month + "-01"` 到 `month + "-31"` 的字符串区间，与实际
/// 月份天数无关。区间由**数据库的**排序规则裁决：SQLite 用 BINARY 字节序（`-`
/// 排在数字前），CI 的 Postgres 集群随镜像默认 `LANG=en_US.UTF-8` 初始化为
/// glibc 规则，标点在主权重被忽略——对这些 ASCII 日期串等价于去掉连字符再
/// 比较。Go 构造的是同一条 SQL，在同一数据库上得到同一批行，端口无须针对
/// 排序规则做任何事；期望随后端走。
fn expected_records(db: &Database, rows: &[(&str, i64)], month: &str) -> Vec<(String, i64)> {
    let start = format!("{month}-01");
    let end = format!("{month}-31");
    let postgres = matches!(db, Database::Postgres(_));
    let in_range = |date: &str| {
        if postgres {
            let date = date.replace('-', "");
            date >= start.replace('-', "") && date <= end.replace('-', "")
        } else {
            date >= start.as_str() && date <= end.as_str()
        }
    };
    let mut selected: Vec<(String, i64)> = rows
        .iter()
        .map(|(date, quota)| ((*date).to_owned(), *quota))
        .filter(|(date, _)| in_range(date))
        .collect();
    // Go `sort.Slice` 按 checkin_date 降序（字符串比较）。
    selected.sort_by(|left, right| right.0.cmp(&left.0));
    selected
}

/// 跨月窗口也不变的三个统计量：累计额度、累计次数、今日是否已签。
/// 收成一个参数，避免 `assert_stats` 的 8 个参数撞上 `too_many_arguments`。
#[derive(Clone, Copy)]
struct AllTime {
    quota: i64,
    count: i64,
    checked_in_today: bool,
}

async fn assert_stats(
    db: &Database,
    app: &AppState,
    uri: &str,
    auth: &str,
    rows: &[(&str, i64)],
    month: &str,
    all_time: AllTime,
) {
    let body = assert_success(send(app, uri, Some(auth)).await).await;
    let stats = &body["data"]["stats"];
    let expected = expected_records(db, rows, month);
    let records = stats["records"].as_array().expect("records");
    assert_eq!(records.len(), expected.len(), "{uri}: {body}");
    for (actual, (date, quota)) in records.iter().zip(&expected) {
        assert_eq!(actual["checkin_date"], json!(date), "{uri}: {body}");
        assert_eq!(actual["quota_awarded"], json!(quota), "{uri}: {body}");
        assert_eq!(
            actual["quota_awarded_display"],
            json!(display(*quota)),
            "{uri}: {body}"
        );
    }
    assert_eq!(
        stats["checkin_count"],
        json!(expected.len() as i64),
        "{body}"
    );
    assert_eq!(stats["total_quota"], json!(all_time.quota), "{body}");
    assert_eq!(
        stats["total_quota_display"],
        json!(display(all_time.quota)),
        "{body}"
    );
    assert_eq!(stats["total_checkins"], json!(all_time.count), "{body}");
    assert_eq!(
        stats["checked_in_today"],
        json!(all_time.checked_in_today),
        "{body}"
    );
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    create_checkins(&db).await;
    exec(&db, QQ_CHECKINS).await;
    seed_user(&db, 7, "pat-checkin").await;
    seed_user(&db, 9, "pat-checkin-nine").await;
    let auth = "Bearer pat-checkin";
    let auth_nine = "Bearer pat-checkin-nine";
    let app = state(&db);
    // 播种与期望都用服务端日界的“现在”：偏移后的 epoch，而非裸 UTC。
    let now = now() + tz_offset_seconds();
    let today = today();
    let month = month_string(now);

    // UserAuth guards the route: no credential is 401.
    assert_eq!(
        send(&app, "/api/user/checkin", None).await.status(),
        StatusCode::UNAUTHORIZED
    );

    // No options: Go process defaults leave checkin disabled.
    assert_failure(
        send(&app, "/api/user/checkin", Some(auth)).await,
        "签到功能未启用",
    )
    .await;

    // Go `strconv.ParseBool` rejects "yes" and keeps the current value, so the
    // feature stays disabled.
    set_option(&db, "checkin_setting.enabled", "yes").await;
    assert_failure(
        send(&app, "/api/user/checkin", Some(auth)).await,
        "签到功能未启用",
    )
    .await;

    // "1" parses: enabled with the Go defaults (1000 / 10000, single platform).
    set_option(&db, "checkin_setting.enabled", "1").await;
    let body = assert_success(send(&app, "/api/user/checkin", Some(auth)).await).await;
    let data = &body["data"];
    assert_eq!(data["enabled"], json!(true));
    assert_eq!(data["min_quota"], json!(1_000));
    assert_eq!(data["min_quota_display"], json!(display(1_000)));
    assert_eq!(data["max_quota"], json!(10_000));
    assert_eq!(data["max_quota_display"], json!(display(10_000)));
    assert_eq!(data["stats"]["records"], json!([]));
    assert_eq!(data["stats"]["checkin_count"], json!(0));
    assert_eq!(data["stats"]["total_quota"], json!(0));
    assert_eq!(data["stats"]["total_quota_display"], json!(0.0));
    assert_eq!(data["stats"]["total_checkins"], json!(0));
    assert_eq!(data["stats"]["checked_in_today"], json!(false));

    // User 7: web rows this month plus one 40-day-old all-time-only row, and
    // QQ rows that the default single-platform mode must merge. Offsets are
    // relative to the run-time clock so month membership is recomputed, not
    // hardcoded.
    let web_today = date_string(now);
    let web_1 = date_string(now - 86_400);
    let web_2 = date_string(now - 2 * 86_400);
    let web_rows: Vec<(&str, i64)> = vec![(&web_today, 2_000), (&web_1, 1_500), (&web_2, 1_200)];
    seed_checkin(&db, 1, 7, web_rows[0].0, 2_000).await;
    seed_checkin(&db, 2, 7, web_rows[1].0, 1_500).await;
    seed_checkin(&db, 3, 7, web_rows[2].0, 1_200).await;
    let qq_3 = date_string(now - 3 * 86_400);
    let qq_4 = date_string(now - 4 * 86_400);
    let qq_rows: Vec<(&str, i64)> = vec![(&qq_3, 3_000), (&qq_4, 500)];
    seed_qq_checkin(&db, 1, 7, qq_rows[0].0, 3_000).await;
    seed_qq_checkin(&db, 2, 7, qq_rows[1].0, 500).await;
    // 40 days back is always in an earlier month (a month spans at most 31
    // days), so this row is all-time-only for every run date.
    let old_date = date_string(now - 40 * 86_400);
    seed_checkin(&db, 4, 7, &old_date, 999).await;

    // 单平台（缺省 true）：合并两条记录列表，全时段跨表求和。
    let mut merged: Vec<(&str, i64)> = Vec::new();
    merged.extend(web_rows.iter().copied());
    merged.extend(qq_rows.iter().copied());
    assert_stats(
        &db,
        &app,
        "/api/user/checkin",
        auth,
        &merged,
        &month,
        AllTime {
            quota: 2_000 + 1_500 + 1_200 + 3_000 + 500 + 999,
            count: 6,
            checked_in_today: true,
        },
    )
    .await;

    // 空 `month=`：Go `DefaultQuery` 只缺键才回退当前月，键在值空时拿到空串，
    // 拼出的 `-01` / `-31` 区间结果完全由数据库排序规则决定（见
    // `expected_records`）：SQLite 一条不匹配，CI 的 Postgres（glibc en_US）
    // 命中全部 0–3 开头的日期——这里播种的六行全部在内。期望全集因此要把
    // `merged` 之外的那条 40 天前老行也加回来；SQLite 下多给的行反正一条
    // 都匹配不上。全时段累计量与 `month=abc` 一样不受窗口影响。
    let mut empty_month_rows: Vec<(&str, i64)> = merged.clone();
    empty_month_rows.push((old_date.as_str(), 999));
    assert_stats(
        &db,
        &app,
        "/api/user/checkin?month=",
        auth,
        &empty_month_rows,
        "",
        AllTime {
            quota: 9_199,
            count: 6,
            checked_in_today: true,
        },
    )
    .await;

    // `?month=` 越界文本：Go 不校验格式，字符串区间匹配不到任何记录。
    assert_stats(
        &db,
        &app,
        "/api/user/checkin?month=abc",
        auth,
        &[],
        "abc",
        AllTime {
            quota: 9_199,
            count: 6,
            checked_in_today: true,
        },
    )
    .await;

    // 40 天前所在月：只有那一条 all-time 行落在窗口内，累计量不变。
    let old_month = month_string(now - 40 * 86_400);
    let old_rows: Vec<(&str, i64)> = vec![(&old_date, 999)];
    assert_stats(
        &db,
        &app,
        &format!("/api/user/checkin?month={old_month}"),
        auth,
        &old_rows,
        &old_month,
        AllTime {
            quota: 9_199,
            count: 6,
            checked_in_today: true,
        },
    )
    .await;

    // 选项解析：坏行保留默认（`updateConfigFromMap` 的 continue），
    // float 文本截断，随后的好行覆盖。
    set_option(&db, "checkin_setting.min_quota", "abc").await;
    let body = assert_success(send(&app, "/api/user/checkin", Some(auth)).await).await;
    assert_eq!(body["data"]["min_quota"], json!(1_000));
    set_option(&db, "checkin_setting.max_quota", "2000.9").await;
    let body = assert_success(send(&app, "/api/user/checkin", Some(auth)).await).await;
    assert_eq!(body["data"]["max_quota"], json!(2_000));
    assert_eq!(body["data"]["max_quota_display"], json!(display(2_000)));
    set_option(&db, "checkin_setting.min_quota", "500").await;
    let body = assert_success(send(&app, "/api/user/checkin", Some(auth)).await).await;
    assert_eq!(body["data"]["min_quota"], json!(500));
    assert_eq!(body["data"]["min_quota_display"], json!(display(500)));
    // 累计量与记录不受配置修正影响。
    assert_stats(
        &db,
        &app,
        "/api/user/checkin",
        auth,
        &merged,
        &month,
        AllTime {
            quota: 9_199,
            count: 6,
            checked_in_today: true,
        },
    )
    .await;

    // User 9: today only in qq_checkins; the single-platform default must
    // still report today as checked in.
    let nine_web_date = date_string(now - 5 * 86_400);
    let nine_web: Vec<(&str, i64)> = vec![(&nine_web_date, 700)];
    seed_checkin(&db, 5, 9, nine_web[0].0, 700).await;
    let nine_qq_old = date_string(now - 6 * 86_400);
    let nine_qq: Vec<(&str, i64)> = vec![(&today, 800), (&nine_qq_old, 100)];
    seed_qq_checkin(&db, 3, 9, nine_qq[0].0, 800).await;
    seed_qq_checkin(&db, 4, 9, nine_qq[1].0, 100).await;
    let mut nine_merged: Vec<(&str, i64)> = Vec::new();
    nine_merged.extend(nine_web.iter().copied());
    nine_merged.extend(nine_qq.iter().copied());
    assert_stats(
        &db,
        &app,
        "/api/user/checkin",
        auth_nine,
        &nine_merged,
        &month,
        AllTime {
            quota: 1_600,
            count: 3,
            checked_in_today: true,
        },
    )
    .await;
    // 用户 7 的视图不受 user 9 数据影响。
    assert_stats(
        &db,
        &app,
        "/api/user/checkin",
        auth,
        &merged,
        &month,
        AllTime {
            quota: 9_199,
            count: 6,
            checked_in_today: true,
        },
    )
    .await;

    // 关闭单平台：判定与统计回到 checkins 单表。
    set_option(&db, "checkin_setting.single_platform_only", "0").await;
    assert_stats(
        &db,
        &app,
        "/api/user/checkin",
        auth_nine,
        &nine_web,
        &month,
        AllTime {
            quota: 700,
            count: 1,
            checked_in_today: false,
        },
    )
    .await;
    assert_stats(
        &db,
        &app,
        "/api/user/checkin",
        auth,
        &web_rows,
        &month,
        AllTime {
            quota: 5_699,
            count: 4,
            checked_in_today: true,
        },
    )
    .await;
}

// ---------------------------------------------------------------------------
// POST /api/user/checkin — Go `billing.DoCheckin`
// ---------------------------------------------------------------------------

async fn run_post_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    create_checkins(&db).await;
    exec(&db, QQ_CHECKINS).await;
    exec(&db, QQ_BINDINGS).await;
    // `quota` 必须显式给值：Go 的 users 行同样非空，且 `quota + x` 在 NULL 上
    // 得 NULL，两个后端都一样，这会让"发放"静默失效。
    seed_checkin_user(&db, 31, "pat-post-checkin", 500_000).await;
    let app = state(&db);
    let auth = "Bearer pat-post-checkin";
    let today = today();

    // ---- 默认关闭 ---------------------------------------------------------
    // Go `do_checkin_setting.go:30` 的 Enabled 缺省 false。
    let response = send_post(&app, "", Some(auth)).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": MSG_DISABLED}),
        "checkin starts disabled, like Go"
    );

    // ---- 一次成功发放 -----------------------------------------------------
    // 区间取等让随机源无分歧：Go `evaluateDailyCheckin` 在 min == max 时直接
    // 返回 min_quota，不调用 rand。
    set_option(&db, "checkin_setting.enabled", "1").await;
    set_option(&db, "checkin_setting.min_quota", "7777").await;
    set_option(&db, "checkin_setting.max_quota", "7777").await;
    let response = send_post(&app, "", Some(auth)).await;
    assert_eq!(
        body_json(response).await,
        json!({
            "success": true,
            "message": MSG_CHECKED_IN,
            "data": {
                "quota_awarded": 7_777,
                "quota_awarded_display": display(7_777),
            },
        }),
        "POST 手写 common.H 带 message；数据字段与 Go 逐字一致"
    );
    assert_eq!(today_award(&db, 31, &today).await, Some(7_777));
    assert_eq!(checkin_count(&db, 31).await, 1);
    assert_eq!(stored_quota(&db, 31).await, 507_777);

    // ---- 重复签到 ---------------------------------------------------------
    // 事务前预判即拦截，不再触达写路径。
    let response = send_post(&app, "", Some(auth)).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": MSG_ALREADY_CHECKED_TODAY})
    );
    assert_eq!(checkin_count(&db, 31).await, 1);
    assert_eq!(stored_quota(&db, 31).await, 507_777);

    // ---- 单平台模式跨两表 -------------------------------------------------
    // 今日只在 qq_checkins 有行时，网页入口也必须报已签到。
    seed_checkin_user(&db, 32, "pat-post-checkin-qq", 100).await;
    seed_qq_checkin(&db, 32, 32, &today, 123).await;
    let response = send_post(&app, "", Some("Bearer pat-post-checkin-qq")).await;
    assert_eq!(
        body_json(response).await,
        json!({"success": false, "message": MSG_ALREADY_CHECKED_TODAY})
    );
    assert_eq!(checkin_count(&db, 32).await, 0);

    // 关闭单平台后，QQ 的行不再挡网页入口。
    set_option(&db, "checkin_setting.single_platform_only", "0").await;
    let response = send_post(&app, "", Some("Bearer pat-post-checkin-qq")).await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(MSG_CHECKED_IN), "{body}");
    assert_eq!(checkin_count(&db, 32).await, 1);
    assert_eq!(stored_quota(&db, 32).await, 7_877);

    // ---- require_qq_bound 门 ----------------------------------------------
    // Go 的顺序：门在 `UserCheckin`（其第一步是重复预判）**之前**，所以一个
    // 今日已签到但未绑 QQ 的用户，先看到的是未绑定提示而不是"今日已签到"。
    set_option(&db, "checkin_setting.single_platform_only", "1").await;
    set_option(&db, "checkin_setting.require_qq_bound", "1").await;
    let response = send_post(&app, "", Some(auth)).await;
    assert_eq!(
        body_json(response).await,
        json!({
            "success": false,
            "code": "qq_not_bound",
            "message": MSG_QQ_NOT_BOUND,
        }),
        "QQ 门先于重复预判：已签到的用户也先看到未绑定提示"
    );
    // 一个全新用户给出同一拒绝体，确认拒绝不依赖用户是否已签到。
    seed_checkin_user(&db, 33, "pat-post-checkin-unbound", 100).await;
    let response = send_post(&app, "", Some("Bearer pat-post-checkin-unbound")).await;
    assert_eq!(
        body_json(response).await,
        json!({
            "success": false,
            "code": "qq_not_bound",
            "message": MSG_QQ_NOT_BOUND,
        }),
        "未绑 QQ 时拒绝体额外带 code"
    );
    assert_eq!(checkin_count(&db, 33).await, 0, "门不应触达写路径");
    // 绑定后放行。
    bind_qq(&db, 33, "open-33").await;
    let response = send_post(&app, "", Some("Bearer pat-post-checkin-unbound")).await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["message"], json!(MSG_CHECKED_IN), "{body}");
    assert_eq!(checkin_count(&db, 33).await, 1);
    // 用户 33 的种子额度是 100，发放 7777 后余量 7877（与上面用户 32 的
    // 7_877 同一算术：种子 100 + 发放 7777）。
    assert_eq!(stored_quota(&db, 33).await, 7_877);

    // ---- 区间宽度与反向区间 ------------------------------------------------
    // 换成未签到的新用户，否则重复预判先命中。
    set_option(&db, "checkin_setting.require_qq_bound", "0").await;
    set_option(&db, "checkin_setting.min_quota", "1000").await;
    set_option(&db, "checkin_setting.max_quota", "10000").await;
    seed_checkin_user(&db, 34, "pat-post-checkin-wide", 0).await;
    let response = send_post(&app, "", Some("Bearer pat-post-checkin-wide")).await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    let awarded = body["data"]["quota_awarded"]
        .as_i64()
        .expect("integer award");
    assert!(
        (1_000..=10_000).contains(&awarded),
        "award {awarded} outside the configured range"
    );
    assert_eq!(today_award(&db, 34, &today).await, Some(awarded));
    assert_eq!(stored_quota(&db, 34).await, awarded);

    // 反向区间被钳成相等：Go `maxQuota < minQuota` 时 `maxQuota = minQuota`。
    set_option(&db, "checkin_setting.min_quota", "3000").await;
    set_option(&db, "checkin_setting.max_quota", "1000").await;
    seed_checkin_user(&db, 35, "pat-post-checkin-reverse", 0).await;
    let response = send_post(&app, "", Some("Bearer pat-post-checkin-reverse")).await;
    let body = body_json(response).await;
    assert_eq!(body["success"], json!(true), "{body}");
    assert_eq!(body["data"]["quota_awarded"], json!(3_000));
    assert_eq!(stored_quota(&db, 35).await, 3_000);

    // ---- Turnstile 未启用时不设卡 ------------------------------------------
    // `AppState::default()` 的 turnstile_check_enabled 为 false，因此不带
    // token 也放行；开启态的行为由 login 的既有用例覆盖。
    seed_checkin_user(&db, 36, "pat-post-checkin-turnstile", 0).await;
    let response = send_post(
        &app,
        "turnstile=",
        Some("Bearer pat-post-checkin-turnstile"),
    )
    .await;
    // 该格区间已被钳成相等（min=3000 / max=1000），发放值可完全写死。
    assert_eq!(
        body_json(response).await,
        json!({
            "success": true,
            "message": MSG_CHECKED_IN,
            "data": {
                "quota_awarded": 3_000,
                "quota_awarded_display": display(3_000),
            },
        }),
        "an empty turnstile token is ignored while the check is disabled"
    );
    assert_eq!(stored_quota(&db, 36).await, 3_000);

    // ---- 鉴权 ------------------------------------------------------------
    let response = send_post(&app, "", None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sqlite_checkin_routes_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_checkin_routes_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect PostgreSQL fixture");
    let schema = format!(
        "checkin_routes_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    assert!(
        schema
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("connect isolated PostgreSQL pool");
    run_contract(Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}

#[tokio::test]
async fn sqlite_post_checkin_contract() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("in-memory SQLite fixture");
    run_post_contract(Database::Sqlite(pool)).await;
}

#[tokio::test]
async fn postgres_post_checkin_contract() {
    let Ok(dsn) = std::env::var("TEST_POSTGRES_DSN") else {
        return;
    };
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("connect PostgreSQL fixture");
    let schema = format!(
        "checkin_post_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    assert!(
        schema
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    );
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE SCHEMA \"{schema}\"")))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path', $1, false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("connect isolated PostgreSQL pool");
    run_post_contract(Database::Postgres(pool)).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema}\" CASCADE"
    )))
    .execute(&admin)
    .await
    .expect("drop isolated schema");
    admin.close().await;
}
