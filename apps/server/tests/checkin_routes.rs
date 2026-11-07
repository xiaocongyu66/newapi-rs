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
const CHECKINS: &str = r#"CREATE TABLE checkins (
    id BIGINT PRIMARY KEY,
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

fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/user/checkin", get(checkin_http::checkin_status))
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
/// 月份天数无关（字典序对所有合法日期成立）。
fn expected_records(rows: &[(&str, i64)], month: &str) -> Vec<(String, i64)> {
    let start = format!("{month}-01");
    let end = format!("{month}-31");
    let mut selected: Vec<(String, i64)> = rows
        .iter()
        .map(|(date, quota)| ((*date).to_owned(), *quota))
        .filter(|(date, _)| date.as_str() >= start.as_str() && date.as_str() <= end.as_str())
        .collect();
    // Go `sort.Slice` 按 checkin_date 降序（字符串比较）。
    selected.sort_by(|left, right| right.0.cmp(&left.0));
    selected
}

async fn assert_stats(
    app: &AppState,
    uri: &str,
    auth: &str,
    rows: &[(&str, i64)],
    month: &str,
    all_time_quota: i64,
    all_time_count: i64,
    checked_in_today: bool,
) {
    let body = assert_success(send(app, uri, Some(auth)).await).await;
    let stats = &body["data"]["stats"];
    let expected = expected_records(rows, month);
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
    assert_eq!(stats["total_quota"], json!(all_time_quota), "{body}");
    assert_eq!(
        stats["total_quota_display"],
        json!(display(all_time_quota)),
        "{body}"
    );
    assert_eq!(stats["total_checkins"], json!(all_time_count), "{body}");
    assert_eq!(stats["checked_in_today"], json!(checked_in_today), "{body}");
}

async fn run_contract(db: Database) {
    exec(&db, USERS).await;
    exec(&db, OPTIONS).await;
    exec(&db, CHECKINS).await;
    exec(&db, QQ_CHECKINS).await;
    seed_user(&db, 7, "pat-checkin").await;
    seed_user(&db, 9, "pat-checkin-nine").await;
    let auth = "Bearer pat-checkin";
    let auth_nine = "Bearer pat-checkin-nine";
    let app = state(&db);
    let now = now();
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
        &app,
        "/api/user/checkin",
        auth,
        &merged,
        &month,
        2_000 + 1_500 + 1_200 + 3_000 + 500 + 999,
        6,
        true,
    )
    .await;

    // 空 `month=` 回退当前月（Go `DefaultQuery` 对空值同样回退）。
    assert_stats(
        &app,
        "/api/user/checkin?month=",
        auth,
        &merged,
        &month,
        9_199,
        6,
        true,
    )
    .await;

    // `?month=` 越界文本：Go 不校验格式，字符串区间匹配不到任何记录。
    assert_stats(
        &app,
        "/api/user/checkin?month=abc",
        auth,
        &[],
        "abc",
        9_199,
        6,
        true,
    )
    .await;

    // 40 天前所在月：只有那一条 all-time 行落在窗口内，累计量不变。
    let old_month = month_string(now - 40 * 86_400);
    let old_rows: Vec<(&str, i64)> = vec![(&old_date, 999)];
    assert_stats(
        &app,
        &format!("/api/user/checkin?month={old_month}"),
        auth,
        &old_rows,
        &old_month,
        9_199,
        6,
        true,
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
        &app,
        "/api/user/checkin",
        auth,
        &merged,
        &month,
        9_199,
        6,
        true,
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
        &app,
        "/api/user/checkin",
        auth_nine,
        &nine_merged,
        &month,
        1_600,
        3,
        true,
    )
    .await;
    // 用户 7 的视图不受 user 9 数据影响。
    assert_stats(
        &app,
        "/api/user/checkin",
        auth,
        &merged,
        &month,
        9_199,
        6,
        true,
    )
    .await;

    // 关闭单平台：判定与统计回到 checkins 单表。
    set_option(&db, "checkin_setting.single_platform_only", "0").await;
    assert_stats(
        &app,
        "/api/user/checkin",
        auth_nine,
        &nine_web,
        &month,
        700,
        1,
        false,
    )
    .await;
    assert_stats(
        &app,
        "/api/user/checkin",
        auth,
        &web_rows,
        &month,
        5_699,
        4,
        true,
    )
    .await;
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
