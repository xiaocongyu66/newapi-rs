//! 策略只读求值契约；SQLite 与隔离 schema 的 PostgreSQL 均真实执行。
use newapi_identity::policy::{
    ADMIN_ROLE, CATALOG, CasbinRuleRepository, Permission, ROOT_ROLE, Role, RuleEffect, can,
    capabilities, is_known_permission, role_from_system_role, role_subject, self_user_permissions,
    user_subject,
};
use newapi_identity::self_user::SidebarModulePermission;
use newapi_storage::Database;
use sqlx::{
    ConnectOptions,
    postgres::{PgConnectOptions, PgPoolOptions},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

macro_rules! backend {
    ($db:expr, $pool:ident, $body:block) => {
        match $db {
            Database::Sqlite($pool) => $body,
            Database::Postgres($pool) => $body,
        }
    };
}

fn checked<T>(result: Result<T, sqlx::Error>, action: &'static str) -> T {
    result.unwrap_or_else(|_| panic!("policy fixture failed: {action}"))
}

async fn execute(db: &Database, statement: &'static str) {
    backend!(db, pool, {
        checked(
            sqlx::QueryBuilder::new(statement)
                .build()
                .execute(pool)
                .await,
            "execute fixed SQL",
        );
    });
}

async fn allow(db: &Database, subject: &str, resource: &str, action: &str) {
    backend!(db, pool, {
        let mut query =
            sqlx::QueryBuilder::new("INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p',");
        query
            .push_bind(subject)
            .push(",")
            .push_bind(resource)
            .push(",")
            .push_bind(action)
            .push(",'allow')");
        checked(query.build().execute(pool).await, "seed allow");
    });
}

async fn deny(db: &Database, subject: &str, resource: &str, action: &str) {
    backend!(db, pool, {
        let mut query =
            sqlx::QueryBuilder::new("INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p',");
        query
            .push_bind(subject)
            .push(",")
            .push_bind(resource)
            .push(",")
            .push_bind(action)
            .push(",'deny')");
        checked(query.build().execute(pool).await, "seed deny");
    });
}

const SYSTEM: Permission = Permission {
    resource: "system",
    action: "settings",
};

async fn create_rules(db: &Database) {
    // 两种驱动的主键自增语法不同；其余列与生产 CasbinRule 对齐。
    match db {
        Database::Sqlite(pool) => {
            checked(
                sqlx::query(
                    "CREATE TABLE casbin_rule (id INTEGER PRIMARY KEY AUTOINCREMENT, ptype TEXT, v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT)",
                )
                .execute(pool)
                .await,
                "create SQLite rules",
            );
        }
        Database::Postgres(pool) => {
            checked(
                sqlx::query(
                    "CREATE TABLE casbin_rule (id BIGSERIAL PRIMARY KEY, ptype TEXT, v0 TEXT, v1 TEXT, v2 TEXT, v3 TEXT, v4 TEXT, v5 TEXT)",
                )
                .execute(pool)
                .await,
                "create PostgreSQL rules",
            );
        }
    }
}

async fn scenarios(db: &Database) {
    create_rules(db).await;
    let repo = CasbinRuleRepository::new(db.clone());

    // 角色映射边界与 Go resolveSubjectRoles 一致。
    assert_eq!(role_from_system_role(100).map(|r| r.key()), Some(ROOT_ROLE));
    assert_eq!(
        role_from_system_role(1000).map(|r| r.key()),
        Some(ROOT_ROLE)
    );
    assert_eq!(role_from_system_role(10).map(|r| r.key()), Some(ADMIN_ROLE));
    assert_eq!(role_from_system_role(99).map(|r| r.key()), Some(ADMIN_ROLE));
    assert!(role_from_system_role(9).is_none());
    assert!(role_from_system_role(1).is_none());
    assert!(role_from_system_role(0).is_none());
    assert!(role_from_system_role(-1).is_none());

    // 目录必须与 Go registry 相同，未知权限不参与求值。
    assert_eq!(CATALOG.len(), 2);
    assert_eq!(CATALOG[0].resource, "channel");
    assert_eq!(CATALOG[0].actions.len(), 5);
    assert_eq!(CATALOG[1].resource, "system");
    assert_eq!(CATALOG[1].actions.len(), 1);
    assert!(is_known_permission(SYSTEM));
    assert!(!is_known_permission(Permission {
        resource: "system",
        action: "unknown",
    }));

    // 超级用户在未知权限上同样放行：Go 先判超级用户，再判已知权限。
    assert!(checked(can(&repo, 7, 100, SYSTEM).await, "root superuser"));
    assert!(checked(
        can(
            &repo,
            7,
            100,
            Permission {
                resource: "system",
                action: "unknown",
            },
        )
        .await,
        "root unknown permission"
    ));

    // 无任何规则时管理员拒绝。
    assert!(!checked(
        can(&repo, 7, 10, SYSTEM).await,
        "admin without rules"
    ));

    // 角色基线来自 casbin_rule，而不是静态 default_roles。
    allow(db, &role_subject(Role::Admin), "system", "settings").await;
    assert!(checked(can(&repo, 7, 10, SYSTEM).await, "admin role allow"));

    // 用户覆盖优先于角色基线；deny 覆盖同主体的 allow。
    allow(db, &user_subject(7), "system", "settings").await;
    assert!(checked(can(&repo, 7, 10, SYSTEM).await, "user allow"));
    deny(db, &user_subject(7), "system", "settings").await;
    assert!(!checked(can(&repo, 7, 10, SYSTEM).await, "user deny wins"));

    // 另一个用户不受影响。
    assert!(checked(
        can(&repo, 8, 10, SYSTEM).await,
        "other admin role allow"
    ));

    // 未知权限即使存在用户规则也不放行（非超级用户）。
    allow(db, &user_subject(9), "system", "unknown").await;
    assert!(!checked(
        can(
            &repo,
            9,
            10,
            Permission {
                resource: "system",
                action: "unknown",
            },
        )
        .await,
        "admin unknown permission"
    ));

    // 普通系统角色在读取任何规则前即拒绝，包括显式用户授权。
    allow(db, &user_subject(11), "system", "settings").await;
    assert!(!checked(
        can(&repo, 11, 1, SYSTEM).await,
        "plain user denied"
    ));

    // 空效果与 NULL 按旧格式视为 allow；未知效果忽略。
    assert_eq!(
        checked(
            repo.subject_effect(&user_subject(20), SYSTEM).await,
            "empty subject"
        ),
        None
    );
    execute(
        db,
        "INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p','user:20','system','settings','')",
    )
    .await;
    assert_eq!(
        checked(
            repo.subject_effect(&user_subject(20), SYSTEM).await,
            "empty effect"
        ),
        Some(RuleEffect::Allow)
    );
    execute(
        db,
        "INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p','user:21','system','settings',NULL)",
    )
    .await;
    assert_eq!(
        checked(
            repo.subject_effect(&user_subject(21), SYSTEM).await,
            "null effect"
        ),
        Some(RuleEffect::Allow)
    );
    execute(
        db,
        "INSERT INTO casbin_rule (ptype,v0,v1,v2,v3) VALUES ('p','user:22','system','settings','other')",
    )
    .await;
    assert_eq!(
        checked(
            repo.subject_effect(&user_subject(22), SYSTEM).await,
            "unknown effect"
        ),
        None
    );

    // 完整矩阵来自静态目录，不包含未注册动作。
    let matrix = checked(capabilities(&repo, 8, 10).await, "capabilities");
    assert_eq!(matrix.len(), 2);
    assert_eq!(matrix["channel"].len(), 5);
    assert_eq!(matrix["system"].len(), 1);
    assert!(matrix["system"]["settings"]);
    assert!(!matrix["channel"]["read"]);

    let root_matrix = checked(capabilities(&repo, 8, 100).await, "root capabilities");
    assert!(root_matrix["channel"].values().all(|allowed| *allowed));
    assert!(root_matrix["system"]["settings"]);

    // SelfUser 权限载荷与 Go calculateUserPermissions 形状一致。
    let root = checked(
        self_user_permissions(&repo, 8, 100).await,
        "root permissions",
    );
    assert!(!root.sidebar_settings);
    assert!(root.sidebar_modules.is_empty());
    assert!(root.admin_permissions["system"]["settings"]);

    let admin = checked(
        self_user_permissions(&repo, 8, 10).await,
        "admin permissions",
    );
    assert!(admin.sidebar_settings);
    assert_eq!(
        admin.sidebar_modules["admin"],
        SidebarModulePermission::Actions(BTreeMap::from([("setting".to_owned(), true)]))
    );
    assert!(admin.admin_permissions["system"]["settings"]);

    let user = checked(self_user_permissions(&repo, 9, 1).await, "user permissions");
    assert!(user.sidebar_settings);
    assert_eq!(
        user.sidebar_modules["admin"],
        SidebarModulePermission::Enabled(false)
    );
    assert!(!user.admin_permissions["system"]["settings"]);
    assert!(!user.admin_permissions["channel"]["read"]);

    for role in [11, 99, 101] {
        let permissions = checked(
            self_user_permissions(&repo, 8, role).await,
            "nonstandard role sidebar",
        );
        assert!(permissions.sidebar_settings);
        assert_eq!(
            permissions.sidebar_modules["admin"],
            SidebarModulePermission::Enabled(false)
        );
    }
}

#[tokio::test]
async fn sqlite_policy_contract() {
    let options = SqliteConnectOptions::new()
        .in_memory(true)
        .disable_statement_logging();
    let pool = checked(
        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await,
        "connect SQLite fixture",
    );
    let db = Database::Sqlite(pool);
    scenarios(&db).await;
    db.close().await;
}

#[tokio::test]
async fn postgres_policy_contract() {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = checked(
        PgPoolOptions::new()
            .max_connections(1)
            .connect_with(options.clone())
            .await,
        "connect PostgreSQL fixture",
    );
    let schema = format!(
        "policy_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    assert!(
        schema
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    );
    let mut create = sqlx::QueryBuilder::new("CREATE SCHEMA \"");
    create.push(&schema).push("\"");
    checked(
        create.build().execute(&admin).await,
        "create isolated schema",
    );
    let search_path = schema.clone();
    let pool = checked(
        PgPoolOptions::new()
            .max_connections(1)
            .after_connect(move |conn, _| {
                let path = search_path.clone();
                Box::pin(async move {
                    sqlx::query::<sqlx::Postgres>("SELECT set_config('search_path', $1, false)")
                        .bind(path)
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await,
        "connect isolated PostgreSQL pool",
    );
    let db = Database::Postgres(pool);
    scenarios(&db).await;
    db.close().await;
    let mut drop_schema = sqlx::QueryBuilder::new("DROP SCHEMA \"");
    drop_schema.push(&schema).push("\" CASCADE");
    checked(
        drop_schema.build().execute(&admin).await,
        "drop isolated schema",
    );
    admin.close().await;
}
