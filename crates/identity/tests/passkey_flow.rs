//! Passkey 切片契约测试：软件 P-256 认证器驱动 register/login/verify 三流
//! 状态机，仓储覆盖 SQLite 与 PostgreSQL（P1 双后端矩阵）。
//!
//! ```
//! ceremony begin → auth_flows payload（TTL 300s）→ 软件认证器按 options
//! 产生真实 CBOR/ECDSA 响应 → finish 校验 → passkey_credentials 落库 →
//! 重建凭据做 verify/login 断言 → update_assertion_state 回写计数器
//! ```
//!
//! 软件认证器只复现 webauthn 协议必需的字段（fmt=none 的无签名 attestation
//! 与 ES256 断言），不模拟传输方式/扩展输出。P256 与 ECDSA 依赖与
//! crypto-glue（webauthn-rs-core 的底层）同版本，lockfile 不新增 crate。

use std::sync::atomic::{AtomicU64, Ordering};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use newapi_identity::auth_flow::{AuthFlowRepository, auth_flow_key};
use newapi_identity::passkey::credential::{PasskeyCredentialRepository, StoredCredential};
use newapi_identity::passkey::settings::DEFAULT_SERVER_ADDRESS;
use newapi_identity::passkey::{
    PURPOSE_PASSKEY_LOGIN, PURPOSE_PASSKEY_REGISTER, PURPOSE_PASSKEY_STEP_UP,
    SCOPE_CHANNEL_KEY_READ, SCOPE_PASSKEY_REGISTER, TransportFacts, create_session_data_flow,
    pop_session_data_flow,
};
use newapi_identity::passkey::{PasskeySettings, PasskeySettingsRepository, build_ceremony};
use newapi_storage::Database;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{ConnectOptions, QueryBuilder};
use webauthn_rs::prelude::{
    DiscoverableAuthentication, PasskeyAuthentication, PasskeyRegistration,
};

const NOW: i64 = 1_700_000_000;
const SECRET: &str = "test-session-secret";
const ORIGIN: &str = "http://localhost:3000";
const RP_ID: &str = "localhost";
static NEXT: AtomicU64 = AtomicU64::new(0);

// `users` 只需仓储实际触及的列；`passkey_credentials`/`auth_flows` 与生产
// DDL 同构（复用 identity 模块的公开常量）。
const SQLITE_USERS_DDL: &str = "CREATE TABLE users (\
    id INTEGER PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL,\
    status INTEGER NOT NULL, auth_version BIGINT NOT NULL DEFAULT 1, deleted_at TIMESTAMP)";
const SQLITE_OPTIONS_DDL: &str = "CREATE TABLE options (\"key\" TEXT PRIMARY KEY, value TEXT)";
const SQLITE_AUTH_FLOWS_DDL: &str = "CREATE TABLE auth_flows (\
    id INTEGER PRIMARY KEY AUTOINCREMENT, token_hash CHAR(64) NOT NULL UNIQUE,\
    purpose VARCHAR(32) NOT NULL, user_id BIGINT, session_id VARCHAR(64),\
    payload TEXT, expires_at DATETIME NOT NULL, consumed_at DATETIME, created_at DATETIME)";

const POSTGRES_USERS_DDL: &str = "CREATE TABLE users (\
    id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL, display_name TEXT NOT NULL,\
    status INTEGER NOT NULL, auth_version BIGINT NOT NULL DEFAULT 1, deleted_at TIMESTAMPTZ)";
const POSTGRES_OPTIONS_DDL: &str = "CREATE TABLE options (\"key\" TEXT PRIMARY KEY, value TEXT)";
const POSTGRES_AUTH_FLOWS_DDL: &str = "CREATE TABLE auth_flows (\
    id BIGSERIAL PRIMARY KEY, token_hash CHAR(64) NOT NULL UNIQUE,\
    purpose VARCHAR(32) NOT NULL, user_id BIGINT, session_id VARCHAR(64),\
    payload TEXT, expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ, created_at TIMESTAMPTZ)";

fn sqlite_dsn() -> String {
    format!(
        "sqlite:file:passkey_fixture_{}_{}?mode=memory&cache=shared",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

async fn sqlite_database() -> Database {
    let db = Database::connect(&sqlite_dsn())
        .await
        .expect("SQLite in-memory fixture");
    for statement in [
        SQLITE_USERS_DDL,
        SQLITE_OPTIONS_DDL,
        SQLITE_AUTH_FLOWS_DDL,
        newapi_identity::passkey::PASSKEY_CREDENTIALS_SQLITE_DDL,
    ] {
        match &db {
            Database::Sqlite(pool) => sqlx::query(statement)
                .execute(pool)
                .await
                .expect("SQLite DDL"),
            Database::Postgres(_) => unreachable!("sqlite fixture"),
        };
    }
    db
}

async fn postgres_database() -> (sqlx::PgPool, Database, String) {
    let dsn = std::env::var("TEST_POSTGRES_DSN")
        .expect("TEST_POSTGRES_DSN required; PostgreSQL must not be skipped");
    let options: PgConnectOptions = dsn
        .parse()
        .unwrap_or_else(|_| panic!("invalid PostgreSQL fixture config"));
    let options = options.disable_statement_logging();
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options.clone())
        .await
        .expect("PostgreSQL fixture connection");
    let schema = format!(
        "passkey_fixture_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let mut create = QueryBuilder::new("CREATE SCHEMA \"");
    create.push(&schema).push("\"");
    create
        .build()
        .execute(&admin)
        .await
        .expect("isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(3)
        .after_connect(move |connection, _| {
            let path = search_path.clone();
            Box::pin(async move {
                sqlx::query("SELECT set_config('search_path',$1,false)")
                    .bind(path)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("isolated PostgreSQL pool");
    let db = Database::Postgres(pool);
    for statement in [
        POSTGRES_USERS_DDL,
        POSTGRES_OPTIONS_DDL,
        POSTGRES_AUTH_FLOWS_DDL,
        newapi_identity::passkey::PASSKEY_CREDENTIALS_POSTGRES_DDL,
    ] {
        match &db {
            Database::Postgres(pool) => sqlx::query(statement).execute(pool).await.expect("PG DDL"),
            Database::Sqlite(_) => unreachable!("postgres fixture"),
        };
    }
    (admin, db, schema)
}

async fn drop_schema(admin: &sqlx::PgPool, schema: &str) {
    let mut statement = QueryBuilder::new("DROP SCHEMA \"");
    statement.push(schema).push("\" CASCADE");
    statement
        .build()
        .execute(admin)
        .await
        .expect("drop isolated PostgreSQL schema");
}

async fn seed_user(db: &Database, id: i64, username: &str) {
    let sql = "INSERT INTO users (id, username, display_name, status, auth_version) \
               VALUES ($1,$2,$2,1,1)";
    match db {
        Database::Sqlite(pool) => sqlx::query(sql).bind(id).bind(username).execute(pool).await,
        Database::Postgres(pool) => sqlx::query(sql).bind(id).bind(username).execute(pool).await,
    }
    .expect("seed user");
}

async fn auth_version(db: &Database, id: i64) -> i64 {
    match db {
        Database::Sqlite(pool) => {
            sqlx::query_scalar::<_, i64>(
                "SELECT CAST(auth_version AS BIGINT) FROM users WHERE id=$1",
            )
            .bind(id)
            .fetch_one(pool)
            .await
        }
        Database::Postgres(pool) => {
            sqlx::query_scalar::<_, i64>(
                "SELECT CAST(auth_version AS BIGINT) FROM users WHERE id=$1",
            )
            .bind(id)
            .fetch_one(pool)
            .await
        }
    }
    .expect("read auth_version")
}

async fn insert_option(db: &Database, key: &str, value: &str) {
    let sql = "INSERT INTO options (\"key\", \"value\") VALUES ($1,$2)";
    match db {
        Database::Sqlite(pool) => sqlx::query(sql).bind(key).bind(value).execute(pool).await,
        Database::Postgres(pool) => sqlx::query(sql).bind(key).bind(value).execute(pool).await,
    }
    .expect("insert option");
}

fn flow_repository(db: &Database) -> AuthFlowRepository {
    AuthFlowRepository::new(db.clone(), auth_flow_key(SECRET))
}

fn test_settings() -> PasskeySettings {
    PasskeySettings {
        enabled: true,
        ..PasskeySettings::default()
    }
}

fn transport_facts() -> TransportFacts {
    TransportFacts {
        host: "localhost:3000".to_owned(),
        is_tls: false,
    }
}

fn ceremony() -> newapi_identity::passkey::Ceremony {
    build_ceremony(&test_settings(), &transport_facts(), DEFAULT_SERVER_ADDRESS)
        .expect("localhost ceremony builds")
}

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn challenge_of(options: &Value) -> Vec<u8> {
    let challenge = options["publicKey"]["challenge"]
        .as_str()
        .expect("challenge present");
    URL_SAFE_NO_PAD
        .decode(challenge)
        .expect("challenge decodes")
}

/// ES256 软件 P-256 认证器：fmt=none 注册 + 可发现断言签名。
struct SoftAuthenticator {
    signing_key: p256::ecdsa::SigningKey,
    credential_id: Vec<u8>,
    counter: u32,
}

impl SoftAuthenticator {
    fn new(seed: [u8; 32], credential_id: Vec<u8>) -> Self {
        let secret = p256::SecretKey::from_slice(&seed).expect("seed is a valid scalar");
        Self {
            signing_key: p256::ecdsa::SigningKey::from(&secret),
            credential_id,
            counter: 0,
        }
    }

    fn cose_key_value(&self) -> serde_cbor_2::Value {
        let public = self.signing_key.verifying_key().to_sec1_bytes();
        let x = public[1..33].to_vec();
        let y = public[33..65].to_vec();
        let mut map = std::collections::BTreeMap::new();
        map.insert(
            serde_cbor_2::Value::Integer(1),
            serde_cbor_2::Value::Integer(2),
        );
        map.insert(
            serde_cbor_2::Value::Integer(3),
            serde_cbor_2::Value::Integer(-7),
        );
        map.insert(
            serde_cbor_2::Value::Integer(-1),
            serde_cbor_2::Value::Integer(1),
        );
        map.insert(
            serde_cbor_2::Value::Integer(-2),
            serde_cbor_2::Value::Bytes(x),
        );
        map.insert(
            serde_cbor_2::Value::Integer(-3),
            serde_cbor_2::Value::Bytes(y),
        );
        serde_cbor_2::Value::Map(map)
    }

    fn auth_data(&self, rp_id: &str, flags: u8, counter: u32, include_attested: bool) -> Vec<u8> {
        let rp_id_hash = Sha256::digest(rp_id.as_bytes()).to_vec();
        let mut data = Vec::with_capacity(64 + 32 + 18 + 132);
        data.extend_from_slice(&rp_id_hash);
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        if include_attested {
            let aaguid = [0u8; 16];
            data.extend_from_slice(&aaguid);
            data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
            data.extend_from_slice(&self.credential_id);
            let cose = serde_cbor_2::to_vec(&self.cose_key_value()).expect("COSE key encodes");
            data.extend_from_slice(&cose);
        }
        data
    }

    fn client_data(&self, type_: &str, challenge: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "type": type_,
            "challenge": b64url(challenge),
            "origin": ORIGIN,
            "crossOrigin": false,
        }))
        .expect("clientDataJSON encodes")
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing_key.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    /// `RegisterPublicKeyCredential`（含顶层 `authenticatorAttachment`，
    /// 与前端 `buildRegistrationResult` 的载荷同构）。
    fn registration_credential(&mut self, challenge: &[u8]) -> Value {
        let auth_data = self.auth_data(RP_ID, 0x45, self.counter, true);
        let attestation = {
            let mut map = std::collections::BTreeMap::new();
            map.insert(
                serde_cbor_2::Value::Text("fmt".to_owned()),
                serde_cbor_2::Value::Text("none".to_owned()),
            );
            map.insert(
                serde_cbor_2::Value::Text("attStmt".to_owned()),
                serde_cbor_2::Value::Map(std::collections::BTreeMap::new()),
            );
            map.insert(
                serde_cbor_2::Value::Text("authData".to_owned()),
                serde_cbor_2::Value::Bytes(auth_data),
            );
            serde_cbor_2::to_vec(&serde_cbor_2::Value::Map(map)).expect("attestation encodes")
        };
        let client_data = self.client_data("webauthn.create", challenge);
        json!({
            "id": b64url(&self.credential_id),
            "rawId": b64url(&self.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "attestationObject": b64url(&attestation),
                "clientDataJSON": b64url(&client_data),
            },
        })
    }

    /// `PublicKeyCredential` 断言；`user_handle` 为 None 时省略字段。
    fn assertion_credential(&mut self, challenge: &[u8], user_handle: Option<&[u8]>) -> Value {
        self.counter += 1;
        let auth_data = self.auth_data(RP_ID, 0x05, self.counter, false);
        let client_data = self.client_data("webauthn.get", challenge);
        let mut message = auth_data.clone();
        message.extend_from_slice(&Sha256::digest(&client_data));
        let signature = self.sign(&message);
        let mut response = json!({
            "authenticatorData": b64url(&auth_data),
            "clientDataJSON": b64url(&client_data),
            "signature": b64url(&signature),
        });
        if let Some(handle) = user_handle {
            response["userHandle"] = json!(b64url(handle));
        }
        json!({
            "id": b64url(&self.credential_id),
            "rawId": b64url(&self.credential_id),
            "type": "public-key",
            "response": response,
        })
    }
}

/// 注册一个凭据并落库，返回（已存记录的重建 Credential，仓储）。
async fn registered_credential(
    db: &Database,
    authenticator: &mut SoftAuthenticator,
    user_id: i64,
) -> webauthn_rs::prelude::Credential {
    let ceremony = ceremony();
    let (options, registration) = ceremony
        .begin_registration(
            newapi_identity::passkey::CeremonyUser {
                id: user_id,
                username: "fixture",
                display_name: "Fixture",
            },
            Vec::new(),
        )
        .expect("begin registration");
    let challenge = challenge_of(&options);
    let credential_json = authenticator.registration_credential(&challenge);
    let attachment = credential_json["authenticatorAttachment"]
        .as_str()
        .map(str::to_owned);
    let registered = ceremony
        .finish_registration(credential_json, &registration)
        .expect("finish registration");
    let stored = StoredCredential {
        credential_id: registered.credential_id.clone(),
        public_key: registered.public_key.clone(),
        attestation_format: registered.attestation_format.clone(),
        counter: registered.counter,
        user_verified: registered.user_verified,
        backup_eligible: registered.backup_eligible,
        backup_state: registered.backup_state,
        transports: registered.transports.clone(),
        attachment,
    };
    let repository = PasskeyCredentialRepository::new(db.clone());
    repository
        .upsert_with_auth_version(user_id, &stored, NOW)
        .await
        .expect("upsert credential");
    let row = repository
        .by_user_id(user_id)
        .await
        .expect("read credential")
        .expect("credential exists");
    row.to_webauthn_credential().expect("credential rebuilds")
}

/// 三流契约：register → verify（指定凭据）→ login（可发现）→ 重复消费拒绝。
async fn three_flows(db: &Database) {
    seed_user(db, 7, "fixture").await;
    let flow = flow_repository(db);
    let mut authenticator = SoftAuthenticator::new([0x42; 32], vec![0xA5; 32]);

    // --- register：begin → flow 状态 → 软件认证器响应 → finish → 落库 ---
    let credential = registered_credential(db, &mut authenticator, 7).await;
    assert_eq!(credential.counter, 0);
    assert!(credential.user_verified);
    assert_eq!(credential.cred_id, vec![0xA5; 32]);

    // begin 的 options 形状与 RP 推导。
    let ceremony = ceremony();
    let (options, registration) = ceremony
        .begin_registration(
            newapi_identity::passkey::CeremonyUser {
                id: 7,
                username: "fixture",
                display_name: "Fixture",
            },
            vec![vec![0xA5; 32]],
        )
        .expect("begin with exclusion");
    assert_eq!(options["publicKey"]["rp"]["id"], RP_ID);
    // 已注册凭据进入排除列表（Go WithExclusions）。
    let exclude = options["publicKey"]["excludeCredentials"]
        .as_array()
        .expect("excludeCredentials present");
    assert_eq!(exclude.len(), 1);
    assert_eq!(exclude[0]["type"], "public-key");

    // --- verify：指定凭据的 allowCredentials 断言流 ---
    let (options, authentication) = ceremony
        .begin_verification(&credential)
        .expect("begin verification");
    let allow = options["publicKey"]["allowCredentials"]
        .as_array()
        .expect("allowCredentials present");
    assert_eq!(allow.len(), 1);
    let challenge = challenge_of(&options);
    let token = create_session_data_flow(
        &flow,
        PURPOSE_PASSKEY_STEP_UP,
        7,
        "sid-fixture",
        SCOPE_CHANNEL_KEY_READ,
        &serde_json::to_value(&authentication).unwrap(),
        NOW,
    )
    .await
    .expect("create verify flow");
    // 5 分钟 TTL（Go passkeyFlowTTL）。
    assert_eq!(token.1, NOW + 300);
    let (state_value, scope) = pop_session_data_flow(
        &flow,
        token.0.expose_secret(),
        PURPOSE_PASSKEY_STEP_UP,
        7,
        "sid-fixture",
        NOW,
    )
    .await
    .expect("consume verify flow");
    assert_eq!(scope, SCOPE_CHANNEL_KEY_READ);
    let authentication: PasskeyAuthentication =
        serde_json::from_value(state_value).expect("state round-trips");
    let assertion_json = authenticator.assertion_credential(&challenge, None);
    let result = ceremony
        .finish_verification(&assertion_json, &authentication)
        .expect("finish verification");
    assert!(result.user_verified());
    assert_eq!(result.counter(), 1);
    let repository = PasskeyCredentialRepository::new(db.clone());
    repository
        .update_assertion_state(
            7,
            &result.cred_id(),
            result.counter(),
            result.user_verified(),
            result.backup_eligible(),
            result.backup_state(),
            NOW,
        )
        .await
        .expect("assertion state persisted");
    let stored = repository.by_user_id(7).await.unwrap().unwrap();
    assert_eq!(stored.sign_count, 1);
    assert!(stored.last_used_at.is_some());

    // --- login：匿名可发现流，凭据 ID 定位用户，userHandle 比对 ---
    let (options, authentication) = ceremony.begin_login_discoverable().expect("begin login");
    // 可发现登录的 allowCredentials 恒为空（Go 序列化 nil 切片为 null，
    // webauthn-rs 序列化空 Vec 为 []；前端 prepareCredentialRequestOptions
    // 对 null 与 [] 行为等价）。
    let allow = options["publicKey"]["allowCredentials"].as_array();
    assert!(allow.is_some_and(|list| list.is_empty()));
    assert!(options.get("mediation").is_none());
    let challenge = challenge_of(&options);
    let token = create_session_data_flow(
        &flow,
        PURPOSE_PASSKEY_LOGIN,
        0,
        "",
        "",
        &serde_json::to_value(&authentication).unwrap(),
        NOW,
    )
    .await
    .expect("create login flow");
    let (state_value, _) = pop_session_data_flow(
        &flow,
        token.0.expose_secret(),
        PURPOSE_PASSKEY_LOGIN,
        0,
        "",
        NOW,
    )
    .await
    .expect("consume login flow");
    let authentication: DiscoverableAuthentication =
        serde_json::from_value(state_value).expect("login state round-trips");
    let mut handle = [0u8; 16];
    handle[8..16].copy_from_slice(&7_i64.to_be_bytes());
    let assertion_json = authenticator.assertion_credential(&challenge, Some(&handle));
    // userHandle 还原为用户 7，与凭据归属一致。
    assert_eq!(
        newapi_identity::passkey::ceremony::user_handle_to_user_id(&handle),
        Some(7)
    );
    let result = ceremony
        .finish_login_discoverable(&assertion_json, authentication, &credential)
        .expect("finish discoverable login");
    assert!(result.user_verified());
    assert_eq!(result.counter(), 2);

    // --- 单次消费：同一 token 再次消费必须失败（Go ConsumeAuthFlow）---
    let error = pop_session_data_flow(
        &flow,
        token.0.expose_secret(),
        PURPOSE_PASSKEY_LOGIN,
        0,
        "",
        NOW,
    )
    .await
    .err()
    .expect("flow token cannot be replayed");
    assert_eq!(error, newapi_identity::passkey::SessionFlowError::NotFound);

    // --- 跨用户绑定：register 流的 token 不能被别的用户消费 ---
    let (_, registration_state) = ceremony
        .begin_registration(
            newapi_identity::passkey::CeremonyUser {
                id: 7,
                username: "fixture",
                display_name: "Fixture",
            },
            Vec::new(),
        )
        .expect("begin registration for mismatch");
    let token = create_session_data_flow(
        &flow,
        PURPOSE_PASSKEY_REGISTER,
        7,
        "sid-fixture",
        SCOPE_PASSKEY_REGISTER,
        &serde_json::to_value(&registration_state).unwrap(),
        NOW,
    )
    .await
    .expect("create register flow");
    let error = pop_session_data_flow(
        &flow,
        token.0.expose_secret(),
        PURPOSE_PASSKEY_REGISTER,
        8,
        "sid-fixture",
        NOW,
    )
    .await
    .err()
    .expect("foreign user cannot consume");
    assert_eq!(error, newapi_identity::passkey::SessionFlowError::NotFound);
}

/// 仓储语义：upsert 替换、auth_version 递增、删除、断言状态与克隆告警。
async fn store_semantics(db: &Database) {
    seed_user(db, 9, "storeuser").await;
    let repository = PasskeyCredentialRepository::new(db.clone());

    // 未绑定用户查询返回 None。
    assert_eq!(repository.by_user_id(9).await.unwrap().is_some(), false);

    let mut authenticator = SoftAuthenticator::new([0x77; 32], vec![0x11; 32]);
    registered_credential(db, &mut authenticator, 9).await;
    assert_eq!(auth_version(db, 9).await, 2);

    // 同一用户再次注册替换旧凭据（Go 的 Unscoped 硬删除 + 插入）。
    let mut second = SoftAuthenticator::new([0x88; 32], vec![0x22; 32]);
    let second_credential = registered_credential(db, &mut second, 9).await;
    assert_eq!(second_credential.cred_id, vec![0x22; 32]);
    assert_eq!(auth_version(db, 9).await, 3);
    assert_eq!(
        repository
            .by_credential_id(&[0x11; 32])
            .await
            .unwrap()
            .is_some(),
        false
    );

    // 断言状态回写：计数器前进、last_used_at 落库。
    repository
        .update_assertion_state(9, &[0x22; 32], 5, true, false, false, NOW)
        .await
        .expect("assertion state writes");
    let stored = repository.by_user_id(9).await.unwrap().unwrap();
    assert_eq!(stored.sign_count, 5);
    assert!(stored.last_used_at.is_some());
    // 公钥列可重建（COSE CBOR 双向编解码）。
    assert_eq!(
        stored.to_webauthn_credential().unwrap().cred_id,
        vec![0x22; 32]
    );

    // 计数器回退疑似克隆：clone_warning 置位（go-webauthn 同语义）。
    repository
        .update_assertion_state(9, &[0x22; 32], 4, true, false, false, NOW)
        .await
        .expect("clone warning writes");
    let stored = repository.by_user_id(9).await.unwrap().unwrap();
    assert!(stored.clone_warning);

    // 不存在的凭据/用户：NotFound。
    assert_eq!(
        repository
            .update_assertion_state(9, &[0xFF; 32], 6, true, false, false, NOW)
            .await
            .err(),
        Some(newapi_identity::passkey::PasskeyStoreError::NotFound)
    );

    // 删除：auth_version 递增并硬删除；再次删除 NotFound。
    let next = repository
        .delete_with_auth_version(9)
        .await
        .expect("delete credential");
    assert_eq!(next, auth_version(db, 9).await);
    assert!(next > 3);
    assert!(repository.by_user_id(9).await.unwrap().is_none());
    assert_eq!(
        repository.delete_with_auth_version(9).await.err(),
        Some(newapi_identity::passkey::PasskeyStoreError::NotFound)
    );
}

/// settings 仓储：options 行加载、默认值与 ServerAddress 派生。
async fn settings_loading(db: &Database) {
    insert_option(db, "passkey", r#"{"enabled":true,"rp_id":"example.com:8443","origins":"https://a.example.com:9443","user_verification":"required"}"#).await;
    insert_option(db, "ServerAddress", "https://newapi.pro").await;
    let (settings, server_address) = PasskeySettingsRepository::new(db.clone())
        .load()
        .await
        .expect("settings load");
    assert!(settings.enabled);
    assert_eq!(settings.rp_id, "example.com:8443");
    assert_eq!(settings.origins, "https://a.example.com:9443");
    assert_eq!(server_address, "https://newapi.pro");

    // 已配置值不被 ServerAddress 派生覆盖（GetPasskeySettings 语义）。
    let effective = settings.resolve(&server_address);
    assert_eq!(effective.rp_id, "example.com:8443");
    assert_eq!(effective.effective_user_verification(), "required");

    // 无 passkey 行：默认值 + ServerAddress 派生 RPID/Origins。
    let (settings, server_address) = PasskeySettingsRepository::new(db.clone())
        .load()
        .await
        .expect("settings reload");
    // options 表里仍有 passkey 行（同一 fixture）；此处验证的是解析后再次
    // 读取的稳定性，而非缺行分支——缺行分支由下一组断言覆盖。
    assert_eq!(settings.enabled, true);
    assert_eq!(server_address, "https://newapi.pro");
}

/// settings 缺行：默认禁用 + ServerAddress 派生。
async fn settings_defaults(db: &Database) {
    let (settings, server_address) = PasskeySettingsRepository::new(db.clone())
        .load()
        .await
        .expect("settings load");
    assert!(!settings.enabled);
    assert_eq!(server_address, DEFAULT_SERVER_ADDRESS);
    let effective = settings.resolve(&server_address);
    assert_eq!(effective.rp_id, "localhost:3000");
    assert_eq!(effective.origins, DEFAULT_SERVER_ADDRESS);
}

#[tokio::test]
async fn sqlite_passkey_three_flows() {
    let db = sqlite_database().await;
    three_flows(&db).await;
    store_semantics(&db).await;
    db.close().await;
}

#[tokio::test]
async fn sqlite_passkey_settings() {
    let db = sqlite_database().await;
    settings_defaults(&db).await;
    settings_loading(&db).await;
    db.close().await;
}

#[tokio::test]
async fn sqlite_passkey_credential_roundtrip_columns() {
    // COSE 公钥列与 user_handle 的字节级断言已在 three_flows 覆盖；
    // 本例固定公共键存储的 base64 STD 形态（Go 同编码）。
    let db = sqlite_database().await;
    seed_user(&db, 3, "roundtrip").await;
    let mut authenticator = SoftAuthenticator::new([0x33; 32], vec![0x99; 32]);
    registered_credential(&db, &mut authenticator, 3).await;
    let repository = PasskeyCredentialRepository::new(db.clone());
    let stored = repository.by_user_id(3).await.unwrap().unwrap();
    assert_eq!(stored.credential_id, STANDARD.encode([0x99; 32]));
    assert!(!stored.public_key.is_empty());
    db.close().await;
}

#[tokio::test]
async fn sqlite_passkey_failures_are_fixed_categories() {
    let db = sqlite_database().await;
    let ceremony = ceremony();
    // 错误的 clientData 类型（webauthn.create 误用 get）被库拒绝。
    let user = newapi_identity::passkey::CeremonyUser {
        id: 5,
        username: "failures",
        display_name: "F",
    };
    let (options, registration) = ceremony
        .begin_registration(user, Vec::new())
        .expect("begin");
    seed_user(&db, 5, "failures").await;
    let mut authenticator = SoftAuthenticator::new([0x55; 32], vec![0x66; 32]);
    let challenge = challenge_of(&options);
    let mut credential_json = authenticator.registration_credential(&challenge);
    // 篡改 clientDataJSON 的 type 字段（解码→改→重编码）。
    let response = credential_json["response"].clone();
    let client: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(response["clientDataJSON"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut client = client;
    client["type"] = json!("webauthn.get");
    let client = serde_json::to_vec(&client).unwrap();
    credential_json["response"]["clientDataJSON"] = json!(b64url(&client));
    let error = ceremony
        .finish_registration(credential_json, &registration)
        .err()
        .expect("wrong client data type rejected");
    assert_eq!(error, newapi_identity::passkey::CeremonyError::Invalid);
    db.close().await;
}

#[tokio::test]
async fn postgres_passkey_three_flows() {
    let (admin, db, schema) = postgres_database().await;
    three_flows(&db).await;
    store_semantics(&db).await;
    db.close().await;
    drop_schema(&admin, &schema).await;
}

#[tokio::test]
async fn postgres_passkey_settings() {
    let (admin, db, schema) = postgres_database().await;
    settings_defaults(&db).await;
    settings_loading(&db).await;
    db.close().await;
    drop_schema(&admin, &schema).await;
}

#[tokio::test]
async fn postgres_passkey_credential_roundtrip_columns() {
    let (admin, db, schema) = postgres_database().await;
    seed_user(&db, 3, "roundtrip").await;
    let mut authenticator = SoftAuthenticator::new([0x33; 32], vec![0x99; 32]);
    registered_credential(&db, &mut authenticator, 3).await;
    let repository = PasskeyCredentialRepository::new(db.clone());
    let stored = repository.by_user_id(3).await.unwrap().unwrap();
    assert_eq!(stored.credential_id, STANDARD.encode([0x99; 32]));
    db.close().await;
    drop_schema(&admin, &schema).await;
}
