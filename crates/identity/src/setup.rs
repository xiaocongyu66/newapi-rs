//! 只读结构门禁与初始化事务；不建表、不迁移、不发布内存配置。
//!
//! 列清单源自 schema-inventory，尚需 Actions 对实际 Go DDL 做类型、默认值及
//! 全库索引差分。通过本门禁不等于完整 schema 兼容验收，生产接线仍须该验收。

use newapi_storage::Database;
use sqlx::{Connection, Row};

use crate::users::{INSERT_ROOT, ROOT_EXISTS, RootDraft, RootPresence, USER_COLUMNS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupError {
    SchemaNotReady,
    Unavailable,
    AlreadyInitialized,
    InvalidInput,
    RootCreationFailed,
    ModeSaveFailed,
    SetupSaveFailed,
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SchemaNotReady => "数据库结构未就绪",
            Self::Unavailable => "数据库不可用",
            Self::AlreadyInitialized => "系统已经初始化完成",
            Self::InvalidInput => "初始化输入无效",
            Self::RootCreationFailed => "创建管理员失败",
            Self::ModeSaveFailed => "保存模式失败",
            Self::SetupSaveFailed => "保存初始化状态失败",
        })
    }
}

impl std::error::Error for SetupError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupDatabaseKind {
    Sqlite,
    Postgres,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupInspection {
    pub initialized: bool,
    pub root: RootPresence,
    pub database_kind: SetupDatabaseKind,
}

/// 不派生 Debug，防止凭据进入日志；时间由调用方的 Clock 提供。
pub struct CompleteSetup {
    pub root: Option<RootDraft>,
    pub version: String,
    pub initialized_at: i64,
    pub self_use_mode_enabled: bool,
    pub demo_site_enabled: bool,
}

/// 仅提交成功后返回，调用方据此发布模式快照，不得提前发布。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetupCompleted {
    pub root_created: bool,
    pub self_use_mode_enabled: bool,
    pub demo_site_enabled: bool,
}

#[derive(Clone)]
pub struct SetupRepository {
    database: Database,
}

impl SetupRepository {
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    pub async fn inspect(&self) -> Result<SetupInspection, SetupError> {
        match &self.database {
            Database::Sqlite(pool) => {
                let mut tx = pool.begin().await.map_err(read_error)?;
                sqlite_schema(&mut tx).await?;
                let state = sqlite_inspect(&mut tx).await?;
                tx.commit().await.map_err(read_error)?;
                Ok(state)
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(read_error)?;
                sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                    .execute(&mut *tx)
                    .await
                    .map_err(read_error)?;
                pg_schema(&mut tx).await?;
                let state = pg_inspect(&mut tx).await?;
                tx.commit().await.map_err(read_error)?;
                Ok(state)
            }
        }
    }

    pub async fn complete(&self, input: CompleteSetup) -> Result<SetupCompleted, SetupError> {
        let result = match &self.database {
            Database::Sqlite(pool) => {
                let mut conn = pool.acquire().await.map_err(read_error)?;
                // SQLx 管理事务生命周期，取消 future 或提前返回也会安排回滚。
                let mut tx = conn
                    .begin_with("BEGIN IMMEDIATE")
                    .await
                    .map_err(read_error)?;
                sqlite_schema(&mut tx).await?;
                let result = sqlite_complete(&mut tx, &input).await;
                match result {
                    Ok(value) => {
                        tx.commit().await.map_err(read_error)?;
                        Ok(value)
                    }
                    Err(error) => {
                        tx.rollback().await.map_err(read_error)?;
                        Err(error)
                    }
                }
            }
            Database::Postgres(pool) => {
                let mut tx = pool.begin().await.map_err(read_error)?;
                // 强制 READ COMMITTED：等待锁之后必须能看到上一初始化事务提交。
                sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                    .execute(&mut *tx)
                    .await
                    .map_err(read_error)?;
                // 空表无法用行锁保护；表锁同时阻止不遵守本仓储协议的普通 INSERT。
                sqlx::query("LOCK TABLE setups, users, options IN SHARE ROW EXCLUSIVE MODE")
                    .execute(&mut *tx)
                    .await
                    .map_err(read_error)?;
                pg_schema(&mut tx).await?;
                let result = pg_complete(&mut tx, &input).await;
                match result {
                    Ok(value) => {
                        tx.commit().await.map_err(read_error)?;
                        Ok(value)
                    }
                    Err(error) => {
                        tx.rollback().await.map_err(read_error)?;
                        Err(error)
                    }
                }
            }
        };
        // 不把任意唯一冲突当成已初始化；回滚后以权威记录重新判定。
        if result == Err(SetupError::SetupSaveFailed) && self.inspect().await?.initialized {
            return Err(SetupError::AlreadyInitialized);
        }
        result
    }
}

fn read_error(error: sqlx::Error) -> SetupError {
    if let sqlx::Error::Database(db) = &error {
        // SQLite 的 SQLITE_ERROR 也包含缺表/列；不将原始 SQL 文本向外传播。
        if matches!(db.code().as_deref(), Some("1" | "42P01" | "42703")) {
            return SetupError::SchemaNotReady;
        }
    }
    SetupError::Unavailable
}

// 公开只读清单供离线 fixture 与门禁复用；不是 DDL，也不授予迁移权限。
// 所有标识符来自固定基线，不允许请求提供表名或列名。
pub const REQUIRED_SCHEMA_COLUMNS: &[(&str, &str)] = &[
    ("users", USER_COLUMNS),
    ("options", "key,value"),
    ("setups", "id,version,initialized_at"),
    ("schema_migrations", "version,applied_at"),
    (
        "tokens",
        "id,user_id,key,status,name,created_time,accessed_time,expired_time,remain_quota,used_quota,unlimited_quota,model_limits_enabled,model_limits,allow_ips,group,auto_groups,cross_group_retry,deleted_at",
    ),
    (
        "user_sessions",
        "sid,user_id,version,user_auth_version,status,refresh_hash,previous_refresh_hash,previous_valid_until,login_method,ip,user_agent,created_at,last_active_at,expires_at,revoked_at,revoked_reason",
    ),
    (
        "auth_flows",
        "id,token_hash,purpose,provider,intent,user_id,session_id,payload,created_at,expires_at,consumed_at",
    ),
    (
        "external_identity_claims",
        "id,provider,subject,user_id,created_at",
    ),
    (
        "passkey_credentials",
        "id,user_id,credential_id,public_key,attestation_type,aaguid,sign_count,clone_warning,user_present,user_verified,backup_eligible,backup_state,transports,attachment,last_used_at,created_at,updated_at,deleted_at",
    ),
    (
        "two_fas",
        "id,user_id,secret,is_enabled,failed_attempts,locked_until,last_used_at,created_at,updated_at,deleted_at",
    ),
    (
        "two_fa_backup_codes",
        "id,user_id,code_hash,is_used,used_at,created_at,deleted_at",
    ),
    (
        "custom_oauth_providers",
        "id,name,slug,icon,enabled,client_id,client_secret,authorization_endpoint,token_endpoint,user_info_endpoint,scopes,user_id_field,username_field,display_name_field,email_field,well_known,auth_style,access_policy,access_denied_message,created_at,updated_at",
    ),
    (
        "user_oauth_bindings",
        "id,user_id,provider_id,provider_user_id,created_at",
    ),
    ("casbin_rule", "id,ptype,v0,v1,v2,v3,v4,v5"),
    (
        "authz_roles",
        "id,key,name,description,built_in,enabled,sort,created_at,updated_at",
    ),
    (
        "qq_bindings",
        "id,user_id,open_id,union_open_id,username,created_at",
    ),
    (
        "qq_bind_codes",
        "id,code,user_id,expired_at,used,created_at",
    ),
    ("qq_unbind_records", "user_id,unbind_at,created_at"),
    ("abilities", "group,model,channel_id,enabled,tag"),
    (
        "channels",
        "id,type,key,open_ai_organization,test_model,status,name,created_time,test_time,balance_updated_time,response_time,base_url,other,models,other_info,balance,group,used_quota,model_mapping,status_code_mapping,auto_ban,tag,setting,param_override,header_override,remark,channel_info,settings",
    ),
    (
        "channel_model_routes",
        "id,public_model_alias,channel_id,key_index,upstream_model,static_weight,enabled",
    ),
    (
        "channel_model_health",
        "channel_id,key_index,model,state,isolation_level,until,version,dormant_disable_count,local_failure_count,upstream_failure_count,last_error_code,last_error_at,last_success_at,ewma_score,latency_ewma_ms,latency_updated_at_ms,request_count,unauthorized_run,ramp_exited,ramp_pending,cooldown_streak,throttle_streak,cooldown_until_ms,score_updated_at_ms,anneal_since_ms,last_cooling_outcome,disable_streak,updated_at",
    ),
    ("gateway_config_revisions", "id,routing_revision"),
    (
        "gateway_config_outboxes",
        "id,routing_revision,created_at,published_at,publish_attempts,last_publish_error_class",
    ),
    (
        "models",
        "id,model_name,description,icon,tags,vendor_id,endpoints,status,sync_official,created_time,updated_time,deleted_at,name_rule",
    ),
    (
        "prefill_groups",
        "id,name,type,items,description,created_time,updated_time,deleted_at",
    ),
    (
        "vendors",
        "id,name,description,icon,status,created_time,updated_time,deleted_at",
    ),
    (
        "redemptions",
        "id,user_id,key,status,name,quota,redeemed_time,created_time,used_user_id,deleted_at,expired_time",
    ),
    (
        "top_ups",
        "id,user_id,amount,money,trade_no,payment_method,payment_provider,create_time,complete_time,status",
    ),
    (
        "checkins",
        "id,user_id,checkin_date,quota_awarded,created_at",
    ),
    (
        "subscription_plans",
        "id,title,subtitle,price_amount,currency,duration_unit,duration_value,custom_seconds,enabled,sort_order,allow_balance_pay,allow_wallet_overflow,stripe_price_id,creem_product_id,waffo_pancake_product_id,max_purchase_per_user,upgrade_group,downgrade_group,total_amount,quota_reset_period,quota_reset_custom_seconds,created_at,updated_at",
    ),
    (
        "subscription_orders",
        "id,user_id,plan_id,money,trade_no,payment_method,payment_provider,status,create_time,complete_time,provider_payload",
    ),
    (
        "user_subscriptions",
        "id,user_id,plan_id,amount_total,amount_used,start_time,end_time,status,source,last_reset_time,next_reset_time,upgrade_group,prev_user_group,downgrade_group,allow_wallet_overflow,created_at,updated_at",
    ),
    (
        "subscription_pre_consume_records",
        "id,request_id,user_id,user_subscription_id,pre_consumed,status,created_at,updated_at",
    ),
    (
        "qq_checkins",
        "id,user_id,checkin_date,quota_awarded,open_id,group_open_id,created_at",
    ),
    (
        "qq_drops",
        "id,user_id,drop_date,quota_awarded,open_id,group_open_id,created_at",
    ),
    (
        "qq_transfers",
        "id,from_user_id,to_user_id,transfer_date,amount,fee,received,from_open_id,to_open_id,group_open_id,created_at",
    ),
    (
        "qq_red_packets",
        "id,user_id,group_open_id,sender_open_id,blessing,total_amount,total_count,remaining_amount,remaining_count,status,expire_at,created_at",
    ),
    (
        "qq_red_packet_grabs",
        "id,packet_id,user_id,open_id,amount,is_luckiest,created_at",
    ),
    (
        "qq_steals",
        "id,thief_user_id,victim_user_id,steal_date,amount,success,reason,thief_open_id,victim_open_id,group_open_id,created_at",
    ),
    (
        "proxy_nodes",
        "id,name,enabled,encrypted_proxy_config,protocol,scope_type,scope_value,health,failure_count,last_error,cooldown_until,last_probe_at,created_at,updated_at",
    ),
    ("smtp_quota_usage", "account,day,used,updated_at"),
    (
        "system_instances",
        "node_name,info,started_at,last_seen_at,created_at,updated_at",
    ),
    (
        "system_tasks",
        "id,task_id,type,status,active_key,payload,state,result,error,locked_by,created_at,updated_at",
    ),
    (
        "system_task_locks",
        "type,task_id,locked_by,locked_until,updated_at",
    ),
    (
        "midjourneys",
        "id,code,user_id,action,mj_id,prompt,prompt_en,description,state,submit_time,start_time,finish_time,image_url,video_url,video_urls,status,progress,fail_reason,channel_id,quota,buttons,properties,token_id,billing_channel_id",
    ),
    (
        "tasks",
        "id,created_at,updated_at,task_id,platform,user_id,group,channel_id,quota,action,status,fail_reason,submit_time,start_time,finish_time,progress,properties,private_data,data",
    ),
    (
        "logs",
        "id,user_id,created_at,type,content,username,token_name,model_name,quota,prompt_tokens,completion_tokens,use_time,is_stream,channel_id,channel_name,token_id,group,ip,request_id,upstream_request_id,other",
    ),
    (
        "quota_data",
        "id,user_id,username,model_name,created_at,use_group,token_id,channel_id,node_name,token_used,count,quota",
    ),
    (
        "user_insight_profiles",
        "user_id,username,first_seen_at,last_seen_at,total_requests,code_requests,roleplay_requests,qa_requests,translate_requests,embedding_requests,other_requests,frontend_score_sum,backend_score_sum,infra_requests,mobile_requests,data_requests,male_guess_requests,female_guess_requests,male_self_report_requests,female_self_report_requests,male_preference_requests,female_preference_requests,ai_female_requests,ai_male_requests,jailbreak_suspect,jailbreak_likely,jailbreak_confirmed,jailbreak_max_score,relay_requests,last_jailbreak_at,clients_json,relay_vendors_json,jailbreak_tags_json,languages_json",
    ),
    (
        "user_insight_samples",
        "id,user_id,username,created_at,request_id,model_name,path,category,client,client_version,is_relay,relay_vendor,risk_level,jailbreak_score,guess_gender,gender_basis,evidence_json,body,body_size,fingerprint,hit_count,last_seen_at,byte_size,priority",
    ),
    ("user_insight_client_bans", "user_id,client,created_at"),
    (
        "perf_metrics",
        "id,model_name,group,bucket_ts,request_count,success_count,total_latency_ms,ttft_sum_ms,ttft_count,output_tokens,generation_ms",
    ),
];

// 两个具体数据库展开同一业务流程，不使用 SQLx Any，也不在事务中另取连接。
macro_rules! backend {
    ($schema:ident, $inspect:ident, $complete:ident, $connection:ty, $kind:expr, $unique:ident) => {
        async fn $schema(conn: &mut $connection) -> Result<(), SetupError> {
            for &(table, columns) in REQUIRED_SCHEMA_COLUMNS {
                // 仅拼接固定白名单标识符，不接受调用方或数据库返回的 SQL 片段。
                let mut query = sqlx::QueryBuilder::new("SELECT ");
                for (index, column) in columns.split(',').enumerate() {
                    if index != 0 {
                        query.push(",");
                    }
                    // 限定列名，防止 SQLite 把不存在的双引号列误作字符串常量。
                    query.push("\"").push(table).push("\".\"").push(column).push("\"");
                }
                query.push(" FROM \"").push(table).push("\" LIMIT 0");
                query.build().execute(&mut *conn).await.map_err(read_error)?;
            }
            $unique(conn).await
        }

        async fn $inspect(conn: &mut $connection) -> Result<SetupInspection, SetupError> {
            let initialized: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM setups)")
                .fetch_one(&mut *conn).await.map_err(read_error)?;
            let exists: bool = sqlx::query_scalar(ROOT_EXISTS)
                .fetch_one(&mut *conn).await.map_err(read_error)?;
            Ok(SetupInspection { initialized, root: RootPresence { exists }, database_kind: $kind })
        }

        async fn $complete(conn: &mut $connection, input: &CompleteSetup) -> Result<SetupCompleted, SetupError> {
            let state = $inspect(conn).await?;
            if state.initialized {
                return Err(SetupError::AlreadyInitialized);
            }
            if input.version.is_empty() || input.version.chars().count() > 50 || input.initialized_at < 0 {
                return Err(SetupError::InvalidInput);
            }
            if !state.root.exists {
                let root = input.root.as_ref().ok_or(SetupError::InvalidInput)?;
                if root.username.len() > 12 || root.password_hash.is_empty() {
                    return Err(SetupError::InvalidInput);
                }
                sqlx::query(INSERT_ROOT).bind(&root.username).bind(&root.password_hash)
                    .bind(input.initialized_at).execute(&mut *conn).await
                    .map_err(|_| SetupError::RootCreationFailed)?;
            }
            for (key, enabled) in [
                ("SelfUseModeEnabled", input.self_use_mode_enabled),
                ("DemoSiteEnabled", input.demo_site_enabled),
            ] {
                sqlx::query("INSERT INTO options (\"key\", value) VALUES ($1, $2) ON CONFLICT (\"key\") DO UPDATE SET value = excluded.value")
                    .bind(key).bind(if enabled { "true" } else { "false" })
                    .execute(&mut *conn).await.map_err(|_| SetupError::ModeSaveFailed)?;
            }
            sqlx::query("INSERT INTO setups (id, version, initialized_at) VALUES (1, $1, $2)")
                .bind(&input.version).bind(input.initialized_at).execute(&mut *conn).await
                .map_err(|_| SetupError::SetupSaveFailed)?;
            Ok(SetupCompleted { root_created: !state.root.exists, self_use_mode_enabled: input.self_use_mode_enabled, demo_site_enabled: input.demo_site_enabled })
        }
    };
}

backend!(
    sqlite_schema,
    sqlite_inspect,
    sqlite_complete,
    sqlx::SqliteConnection,
    SetupDatabaseKind::Sqlite,
    sqlite_unique
);
backend!(
    pg_schema,
    pg_inspect,
    pg_complete,
    sqlx::PgConnection,
    SetupDatabaseKind::Postgres,
    pg_unique
);

// 必需的单列唯一性不接受部分索引、表达式索引或复合索引冒充。
const UNIQUE_COLUMNS: &[(&str, &str)] = &[
    ("users", "id"),
    ("users", "username"),
    ("users", "aff_code"),
    ("users", "access_token"),
    ("options", "key"),
    ("setups", "id"),
];

async fn sqlite_unique(conn: &mut sqlx::SqliteConnection) -> Result<(), SetupError> {
    for &(table, column) in UNIQUE_COLUMNS {
        let primary: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info($1) WHERE pk > 0 ORDER BY pk")
                .bind(table)
                .fetch_all(&mut *conn)
                .await
                .map_err(read_error)?;
        if primary == [column] {
            continue;
        }
        if column == "id" || table == "options" {
            return Err(SetupError::SchemaNotReady);
        }
        let indexes = sqlx::query(
            "SELECT name FROM pragma_index_list($1) WHERE \"unique\" = 1 AND partial = 0",
        )
        .bind(table)
        .fetch_all(&mut *conn)
        .await
        .map_err(read_error)?;
        let mut found = false;
        for index in indexes {
            let name: String = index.try_get("name").map_err(read_error)?;
            let columns: Vec<Option<String>> =
                sqlx::query_scalar("SELECT name FROM pragma_index_info($1) ORDER BY seqno")
                    .bind(name)
                    .fetch_all(&mut *conn)
                    .await
                    .map_err(read_error)?;
            if columns.len() == 1 && columns[0].as_deref() == Some(column) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(SetupError::SchemaNotReady);
        }
    }
    Ok(())
}

async fn pg_unique(conn: &mut sqlx::PgConnection) -> Result<(), SetupError> {
    for &(table, column) in UNIQUE_COLUMNS {
        let found: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = i.indkey[0] WHERE i.indrelid = to_regclass($1) AND i.indisunique AND i.indisvalid AND i.indisready AND i.indimmediate AND i.indnatts = 1 AND i.indpred IS NULL AND i.indexprs IS NULL AND a.attname = $2 AND (NOT $3 OR i.indisprimary))",
        ).bind(table).bind(column).bind(column == "id" || table == "options").fetch_one(&mut *conn).await.map_err(read_error)?;
        if !found {
            return Err(SetupError::SchemaNotReady);
        }
    }
    Ok(())
}
