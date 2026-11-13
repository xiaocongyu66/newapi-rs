//! Go `internal/usage/user_insight_client_ban.go` 的判定与归一化部分。
//!
//! 存储层（option `blocked_clients` 与 `user_insight_client_bans` 表）由
//! 服务装配层 / user-insight 切片持有；本模块只提供端口约定与纯判定：
//! `CheckClientBan` 的级别语义（"" / "global" / "user"）与缓存 TTL 常量。

/// Go `maxBlockedClients`：全局封禁列表长度上限。
pub const MAX_BLOCKED_CLIENTS: usize = 200;

/// Go `maxClientIDLength`：与数据库列宽一致。
pub const MAX_CLIENT_ID_LENGTH: usize = 64;

/// Go `userClientBanCacheTTL`：单位秒（注意不是 Duration 数值）。
pub const USER_CLIENT_BAN_CACHE_TTL: i64 = 30;

/// 单用户封禁缓存触顶重建阈值。
pub const USER_CLIENT_BAN_CACHE_CAPACITY: usize = 4096;

/// Go `SanitizeClientID`（user_insight_client_ban.go:107-116）。
pub fn sanitize_client_id(client: &str) -> Result<String, String> {
    let client = client.trim();
    if client.is_empty() {
        return Err("client is empty".to_owned());
    }
    if client.len() > MAX_CLIENT_ID_LENGTH {
        return Err("client is too long".to_owned());
    }
    Ok(client.to_owned())
}

/// Go `CheckClientBan`（user_insight_client_ban.go:226-242）的纯判定版本：
/// `""` 未封禁；`"global"` 命中全局封禁列表；`"user"` 命中单用户封禁。
/// client 为空（识别不出客户端）时不封。
pub fn check_client_ban(
    user_id: i64,
    client: &str,
    blocked_clients: &[String],
    user_ban_set: &std::collections::HashSet<String>,
) -> &'static str {
    if client.is_empty() {
        return "";
    }
    if blocked_clients.iter().any(|blocked| blocked == client) {
        return "global";
    }
    if user_id > 0 && user_ban_set.contains(client) {
        return "user";
    }
    ""
}

/// Go `SetGlobalClientBan` 的纯列表重建逻辑（去重保序、上限 200）：
/// 输入当前列表与操作，输出新列表。
pub fn rebuild_blocked_clients(
    current: &[String],
    client: &str,
    ban: bool,
) -> Result<Vec<String>, String> {
    let client = sanitize_client_id(client)?;
    let mut list: Vec<String> = Vec::with_capacity(current.len() + 1);
    let mut seen = std::collections::HashSet::new();
    for existing in current {
        if existing == &client || !seen.insert(existing.clone()) {
            continue;
        }
        list.push(existing.clone());
    }
    if ban && list.len() < MAX_BLOCKED_CLIENTS {
        list.push(client);
    }
    Ok(list)
}

/// Go `CheckClientBan` 命中后的拒绝文案（middleware/insight_client_ban.go:46-50）。
pub fn ban_rejection_message(scope: &str) -> &'static str {
    if scope == "user" {
        "该客户端已被管理员对您的账号禁用"
    } else {
        "您使用的客户端已被站点管理员封禁"
    }
}

/// Go `rejectBannedClient` 的审计日志行格式。
pub fn ban_rejection_log(user_id: i64, client: &str, scope: &str, path: &str) -> String {
    format!("insight client ban rejected: user={user_id} client={client} scope={scope} path={path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn sanitize_rejects_empty_and_long() {
        assert_eq!(sanitize_client_id("  x  "), Ok("x".to_owned()));
        assert!(sanitize_client_id("  ").is_err());
        let long = "a".repeat(65);
        assert!(sanitize_client_id(&long).is_err());
        let exactly = "a".repeat(64);
        assert_eq!(sanitize_client_id(&exactly), Ok(exactly));
    }

    #[test]
    fn check_ban_scopes() {
        let blocked = vec!["curl".to_owned()];
        let mut user_set = HashSet::new();
        user_set.insert("okhttp".to_owned());
        assert_eq!(check_client_ban(1, "curl", &blocked, &user_set), "global");
        assert_eq!(check_client_ban(1, "okhttp", &blocked, &user_set), "user");
        assert_eq!(check_client_ban(1, "chrome", &blocked, &user_set), "");
        // client 为空不封；user_id <= 0 不做单用户匹配。
        assert_eq!(check_client_ban(1, "", &blocked, &user_set), "");
        assert_eq!(check_client_ban(0, "okhttp", &blocked, &user_set), "");
    }

    #[test]
    fn rebuild_list_semantics() {
        let current = vec!["a".to_owned(), "b".to_owned(), "a".to_owned()];
        let next = rebuild_blocked_clients(&current, "c", true).unwrap();
        assert_eq!(next, vec!["a", "b", "c"]);
        let removed = rebuild_blocked_clients(&next, "a", false).unwrap();
        assert_eq!(removed, vec!["b", "c"]);
    }

    #[test]
    fn rejection_messages() {
        assert_eq!(
            ban_rejection_message("global"),
            "您使用的客户端已被站点管理员封禁"
        );
        assert_eq!(
            ban_rejection_message("user"),
            "该客户端已被管理员对您的账号禁用"
        );
    }
}
