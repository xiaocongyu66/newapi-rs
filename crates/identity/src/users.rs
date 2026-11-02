//! 初始化专用用户投影，不是登录或个人资料完整模型。

/// 仅供初始化判断；不包含密码、令牌、邮箱及权限展示。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootPresence {
    pub exists: bool,
}

/// 已由调用方校验并散列的凭据，不实现 Debug 或序列化。
/// 调用方负责 bcrypt cost10、原密码字节限制及确认密码检查。
pub struct RootDraft {
    pub username: String,
    pub password_hash: String,
}

pub(crate) const USER_COLUMNS: &str = "id,username,password,display_name,role,status,email,github_id,discord_id,oidc_id,wechat_id,telegram_id,access_token,quota,used_quota,request_count,group,aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version";

pub(crate) const ROOT_EXISTS: &str =
    "SELECT EXISTS(SELECT 1 FROM users WHERE role = 100 AND deleted_at IS NULL)";

// 显式填写 Go 零值，避免旧库缺少默认值时落入 NULL；不覆盖既有账户。
pub(crate) const INSERT_ROOT: &str = r#"
INSERT INTO users (
    username,password,display_name,role,status,email,github_id,discord_id,
    oidc_id,wechat_id,telegram_id,access_token,quota,used_quota,request_count,
    "group",aff_code,aff_count,aff_quota,aff_history,inviter_id,deleted_at,
    linux_do_id,setting,remark,stripe_customer,created_at,last_login_at,auth_version
) VALUES (
    $1,$2,'Root User',100,1,'','','','','','',NULL,100000000,0,0,
    'default','',0,0,0,0,NULL,'','','','',$3,0,1
)"#;
