//! Notify hook ported from Go
//! `apps/api/internal/billing/notify_user_hook.go`.
//!
//! Contract (oracle `/root/newapi`, read-only):
//! - `billing.OnNotifyUser` (`notify_user_hook.go:12`): the delivery callback,
//!   registered by the ops domain's `init()` (`ops/notify_user.go:18-20`)
//!   because ops imports billing, not the reverse. **Unregistered means no
//!   notification was sent** — quota-notify callers only log delivery
//!   failures (`notify_user_hook.go:14-19`, the `nil` hook returns nil).
//! - `dto.Notify` (`relaykit/dto/notify.go:3-8`): `{type, title, content,
//!   values}` with the `{{value}}` placeholder constant and the three notify
//!   types (`quota_exceed`, `channel_update`, `channel_test`).
//! - The user setting travels through the hook as Go's `dto.UserSetting`;
//!   the Rust port passes the raw setting JSON and lets the delivery side
//!   (ops slice) parse its own fields, keeping this crate free of the
//!   settings schema.
//!
//! The call sites (`billing/consume_quota_realtime.go:489,539`, the
//! quota-exceed notify) live in the billing-session slice's un-ported notify
//! arms; they call [`notify_user`] and tolerate every outcome.

use std::sync::{Arc, Mutex, OnceLock};

/// Go `dto.ContentValueParam` (`relaykit/dto/notify.go:10`).
pub const CONTENT_VALUE_PARAM: &str = "{{value}}";

/// Go `dto.NotifyTypeQuotaExceed` / `NotifyTypeChannelUpdate` /
/// `NotifyTypeChannelTest` (`relaykit/dto/notify.go:13-15`).
pub const NOTIFY_TYPE_QUOTA_EXCEED: &str = "quota_exceed";
pub const NOTIFY_TYPE_CHANNEL_UPDATE: &str = "channel_update";
pub const NOTIFY_TYPE_CHANNEL_TEST: &str = "channel_test";

/// Go `dto.Notify` (`relaykit/dto/notify.go:3-8`); values stay open like Go's
/// `[]interface{}`.
#[derive(Clone, Debug, PartialEq)]
pub struct Notify {
    pub notify_type: String,
    pub title: String,
    pub content: String,
    pub values: Vec<serde_json::Value>,
}

impl Notify {
    /// Go `dto.NewNotify` (`relaykit/dto/notify.go:18-25`).
    pub fn new(
        notify_type: impl Into<String>,
        title: impl Into<String>,
        content: impl Into<String>,
        values: Vec<serde_json::Value>,
    ) -> Self {
        Self {
            notify_type: notify_type.into(),
            title: title.into(),
            content: content.into(),
            values,
        }
    }

    /// Go `sendEmailNotify`'s placeholder expansion
    /// (`ops/notify_user.go:113-121`): each value replaces the next
    /// `{{value}}` occurrence, formatted with Go's `%v`.
    pub fn expand_content(&self) -> String {
        let mut content = self.content.clone();
        for value in &self.values {
            content = content.replacen(CONTENT_VALUE_PARAM, &go_value(value), 1);
        }
        content
    }
}

/// Go `fmt.Sprintf("%v", value)` for the value kinds the notify path sees.
fn go_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "<nil>".to_owned(),
        serde_json::Value::Bool(true) => "true".to_owned(),
        serde_json::Value::Bool(false) => "false".to_owned(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(string) => string.clone(),
        // Composite kinds render through Go's %+v; the delivery slice does
        // not pass them today, so the JSON form is the documented fallback.
        other => other.to_string(),
    }
}

/// Go `billing.OnNotifyUser`: `(userId, userEmail, userSetting, data)`.
/// The setting travels as raw JSON (see module docs). `Err(String)` is Go's
/// `error`; no error detail crosses this boundary unparsed.
pub type OnNotifyUser =
    dyn Fn(i64, &str, &serde_json::Value, &Notify) -> Result<(), String> + Send + Sync;

static ON_NOTIFY_USER: OnceLock<Mutex<Option<Arc<OnNotifyUser>>>> = OnceLock::new();

fn hook_slot() -> &'static Mutex<Option<Arc<OnNotifyUser>>> {
    ON_NOTIFY_USER.get_or_init(|| Mutex::new(None))
}

/// Go's registration (`ops/notify_user.go:18-20`): the ops domain installs
/// the sender at startup. Re-registration replaces the previous hook (Go's
/// function variable assignment).
pub fn register_notify_user(hook: Arc<OnNotifyUser>) {
    *hook_slot().lock().expect("notify hook lock") = Some(hook);
}

/// Removes the hook; used by tests (Go resets it by reassigning the var).
pub fn unregister_notify_user() {
    *hook_slot().lock().expect("notify hook lock") = None;
}

/// Go `notifyUser` (`notify_user_hook.go:14-19`): an unregistered hook is a
/// successful no-op — "no notification was sent" is not an error.
pub fn notify_user(
    user_id: i64,
    user_email: &str,
    user_setting: &serde_json::Value,
    data: &Notify,
) -> Result<(), String> {
    let guard = hook_slot().lock().expect("notify hook lock");
    match guard.as_ref() {
        None => Ok(()),
        Some(hook) => hook(user_id, user_email, user_setting, data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_hook_is_a_silent_no_op() {
        unregister_notify_user();
        let notify = Notify::new(NOTIFY_TYPE_QUOTA_EXCEED, "t", "c", vec![]);
        assert_eq!(
            notify_user(1, "a@b.c", &serde_json::Value::Null, &notify),
            Ok(())
        );
    }

    #[test]
    fn registered_hook_receives_arguments_and_errors_propagate() {
        struct Recorder {
            seen: Mutex<Vec<(i64, String, String)>>,
        }
        impl Recorder {
            fn record(&self, user_id: i64, email: &str, notify: &Notify) -> Result<(), String> {
                self.seen.lock().unwrap().push((
                    user_id,
                    email.to_owned(),
                    notify.notify_type.clone(),
                ));
                if email.is_empty() {
                    Err("no email".to_owned())
                } else {
                    Ok(())
                }
            }
        }
        let recorder = Arc::new(Recorder {
            seen: Mutex::new(Vec::new()),
        });
        let hook_recorder = recorder.clone();
        register_notify_user(Arc::new(move |user_id, email, _setting, notify| {
            hook_recorder.record(user_id, email, notify)
        }));
        let notify = Notify::new(NOTIFY_TYPE_CHANNEL_TEST, "t", "c", vec![]);
        assert_eq!(
            notify_user(7, "u@x.y", &serde_json::Value::Null, &notify),
            Ok(())
        );
        assert_eq!(
            notify_user(8, "", &serde_json::Value::Null, &notify),
            Err("no email".to_owned())
        );
        let seen = recorder.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], (7, "u@x.y".to_owned(), "channel_test".to_owned()));
        unregister_notify_user();
    }

    #[test]
    fn content_expansion_matches_go_placeholder_order() {
        let notify = Notify::new(
            NOTIFY_TYPE_QUOTA_EXCEED,
            "额度提醒",
            "用户 {{value}}，剩余额度 {{value}}",
            vec![
                serde_json::Value::Number(42.into()),
                serde_json::Value::String("0.5".to_owned()),
            ],
        );
        assert_eq!(notify.expand_content(), "用户 42，剩余额度 0.5");
        // Fewer values than placeholders leaves the rest intact (Go replaces
        // only len(values) occurrences).
        let notify = Notify::new("t", "t", "a {{value}} b {{value}}", vec![]);
        assert_eq!(notify.expand_content(), "a {{value}} b {{value}}");
        assert_eq!(CONTENT_VALUE_PARAM, "{{value}}");
        assert_eq!(NOTIFY_TYPE_QUOTA_EXCEED, "quota_exceed");
        assert_eq!(NOTIFY_TYPE_CHANNEL_UPDATE, "channel_update");
    }

    #[test]
    fn go_value_formats_like_fmt_percent_v() {
        assert_eq!(go_value(&serde_json::Value::Null), "<nil>");
        assert_eq!(go_value(&serde_json::Value::Bool(true)), "true");
        assert_eq!(go_value(&serde_json::json!(1_000_000)), "1000000");
        assert_eq!(go_value(&serde_json::json!("x")), "x");
    }
}
