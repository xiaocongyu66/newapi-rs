use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard, OnceLock},
    time::Instant,
};

use super::config::{Config, ConfigSnapshot};

/// Cached upstream response: status, content type, body, and the usage record
/// the original miss settled against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Payload {
    pub status: i32,
    pub content_type: String,
    pub body: Vec<u8>,
    pub usage_json: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    pub entries: usize,
    pub bytes: usize,
    pub hits: i64,
    pub misses: i64,
}

struct Entry {
    status: i32,
    content_type: String,
    body: Vec<u8>,
    usage_json: Vec<u8>,
    expires_at: Instant,
}

struct State {
    config: ConfigSnapshot,
    store: HashMap<String, Entry>,
    current_size: usize,
    hits: i64,
    misses: i64,
}

impl State {
    fn new() -> Self {
        Self {
            config: ConfigSnapshot::from_raw(Config::default()),
            store: HashMap::new(),
            current_size: 0,
            hits: 0,
            misses: 0,
        }
    }
}

static STATE: OnceLock<Mutex<State>> = OnceLock::new();

fn state() -> MutexGuard<'static, State> {
    STATE
        .get_or_init(|| Mutex::new(State::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Replace the runtime configuration (hot reload from the option system).
/// Disabling the cache or shrinking the entry cap below the current size
/// resets the store.
pub fn set_config(next: Config) {
    let mut state = state();
    let snapshot = ConfigSnapshot::from_raw(next);
    state.config = snapshot;
    if !snapshot.enabled || state.store.len() > snapshot.max_entries {
        state.store.clear();
        state.current_size = 0;
    }
}

/// Snapshot of the current configuration.
pub fn config() -> Config {
    let state = state();
    Config {
        enabled: state.config.enabled,
        ttl_seconds: state.config.ttl.as_secs() as i64,
        max_entries: state.config.max_entries as i64,
        max_body_size: state.config.max_body_size,
    }
}

/// Return a cached payload when the cache is enabled and the entry is
/// unexpired. Copies are handed out so callers cannot mutate the stored bytes.
pub fn get(key: &str) -> Option<Payload> {
    let mut state = state();
    if !state.config.enabled {
        return None;
    }
    let now = Instant::now();
    if state
        .store
        .get(key)
        .is_some_and(|entry| now > entry.expires_at)
    {
        if let Some(entry) = state.store.remove(key) {
            state.current_size = state.current_size.saturating_sub(entry.body.len());
        }
        return None;
    }
    state.store.get(key).map(|entry| Payload {
        status: entry.status,
        content_type: entry.content_type.clone(),
        body: entry.body.clone(),
        usage_json: entry.usage_json.clone(),
    })
}

/// Store a payload. A body larger than the live cap is refused. Expired or
/// over-cap entries are evicted in insertion order.
pub fn put(key: &str, payload: Payload, max_body_size: i64) -> bool {
    let mut state = state();
    if !state.config.enabled {
        return false;
    }
    if max_body_size > 0 && payload.body.len() > max_body_size as usize {
        return false;
    }
    if let Some(old) = state.store.remove(key) {
        state.current_size = state.current_size.saturating_sub(old.body.len());
    }
    let max_entries = state.config.max_entries;
    while state.store.len() >= max_entries {
        evict_one(&mut state);
    }
    let ttl = state.config.ttl;
    let body_len = payload.body.len();
    state.store.insert(
        key.to_owned(),
        Entry {
            status: payload.status,
            content_type: payload.content_type,
            body: payload.body,
            usage_json: payload.usage_json,
            expires_at: Instant::now() + ttl,
        },
    );
    state.current_size += body_len;
    true
}

/// Drop every cached entry (admin action).
pub fn clear() {
    let mut state = state();
    state.store.clear();
    state.current_size = 0;
}

pub fn record_hit() {
    state().hits += 1;
}

pub fn record_miss() {
    state().misses += 1;
}

pub fn stats() -> Stats {
    let state = state();
    Stats {
        entries: state.store.len(),
        bytes: state.current_size,
        hits: state.hits,
        misses: state.misses,
    }
}

#[cfg(test)]
pub(super) fn reset_for_test(next: Config) {
    let mut state = state();
    state.store.clear();
    state.current_size = 0;
    state.hits = 0;
    state.misses = 0;
    state.config = ConfigSnapshot::from_raw(next);
}

#[cfg(test)]
pub(super) fn expire_for_test(key: &str) {
    let mut state = state();
    if let Some(entry) = state.store.get_mut(key) {
        entry.expires_at = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
    }
}

fn evict_one(state: &mut State) {
    let oldest = state
        .store
        .iter()
        .min_by_key(|(_, entry)| entry.expires_at)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        if let Some(entry) = state.store.remove(&key) {
            state.current_size = state.current_size.saturating_sub(entry.body.len());
        }
    }
}
