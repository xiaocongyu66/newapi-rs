//! Response-cache policy primitives. This module intentionally has no storage or HTTP code.

use std::{fmt, time::Duration};

pub const DEFAULT_ENABLED: bool = false;
pub const DEFAULT_TTL_SECONDS: u64 = 300;
pub const DEFAULT_MAX_ENTRIES: usize = 1_000;
pub const DEFAULT_MAX_BODY_SIZE: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseCacheConfig {
    pub enabled: bool,
    pub ttl: Duration,
    pub max_entries: usize,
    /// Zero means unlimited body size.
    pub max_body_size: usize,
}

impl Default for ResponseCacheConfig {
    fn default() -> Self {
        Self {
            enabled: DEFAULT_ENABLED,
            ttl: Duration::from_secs(DEFAULT_TTL_SECONDS),
            max_entries: DEFAULT_MAX_ENTRIES,
            max_body_size: DEFAULT_MAX_BODY_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseCacheConfigError;

impl fmt::Display for ResponseCacheConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid response cache configuration")
    }
}
impl std::error::Error for ResponseCacheConfigError {}

impl ResponseCacheConfig {
    pub fn new(
        enabled: bool,
        ttl_seconds: u64,
        max_entries: usize,
        max_body_size: usize,
    ) -> Result<Self, ResponseCacheConfigError> {
        let config = Self {
            enabled,
            ttl: Duration::from_secs(ttl_seconds),
            max_entries,
            max_body_size,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ResponseCacheConfigError> {
        if self.ttl.is_zero() || self.max_entries == 0 {
            return Err(ResponseCacheConfigError);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheScope<'a> {
    Authenticated(&'a str),
    Unauthenticated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponseCacheRequest<'a> {
    pub method: &'a str,
    pub streaming: bool,
    pub system_prompt: Option<&'a str>,
    pub preset: Option<&'a str>,
    pub user_scope: CacheScope<'a>,
    pub channel_scope: CacheScope<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheKey([u8; 32]);

impl CacheKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheEligibilityError;

impl fmt::Display for CacheEligibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("request is not eligible for response caching")
    }
}
impl std::error::Error for CacheEligibilityError {}

impl<'a> ResponseCacheRequest<'a> {
    /// Returns a scope-bound, secret-free digest. Both scopes must be authenticated
    /// identities; callers must not pass raw credentials as scope values.
    pub fn cache_key(&self) -> Result<CacheKey, CacheEligibilityError> {
        if self.method.trim().is_empty()
            || self.method.chars().any(char::is_control)
            || self.streaming
            || !valid_scope(self.user_scope)
            || !valid_scope(self.channel_scope)
            || self.system_prompt.is_none() && self.preset.is_none()
            || self
                .system_prompt
                .is_some_and(|s| s.chars().any(char::is_control))
            || self.preset.is_some_and(|s| s.chars().any(char::is_control))
        {
            return Err(CacheEligibilityError);
        }
        let mut digest = Sha256::new();
        for part in [
            self.method,
            if self.streaming {
                "streaming"
            } else {
                "non-streaming"
            },
            self.system_prompt.unwrap_or("<absent>"),
            self.preset.unwrap_or("<absent>"),
            scope_value(self.user_scope),
            scope_value(self.channel_scope),
        ] {
            digest.update(&(part.len() as u64).to_be_bytes());
            digest.update(part.as_bytes());
        }
        Ok(CacheKey(digest.finalize()))
    }
}

fn valid_scope(scope: CacheScope<'_>) -> bool {
    matches!(scope, CacheScope::Authenticated(value) if !value.trim().is_empty() && !value.chars().any(char::is_control))
}

fn scope_value(scope: CacheScope<'_>) -> &str {
    match scope {
        CacheScope::Authenticated(value) => value,
        CacheScope::Unauthenticated => {
            unreachable!("invalid scope is rejected before key construction")
        }
    }
}

// Small self-contained SHA-256 implementation keeps secrets out of logs and avoids
// adding a dependency to this policy-only crate.
struct Sha256 {
    state: [u32; 8],
    buffer: Vec<u8>,
    length: u64,
}
impl Sha256 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: Vec::new(),
            length: 0,
        }
    }
    fn update(&mut self, data: &[u8]) {
        self.length += data.len() as u64;
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= 64 {
            let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
            self.compress(&block);
            self.buffer.drain(..64);
        }
    }
    fn finalize(mut self) -> [u8; 32] {
        let bits = self.length * 8;
        self.buffer.push(0x80);
        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }
        self.buffer.extend_from_slice(&bits.to_be_bytes());
        while !self.buffer.is_empty() {
            let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
            self.compress(&block);
            self.buffer.drain(..64);
        }
        let mut out = [0; 32];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut w = [0; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state;
        for i in 0..64 {
            let s1 = e1(a[4]);
            let ch = (a[4] & a[5]) ^ (!a[4] & a[6]);
            let t1 = a[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = e0(a[0]);
            let maj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
            let t2 = s0.wrapping_add(maj);
            a = [
                t1.wrapping_add(t2),
                a[0],
                a[1],
                a[2],
                a[3].wrapping_add(t1),
                a[4],
                a[5],
                a[6],
            ];
        }
        for (state, word) in self.state.iter_mut().zip(a) {
            *state = state.wrapping_add(word);
        }
    }
}
fn e0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
fn e1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
