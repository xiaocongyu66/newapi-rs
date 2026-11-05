//! Internationalization for the Rust API.
//!
//! This is a direct port of the upstream Go package at
//! `apps/api/internal/i18n`. The supported languages are `zh-CN`, `zh-TW`, and
//! `en`; every other language normalizes to English. Locale catalogs are
//! embedded at compile time and no field in this crate performs I/O.

#![forbid(unsafe_code)]

pub mod locale;

pub use locale::{
    DEFAULT_LANG, LANG_EN, LANG_ZH_CN, LANG_ZH_TW, is_supported, normalize_lang,
    parse_accept_language, supported_languages, t, translate,
};

/// Language sources resolved by [`resolve_language`], in upstream priority
/// order.
///
/// Database and middleware access stay outside this crate; callers pass the
/// already-loaded values. No field performs I/O.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LanguageContext<'a> {
    /// User setting, when the full settings object is already loaded.
    pub user_setting_language: Option<&'a str>,
    /// Language lazily loaded from the user ID (cache/database).
    pub user_id_language: Option<&'a str>,
    /// Language stored by the i18n middleware, normally parsed from
    /// `Accept-Language`.
    pub middleware_language: Option<&'a str>,
    /// Raw `Accept-Language` header, used when middleware did not run.
    pub accept_language: Option<&'a str>,
}

/// Resolve the effective language using the upstream priority order.
///
/// 1. non-empty user setting;
/// 2. non-empty language loaded by user ID;
/// 3. non-empty middleware language;
/// 4. non-empty `Accept-Language` header;
/// 5. English.
///
/// A candidate is normalized before the support check. Because normalization
/// only produces supported codes, the first non-empty candidate always wins.
pub fn resolve_language(ctx: LanguageContext<'_>) -> String {
    if let Some(lang) = supported_candidate(ctx.user_setting_language) {
        return lang.to_owned();
    }
    if let Some(lang) = supported_candidate(ctx.user_id_language) {
        return lang.to_owned();
    }
    if let Some(lang) = supported_candidate(ctx.middleware_language) {
        return lang.to_owned();
    }
    if let Some(header) = ctx.accept_language.filter(|value| !value.is_empty()) {
        let lang = parse_accept_language(header);
        if is_supported(lang) {
            return lang.to_owned();
        }
    }
    DEFAULT_LANG.to_owned()
}

fn supported_candidate(candidate: Option<&str>) -> Option<&'static str> {
    let value = candidate.filter(|value| !value.is_empty())?;
    let normalized = normalize_lang(value);
    is_supported(normalized).then_some(normalized)
}
