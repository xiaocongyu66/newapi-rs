//! Language tag normalization and `Accept-Language` parsing.

/// Simplified Chinese language code.
pub const LANG_ZH_CN: &str = "zh-CN";
/// Traditional Chinese language code.
pub const LANG_ZH_TW: &str = "zh-TW";
/// English language code.
pub const LANG_EN: &str = "en";
/// Fallback language used when a code is unsupported.
pub const DEFAULT_LANG: &str = LANG_EN;

/// Languages recognized by the catalogs, in upstream order.
pub fn supported_languages() -> [&'static str; 3] {
    [LANG_ZH_CN, LANG_ZH_TW, LANG_EN]
}

/// Normalize a language tag exactly like upstream `normalizeLang`.
///
/// The input is trimmed and lowercased before prefix matching: `zh-tw*`
/// becomes `zh-TW`; any other `zh*` (including `zh-Hant` and `zh-Hans`)
/// becomes `zh-CN`; `en*` becomes `en`; everything else falls back to English.
pub fn normalize_lang(lang: &str) -> &'static str {
    let lang = lang.trim().to_lowercase();
    if lang.starts_with("zh-tw") {
        LANG_ZH_TW
    } else if lang.starts_with("zh") {
        LANG_ZH_CN
    } else if lang.starts_with("en") {
        LANG_EN
    } else {
        DEFAULT_LANG
    }
}

/// Return whether a language code is supported.
///
/// Upstream normalizes first and then checks the three-code list. Because
/// normalization can only produce a supported code, this is true for every
/// input, including unsupported tags such as `fr`.
pub fn is_supported(lang: &str) -> bool {
    supported_languages().contains(&normalize_lang(lang))
}

/// Parse the first entry of an `Accept-Language` header.
///
/// Only the first comma-separated tag is considered; a `;q=` suffix is
/// removed when the semicolon is not the first character, then the tag is
/// normalized. There is no quality-value sorting.
pub fn parse_accept_language(header: &str) -> &'static str {
    if header.is_empty() {
        return DEFAULT_LANG;
    }

    let first = header.split(',').next().unwrap_or_default().trim();
    let first = match first.find(';') {
        Some(index) if index > 0 => &first[..index],
        _ => first,
    };

    normalize_lang(first)
}
