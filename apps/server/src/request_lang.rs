//! Request-language resolution for anonymous endpoints (P2, e.g. login).
//!
//! Mirrors upstream `GetLangFromCtx`: for anonymous requests only the
//! `Accept-Language` source applies, because no user setting, user-ID
//! language, or middleware language exists yet. Authenticated paths gain the
//! higher-priority sources when the auth-context slice lands.

use axum::http::{HeaderMap, header};

/// 从请求头解析响应语言（匿名路径：仅 Accept-Language；认证路径后续切片再接用户设置）。
pub fn request_language(accept_language: Option<&str>) -> String {
    newapi_i18n::resolve_language(newapi_i18n::LanguageContext {
        accept_language,
        ..Default::default()
    })
}

/// Extract the raw `Accept-Language` header for [`request_language`].
///
/// Upstream Go reads the header via `c.Header("Accept-Language")`, which
/// yields the raw value with multiple header lines merged into a single
/// comma-separated string (fasthttp's `Peek` behavior). Mirror that here:
/// take every value of a repeated header via `get_all` and join them with
/// `", "` so `parse_accept_language`'s "first tag wins, no q sorting" rule
/// observes the same string Go would.
///
/// Values that fail `to_str` (non-ASCII bytes) are skipped rather than
/// rejecting the request, matching upstream's permissive header reads.
pub fn accept_language_header(headers: &HeaderMap) -> Option<String> {
    let mut values = headers
        .get_all(header::ACCEPT_LANGUAGE)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?;
    Some(values.fold(first.to_owned(), |mut acc, value| {
        acc.push_str(", ");
        acc.push_str(value);
        acc
    }))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers_with(values: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                header::ACCEPT_LANGUAGE,
                HeaderValue::from_bytes(value).expect("header bytes are legal"),
            );
        }
        headers
    }

    #[test]
    fn simplified_chinese_passes_through() {
        assert_eq!(request_language(Some("zh-CN")), "zh-CN");
        assert_eq!(request_language(Some("zh-CN,zh;q=0.9")), "zh-CN");
    }

    #[test]
    fn bare_zh_normalizes_to_zh_cn() {
        // `normalize_lang` prefix-matches: any `zh*` that is not `zh-tw*`
        // (including bare `zh` and `zh-Hant`) becomes `zh-CN`.
        assert_eq!(request_language(Some("zh")), "zh-CN");
        assert_eq!(request_language(Some("zh-Hant")), "zh-CN");
        assert_eq!(request_language(Some("zh-Hans")), "zh-CN");
    }

    #[test]
    fn traditional_chinese_is_preserved() {
        assert_eq!(request_language(Some("zh-TW")), "zh-TW");
        assert_eq!(request_language(Some("zh-tw")), "zh-TW");
        assert_eq!(request_language(Some("zh-TW,zh;q=0.9")), "zh-TW");
    }

    #[test]
    fn english_variants_normalize_to_en() {
        assert_eq!(request_language(Some("en-US")), "en");
        assert_eq!(request_language(Some("en-GB,en;q=0.9")), "en");
    }

    #[test]
    fn unsupported_language_falls_back_to_default_en() {
        // `DEFAULT_LANG` is `en` (upstream `DefaultLang = LangEn`), not zh-CN.
        assert_eq!(request_language(Some("de")), "en");
        assert_eq!(request_language(Some("de-DE,de;q=0.9")), "en");
    }

    #[test]
    fn missing_or_empty_header_falls_back_to_default_en() {
        assert_eq!(request_language(None), "en");
        assert_eq!(request_language(Some("")), "en");
    }

    #[test]
    fn first_tag_wins_without_quality_sorting() {
        // `parse_accept_language` only inspects the first comma-separated tag
        // and strips its `;q=` suffix; it never re-sorts by quality value.
        // `fr` normalizes to English, so the first tag wins with `en`.
        assert_eq!(request_language(Some("fr, zh;q=0.9, en;q=0.8")), "en");
        // Even when `zh` carries the higher quality, the first tag wins.
        assert_eq!(request_language(Some("en-US;q=0.8, zh;q=0.9")), "en");
        // Leading supported tag wins regardless of later quality values.
        assert_eq!(request_language(Some("zh;q=0.9, en;q=0.8")), "zh-CN");
    }

    #[test]
    fn single_header_extraction() {
        let headers = headers_with(&[b"zh-TW"]);
        assert_eq!(
            accept_language_header(&headers).as_deref(),
            Some("zh-TW"),
            "single value passes through unchanged"
        );
        assert_eq!(
            request_language(accept_language_header(&headers).as_deref()),
            "zh-TW"
        );
    }

    #[test]
    fn multiple_headers_join_with_comma_space() {
        // Go/fasthttp merge multiple `Accept-Language` lines into one
        // comma-separated string; the first tag then wins after the join.
        let headers = headers_with(&[b"fr", b"zh-CN"]);
        assert_eq!(
            accept_language_header(&headers).as_deref(),
            Some("fr, zh-CN"),
            "values merge comma-separated, first tag still wins"
        );
        assert_eq!(
            request_language(accept_language_header(&headers).as_deref()),
            "en"
        );
    }

    #[test]
    fn non_ascii_values_are_skipped_not_rejected() {
        // A garbled (non-ASCII) value is skipped; the next valid value wins.
        let headers = headers_with(&[b"zh\xff-TW", b"zh-CN"]);
        assert_eq!(accept_language_header(&headers).as_deref(), Some("zh-CN"));
        assert_eq!(
            request_language(accept_language_header(&headers).as_deref()),
            "zh-CN"
        );

        // When every value is garbled there is no header to parse, so the
        // caller falls back to the default language rather than an error.
        let headers = headers_with(&[b"\xff\xfe"]);
        assert_eq!(accept_language_header(&headers), None);
        assert_eq!(
            request_language(accept_language_header(&headers).as_deref()),
            "en"
        );
    }

    #[test]
    fn absent_header_yields_none() {
        assert_eq!(accept_language_header(&HeaderMap::new()), None);
    }
}
