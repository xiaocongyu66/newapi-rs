//! Message translation with `go-i18n`-style `{{.Name}}` substitution.

use std::{collections::BTreeMap, fmt::Display};

use super::{catalog, normalize_lang};

/// Translate `key` for `lang` without template arguments.
///
/// Missing messages return `key`. If the catalog message contains a template
/// action, upstream `Translate` is called with nil template data, which makes
/// execution fail; this function therefore also returns `key` in that case.
pub fn t<'a>(lang: &str, key: &'a str) -> &'a str {
    let lang = normalize_lang(lang);
    match catalog().message(lang, key) {
        Some(message) if render(message, None).is_some() => message,
        _ => key,
    }
}

/// Translate `key` for `lang`, substituting `{{.Name}}` placeholders.
///
/// `args` supplies `(name, value)` pairs; values are rendered with
/// [`Display`]. Missing messages and template failures return `key`, matching
/// upstream `Translate`. Missing placeholders render as `<no value>`, the
/// `text/template` default used by go-i18n.
pub fn translate<I, K, V>(lang: &str, key: &str, args: I) -> String
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: Display,
{
    let lang = normalize_lang(lang);
    let Some(message) = catalog().message(lang, key) else {
        return key.to_owned();
    };

    let data: BTreeMap<String, String> = args
        .into_iter()
        .map(|(name, value)| (name.as_ref().to_owned(), value.to_string()))
        .collect();

    if data.is_empty() {
        return render(message, None).unwrap_or_else(|| key.to_owned());
    }

    render(message, Some(&data)).unwrap_or_else(|| key.to_owned())
}

fn render(template: &str, data: Option<&BTreeMap<String, String>>) -> Option<String> {
    let mut output = String::with_capacity(template.len());
    let mut remaining = template;

    while let Some(start) = remaining.find("{{") {
        output.push_str(&remaining[..start]);
        let action = &remaining[start + 2..];
        let end = action.find("}}")?;
        let expression = action[..end].trim();
        let name = expression.strip_prefix('.')?;
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return None;
        }
        let data = data?;
        match data.get(name) {
            Some(value) => output.push_str(value),
            None => output.push_str("<no value>"),
        }
        remaining = &action[end + 2..];
    }

    output.push_str(remaining);
    Some(output)
}
