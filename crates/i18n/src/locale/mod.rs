//! Embedded locale catalogs and the language normalization helpers.

mod normalize;
mod translate;

pub use normalize::{
    DEFAULT_LANG, LANG_EN, LANG_ZH_CN, LANG_ZH_TW, is_supported, normalize_lang,
    parse_accept_language, supported_languages,
};
pub use translate::{t, translate};

use std::{collections::BTreeMap, sync::LazyLock};

const EN_YAML: &str = include_str!("../../locales/en.yaml");
const ZH_CN_YAML: &str = include_str!("../../locales/zh-CN.yaml");
const ZH_TW_YAML: &str = include_str!("../../locales/zh-TW.yaml");

static CATALOG: LazyLock<Catalog> = LazyLock::new(|| {
    Catalog::from_yaml(EN_YAML, ZH_CN_YAML, ZH_TW_YAML)
        .expect("embedded locale catalogs must be valid YAML string maps")
});

pub(crate) struct Catalog {
    en: BTreeMap<String, String>,
    zh_cn: BTreeMap<String, String>,
    zh_tw: BTreeMap<String, String>,
}

impl Catalog {
    fn from_yaml(en: &str, zh_cn: &str, zh_tw: &str) -> Result<Self, serde_yaml::Error> {
        Ok(Self {
            en: serde_yaml::from_str(en)?,
            zh_cn: serde_yaml::from_str(zh_cn)?,
            zh_tw: serde_yaml::from_str(zh_tw)?,
        })
    }

    /// Message for an already-normalized language code. There is no
    /// cross-language fallback: a key missing from the requested catalog is
    /// reported as missing, matching the upstream localizer setup.
    pub(crate) fn message(&self, lang: &str, key: &str) -> Option<&str> {
        let messages = match lang {
            LANG_ZH_CN => &self.zh_cn,
            LANG_ZH_TW => &self.zh_tw,
            _ => &self.en,
        };
        messages.get(key).map(String::as_str)
    }
}

pub(crate) fn catalog() -> &'static Catalog {
    &CATALOG
}
