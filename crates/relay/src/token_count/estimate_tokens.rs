//! Heuristic character-class token estimator. Verbatim port of the upstream
//! Go `internal/relay/common/estimate_tokens.go` (lines 1-230). This is the
//! engine behind `EstimateTokenByModel` — no tiktoken is involved on this
//! path; the provider multipliers are billing-relevant weights, so the tables
//! below must stay byte-identical to the Go oracle.

/// Go `common.Provider` (estimate_tokens.go:11-18).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    OpenAI,
    Gemini,
    Claude,
}

/// Go `multipliers` (estimate_tokens.go:21-33). `base_pad` is the start/end
/// token padding (0 for every provider in the oracle).
#[derive(Clone, Copy, Debug)]
pub struct Multipliers {
    pub word: f64,
    pub number: f64,
    pub cjk: f64,
    pub symbol: f64,
    pub math_symbol: f64,
    pub url_delim: f64,
    pub at_sign: f64,
    pub emoji: f64,
    pub newline: f64,
    pub space: f64,
    pub base_pad: i64,
}

impl Multipliers {
    const OPENAI: Multipliers = Multipliers {
        word: 1.02,
        number: 1.55,
        cjk: 0.85,
        symbol: 0.4,
        math_symbol: 2.68,
        url_delim: 1.0,
        at_sign: 2.0,
        emoji: 2.12,
        newline: 0.5,
        space: 0.42,
        base_pad: 0,
    };
    const GEMINI: Multipliers = Multipliers {
        word: 1.15,
        number: 2.8,
        cjk: 0.68,
        symbol: 0.38,
        math_symbol: 1.05,
        url_delim: 1.2,
        at_sign: 2.5,
        emoji: 1.08,
        newline: 1.15,
        space: 0.2,
        base_pad: 0,
    };
    const CLAUDE: Multipliers = Multipliers {
        word: 1.13,
        number: 1.63,
        cjk: 1.21,
        symbol: 0.4,
        math_symbol: 4.52,
        url_delim: 1.26,
        at_sign: 2.82,
        emoji: 2.6,
        newline: 0.89,
        space: 0.39,
        base_pad: 0,
    };
}

/// Go `getMultipliers` (estimate_tokens.go:51-66): unknown provider falls
/// back to the OpenAI weights.
pub fn get_multipliers(provider: Provider) -> Multipliers {
    match provider {
        Provider::Gemini => Multipliers::GEMINI,
        Provider::Claude => Multipliers::CLAUDE,
        Provider::OpenAI => Multipliers::OPENAI,
    }
}

enum WordType {
    None,
    Latin,
    Number,
}

fn is_word_type(r: char) -> bool {
    // Go isLatinOrNumber: unicode.IsLetter || unicode.IsNumber.
    r.is_alphabetic() || r.is_numeric()
}

fn is_cjk(r: char) -> bool {
    // Go isCJK (estimate_tokens.go:151-155): Han + kana ranges + Hangul.
    if (r as u32) >= 0x3040 && (r as u32) <= 0x30FF {
        return true;
    }
    if (r as u32) >= 0xAC00 && (r as u32) <= 0xD7A3 {
        return true;
    }
    // Go unicode.Is(unicode.Han, r) — the Han script ranges from
    // Unicode Scripts.txt (2E80-2EF1 radical supplement, 2F00-2FD5 Kangxi
    // radicals, 3005, 3007, 3021-3029, 3038-303A, 31C0-31E3 strokes,
    // 3400-4DBF ext-A, 4E00-9FFF, F900-FA6D compat, FA70-FAD9, and the
    // supplementary planes).
    let c = r as u32;
    matches!(c,
        0x2E80..=0x2EF1
            | 0x2F00..=0x2FD5
            | 0x3005
            | 0x3007
            | 0x3021..=0x3029
            | 0x3038..=0x303A
            | 0x31C0..=0x31E3
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xF900..=0xFA6D
            | 0xFA70..=0xFAD9
            | 0x20000..=0x2A6DF
            | 0x2A700..=0x2B739
            | 0x2B740..=0x2B81D
            | 0x2B820..=0x2CEA1
            | 0x2CEB0..=0x2EBE0
            | 0x2F800..=0x2FA1D
            | 0x30000..=0x3134A
    )
}

fn is_emoji(r: char) -> bool {
    // Go isEmoji (estimate_tokens.go:163-175).
    let c = r as u32;
    (0x1F300..=0x1F9FF).contains(&c)
        || (0x2600..=0x26FF).contains(&c)
        || (0x2700..=0x27BF).contains(&c)
        || (0x1F600..=0x1F64F).contains(&c)
        || (0x1F900..=0x1F9FF).contains(&c)
        || (0x1FA00..=0x1FAFF).contains(&c)
}

const MATH_SYMBOLS: &str =
    "∑∫∂√∞≤≥≠≈±×÷∈∉∋∌⊂⊃⊆⊇∪∩∧∨¬∀∃∄∅∆∇∝∟∠∡∢°′″‴⁺⁻⁼⁽⁾ⁿ₀₁₂₃₄₅₆₇₈₉₊₋₌₍₎²³¹⁴⁵⁶⁷⁸⁹⁰";

fn is_math_symbol(r: char) -> bool {
    if MATH_SYMBOLS.contains(r) {
        return true;
    }
    let c = r as u32;
    (0x2200..=0x22FF).contains(&c)
        || (0x2A00..=0x2AFF).contains(&c)
        || (0x1D400..=0x1D7FF).contains(&c)
}

fn is_url_delim(r: char) -> bool {
    "/:?&=;#%".contains(r)
}

/// Go `EstimateToken` (estimate_tokens.go:69-148).
pub fn estimate_token(provider: Provider, text: &str) -> i64 {
    let m = get_multipliers(provider);
    let mut count = 0.0f64;
    let mut current_word_type = WordType::None;

    for r in text.chars() {
        // 1. Whitespace.
        if r.is_whitespace() {
            current_word_type = WordType::None;
            if r == '\n' || r == '\t' {
                count += m.newline;
            } else {
                count += m.space;
            }
            continue;
        }

        // 2. CJK.
        if is_cjk(r) {
            current_word_type = WordType::None;
            count += m.cjk;
            continue;
        }

        // 3. Emoji.
        if is_emoji(r) {
            current_word_type = WordType::None;
            count += m.emoji;
            continue;
        }

        // 4. Latin letters / numbers.
        if is_word_type(r) {
            let new_type = if r.is_numeric() {
                WordType::Number
            } else {
                WordType::Latin
            };
            let is_new = match &current_word_type {
                WordType::None => true,
                WordType::Latin => !matches!(new_type, WordType::Latin),
                WordType::Number => !matches!(new_type, WordType::Number),
            };
            if is_new {
                if matches!(new_type, WordType::Number) {
                    count += m.number;
                } else {
                    count += m.word;
                }
                current_word_type = new_type;
            }
            continue;
        }

        // 5. Punctuation / special characters.
        current_word_type = WordType::None;
        if is_math_symbol(r) {
            count += m.math_symbol;
        } else if r == '@' {
            count += m.at_sign;
        } else if is_url_delim(r) {
            count += m.url_delim;
        } else {
            count += m.symbol;
        }
    }

    count.ceil() as i64 + m.base_pad
}

/// Go `EstimateTokenByModel` (estimate_tokens.go:216-230): model-name routing
/// onto providers. Empty text → 0.
pub fn estimate_token_by_model(model: &str, text: &str) -> i64 {
    if text.is_empty() {
        return 0;
    }
    let model = model.to_lowercase();
    if model.contains("gemini") {
        estimate_token(Provider::Gemini, text)
    } else if model.contains("claude") {
        estimate_token(Provider::Claude, text)
    } else {
        estimate_token(Provider::OpenAI, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty text is free for every provider (estimate_tokens.go:218-220).
    #[test]
    fn empty_text_counts_zero() {
        for model in ["gpt-4o", "claude-3", "gemini-1.5", "", "unknown"] {
            assert_eq!(estimate_token_by_model(model, ""), 0);
        }
    }

    /// Pure-ASCII word: one word token per contiguous latin run.
    /// "hello world" → two words + one space.
    #[test]
    fn ascii_words_and_spaces() {
        // OpenAI: word 1.02, space 0.42 → 2*1.02 + 0.42 = 2.46 → ceil 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "hello world"), 3);
        // Claude: 2*1.13 + 0.39 = 2.65 → ceil 3.
        assert_eq!(estimate_token_by_model("claude-3", "hello world"), 3);
        // Gemini: 2*1.15 + 0.2 = 2.5 → ceil 3.
        assert_eq!(estimate_token_by_model("gemini-1.5", "hello world"), 3);
    }

    /// Latin↔digit boundaries restart the word counter
    /// (estimate_tokens.go:118-128).
    #[test]
    fn latin_number_boundaries() {
        // "abc123" → word + number = 1.02 + 1.55 = 2.57 → ceil 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "abc123"), 3);
        // "abc" single word → 1.02 → ceil 2.
        assert_eq!(estimate_token_by_model("gpt-4o", "abc"), 2);
        // "123" single number run → 1.55 → ceil 2.
        assert_eq!(estimate_token_by_model("gpt-4o", "123"), 2);
    }

    /// Newline uses the newline weight; tab too; other whitespace (e.g. the
    /// ideographic space U+3000) uses the space weight.
    #[test]
    fn newline_and_whitespace_weights() {
        // "a\nb": 1.02 + 0.5 + 1.02 = 2.54 → ceil 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "a\nb"), 3);
        // "a\tb": same weights for tab → 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "a\tb"), 3);
    }

    /// CJK bills per character (Go 0x4E00 block, e.g. 中).
    #[test]
    fn cjk_per_character() {
        // "中文" → 2 * 0.85 = 1.7 → ceil 2.
        assert_eq!(estimate_token_by_model("gpt-4o", "中文"), 2);
        // Claude CJK weight 1.21 → 2.42 → ceil 3.
        assert_eq!(estimate_token_by_model("claude-3", "中文"), 3);
        // Gemini CJK weight 0.68 → 1.36 → ceil 2.
        assert_eq!(estimate_token_by_model("gemini-1.5", "中文"), 2);
    }

    /// Kana is CJK-classified via the 0x3040–0x30FF range; Hangul via
    /// 0xAC00–0xD7A3.
    #[test]
    fn kana_and_hangul_count_as_cjk() {
        assert_eq!(estimate_token_by_model("gpt-4o", "あん"), 2);
        assert_eq!(estimate_token_by_model("gpt-4o", "한글"), 2);
    }

    /// Emoji uses the dedicated weight (U+1F600 block).
    #[test]
    fn emoji_weight() {
        // "😀" → 2.12 → ceil 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "\u{1F600}"), 3);
    }

    /// Math symbols: explicit table membership and Unicode math blocks.
    #[test]
    fn math_symbol_weights() {
        // "∑" table symbol → 2.68 → ceil 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "∑"), 3);
        // "∈" inside U+2200–22FF → 3.
        assert_eq!(estimate_token_by_model("gpt-4o", "∈"), 3);
    }

    /// @ and URL delimiters use their dedicated weights.
    #[test]
    fn at_sign_and_url_delims() {
        // "@" → 2.0 → ceil 2.
        assert_eq!(estimate_token_by_model("gpt-4o", "@"), 2);
        // "/" URL delim → 1.0 → ceil 1.
        assert_eq!(estimate_token_by_model("gpt-4o", "/"), 1);
        // Generic punctuation "." → 0.4 → ceil 1.
        assert_eq!(estimate_token_by_model("gpt-4o", "."), 1);
    }

    /// URL-shaped text exercises delims + words together.
    #[test]
    fn url_shape() {
        // "a/b" → word 1.02 + delim 1.0 + word 1.02 = 3.04 → ceil 4.
        assert_eq!(estimate_token_by_model("gpt-4o", "a/b"), 4);
    }

    /// Unknown model falls back to OpenAI weights (estimate_tokens.go:227-229).
    #[test]
    fn unknown_model_uses_openai() {
        assert_eq!(
            estimate_token_by_model("mistral-large", "hello world"),
            estimate_token_by_model("gpt-4o", "hello world")
        );
    }

    /// Model routing: contains "gemini"/"claude" (case-insensitive).
    #[test]
    fn model_routing() {
        assert_eq!(
            estimate_token_by_model("Google/Gemini-Flash", "hello world"),
            estimate_token_by_model("gemini", "hello world")
        );
        assert_eq!(
            estimate_token_by_model("Anthropic/CLAUDE-3", "hello world"),
            estimate_token_by_model("claude", "hello world")
        );
    }

    /// Provider multipliers match the Go tables byte-for-byte
    /// (estimate_tokens.go:36-46).
    #[test]
    fn multiplier_tables_match_go_oracle() {
        let openai = get_multipliers(Provider::OpenAI);
        assert_eq!(openai.word, 1.02);
        assert_eq!(openai.number, 1.55);
        assert_eq!(openai.cjk, 0.85);
        assert_eq!(openai.symbol, 0.4);
        assert_eq!(openai.math_symbol, 2.68);
        assert_eq!(openai.url_delim, 1.0);
        assert_eq!(openai.at_sign, 2.0);
        assert_eq!(openai.emoji, 2.12);
        assert_eq!(openai.newline, 0.5);
        assert_eq!(openai.space, 0.42);
        assert_eq!(openai.base_pad, 0);

        let gemini = get_multipliers(Provider::Gemini);
        assert_eq!(gemini.word, 1.15);
        assert_eq!(gemini.number, 2.8);
        assert_eq!(gemini.cjk, 0.68);
        assert_eq!(gemini.math_symbol, 1.05);
        assert_eq!(gemini.emoji, 1.08);

        let claude = get_multipliers(Provider::Claude);
        assert_eq!(claude.word, 1.13);
        assert_eq!(claude.number, 1.63);
        assert_eq!(claude.cjk, 1.21);
        assert_eq!(claude.math_symbol, 4.52);
        assert_eq!(claude.emoji, 2.6);
    }
}
