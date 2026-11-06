//! Pure Cloudflare Turnstile decision layer.
//!
//! This module deliberately performs no network I/O: the caller owns the
//! siteverify request and passes its outcome in. That keeps the Go contract
//! (disabled -> pass, empty token -> reject, verify failure -> reject) testable
//! without an HTTP client dependency.

/// Outcome for the request middleware to apply. Every string is an i18n key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Pass,
    Reject(&'static str),
    Unavailable(&'static str),
}

/// Extract the first `turnstile` value from a raw URI query string.
///
/// `fasthttp`'s `Args.Peek` returns the first value for a repeated key, so
/// repeated parameters are not combined or overridden. Decoding follows
/// `application/x-www-form-urlencoded`: `+` is a space and `%XX` is a byte.
pub fn query_token(query: Option<&str>) -> Option<String> {
    let query = query?;
    for pair in query.split('&') {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        if decode_component(raw_key) == "turnstile" {
            let token = decode_component(raw_value);
            return (!token.is_empty()).then_some(token);
        }
    }
    None
}

/// Parse the siteverify response, requiring a top-level boolean `success`.
///
/// Unknown fields are skipped, matching Go's decoding of the two-field struct.
/// Missing fields, non-object bodies, wrong value types, and trailing garbage
/// all report `None`.
pub fn parse_verify_success(body: &str) -> Option<bool> {
    match Parser::new(body).parse_document()? {
        JsonValue::Object(fields) => {
            let mut success = None;
            for (key, value) in fields {
                if key == "success" {
                    match value {
                        JsonValue::Bool(flag) => success = Some(flag),
                        _ => return None,
                    }
                }
            }
            success
        }
        _ => None,
    }
}

/// Apply the switch, token, and verification outcome in the Go middleware order.
pub fn decide(enabled: bool, token: Option<&str>, verify: Option<Result<bool, ()>>) -> Decision {
    if !enabled {
        return Decision::Pass;
    }
    match token {
        None | Some("") => Decision::Reject("turnstile.token_empty"),
        Some(_) => match verify {
            None => Decision::Unavailable("turnstile.unavailable"),
            Some(Err(())) => Decision::Reject("turnstile.verify_error"),
            Some(Ok(true)) => Decision::Pass,
            Some(Ok(false)) => Decision::Reject("turnstile.verify_failed"),
        },
    }
}

fn decode_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_value);
                let low = bytes.get(index + 2).copied().and_then(hex_value);
                match (high, low) {
                    (Some(high), Some(low)) => {
                        decoded.push((high << 4) | low);
                        index += 3;
                    }
                    // Match fasthttp: an incomplete or non-hex escape stays literal.
                    _ => {
                        decoded.push(b'%');
                        index += 1;
                    }
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

const MAX_JSON_DEPTH: usize = 64;

enum JsonValue {
    Null,
    Bool(bool),
    Number,
    String,
    Array,
    Object(Vec<(String, JsonValue)>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            position: 0,
        }
    }

    fn parse_document(&mut self) -> Option<JsonValue> {
        self.skip_whitespace();
        let value = self.parse_value(0)?;
        self.skip_whitespace();
        (self.position == self.bytes.len()).then_some(value)
    }

    fn parse_value(&mut self, depth: usize) -> Option<JsonValue> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.skip_whitespace();
        match self.peek()? {
            b'{' => self.parse_object(depth),
            b'[' => self.parse_array(depth),
            b'"' => self.parse_string().map(|_| JsonValue::String),
            b't' => self.parse_literal(b"true").map(|_| JsonValue::Bool(true)),
            b'f' => self.parse_literal(b"false").map(|_| JsonValue::Bool(false)),
            b'n' => self.parse_literal(b"null").map(|_| JsonValue::Null),
            b'-' | b'0'..=b'9' => self.parse_number(),
            _ => None,
        }
    }

    fn parse_object(&mut self, depth: usize) -> Option<JsonValue> {
        self.consume(b'{')?;
        let mut fields = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Some(JsonValue::Object(fields));
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            self.skip_whitespace();
            self.consume(b':')?;
            let value = self.parse_value(depth + 1)?;
            fields.push((key, value));
            self.skip_whitespace();
            match self.peek()? {
                b',' => self.position += 1,
                b'}' => {
                    self.position += 1;
                    return Some(JsonValue::Object(fields));
                }
                _ => return None,
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Option<JsonValue> {
        self.consume(b'[')?;
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Some(JsonValue::Array);
        }
        loop {
            self.parse_value(depth + 1)?;
            self.skip_whitespace();
            match self.peek()? {
                b',' => self.position += 1,
                b']' => {
                    self.position += 1;
                    return Some(JsonValue::Array);
                }
                _ => return None,
            }
        }
    }

    fn parse_string(&mut self) -> Option<String> {
        self.consume(b'"')?;
        let mut value = String::new();
        loop {
            match self.peek()? {
                b'"' => {
                    self.position += 1;
                    return Some(value);
                }
                b'\\' => {
                    self.position += 1;
                    match self.peek()? {
                        b'"' => {
                            value.push('"');
                            self.position += 1;
                        }
                        b'\\' => {
                            value.push('\\');
                            self.position += 1;
                        }
                        b'/' => {
                            value.push('/');
                            self.position += 1;
                        }
                        b'b' => {
                            value.push('\u{08}');
                            self.position += 1;
                        }
                        b'f' => {
                            value.push('\u{0c}');
                            self.position += 1;
                        }
                        b'n' => {
                            value.push('\n');
                            self.position += 1;
                        }
                        b'r' => {
                            value.push('\r');
                            self.position += 1;
                        }
                        b't' => {
                            value.push('\t');
                            self.position += 1;
                        }
                        b'u' => {
                            self.position += 1;
                            let code = self.parse_hex4()?;
                            let scalar = if (0xd800..=0xdbff).contains(&code) {
                                if !self.bytes[self.position..].starts_with(b"\\u") {
                                    return None;
                                }
                                self.position += 2;
                                let low = self.parse_hex4()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return None;
                                }
                                0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00)
                            } else if (0xdc00..=0xdfff).contains(&code) {
                                return None;
                            } else {
                                code
                            };
                            value.push(char::from_u32(scalar)?);
                        }
                        _ => return None,
                    }
                }
                byte if byte < 0x20 => return None,
                _ => {
                    let rest = std::str::from_utf8(&self.bytes[self.position..]).ok()?;
                    let character = rest.chars().next()?;
                    value.push(character);
                    self.position += character.len_utf8();
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Option<u32> {
        let mut code = 0_u32;
        for _ in 0..4 {
            let digit = self.peek()?;
            code = code * 16 + u32::from(hex_value(digit)?);
            self.position += 1;
        }
        Some(code)
    }

    fn parse_number(&mut self) -> Option<JsonValue> {
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        match self.peek()? {
            b'0' => self.position += 1,
            b'1'..=b'9' => {
                self.position += 1;
                self.skip_digits();
            }
            _ => return None,
        }
        if self.peek() == Some(b'.') {
            self.position += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            self.skip_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return None;
            }
            self.skip_digits();
        }
        Some(JsonValue::Number)
    }

    fn skip_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
    }

    fn parse_literal(&mut self, literal: &[u8]) -> Option<()> {
        if self.bytes[self.position..].starts_with(literal) {
            self.position += literal.len();
            Some(())
        } else {
            None
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn consume(&mut self, expected: u8) -> Option<()> {
        if self.peek()? == expected {
            self.position += 1;
            Some(())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_check_passes_even_without_a_token() {
        assert_eq!(decide(false, None, None), Decision::Pass);
        assert_eq!(decide(false, Some(""), Some(Ok(false))), Decision::Pass);
    }

    #[test]
    fn missing_or_empty_token_rejects_before_verification() {
        assert_eq!(
            decide(true, None, None),
            Decision::Reject("turnstile.token_empty"),
        );
        assert_eq!(
            decide(true, Some(""), None),
            Decision::Reject("turnstile.token_empty"),
        );
        // A verification result cannot rescue an empty token.
        assert_eq!(
            decide(true, Some(""), Some(Ok(true))),
            Decision::Reject("turnstile.token_empty"),
        );
    }

    #[test]
    fn absent_verification_transport_is_unavailable() {
        assert_eq!(
            decide(true, Some("token"), None),
            Decision::Unavailable("turnstile.unavailable"),
        );
    }

    #[test]
    fn transport_and_decode_errors_are_rejections() {
        assert_eq!(
            decide(true, Some("token"), Some(Err(()))),
            Decision::Reject("turnstile.verify_error"),
        );
    }

    #[test]
    fn verification_outcome_controls_the_decision() {
        assert_eq!(decide(true, Some("token"), Some(Ok(true))), Decision::Pass);
        assert_eq!(
            decide(true, Some("token"), Some(Ok(false))),
            Decision::Reject("turnstile.verify_failed"),
        );
    }

    #[test]
    fn query_token_reads_the_first_value() {
        assert_eq!(query_token(None), None);
        assert_eq!(query_token(Some("")), None);
        assert_eq!(query_token(Some("turnstile=abc")), Some("abc".into()));
        assert_eq!(
            query_token(Some("a=1&turnstile=abc&b=2")),
            Some("abc".into()),
        );
        assert_eq!(
            query_token(Some("turnstile=first&turnstile=second")),
            Some("first".into()),
        );
        // The first occurrence wins even when it is empty.
        assert_eq!(query_token(Some("turnstile=&turnstile=second")), None);
        assert_eq!(query_token(Some("turnstile")), None);
        assert_eq!(query_token(Some("turnstile=")), None);
    }

    #[test]
    fn query_token_decodes_form_encoding() {
        assert_eq!(query_token(Some("turnstile=a+b")), Some("a b".into()));
        assert_eq!(query_token(Some("turnstile=a%20b")), Some("a b".into()));
        assert_eq!(query_token(Some("turnstile=%E4%B8%AD")), Some("中".into()));
        assert_eq!(query_token(Some("%74urnstile=ok")), Some("ok".into()));
        assert_eq!(query_token(Some("turnstile=a%3Db")), Some("a=b".into()));
    }

    #[test]
    fn query_token_survives_invalid_percent_escapes() {
        assert_eq!(query_token(Some("turnstile=%ZZ")), Some("%ZZ".into()));
        assert_eq!(query_token(Some("turnstile=%2")), Some("%2".into()));
        assert_eq!(query_token(Some("turnstile=%")), Some("%".into()));
    }

    #[test]
    fn parses_success_booleans() {
        assert_eq!(parse_verify_success(r#"{"success":true}"#), Some(true));
        assert_eq!(parse_verify_success(r#"{"success":false}"#), Some(false));
        assert_eq!(
            parse_verify_success(" \n { \"success\" : true } \t"),
            Some(true),
        );
        assert_eq!(
            parse_verify_success(r#"{"challenge_ts":"x","success":true,"error-codes":[]}"#),
            Some(true),
        );
        assert_eq!(
            parse_verify_success(r#"{"note":"\ud83d\ude00","success":false}"#),
            Some(false),
        );
    }

    #[test]
    fn rejects_malformed_or_unrelated_verify_bodies() {
        assert_eq!(parse_verify_success(""), None);
        assert_eq!(parse_verify_success("not json"), None);
        assert_eq!(parse_verify_success("[]"), None);
        assert_eq!(parse_verify_success("null"), None);
        assert_eq!(parse_verify_success("{}"), None);
        assert_eq!(parse_verify_success(r#"{"success":"true"}"#), None);
        assert_eq!(parse_verify_success(r#"{"success":null}"#), None);
        assert_eq!(parse_verify_success(r#"{"success":1}"#), None);
        assert_eq!(parse_verify_success(r#"{"success":true"#), None);
        assert_eq!(parse_verify_success(r#"{"success":true} trailing"#), None);
    }
}
