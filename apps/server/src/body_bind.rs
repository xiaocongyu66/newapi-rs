//! 请求体绑定：Go `common.UnmarshalBodyReusable`（`gin.go:111-169`）的
//! Content-Type 分发语义。
//!
//! Go 的 `c.BindJSON` 并不只读 JSON：`UnmarshalBodyReusable` 按 Content-Type
//! 分发——
//! - 无/空 Content-Type：按 `application/json` 处理（保持旧行为）；
//! - 前缀 `application/json`：JSON 解码；
//! - 含 `application/x-www-form-urlencoded`：`url.ParseQuery` 后按
//!   `processFormMap`（map→JSON→struct）绑定，键即 JSON 字段名；
//! - 含 `multipart/form-data`：从完整 Content-Type 头取 boundary，
//!   解析 `multipart.Reader.ReadForm` 的 `form.Value`（文件 part 不参与）
//!   后走同一条 map→JSON→struct 绑定；boundary 缺失时回退 JSON 解码；
//! - 其它 Content-Type：跳过解析，目标保持零值（不是错误）；
//! - 空体：零值（不是错误），且该分支在 Content-Type 分发之前。
//!
//! 任何一条分支的解析失败都是绑定错误，调用方对外固定为
//! `common.invalid_params`。本模块只做字节→值的解析，不触达响应。
//!
//! ` ContentType()` 在 Go 契约里会先剥掉 `;` 后的参数再返回
//! （`fiberadapter/context.go:418-424`），所以下面的分发值也是剥掉参数后
//! 的小写主类型；multipart 的 boundary 只能从完整头取，与 Go
//! `parseMultipartFormData` 读 `c.Header("Content-Type")` 一致。

use axum::http::{HeaderMap, header};
use serde::de::DeserializeOwned;

/// 绑定结果；失败统一为 `()`，调用方折叠成 `common.invalid_params`。
/// `Default` 上界对应 Go 的“空体/未知 Content-Type 保持零值”分支。
pub fn bind_body<T: DeserializeOwned + Default>(headers: &HeaderMap, body: &[u8]) -> Result<T, ()> {
    if body.is_empty() {
        // Go：空体保持零值，不是错误（GET/DELETE 也经此路径）。
        return Ok(T::default());
    }
    match content_type_kind(headers) {
        ContentTypeKind::Json => serde_json::from_slice(body).map_err(|_| ()),
        ContentTypeKind::FormUrlencoded => {
            let pairs = parse_form_query(body)?;
            from_form_pairs::<T>(pairs)
        }
        ContentTypeKind::Multipart => {
            let full = full_content_type(headers);
            parse_multipart::<T>(&full, body)
        }
        ContentTypeKind::Skip => {
            // Go 的 `else { /* skip for now */ }`：零值，不是错误。
            Ok(T::default())
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentTypeKind {
    Json,
    FormUrlencoded,
    Multipart,
    Skip,
}

/// Go `c.ContentType()`：剥掉第一个 `;` 后的参数并 trim；空头按
/// `application/json` 处理。匹配用 `HasPrefix`（json）与 `Contains`（表单），
/// 复刻 `UnmarshalBodyReusable` 的判定。
fn content_type_kind(headers: &HeaderMap) -> ContentTypeKind {
    let Some(value) = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    else {
        return ContentTypeKind::Json;
    };
    if value.is_empty() {
        return ContentTypeKind::Json;
    }
    let stripped = match value.split(';').next() {
        Some(part) => part.trim(),
        None => value,
    };
    let lowered = stripped.to_ascii_lowercase();
    if lowered.starts_with("application/json") {
        ContentTypeKind::Json
    } else if lowered.contains("application/x-www-form-urlencoded") {
        ContentTypeKind::FormUrlencoded
    } else if lowered.contains("multipart/form-data") {
        ContentTypeKind::Multipart
    } else {
        ContentTypeKind::Skip
    }
}

fn full_content_type(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

/// Go `processFormMap`（`gin.go:307-319`）：单值 → 字符串，多值 → 字符串
/// 数组；marshal 成 JSON 后 `Unmarshal` 进目标结构。键即 JSON 字段名，
/// 因此重复键绑进字符串字段会让 `serde_json` 报类型错误，与 Go 一致。
fn from_form_pairs<T: DeserializeOwned>(pairs: Vec<(String, String)>) -> Result<T, ()> {
    let mut grouped: Vec<(String, Vec<String>)> = Vec::new();
    for (key, value) in pairs {
        match grouped.iter_mut().find(|(existing, _)| existing == &key) {
            Some((_, values)) => values.push(value),
            None => grouped.push((key, vec![value])),
        }
    }
    let mut object = serde_json::Map::new();
    for (key, values) in grouped {
        let value = if values.len() == 1 {
            serde_json::Value::String(values.into_iter().next().unwrap_or_default())
        } else {
            serde_json::Value::Array(values.into_iter().map(serde_json::Value::String).collect())
        };
        object.insert(key, value);
    }
    serde_json::from_value(serde_json::Value::Object(object)).map_err(|_| ())
}

/// Go `url.ParseQuery`（`parseFormData`，`gin.go:321-336`）。
/// 分隔符为 `&`；pair 以第一个 `=` 切分；键值做 QueryUnescape
/// （`+`→空格、`%XX`）；非法转义或 pair 内出现 `;` 都让整次解析失败
/// （Go 1.17 起分号分隔符是错误）。空 pair 被跳过。
fn parse_form_query(body: &[u8]) -> Result<Vec<(String, String)>, ()> {
    let text = String::from_utf8_lossy(body);
    let mut pairs = Vec::new();
    for raw_pair in text.split('&') {
        if raw_pair.is_empty() {
            continue;
        }
        if raw_pair.contains(';') {
            return Err(());
        }
        let (raw_key, raw_value) = raw_pair.split_once('=').unwrap_or((raw_pair, ""));
        let key = query_unescape(raw_key)?;
        let value = query_unescape(raw_value)?;
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// Go `url.QueryUnescape`：`+`→空格、`%XX`→字节；非法转义返回错误。
fn query_unescape(input: &str) -> Result<String, ()> {
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
                    // Go：非法转义整次解析失败。
                    _ => return Err(()),
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    Ok(String::from_utf8_lossy(&decoded).into_owned())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Go `parseMultipartFormData`（`gin.go:338-370`）：从完整 Content-Type 头
/// 取 boundary（`mime.ParseMediaType` 的 params）；缺失 boundary 时 Go 回退
/// 到 JSON 解码（`errBoundaryNotFound`），随后 `multipart.Reader.ReadForm`
/// 的 `form.Value` 走 `processFormMap`。带 `filename` 的 part 属于
/// `form.File`，不参与值绑定。
fn parse_multipart<T: DeserializeOwned>(content_type: &str, body: &[u8]) -> Result<T, ()> {
    let Some(boundary) = parse_boundary(content_type) else {
        // Go：boundary 缺失 → `Unmarshal(data, v)` 回退 JSON。
        return serde_json::from_slice(body).map_err(|_| ());
    };
    let pairs = read_form_values(&boundary, body)?;
    from_form_pairs::<T>(pairs)
}

/// Go `parseBoundary`（`gin.go:374-386`）：`mime.ParseMediaType` 取
/// `boundary` 参数。空 Content-Type → `errBoundaryNotFound`（调用方回退
/// JSON）。
fn parse_boundary(content_type: &str) -> Option<String> {
    if content_type.is_empty() {
        return None;
    }
    for param in content_type.split(';').skip(1) {
        let param = param.trim();
        if let Some((name, value)) = param.split_once('=') {
            if name.trim().eq_ignore_ascii_case("boundary") {
                let value = value.trim();
                // Go 的 ParseMediaType 去掉参数值的引号。
                let value = value
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or(value);
                if !value.is_empty() {
                    return Some(value.to_owned());
                }
            }
        }
    }
    None
}

/// Go `multipart.Reader.ReadForm` 的值收集：part 依次由
/// `\r\n--boundary` 分隔，首个边界前没有 CRLF；边界后可跟传输填充
/// （空格/制表符）再接行结束；`--boundary--` 是结束边界。每个 part 的
/// 头读至空行，值持续到下一条边界前；尾部的单个 CRLF 属于分隔符不属值。
/// 无 `Content-Disposition` 或无 `name` 参数的 part 被跳过（Go
/// `FormName() == ""` 时 `continue`）；带 `filename` 的文件 part 不进
/// `form.Value`。
///
/// 简化边界（与浏览器/常见客户端一致）：不做 RFC 2046 的 7bit 编码转换、
/// 不区分 `part.Header` 的重复头。Go 的行为等价性在这些场景下成立。
fn read_form_values(boundary: &str, body: &[u8]) -> Result<Vec<(String, String)>, ()> {
    let dash_boundary: Vec<u8> = format!("--{boundary}").into_bytes();
    let mut values = Vec::new();
    // 游标始终指向“下一个要解析的 part 之前的边界词元”的开头：
    // 首条边界允许在 body 开头（无前导 CRLF）。
    let mut cursor = match find_token_start(body, 0, &dash_boundary) {
        Some(start) => start,
        // Go：首条边界不匹配即 `NextPart` 错误。
        None => return Err(()),
    };
    loop {
        let after_delimiter = cursor + dash_boundary.len();
        // 结束边界 `--boundary--`：后续无效，停止解析。
        if body[after_delimiter..].starts_with(b"--") {
            break;
        }
        let part_start = skip_line_ending(body, after_delimiter);
        let Some((header_end, data_start)) = find_header_end(body, part_start) else {
            return Err(());
        };
        let headers = &body[part_start..header_end];
        // part 数据延续到下一条边界词元；其前的单个 CRLF 属于分隔符。
        let next_token = match find_token_start(body, data_start, &dash_boundary) {
            Some(start) => start,
            None => return Err(()),
        };
        if let Some(name) = form_value_name(headers) {
            let mut data = body[data_start..next_token].to_owned();
            strip_one_crlf(&mut data);
            values.push((name, String::from_utf8_lossy(&data).into_owned()));
        }
        cursor = next_token;
    }
    Ok(values)
}

/// 找到从 `from` 开始的下一条边界词元的**开头**：`from == 0` 时允许
/// body 直接以 `--boundary` 开始；否则按 `\r\n--boundary` 定位，词元
/// 开头即 CRLF 之后的位置（数据段使用 `..token_start` 截取）。
fn find_token_start(body: &[u8], from: usize, dash_boundary: &[u8]) -> Option<usize> {
    if from == 0 && body.starts_with(dash_boundary) {
        return Some(0);
    }
    let search = match body.get(from..) {
        Some(slice) => slice,
        None => return None,
    };
    let pattern = [&b"\r\n"[..], dash_boundary].concat();
    let offset = search
        .windows(pattern.len())
        .position(|w| w == pattern.as_slice())?;
    Some(from + offset + 2)
}

/// 跳过边界词元后的传输填充与行结束。
fn skip_line_ending(body: &[u8], from: usize) -> usize {
    let mut index = from;
    while matches!(body.get(index), Some(b' ') | Some(b'\t')) {
        index += 1;
    }
    if body[index..].starts_with(b"\r\n") {
        index + 2
    } else if body[index..].starts_with(b"\n") {
        index + 1
    } else {
        index
    }
}

/// part 头以空行结束；返回（头区终点，数据起点）。
fn find_header_end(body: &[u8], from: usize) -> Option<(usize, usize)> {
    let rest = body.get(from..)?;
    let crlf = rest.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_end = from + crlf + 2;
    Some((header_end, header_end + 2))
}

/// 从 part 头解析 `Content-Disposition: form-data; name="..."` 的 `name`。
/// 带 `filename` 参数（文件 part）返回 `None`，与 Go `form.Value` 一致。
fn form_value_name(headers: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(headers);
    for line in text.split("\r\n") {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("content-disposition:") {
            continue;
        }
        let value = line["content-disposition:".len()..].trim();
        if !value.to_ascii_lowercase().starts_with("form-data") {
            continue;
        }
        let disposition = &value["form-data".len()..];
        let mut name = None;
        let mut has_filename = false;
        for param in disposition.split(';') {
            let param = param.trim();
            if let Some((key, raw)) = param.split_once('=') {
                let key = key.trim().to_ascii_lowercase();
                let value = raw.trim();
                let value = value
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or(value);
                match key.as_str() {
                    "name" => name = Some(value.to_owned()),
                    "filename" => has_filename = true,
                    _ => {}
                }
            }
        }
        return if has_filename { None } else { name };
    }
    None
}

fn strip_one_crlf(data: &mut Vec<u8>) {
    if data.ends_with(b"\r\n") {
        data.truncate(data.len() - 2);
    } else if data.ends_with(&[b'\n']) {
        data.truncate(data.len() - 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use serde::Deserialize;

    #[derive(Debug, Default, Deserialize, PartialEq)]
    struct Sample {
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        verification_code: String,
    }

    fn headers(content_type: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = content_type {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(value).unwrap());
        }
        headers
    }

    #[test]
    fn empty_body_is_zero_values_not_an_error() {
        let bound = bind_body::<Sample>(&headers(Some("application/json")), b"").unwrap();
        assert_eq!(bound, Sample::default());
    }

    #[test]
    fn unknown_content_type_is_skipped_not_an_error() {
        let bound = bind_body::<Sample>(&headers(Some("text/plain")), br#"{"username":"ignored"}"#)
            .unwrap();
        assert_eq!(bound, Sample::default());
    }

    #[test]
    fn missing_content_type_is_treated_as_json() {
        let bound = bind_body::<Sample>(
            &headers(None),
            br#"{"username":"alice","password":"secret123"}"#,
        )
        .unwrap();
        assert_eq!(bound.username, "alice");
        assert_eq!(bound.password, "secret123");
    }

    #[test]
    fn json_with_parameters_matches_by_prefix() {
        let bound = bind_body::<Sample>(
            &headers(Some("application/json; charset=utf-8")),
            br#"{"username":"alice"}"#,
        )
        .unwrap();
        assert_eq!(bound.username, "alice");
    }

    #[test]
    fn malformed_json_is_a_bind_error() {
        assert!(bind_body::<Sample>(&headers(Some("application/json")), b"{").is_err());
    }

    #[test]
    fn form_urlencoded_binds_by_json_field_name() {
        let bound = bind_body::<Sample>(
            &headers(Some("application/x-www-form-urlencoded")),
            b"username=alice&password=secret%31%32%33",
        )
        .unwrap();
        assert_eq!(bound.username, "alice");
        assert_eq!(bound.password, "secret123");
    }

    #[test]
    fn form_urlencoded_decodes_plus_as_space_and_repeated_key_fails() {
        let bound = bind_body::<Sample>(
            &headers(Some("application/x-www-form-urlencoded")),
            b"verification_code=123+456",
        )
        .unwrap();
        assert_eq!(bound.verification_code, "123 456");

        // Go：多值成为 JSON 数组，字符串字段类型不符 → 绑定错误。
        assert!(
            bind_body::<Sample>(
                &headers(Some("application/x-www-form-urlencoded")),
                b"username=a&username=b"
            )
            .is_err()
        );
    }

    #[test]
    fn form_urlencoded_invalid_escape_and_semicolon_are_errors() {
        let headers = headers(Some("application/x-www-form-urlencoded"));
        assert!(bind_body::<Sample>(&headers, b"username=a%ZZ").is_err());
        assert!(bind_body::<Sample>(&headers, b"username=a;b").is_err());
        // 空 pair 被跳过，不是错误。
        let bound = bind_body::<Sample>(&headers, b"username=alice&&password=x").unwrap();
        assert_eq!(bound.username, "alice");
        assert_eq!(bound.password, "x");
    }

    const MULTIPART_BODY: &[u8] = b"--BOUNDARY\r\n\
Content-Disposition: form-data; name=\"username\"\r\n\
\r\n\
alice\r\n\
--BOUNDARY\r\n\
Content-Disposition: form-data; name=\"verification_code\"\r\n\
\r\n\
654321\r\n\
--BOUNDARY\r\n\
Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n\
Content-Type: text/plain\r\n\
\r\n\
file-bytes\r\n\
--BOUNDARY--\r\n";

    #[test]
    fn multipart_binds_values_and_skips_file_parts() {
        let bound = bind_body::<Sample>(
            &headers(Some("multipart/form-data; boundary=BOUNDARY")),
            MULTIPART_BODY,
        )
        .unwrap();
        assert_eq!(bound.username, "alice");
        assert_eq!(bound.verification_code, "654321");
    }

    #[test]
    fn multipart_without_boundary_falls_back_to_json() {
        // Go：boundary 缺失 → JSON 回退；这里 JSON 失败 → 绑定错误。
        assert!(
            bind_body::<Sample>(&headers(Some("multipart/form-data")), MULTIPART_BODY,).is_err()
        );
        // 但 body 本身是合法 JSON 时回退成功（Go 同样如此）。
        let bound = bind_body::<Sample>(
            &headers(Some("multipart/form-data")),
            br#"{"username":"json-fallback"}"#,
        )
        .unwrap();
        assert_eq!(bound.username, "json-fallback");
    }

    #[test]
    fn multipart_body_without_any_boundary_is_an_error() {
        assert!(
            bind_body::<Sample>(
                &headers(Some("multipart/form-data; boundary=BOUNDARY")),
                b"no boundary here at all",
            )
            .is_err()
        );
    }

    #[test]
    fn parse_boundary_handles_quoted_and_case_variants() {
        assert_eq!(
            parse_boundary("multipart/form-data; boundary=----abc123"),
            Some("----abc123".to_owned()),
        );
        assert_eq!(
            parse_boundary("multipart/form-data; boundary=\"==xyz==\""),
            Some("==xyz==".to_owned()),
        );
        assert_eq!(
            parse_boundary("multipart/form-data; BOUNDARY=up"),
            Some("up".to_owned()),
        );
        assert_eq!(parse_boundary("multipart/form-data"), None);
        assert_eq!(parse_boundary(""), None);
    }

    #[test]
    fn content_type_dispatch_matches_go_prefix_and_contains() {
        assert_eq!(
            content_type_kind(&headers(Some("application/json"))),
            ContentTypeKind::Json
        );
        assert_eq!(
            content_type_kind(&headers(Some("APPLICATION/X-WWW-FORM-URLENCODED"))),
            ContentTypeKind::FormUrlencoded
        );
        assert_eq!(
            content_type_kind(&headers(Some("multipart/form-data; boundary=x"))),
            ContentTypeKind::Multipart
        );
        assert_eq!(
            content_type_kind(&headers(Some("application/octet-stream"))),
            ContentTypeKind::Skip
        );
    }
}
