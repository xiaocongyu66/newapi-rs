//! Image dimension/MIME detection. Ports of the upstream Go
//! `internal/relay/common/decode_image.go` (`DecodeBase64ImageData`,
//! `DecodeBase64FileData`, `getImageConfig` lines 120-153), `decode_file.go`
//! (`GetMimeTypeByExtension`, `DetectFileType`, `detectHEIF`,
//! `parseHEIFDimensions`, `findISPE`, `guessMimeTypeFromURL`, lines 157-210 /
//! 454-611) and `decode_audio.go` (`ParseAudio`, lines 1-31).
//!
//! Go decodes dimensions through `image.DecodeConfig` (jpeg/png/gif blank
//! imports) + `x/image/webp` + the hand-rolled HEIF ISOBMFF walk. The Rust
//! port implements the same format set as header parsers: PNG IHDR, JPEG SOF,
//! GIF logical screen descriptor, BMP header, TIFF IFD, WebP VP8/VP8L/VP8X
//! and the HEIF box walk — byte-exact against the Go behaviors for the
//! formats the oracle supports.

use serde_json::Value;

/// Go `image.Config` (width/height only; the color model is unused here).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImageConfig {
    pub width: i64,
    pub height: i64,
}

/// Error text mirrors the Go messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError(pub String);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DecodeError {}

fn decode_error(message: impl Into<String>) -> DecodeError {
    DecodeError(message.into())
}

// ---------------------------------------------------------------------------
// Format header parsers
// ---------------------------------------------------------------------------

fn png_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    // \x89PNG\r\n\x1a\n + IHDR length(4) "IHDR" width(4) height(4)
    if data.len() < 24 || &data[0..8] != b"\x89PNG\r\n\x1a\n" || &data[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]) as i64;
    let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]) as i64;
    Some((width, height))
}

fn gif_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    // "GIF87a"/"GIF89a" + logical screen descriptor: width(2 LE) height(2 LE).
    if data.len() < 10 || (&data[0..6] != b"GIF87a" && &data[0..6] != b"GIF89a") {
        return None;
    }
    let width = u16::from_le_bytes([data[6], data[7]]) as i64;
    let height = u16::from_le_bytes([data[8], data[9]]) as i64;
    Some((width, height))
}

fn bmp_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    // "BM" + file size(4) reserved(4) data offset(4) header size(4).
    // Go's x/image/bmp: BITMAPCOREHEADER (12) keeps int16 dims at 18/20;
    // BITMAPINFOHEADER (40+) keeps int32 dims at 18/22. Height can be
    // negative (top-down) in the info-header form.
    if data.len() < 26 || &data[0..2] != b"BM" {
        return None;
    }
    let header_size = u32::from_le_bytes([data[14], data[15], data[16], data[17]]);
    if header_size == 12 {
        if data.len() < 22 {
            return None;
        }
        let width = i16::from_le_bytes([data[18], data[19]]) as i64;
        let height = i16::from_le_bytes([data[20], data[21]]) as i64;
        return Some((width, height.abs()));
    }
    let width = i32::from_le_bytes([data[18], data[19], data[20], data[21]]);
    let height_raw = i32::from_le_bytes([data[22], data[23], data[24], data[25]]);
    Some((width as i64, height_raw.unsigned_abs() as i64))
}

fn tiff_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    // II*\0 / MM\0* + IFD offset(4) → entry count(2) → 12-byte entries.
    if data.len() < 8 {
        return None;
    }
    let little_endian = match &data[0..4] {
        b"II\x2a\x00" => true,
        b"MM\x00\x2a" => false,
        _ => return None,
    };
    let read_u16 = |b: &[u8]| -> u16 {
        if little_endian {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let read_u32 = |b: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let ifd_offset = read_u32(&data[4..8]) as usize;
    if ifd_offset + 2 > data.len() {
        return None;
    }
    let count = read_u16(&data[ifd_offset..ifd_offset + 2]) as usize;
    let mut width = None;
    let mut height = None;
    for i in 0..count {
        let entry = ifd_offset + 2 + i * 12;
        if entry + 12 > data.len() {
            return None;
        }
        let tag = read_u16(&data[entry..entry + 2]);
        let value = read_u32(&data[entry + 8..entry + 12]) as i64;
        // Go image/tiff reports the first IFD's ImageWidth (256) and
        // ImageLength (257) values; values fit inline for shorts.
        match tag {
            256 => width = Some(value),
            257 => height = Some(value),
            _ => {}
        }
    }
    Some((width?, height?))
}

fn jpeg_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    // Walk SOF markers; Go image/jpeg accepts the SOF0-3, SOF9-11 etc.
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }
    let mut i = 2usize;
    while i + 4 <= data.len() {
        if data[i] != 0xFF {
            return None;
        }
        let marker = data[i + 1];
        if marker == 0xFF {
            i += 1;
            continue;
        }
        // Standalone markers carry no length.
        if (0xD0..=0xD9).contains(&marker) || marker == 0x01 {
            i += 2;
            continue;
        }
        if i + 4 > data.len() {
            return None;
        }
        let length = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        // SOF0-15 excluding DHT (C4), DAC (CC), JPG (C8), DAC-like markers.
        if (0xC0..=0xCF).contains(&marker) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC {
            // precision(1) height(2) width(2)
            if i + 9 > data.len() {
                return None;
            }
            let height = u16::from_be_bytes([data[i + 5], data[i + 6]]) as i64;
            let width = u16::from_be_bytes([data[i + 7], data[i + 8]]) as i64;
            return Some((width, height));
        }
        i += 2 + length;
    }
    None
}

fn webp_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    // RIFF....WEBPVP8 / VP8L / VP8X variants; mirrors x/image/webp DecodeConfig.
    if data.len() < 12 || &data[0..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return None;
    }
    // chunk = data[12..]: chunk fourcc (0..4), size (4..8), payload (8..).
    let chunk = &data[12..];
    if chunk.len() < 8 {
        return None;
    }
    match &chunk[0..4] {
        b"VP8 " => {
            // Lossy payload: frame tag (3 bytes), start code 0x9D 0x01 0x2A,
            // width (2 LE, 14 bits), height (2 LE, 14 bits).
            if chunk.len() < 18 {
                return None;
            }
            if chunk[11] != 0x9D || chunk[12] != 0x01 || chunk[13] != 0x2A {
                return None;
            }
            let width = (u16::from_le_bytes([chunk[14], chunk[15]]) & 0x3FFF) as i64;
            let height = (u16::from_le_bytes([chunk[16], chunk[17]]) & 0x3FFF) as i64;
            Some((width, height))
        }
        b"VP8L" => {
            // Lossless payload: signature 0x2F then 14-bit width-1 / 14-bit
            // height-1 packed into 4 LE bytes.
            if chunk.len() < 13 || chunk[8] != 0x2F {
                return None;
            }
            let bits = u32::from_le_bytes([chunk[9], chunk[10], chunk[11], chunk[12]]);
            let width = ((bits & 0x3FFF) + 1) as i64;
            let height = (((bits >> 14) & 0x3FFF) + 1) as i64;
            Some((width, height))
        }
        b"VP8X" => {
            // Extended payload: 4 flag bytes, then 24-bit canvas width-1 and
            // height-1.
            if chunk.len() < 18 {
                return None;
            }
            let width =
                ((chunk[12] as i64) | ((chunk[13] as i64) << 8) | ((chunk[14] as i64) << 16)) + 1;
            let height =
                ((chunk[15] as i64) | ((chunk[16] as i64) << 8) | ((chunk[17] as i64) << 16)) + 1;
            Some((width, height))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// HEIF / HEIC (byte-exact port of the Go helpers)
// ---------------------------------------------------------------------------

/// Go `detectHEIF` (decode_file.go:499-516): returns "image/heic",
/// "image/heif", or "" (None here).
pub fn detect_heif(data: &[u8]) -> Option<&'static str> {
    if data.len() < 12 {
        return None;
    }
    // ISOBMFF: bytes[4:8] must be "ftyp".
    if &data[4..8] != b"ftyp" {
        return None;
    }
    match std::str::from_utf8(&data[8..12]) {
        Ok("heic" | "heix" | "hevc" | "hevx" | "heim" | "heis") => Some("image/heic"),
        Ok("mif1" | "msf1") => Some("image/heif"),
        _ => None,
    }
}

/// Go `parseHEIFDimensions` (decode_file.go:520-560): walk top-level boxes to
/// find "meta", then search the (version/flags-stripped) body for ispe.
pub fn parse_heif_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    let size = data.len();
    if size < 12 {
        return None;
    }

    let mut offset = 0usize;
    while offset + 8 <= size {
        let mut box_size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;
        let box_type = &data[offset + 4..offset + 8];
        let mut header_len = 8usize;

        if box_size == 1 {
            // 64-bit extended size.
            if offset + 16 > size {
                break;
            }
            box_size = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            header_len = 16;
        } else if box_size == 0 {
            // Box extends to end of data.
            box_size = (size - offset) as u64;
        }

        if (box_size as usize) < header_len || offset as u64 + box_size > size as u64 {
            break;
        }

        if box_type == b"meta" {
            // meta is a full box: 4 bytes version/flags after header.
            let meta_data = &data[offset + header_len..offset + box_size as usize];
            if meta_data.len() < 4 {
                return None;
            }
            return find_ispe(&meta_data[4..]);
        }
        offset += box_size as usize;
    }
    None
}

/// Go `findISPE` (decode_file.go:564-591): recursive search through iprp/ipco
/// container boxes for the ispe box. The Go recursion is a loop over
/// container types — flattened here identically.
fn find_ispe(data: &[u8]) -> Option<(i64, i64)> {
    let mut offset = 0usize;
    let size = data.len();
    while offset + 8 <= size {
        let box_size = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        let box_type = &data[offset + 4..offset + 8];
        if box_size < 8 || offset + box_size > size {
            break;
        }
        let content = &data[offset + 8..offset + box_size];
        match box_type {
            b"iprp" | b"ipco" => {
                if let Some(dims) = find_ispe(content) {
                    return Some(dims);
                }
            }
            // ispe is a full box: 4 bytes version/flags, then 4 bytes
            // width, 4 bytes height.
            b"ispe" if content.len() >= 12 => {
                let width =
                    u32::from_be_bytes([content[4], content[5], content[6], content[7]]) as i64;
                let height =
                    u32::from_be_bytes([content[8], content[9], content[10], content[11]]) as i64;
                if width > 0 && height > 0 {
                    return Some((width, height));
                }
            }
            _ => {}
        }
        offset += box_size;
    }
    None
}

// ---------------------------------------------------------------------------
// Public decode APIs
// ---------------------------------------------------------------------------

/// Go `getImageConfig` / `decodeImageConfig` (decode_image.go:120-153,
/// decode_file.go:468-495): try the standard set (gif, jpg, png — plus the
/// bmp/tiff the host registers), then webp, then HEIF/HEIC.
pub fn decode_image_config(data: &[u8]) -> Result<(ImageConfig, &'static str), DecodeError> {
    let format = detect_image_format(data);
    if let Some((width, height, format)) = format {
        return Ok((ImageConfig { width, height }, format));
    }
    Err(decode_error(
        "failed to decode image config: unsupported format",
    ))
}

/// Returns (width, height, format) for the first matching decoder, mirroring
/// the Go DecodeConfig + webp + HEIF fallback chain.
fn detect_image_format(data: &[u8]) -> Option<(i64, i64, &'static str)> {
    if let Some((width, height)) = png_dimensions(data) {
        return Some((width, height, "png"));
    }
    if let Some((width, height)) = jpeg_dimensions(data) {
        return Some((width, height, "jpeg"));
    }
    if let Some((width, height)) = gif_dimensions(data) {
        return Some((width, height, "gif"));
    }
    if let Some((width, height)) = bmp_dimensions(data) {
        return Some((width, height, "bmp"));
    }
    if let Some((width, height)) = tiff_dimensions(data) {
        return Some((width, height, "tiff"));
    }
    if let Some((width, height)) = webp_dimensions(data) {
        return Some((width, height, "webp"));
    }
    if detect_heif(data).is_some() {
        let format_name = if detect_heif(data) == Some("image/heic") {
            "heic"
        } else {
            "heif"
        };
        if let Some((width, height)) = parse_heif_dimensions(data) {
            return Some((width, height, format_name));
        }
        return None;
    }
    None
}

/// Go `DecodeBase64ImageData` (decode_image.go:21-42): strip a data-URL
/// prefix (first comma), decode base64, return (config, format,
/// clean_base64). Std-encoding only — matches Go `base64.StdEncoding`.
pub fn decode_base64_image_data(
    base64_string: &str,
) -> Result<(ImageConfig, &'static str, String), DecodeError> {
    let base64_string = match base64_string.find(',') {
        Some(idx) => &base64_string[idx + 1..],
        None => base64_string,
    };

    if base64_string.is_empty() {
        return Err(decode_error("base64 string is empty"));
    }

    let decoded = base64_std_decode(base64_string)
        .ok_or_else(|| decode_error("failed to decode base64 string: illegal base64 data"))?;

    let (config, format) = decode_image_config(&decoded)?;
    Ok((config, format, base64_string.to_owned()))
}

/// Go `DecodeBase64FileData` (decode_image.go:44-67): `mime;base64,data`
/// header parsing with image fallbacks. Returns (mime_type, clean_base64).
pub fn decode_base64_file_data(base64_string: &str) -> Result<(String, String), DecodeError> {
    let Some(idx) = base64_string.find(',') else {
        let (_, file_type, base64) = decode_base64_image_data(base64_string)?;
        return Ok((format!("image/{file_type}"), base64));
    };
    let mut mime_type = base64_string[..idx].to_owned();
    let base64_string = &base64_string[idx + 1..];
    let Some(idx) = mime_type.find(';') else {
        let (_, file_type, base64) = decode_base64_image_data(base64_string)?;
        return Ok((format!("image/{file_type}"), base64));
    };
    mime_type.truncate(idx);
    let Some(idx) = mime_type.find(':') else {
        let (_, file_type, base64) = decode_base64_image_data(base64_string)?;
        return Ok((format!("image/{file_type}"), base64));
    };
    Ok((mime_type[idx + 1..].to_owned(), base64_string.to_owned()))
}

/// Go `ParseAudio` (decode_audio.go:8-31): sample-count / sample-rate
/// duration for the realtime audio formats.
pub fn parse_audio(audio_base64: &str, format: &str) -> Result<f64, DecodeError> {
    let audio_data = base64_std_decode(audio_base64)
        .ok_or_else(|| decode_error("base64 decode error: illegal base64 data"))?;

    let (samples_count, sample_rate) = match format {
        "pcm16" => (audio_data.len() / 2, 24000),
        "g711_ulaw" | "g711_alaw" => (audio_data.len(), 8000),
        _ => (audio_data.len(), 8000),
    };

    Ok(samples_count as f64 / sample_rate as f64)
}

/// Go base64.StdEncoding.DecodeString: strict standard alphabet with padding.
fn base64_std_decode(input: &str) -> Option<Vec<u8>> {
    base64_std_decode_impl(input.as_bytes())
}

fn base64_std_decode_impl(input: &[u8]) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let index_of = |c: u8| -> Option<u8> { TABLE.iter().position(|t| *t == c).map(|p| p as u8) };
    // Go StdEncoding.DecodeString is strict: whitespace is invalid.
    let cleaned: Vec<u8> = input.to_vec();
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    let mut chunk = [0u8; 4];
    let mut filled = 0usize;
    let mut padding = 0usize;
    for &c in &cleaned {
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            // Data after padding is invalid.
            return None;
        }
        if filled == 4 {
            return None;
        }
        chunk[filled] = index_of(c)?;
        filled += 1;
        if filled == 4 {
            let n = ((chunk[0] as u32) << 18)
                | ((chunk[1] as u32) << 12)
                | ((chunk[2] as u32) << 6)
                | chunk[3] as u32;
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
            out.push(n as u8);
            filled = 0;
        }
    }
    match filled {
        0 => {}
        2 => {
            if padding != 2 {
                return None;
            }
            let n = ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12);
            out.push((n >> 16) as u8);
        }
        3 => {
            if padding != 1 {
                return None;
            }
            let n =
                ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12) | ((chunk[2] as u32) << 6);
            out.push((n >> 16) as u8);
            out.push((n >> 8) as u8);
        }
        _ => return None,
    }
    Some(out)
}

/// Go `GetMimeTypeByExtension` (decode_file.go:157-210).
pub fn get_mime_type_by_extension(ext: &str) -> &'static str {
    match ext.to_lowercase().as_str() {
        // Text files
        "txt" | "md" | "markdown" | "csv" | "json" | "xml" | "html" | "htm" => "text/plain",
        // Image files
        "jpg" | "jpeg" | "jfif" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "heic" => "image/heic",
        "heif" => "image/heif",
        // Audio files
        "mp3" => "audio/mp3",
        "wav" => "audio/wav",
        "mpeg" => "audio/mpeg",
        // Video files
        "mp4" => "video/mp4",
        "wmv" => "video/wmv",
        "flv" => "video/flv",
        "mov" => "video/mov",
        "mpg" => "video/mpg",
        "avi" => "video/avi",
        "mpegps" => "video/mpegps",
        // Document files
        "pdf" => "application/pdf",
        _ => "application/octet-stream",
    }
}

/// Go `DetectFileType` (decode_file.go:454-465). Returns the Go FileType
/// strings ("image"/"audio"/"video"/"file").
pub fn detect_file_type(mime_type: &str) -> &'static str {
    if mime_type.starts_with("image/") {
        "image"
    } else if mime_type.starts_with("audio/") {
        "audio"
    } else if mime_type.starts_with("video/") {
        "video"
    } else {
        "file"
    }
}

/// Go `guessMimeTypeFromURL` (decode_file.go:595-610): strip the query, take
/// the last path segment's extension.
pub fn guess_mime_type_from_url(url: &str) -> &'static str {
    let cleaned_url = match url.find('?') {
        Some(q) => &url[..q],
        None => url,
    };
    if let Some(slash) = cleaned_url.rfind('/')
        && slash + 1 < cleaned_url.len()
    {
        let last = &cleaned_url[slash + 1..];
        if let Some(dot) = last.rfind('.')
            && dot + 1 < last.len()
        {
            return get_mime_type_by_extension(&last[dot + 1..]);
        }
    }
    "application/octet-stream"
}

/// Go `http.DetectContentType` restricted to the signatures the relay cares
/// about for media classification (decode_file.go's sniffing loop lines
/// 100-127 uses it on 512B-64KB prefixes). Full Go signature table for the
/// detection set; unknown → "application/octet-stream".
pub fn detect_content_type(data: &[u8]) -> &'static str {
    // Go http.DetectContentType always sniffs the first 512 bytes.
    const SNIFF_LIMIT: usize = 512;
    let data = &data[..SNIFF_LIMIT.min(data.len())];
    let trimmed = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|p| &data[p..])
        .unwrap_or(data);

    // HTML/XML signatures in Go's order.
    const HTML_SNIFFS: &[&[u8]] = &[
        b"<!DOCTYPE HTML",
        b"<HTML",
        b"<HEAD",
        b"<SCRIPT",
        b"<IFRAME",
        b"<H1",
        b"<DIV",
        b"<FONT",
        b"<TABLE",
        b"<A",
        b"<STYLE",
        b"<TITLE",
        b"<B",
        b"<BODY",
        b"<BR",
        b"<P",
        b"<!--",
    ];
    if !trimmed.is_empty() && trimmed[0] == b'<' {
        let upper: Vec<u8> = trimmed.iter().map(|b| b.to_ascii_uppercase()).collect();
        for sig in HTML_SNIFFS {
            if upper.starts_with(sig) {
                return "text/html; charset=utf-8";
            }
        }
        if upper.starts_with(b"<?XML") {
            return "text/xml; charset=utf-8";
        }
    }

    // Binary signatures, order preserved from net/http sniff.go.
    if trimmed.starts_with(b"%PDF-") {
        return "application/pdf";
    }
    if trimmed.starts_with(b"%!PS-Adobe-") {
        return "application/postscript";
    }
    if trimmed.starts_with(b"\xFE\xFF\x00\x00") {
        return "text/plain; charset=utf-32be";
    }
    if trimmed.starts_with(b"\xFF\xFE\x00\x00") {
        return "text/plain; charset=utf-32le";
    }
    if trimmed.starts_with(b"\xFE\xFF") {
        return "text/plain; charset=utf-16be";
    }
    if trimmed.starts_with(b"\xFF\xFE") {
        return "text/plain; charset=utf-16le";
    }
    if trimmed.starts_with(b"\xEF\xBB\xBF") {
        return "text/plain; charset=utf-8";
    }
    if trimmed.starts_with(b"\x00\x00\x00\x18ftypmp42")
        || trimmed.starts_with(b"\x00\x00\x00\x18ftypisom")
        || trimmed.starts_with(b"\x00\x00\x00\x18ftypm4a ")
    {
        return "video/mp4";
    }
    // GIF
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return "image/gif";
    }
    // RIFF variants.
    if data.starts_with(b"RIFF") && data.len() >= 12 {
        match &data[8..12] {
            b"WEBP" => return "image/webp",
            b"AVI " => return "video/avi",
            b"WAVE" => return "audio/wav",
            _ => {}
        }
    }
    // PNG
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "image/png";
    }
    // JPEG
    if data.starts_with(b"\xFF\xD8\xFF") {
        return "image/jpeg";
    }
    // MP3 with ID3
    if data.starts_with(b"ID3") {
        return "audio/mpeg";
    }
    // TIFF
    if data.starts_with(b"II*\x00") || data.starts_with(b"MM\x00*") {
        return "image/tiff";
    }
    // BMP
    if data.starts_with(b"BM") {
        return "image/bmp";
    }
    // HEIC/HEIF detection beyond Go stdlib: reuse the ISOBMFF magic check.
    if let Some(mime) = detect_heif(data) {
        return mime;
    }
    if data.starts_with(b"\x1A\x45\xDF\xA3") {
        return "video/webm";
    }
    if data.starts_with(b"OggS") {
        return "application/ogg";
    }
    if data.starts_with(b"fLaC") {
        return "audio/flac";
    }

    // Text heuristic: Go treats buffers without control bytes as text.
    let is_text = data.iter().all(|&b| {
        b == 0x09
            || b == 0x0A
            || b == 0x0C
            || b == 0x0D
            || b == 0x0B
            || (0x20..=0x7E).contains(&b)
            || b >= 0x80
    });
    if is_text {
        return "text/plain; charset=utf-8";
    }
    "application/octet-stream"
}

/// Go `types.FileSource` discriminator over the wire `data` string
/// (file_source.go:134-139): http(s) prefixes are URL sources.
pub fn is_url_source_data(data: &str) -> bool {
    data.starts_with("http://") || data.starts_with("https://")
}

/// Value-level helper mirroring Go `FileMeta.GetIdentifier` for logging.
pub fn file_meta_identifier(source: Option<&Value>) -> String {
    match source {
        Some(Value::String(s)) => {
            if s.len() > 100 {
                format!("{}...", &s[..100])
            } else {
                s.clone()
            }
        }
        _ => "unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-local standard base64 encoder (the production decoder is strict
    /// StdEncoding; the encoder mirrors Go base64.StdEncoding.EncodeToString).
    fn encode_b64(data: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = chunk.get(1).map(|b| *b as u32).unwrap_or(0);
            let b2 = chunk.get(2).map(|b| *b as u32).unwrap_or(0);
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(TABLE[(n >> 18) as usize & 63] as char);
            out.push(TABLE[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    /// Minimal valid PNG: signature + IHDR with 3×2 dims.
    fn sample_png(width: u32, height: u32) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        data.extend_from_slice(&13u32.to_be_bytes());
        data.extend_from_slice(b"IHDR");
        data.extend_from_slice(&width.to_be_bytes());
        data.extend_from_slice(&height.to_be_bytes());
        data.extend_from_slice(&[8, 6, 0, 0, 0]);
        data
    }

    /// Minimal GIF89a with logical screen 10×20.
    fn sample_gif() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"GIF89a");
        data.extend_from_slice(&10u16.to_le_bytes());
        data.extend_from_slice(&20u16.to_le_bytes());
        data.extend_from_slice(&[0x70, 0, 0]);
        data
    }

    /// Minimal BMP with a 40-byte info header and 16×8 dims.
    fn sample_bmp() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"BM");
        data.extend_from_slice(&[0; 12]); // size, reserved, offset
        data.extend_from_slice(&40u32.to_le_bytes()); // BITMAPINFOHEADER size
        data.extend_from_slice(&16i32.to_le_bytes());
        data.extend_from_slice(&8i32.to_le_bytes());
        data
    }

    /// JPEG SOF0 frame with 4×3 dims.
    fn sample_jpeg() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xFF, 0xD8]); // SOI
        data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B]); // SOF0, len 11
        data.extend_from_slice(&[0x08]); // precision
        data.extend_from_slice(&3u16.to_be_bytes()); // height
        data.extend_from_slice(&4u16.to_be_bytes()); // width
        data.extend_from_slice(&[1, 0x11, 0]); // components
        data.extend_from_slice(&[0xFF, 0xD9]); // EOI
        data
    }

    /// WebP VP8X extended canvas 5×7.
    fn sample_webp_vp8x() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(b"WEBP");
        data.extend_from_slice(b"VP8X");
        data.extend_from_slice(&[4, 0, 0, 0]); // chunk size
        data.extend_from_slice(&[0, 0, 0, 0]); // flags
        data.extend_from_slice(&[4, 0, 0]); // canvas width - 1 (5)
        data.extend_from_slice(&[6, 0, 0]); // canvas height - 1 (7)
        data
    }

    /// TIFF II little-endian IFD with width 640 / height 480.
    fn sample_tiff() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"II\x2a\x00");
        data.extend_from_slice(&8u32.to_le_bytes()); // IFD offset
        data.extend_from_slice(&2u16.to_le_bytes()); // entry count
        // Entry: tag(2) type(2) count(4) value(4).
        data.extend_from_slice(&256u16.to_le_bytes()); // ImageWidth
        data.extend_from_slice(&3u16.to_le_bytes()); // SHORT
        data.extend_from_slice(&1u32.to_le_bytes()); // count
        data.extend_from_slice(&640u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&257u16.to_le_bytes()); // ImageLength
        data.extend_from_slice(&3u16.to_le_bytes()); // SHORT
        data.extend_from_slice(&1u32.to_le_bytes()); // count
        data.extend_from_slice(&480u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data
    }

    /// HEIF with a meta → iprp → ipco → ispe box chain (Go helper walk).
    fn sample_heif(brand: &[u8; 4]) -> Vec<u8> {
        let mut data = Vec::new();
        // ispe box: fourcc + version/flags + width + height.
        let mut ispe = Vec::new();
        ispe.extend_from_slice(b"ispe");
        ispe.extend_from_slice(&[0, 0, 0, 0]); // version/flags
        ispe.extend_from_slice(&128u32.to_be_bytes());
        ispe.extend_from_slice(&64u32.to_be_bytes());
        // ipco box: header + ispe.
        let mut ipco_box = Vec::new();
        ipco_box.extend_from_slice(&((8 + ispe.len()) as u32).to_be_bytes());
        ipco_box.extend_from_slice(b"ipco");
        ipco_box.extend_from_slice(&ispe);
        // iprp box: header + ipco box.
        let mut iprp_box = Vec::new();
        iprp_box.extend_from_slice(&((8 + ipco_box.len()) as u32).to_be_bytes());
        iprp_box.extend_from_slice(b"iprp");
        iprp_box.extend_from_slice(&ipco_box);
        // meta box: header + version/flags + iprp box.
        let meta_body_len = 4 + iprp_box.len();
        let mut meta_box = Vec::new();
        meta_box.extend_from_slice(&((8 + meta_body_len) as u32).to_be_bytes());
        meta_box.extend_from_slice(b"meta");
        meta_box.extend_from_slice(&[0, 0, 0, 0]); // version/flags
        meta_box.extend_from_slice(&iprp_box);
        // ftyp box: header + brand + 4 reserved bytes, total 20 bytes.
        data.extend_from_slice(&20u32.to_be_bytes());
        data.extend_from_slice(b"ftyp");
        data.extend_from_slice(brand);
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&[0, 0, 0, 0]);
        data.extend_from_slice(&meta_box);
        data
    }

    /// Go decodeImageConfig: png/jpeg/gif/bmp/tiff/webp/heif dimension walk.
    #[test]
    fn decode_image_config_formats() {
        let (config, format) = decode_image_config(&sample_png(3, 2)).expect("png");
        assert_eq!(
            config,
            ImageConfig {
                width: 3,
                height: 2
            }
        );
        assert_eq!(format, "png");

        let (config, format) = decode_image_config(&sample_gif()).expect("gif");
        assert_eq!(
            config,
            ImageConfig {
                width: 10,
                height: 20
            }
        );
        assert_eq!(format, "gif");

        let (config, format) = decode_image_config(&sample_jpeg()).expect("jpeg");
        assert_eq!(
            config,
            ImageConfig {
                width: 4,
                height: 3
            }
        );
        assert_eq!(format, "jpeg");

        let (config, format) = decode_image_config(&sample_bmp()).expect("bmp");
        assert_eq!(
            config,
            ImageConfig {
                width: 16,
                height: 8
            }
        );
        assert_eq!(format, "bmp");

        let (config, format) = decode_image_config(&sample_tiff()).expect("tiff");
        assert_eq!(
            config,
            ImageConfig {
                width: 640,
                height: 480
            }
        );
        assert_eq!(format, "tiff");

        let (config, format) = decode_image_config(&sample_webp_vp8x()).expect("webp");
        assert_eq!(
            config,
            ImageConfig {
                width: 5,
                height: 7
            }
        );
        assert_eq!(format, "webp");

        let (config, format) = decode_image_config(&sample_heif(b"mif1")).expect("heif");
        assert_eq!(
            config,
            ImageConfig {
                width: 128,
                height: 64
            }
        );
        assert_eq!(format, "heif");

        let (config, format) = decode_image_config(&sample_heif(b"heic")).expect("heic");
        assert_eq!(
            config,
            ImageConfig {
                width: 128,
                height: 64
            }
        );
        assert_eq!(format, "heic");

        assert!(decode_image_config(b"not an image").is_err());
    }

    /// Go detectHEIF brand table (decode_file.go:507-515).
    #[test]
    fn heif_brand_table() {
        assert_eq!(detect_heif(b"\0\0\0\x08ftypheic"), Some("image/heic"));
        assert_eq!(detect_heif(b"\0\0\0\x08ftypheix"), Some("image/heic"));
        assert_eq!(detect_heif(b"\0\0\0\x08ftypmif1"), Some("image/heif"));
        assert_eq!(detect_heif(b"\0\0\0\x08ftypmsf1"), Some("image/heif"));
        assert_eq!(detect_heif(b"\0\0\0\x08ftypmp42"), None);
        assert_eq!(detect_heif(b"short"), None);
    }

    /// Go GetMimeTypeByExtension table (decode_file.go:157-210).
    #[test]
    fn mime_type_by_extension_table() {
        assert_eq!(get_mime_type_by_extension("txt"), "text/plain");
        assert_eq!(get_mime_type_by_extension("JSON"), "text/plain");
        assert_eq!(get_mime_type_by_extension("jpg"), "image/jpeg");
        assert_eq!(get_mime_type_by_extension("JFIF"), "image/jpeg");
        assert_eq!(get_mime_type_by_extension("heic"), "image/heic");
        assert_eq!(get_mime_type_by_extension("mp3"), "audio/mp3");
        assert_eq!(get_mime_type_by_extension("wav"), "audio/wav");
        assert_eq!(get_mime_type_by_extension("mp4"), "video/mp4");
        assert_eq!(get_mime_type_by_extension("mpegps"), "video/mpegps");
        assert_eq!(get_mime_type_by_extension("pdf"), "application/pdf");
        assert_eq!(
            get_mime_type_by_extension("xyz"),
            "application/octet-stream"
        );
    }

    /// Go DetectFileType prefix rules (decode_file.go:454-465).
    #[test]
    fn detect_file_type_prefixes() {
        assert_eq!(detect_file_type("image/png"), "image");
        assert_eq!(detect_file_type("audio/wav"), "audio");
        assert_eq!(detect_file_type("video/mp4"), "video");
        assert_eq!(detect_file_type("application/pdf"), "file");
        assert_eq!(detect_file_type(""), "file");
    }

    /// Go guessMimeTypeFromURL (decode_file.go:595-610).
    #[test]
    fn guess_mime_from_url() {
        assert_eq!(
            guess_mime_type_from_url("https://a.b/img/cat.PNG?x=1"),
            "image/jpeg"
        );
        assert_eq!(
            guess_mime_type_from_url("https://a.b/doc.pdf"),
            "application/pdf"
        );
        assert_eq!(
            guess_mime_type_from_url("https://a.b/noext"),
            "application/octet-stream"
        );
        assert_eq!(
            guess_mime_type_from_url("https://a.b/trailing/"),
            "application/octet-stream"
        );
    }

    /// Go ParseAudio sample-rate table (decode_audio.go:14-27).
    #[test]
    fn parse_audio_rates() {
        // pcm16: 2 bytes per sample at 24 kHz. 48000 bytes = 24000 samples
        // = 1.0 second.
        let pcm = "AA=="; // 1 byte → 0 samples at /2 → 0 duration
        assert_eq!(parse_audio(pcm, "pcm16").unwrap(), 0.0);
        // g711: 1 byte per sample at 8 kHz → 8000 bytes = 1 second.
        let mut g711_bytes = Vec::new();
        for _ in 0..8000 {
            g711_bytes.push(0x55u8);
        }
        let encoded = encode_b64(&g711_bytes);
        assert!((parse_audio(&encoded, "g711_ulaw").unwrap() - 1.0).abs() < 1e-9);
        assert!((parse_audio(&encoded, "g711_alaw").unwrap() - 1.0).abs() < 1e-9);
        assert!((parse_audio(&encoded, "unknown").unwrap() - 1.0).abs() < 1e-9);
        assert_eq!(
            parse_audio("!!!", "pcm16").unwrap_err().0,
            "base64 decode error: illegal base64 data"
        );
    }

    /// Go DecodeBase64ImageData comma stripping + error text
    /// (decode_image.go:21-42).
    #[test]
    fn base64_image_data() {
        // "iVBORw0KGgo" prefix is the PNG magic in base64; build one properly.
        let png = sample_png(3, 2);
        let encoded = encode_b64(&png);
        let (config, format, clean) = decode_base64_image_data(&encoded).expect("png");
        assert_eq!(
            config,
            ImageConfig {
                width: 3,
                height: 2
            }
        );
        assert_eq!(format, "png");
        assert_eq!(clean, encoded);

        let (config, _, _) = decode_base64_image_data(&format!("data:image/png;base64,{encoded}"))
            .expect("data url");
        assert_eq!(
            config,
            ImageConfig {
                width: 3,
                height: 2
            }
        );

        assert_eq!(
            decode_base64_image_data("").unwrap_err().0,
            "base64 string is empty"
        );
        assert!(decode_base64_image_data("!!!!").is_err());
    }

    /// Go DecodeBase64FileData header parsing (decode_image.go:44-67).
    #[test]
    fn base64_file_data_headers() {
        // data: mime;param,base64 form passes the mime through.
        let (mime, clean) =
            decode_base64_file_data("data:application/pdf;base64,QUJD").expect("full header");
        assert_eq!(mime, "application/pdf");
        assert_eq!(clean, "QUJD");

        // No comma → image fallback.
        let png = sample_png(3, 2);
        let encoded = encode_b64(&png);
        let (mime, _) = decode_base64_file_data(&encoded).expect("image fallback");
        assert_eq!(mime, "image/png");
    }

    /// Content sniffing signatures (Go http.DetectContentType subset).
    #[test]
    fn content_type_sniffing() {
        assert_eq!(detect_content_type(b"%PDF-1.4 rest"), "application/pdf");
        assert_eq!(detect_content_type(b"\x89PNG\r\n\x1a\n...."), "image/png");
        assert_eq!(detect_content_type(b"\xFF\xD8\xFF\xE0"), "image/jpeg");
        assert_eq!(detect_content_type(b"GIF89a...."), "image/gif");
        assert_eq!(
            detect_content_type(b"RIFF\x00\x00\x00\x00WEBPVP8 "),
            "image/webp"
        );
        assert_eq!(
            detect_content_type(b"RIFF\x00\x00\x00\x00WAVEfmt "),
            "audio/wav"
        );
        assert_eq!(detect_content_type(b"BM\x00\x00"), "image/bmp");
        assert_eq!(detect_content_type(b"II*\x00"), "image/tiff");
        assert_eq!(detect_content_type(b"ID3\x03"), "audio/mpeg");
        assert_eq!(detect_content_type(b"\x1A\x45\xDF\xA3"), "video/webm");
        assert_eq!(detect_content_type(b"fLaC"), "audio/flac");
        assert_eq!(detect_content_type(b"\0\0\0\x08ftypheic"), "image/heic");
        assert_eq!(
            detect_content_type(b"plain text body"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            detect_content_type(b"<html><body>"),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            detect_content_type(b"\x00\x01\x02\x03"),
            "application/octet-stream"
        );
    }

    /// URL source discrimination (file_source.go:134-139).
    #[test]
    fn url_source_discrimination() {
        assert!(is_url_source_data("https://a.b/c.png"));
        assert!(is_url_source_data("http://a.b/c.png"));
        assert!(!is_url_source_data("data:image/png;base64,QUJD"));
        assert!(!is_url_source_data(""));
    }

    /// Identifier truncation mirrors FileMeta.GetIdentifier (request_meta.go:
    /// 58-63) for URL sources.
    #[test]
    fn identifier_truncation() {
        let long_url = "a".repeat(150);
        let id = file_meta_identifier(Some(&Value::String(long_url)));
        assert_eq!(id.len(), 103);
        assert!(id.ends_with("..."));
        assert_eq!(
            file_meta_identifier(Some(&Value::String("short".into()))),
            "short"
        );
        assert_eq!(file_meta_identifier(None), "unknown");
    }
}
