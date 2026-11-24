use std::io::{self, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::config::{RouteMatch, MAX_HEADERS_CAP};
use crate::error::ProxyError;

/// Strict-Transport-Security preload header emitted on TLS responses (2-year max-age).
pub const HSTS_HEADER_LINE: &str =
    "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n";

/// Restrictive Permissions-Policy header disabling sensitive browser APIs by default.
pub const PERMISSIONS_POLICY_HEADER_LINE: &str =
    "Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()\r\n";

/// Zero-copy borrowed HTTP header name/value view pointing into the fixed read buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderView<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> HeaderView<'a> {
    const EMPTY: Self = Self {
        name: b"",
        value: b"",
    };
}

/// Zero-copy parsed HTTP/1.x request head.
#[derive(Debug, Clone, Copy)]
pub struct ParsedRequest<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version_minor: u8,
    headers: [HeaderView<'a>; MAX_HEADERS_CAP],
    header_count: usize,
    pub content_length: Option<u64>,
    pub is_chunked: bool,
    pub header_end: usize,
}

impl<'a> ParsedRequest<'a> {
    /// Returns the slice of parsed request headers.
    pub fn headers(&self) -> &[HeaderView<'a>] {
        &self.headers[..self.header_count]
    }

    /// Returns the `Host` header value if present and valid ASCII.
    pub fn host(&self) -> Option<&'a str> {
        for hv in self.headers() {
            if hv.name.eq_ignore_ascii_case(b"host") {
                return std::str::from_utf8(hv.value).ok();
            }
        }
        None
    }
}

/// Zero-copy parsed HTTP/1.x upstream response head.
#[derive(Debug, Clone, Copy)]
pub struct ParsedResponse<'a> {
    pub status_code: u16,
    pub reason: &'a str,
    headers: [HeaderView<'a>; MAX_HEADERS_CAP],
    header_count: usize,
    pub content_length: Option<u64>,
    pub is_chunked: bool,
    pub header_end: usize,
}

impl<'a> ParsedResponse<'a> {
    /// Returns the slice of parsed response headers.
    pub fn headers(&self) -> &[HeaderView<'a>] {
        &self.headers[..self.header_count]
    }

    /// Returns true if HTTP/1.1 forbids a message body for this response.
    pub fn has_no_body(&self, is_head_request: bool) -> bool {
        is_head_request
            || (100..200).contains(&self.status_code)
            || self.status_code == 204
            || self.status_code == 304
    }
}

/// Scans `buf` for the `\r\n\r\n` header terminator while immediately rejecting
/// bare CR (`\r` not followed by `\n`) and bare LF (`\n` not preceded by `\r`).
///
/// Returns `Ok(Some(end_offset))` where `end_offset` is the byte index immediately
/// after `\r\n\r\n`, or `Ok(None)` if more bytes are needed.
pub fn scan_header_terminator(buf: &[u8]) -> Result<Option<usize>, ProxyError> {
    let mut i = 0;
    while i < buf.len() {
        match buf[i] {
            b'\r' => {
                if i + 1 < buf.len() {
                    if buf[i + 1] != b'\n' {
                        return Err(ProxyError::BadRequest("bare CR in headers\n"));
                    }
                    if i >= 2 && buf[i - 2] == b'\r' && buf[i - 1] == b'\n' {
                        return Ok(Some(i + 2));
                    }
                    i += 2;
                    continue;
                }
                // Trailing `\r` at the end of a partial read may be completed by `\n` next read.
                return Ok(None);
            }
            b'\n' => {
                return Err(ProxyError::BadRequest("bare LF in headers\n"));
            }
            _ => {
                i += 1;
            }
        }
    }
    Ok(None)
}

/// Strictly parses an HTTP/1.0 or HTTP/1.1 request head from `buf` with zero heap allocation.
///
/// Rejects bare CR/LF, invalid tokens, obs-fold, whitespace before `:`, `CL+TE` smuggling,
/// duplicate `Content-Length`, duplicate/missing `Host` (HTTP/1.1), oversized header count (`431`),
/// and `Content-Length > max_body_bytes` (`413`).
pub fn parse_request<'a>(
    buf: &'a [u8],
    max_body_bytes: u64,
    max_headers: usize,
) -> Result<ParsedRequest<'a>, ProxyError> {
    let header_end = scan_header_terminator(buf)?
        .ok_or(ProxyError::BadRequest("incomplete request headers\n"))?;
    let head = &buf[..header_end - 4];
    let mut lines = split_crlf(head);

    let req_line = lines
        .next()
        .ok_or(ProxyError::BadRequest("empty request line\n"))?;
    let (method, target, version_minor) = parse_request_line(req_line)?;

    let mut headers = [HeaderView::EMPTY; MAX_HEADERS_CAP];
    let mut header_count = 0usize;
    let mut host_count = 0usize;
    let mut content_length: Option<u64> = None;
    let mut is_chunked = false;
    let mut te_seen = false;
    let limit = max_headers.min(MAX_HEADERS_CAP);

    for line in lines {
        let hv = parse_header_line(line)?;
        if header_count >= limit {
            return Err(ProxyError::HeadersTooLarge);
        }
        headers[header_count] = hv;
        header_count += 1;

        if hv.name.eq_ignore_ascii_case(b"host") {
            if hv.value.is_empty() || hv.value.iter().any(|&b| b == b' ' || b == b'\t') {
                return Err(ProxyError::BadRequest("invalid Host header\n"));
            }
            host_count += 1;
            if host_count > 1 {
                return Err(ProxyError::BadRequest("duplicate Host header\n"));
            }
        } else if hv.name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(ProxyError::BadRequest("duplicate Content-Length header\n"));
            }
            let cl = parse_strict_u64(hv.value)
                .ok_or(ProxyError::BadRequest("invalid Content-Length header\n"))?;
            content_length = Some(cl);
        } else if hv.name.eq_ignore_ascii_case(b"transfer-encoding") {
            if te_seen {
                return Err(ProxyError::BadRequest("duplicate Transfer-Encoding header\n"));
            }
            te_seen = true;
            if !hv.value.eq_ignore_ascii_case(b"chunked") {
                return Err(ProxyError::BadRequest("unsupported Transfer-Encoding\n"));
            }
            is_chunked = true;
        }
    }

    if content_length.is_some() && is_chunked {
        return Err(ProxyError::BadRequest(
            "conflicting Content-Length and Transfer-Encoding\n",
        ));
    }
    if version_minor == 1 && host_count != 1 {
        return Err(ProxyError::BadRequest("HTTP/1.1 requires Host header\n"));
    }
    if let Some(cl) = content_length {
        if cl > max_body_bytes {
            return Err(ProxyError::PayloadTooLarge);
        }
    }

    Ok(ParsedRequest {
        method,
        target,
        version_minor,
        headers,
        header_count,
        content_length,
        is_chunked,
        header_end,
    })
}

/// Strictly parses an upstream HTTP/1.x response head from `buf` with zero heap allocation.
pub fn parse_response_head<'a>(
    buf: &'a [u8],
    max_headers: usize,
) -> Result<ParsedResponse<'a>, ProxyError> {
    let header_end = scan_header_terminator(buf)?
        .ok_or(ProxyError::UpstreamUnavailable)?;
    let head = &buf[..header_end - 4];
    let mut lines = split_crlf(head);

    let status_line = lines.next().ok_or(ProxyError::UpstreamUnavailable)?;
    let (status_code, reason) = parse_status_line(status_line)?;

    let mut headers = [HeaderView::EMPTY; MAX_HEADERS_CAP];
    let mut header_count = 0usize;
    let mut content_length: Option<u64> = None;
    let mut is_chunked = false;
    let mut te_seen = false;
    let limit = max_headers.min(MAX_HEADERS_CAP);

    for line in lines {
        let hv = parse_header_line(line).map_err(|_| ProxyError::UpstreamUnavailable)?;
        if header_count >= limit {
            return Err(ProxyError::UpstreamUnavailable);
        }
        headers[header_count] = hv;
        header_count += 1;

        if hv.name.eq_ignore_ascii_case(b"content-length") {
            if content_length.is_some() {
                return Err(ProxyError::UpstreamUnavailable);
            }
            let cl = parse_strict_u64(hv.value).ok_or(ProxyError::UpstreamUnavailable)?;
            content_length = Some(cl);
        } else if hv.name.eq_ignore_ascii_case(b"transfer-encoding") {
            if te_seen || !hv.value.eq_ignore_ascii_case(b"chunked") {
                return Err(ProxyError::UpstreamUnavailable);
            }
            te_seen = true;
            is_chunked = true;
        }
    }

    if content_length.is_some() && is_chunked {
        return Err(ProxyError::UpstreamUnavailable);
    }

    Ok(ParsedResponse {
        status_code,
        reason,
        headers,
        header_count,
        content_length,
        is_chunked,
        header_end,
    })
}

/// Formats the rewritten upstream HTTP/1.1 request head into `out` with zero heap allocation.
///
/// Strips hop-by-hop headers, appends `client_ip` to `X-Forwarded-For`, sets
/// `X-Forwarded-Proto: http`, and forces `Connection: close`.
pub fn write_forwarded_request_head(
    out: &mut [u8],
    req: &ParsedRequest<'_>,
    route: RouteMatch<'_>,
    client_ip: IpAddr,
) -> Result<usize, ProxyError> {
    write_forwarded_request_head_proto(out, req, route, client_ip, false)
}

/// Formats the rewritten upstream HTTP/1.1 request head with explicit `http`/`https` proto.
pub fn write_forwarded_request_head_proto(
    out: &mut [u8],
    req: &ParsedRequest<'_>,
    route: RouteMatch<'_>,
    client_ip: IpAddr,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    write_forwarded_request_head_blindbind(out, req, route, client_ip, is_tls, None)
}

/// Formats the rewritten upstream HTTP/1.1 request head, unconditionally stripping inbound
/// BlindBind headers and emitting `X-BlindBind-Verified` only for cryptographically verified peers.
pub fn write_forwarded_request_head_blindbind(
    out: &mut [u8],
    req: &ParsedRequest<'_>,
    route: RouteMatch<'_>,
    client_ip: IpAddr,
    is_tls: bool,
    blindbind_key_sha256: Option<&str>,
) -> Result<usize, ProxyError> {
    let mut cursor = io::Cursor::new(out);

    write_slice(&mut cursor, req.method.as_bytes())?;
    write_slice(&mut cursor, b" ")?;
    if route.prepend_slash {
        write_slice(&mut cursor, b"/")?;
    }
    write_slice(&mut cursor, route.tail.as_bytes())?;
    write_slice(&mut cursor, b" HTTP/1.1\r\n")?;

    let mut has_xff = false;
    for hv in req.headers() {
        if is_hop_by_hop_request(hv.name, req.is_chunked)
            || is_named_in_connection(req.headers(), hv.name)
            || hv.name.eq_ignore_ascii_case(b"x-forwarded-proto")
            || hv.name.eq_ignore_ascii_case(b"x-real-ip")
            || is_reserved_blindbind_header(hv.name)
        {
            continue;
        }
        if hv.name.eq_ignore_ascii_case(b"x-forwarded-for") {
            has_xff = true;
            continue;
        }
        write_slice(&mut cursor, hv.name)?;
        write_slice(&mut cursor, b": ")?;
        write_slice(&mut cursor, hv.value)?;
        write_slice(&mut cursor, b"\r\n")?;
    }

    write_slice(&mut cursor, b"X-Forwarded-For: ")?;
    if has_xff {
        let mut first = true;
        for hv in req.headers() {
            if hv.name.eq_ignore_ascii_case(b"x-forwarded-for") && !hv.value.is_empty() {
                if !first {
                    write_slice(&mut cursor, b", ")?;
                }
                write_slice(&mut cursor, hv.value)?;
                first = false;
            }
        }
        if !first {
            write_slice(&mut cursor, b", ")?;
        }
    }
    write!(cursor, "{}\r\n", client_ip).map_err(|_| ProxyError::HeadersTooLarge)?;
    write!(cursor, "X-Real-IP: {}\r\n", client_ip).map_err(|_| ProxyError::HeadersTooLarge)?;
    if is_tls {
        write_slice(&mut cursor, b"X-Forwarded-Proto: https\r\n")?;
    } else {
        write_slice(&mut cursor, b"X-Forwarded-Proto: http\r\n")?;
    }
    if let Some(key_sha256) = blindbind_key_sha256 {
        write_slice(&mut cursor, b"X-BlindBind-Verified: 1\r\n")?;
        write_slice(&mut cursor, b"X-BlindBind-Key-Sha256: ")?;
        write_slice(&mut cursor, key_sha256.as_bytes())?;
        write_slice(&mut cursor, b"\r\n")?;
    }
    write_slice(&mut cursor, b"Connection: close\r\n\r\n")?;

    Ok(cursor.position() as usize)
}

/// Writes a `301 Moved Permanently` redirect response with CRLF-injection protection.
pub fn write_redirect_response<W: Write>(
    writer: &mut W,
    base: &str,
    target: &str,
) -> Result<usize, ProxyError> {
    write_redirect_response_tls(writer, base, target, false)
}

/// Writes a `301 Moved Permanently` redirect response, emitting HSTS preload on TLS.
pub fn write_redirect_response_tls<W: Write>(
    writer: &mut W,
    base: &str,
    target: &str,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    write_redirect_with_status(writer, "301 Moved Permanently", base, target, is_tls)
}

/// Writes a `308 Permanent Redirect` response preserving query string, emitting HSTS on TLS.
pub fn write_path_redirect_response<W: Write>(
    writer: &mut W,
    location: &str,
    query: &str,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    write_redirect_with_status(writer, "308 Permanent Redirect", location, query, is_tls)
}

fn write_redirect_with_status<W: Write>(
    writer: &mut W,
    status_line: &str,
    part1: &str,
    part2: &str,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    if part1.bytes().any(|b| b <= 0x20 || b >= 0x7f)
        || part2.bytes().any(|b| b <= 0x20 || b >= 0x7f)
    {
        return Err(ProxyError::BadRequest("invalid redirect location\n"));
    }
    let hsts = if is_tls { HSTS_HEADER_LINE } else { "" };
    let mut buf = [0u8; 2048];
    let mut cursor = io::Cursor::new(&mut buf[..]);
    write!(
        cursor,
        "HTTP/1.1 {}\r\n\
         Location: {}{}\r\n\
         Content-Length: 0\r\n\
         {}\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         {}\
         Connection: close\r\n\r\n",
        status_line, part1, part2, hsts, PERMISSIONS_POLICY_HEADER_LINE
    )
    .map_err(|_| ProxyError::HeadersTooLarge)?;
    let n = cursor.position() as usize;
    writer.write_all(&buf[..n])?;
    Ok(n)
}

/// Writes an HTTP/1.1 `200 OK` response for an ACME HTTP-01 challenge token.
pub fn write_acme_challenge_response<W: Write>(
    writer: &mut W,
    key_auth: &str,
    is_head: bool,
) -> Result<usize, ProxyError> {
    let mut buf = [0u8; 1024];
    let mut cursor = io::Cursor::new(&mut buf[..]);
    write!(
        cursor,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Connection: close\r\n\r\n",
        key_auth.len()
    )
    .map_err(|_| ProxyError::HeadersTooLarge)?;
    if !is_head {
        cursor
            .write_all(key_auth.as_bytes())
            .map_err(|_| ProxyError::HeadersTooLarge)?;
    }
    let n = cursor.position() as usize;
    writer.write_all(&buf[..n])?;
    Ok(n)
}

/// Formats an HTTP/1.1 `200 OK` static file response header block into `out`.
pub fn write_static_response_head(
    out: &mut [u8],
    content_type: &str,
    content_len: u64,
) -> Result<usize, ProxyError> {
    write_static_response_head_full(out, content_type, content_len, None, None, false)
}

/// Formats an HTTP/1.1 `200 OK` static file response header block with optional RFC 9530
/// `Content-Digest`, optional `Content-Security-Policy`, `Permissions-Policy`, and TLS HSTS.
pub fn write_static_response_head_full(
    out: &mut [u8],
    content_type: &str,
    content_len: u64,
    content_digest_b64: Option<&str>,
    csp: Option<&str>,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    write_static_response_head_cors(
        out,
        content_type,
        content_len,
        content_digest_b64,
        csp,
        is_tls,
        false,
    )
}

/// Formats an HTTP/1.1 `200 OK` static file response header block with optional RFC 9530
/// `Content-Digest`, optional `Content-Security-Policy`, `Permissions-Policy`, TLS HSTS,
/// and optional public CORS (`Access-Control-Allow-Origin: *`) for CORS-enabled static assets.
pub fn write_static_response_head_cors(
    out: &mut [u8],
    content_type: &str,
    content_len: u64,
    content_digest_b64: Option<&str>,
    csp: Option<&str>,
    is_tls: bool,
    allow_cors: bool,
) -> Result<usize, ProxyError> {
    let mut cursor = io::Cursor::new(out);
    write!(
        cursor,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n",
        content_type, content_len
    )
    .map_err(|_| ProxyError::HeadersTooLarge)?;
    if let Some(digest_b64) = content_digest_b64 {
        write!(cursor, "Content-Digest: sha-256=:{digest_b64}:\r\n")
            .map_err(|_| ProxyError::HeadersTooLarge)?;
    }
    if let Some(policy) = csp {
        write!(cursor, "Content-Security-Policy: {policy}\r\n")
            .map_err(|_| ProxyError::HeadersTooLarge)?;
    }
    if allow_cors {
        write_slice(&mut cursor, b"Access-Control-Allow-Origin: *\r\n")?;
    }
    if is_tls {
        write_slice(&mut cursor, HSTS_HEADER_LINE.as_bytes())?;
    }
    write_slice(&mut cursor, b"X-Content-Type-Options: nosniff\r\n")?;
    write_slice(&mut cursor, b"X-Frame-Options: DENY\r\n")?;
    write_slice(&mut cursor, b"Referrer-Policy: no-referrer\r\n")?;
    write_slice(&mut cursor, PERMISSIONS_POLICY_HEADER_LINE.as_bytes())?;
    write_slice(&mut cursor, b"Connection: close\r\n\r\n")?;
    Ok(cursor.position() as usize)
}

/// Formats an HTTP/1.1 `200 OK` response header block for `/.well-known/edge-integrity.json`.
pub fn write_integrity_response_head(
    out: &mut [u8],
    content_len: u64,
    content_digest_b64: &str,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    let mut cursor = io::Cursor::new(out);
    let hsts = if is_tls { HSTS_HEADER_LINE } else { "" };
    write!(
        cursor,
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Content-Digest: sha-256=:{content_digest_b64}:\r\n\
         {}\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         {}\
         Connection: close\r\n\r\n",
        content_len, hsts, PERMISSIONS_POLICY_HEADER_LINE
    )
    .map_err(|_| ProxyError::HeadersTooLarge)?;
    Ok(cursor.position() as usize)
}

/// Infers a safe static `Content-Type` header value from a file extension.
pub fn content_type_for_path(path: &Path) -> &'static str {
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e,
        None => return "application/octet-stream",
    };
    if ext.eq_ignore_ascii_case("html") || ext.eq_ignore_ascii_case("htm") {
        "text/html; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("js") || ext.eq_ignore_ascii_case("mjs") {
        "application/javascript; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("css") {
        "text/css; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("json") {
        "application/json; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("svg") {
        "image/svg+xml"
    } else if ext.eq_ignore_ascii_case("png") {
        "image/png"
    } else if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
        "image/jpeg"
    } else if ext.eq_ignore_ascii_case("gif") {
        "image/gif"
    } else if ext.eq_ignore_ascii_case("ico") {
        "image/x-icon"
    } else if ext.eq_ignore_ascii_case("wasm") {
        "application/wasm"
    } else if ext.eq_ignore_ascii_case("txt") {
        "text/plain; charset=utf-8"
    } else if ext.eq_ignore_ascii_case("xml") {
        "application/xml; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

/// Formats the sanitized client HTTP/1.1 response head into `out` with zero heap allocation.
///
/// Strips hop-by-hop headers and enforces canonical `X-Content-Type-Options: nosniff`,
/// `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`,
/// and `Connection: close`.
pub fn write_forwarded_response_head(
    out: &mut [u8],
    resp: &ParsedResponse<'_>,
) -> Result<usize, ProxyError> {
    write_forwarded_response_head_tls(out, resp, false)
}

/// Formats the sanitized client HTTP/1.1 response head, adding HSTS preload when `is_tls`.
pub fn write_forwarded_response_head_tls(
    out: &mut [u8],
    resp: &ParsedResponse<'_>,
    is_tls: bool,
) -> Result<usize, ProxyError> {
    write_forwarded_response_head_with_policy(out, resp, is_tls, None)
}

/// Formats the sanitized client HTTP/1.1 response head with optional TLS HSTS and
/// per-route `Permissions-Policy` override (defaulting to locked-down policy when `None`).
pub fn write_forwarded_response_head_with_policy(
    out: &mut [u8],
    resp: &ParsedResponse<'_>,
    is_tls: bool,
    permissions_policy: Option<&str>,
) -> Result<usize, ProxyError> {
    let mut cursor = io::Cursor::new(out);

    write!(cursor, "HTTP/1.1 {} {}\r\n", resp.status_code, resp.reason)
        .map_err(|_| ProxyError::UpstreamUnavailable)?;

    for hv in resp.headers() {
        if is_hop_by_hop_response(hv.name, resp.is_chunked)
            || is_named_in_connection(resp.headers(), hv.name)
            || is_managed_security_header(hv.name)
        {
            continue;
        }
        write_slice(&mut cursor, hv.name).map_err(|_| ProxyError::UpstreamUnavailable)?;
        write_slice(&mut cursor, b": ").map_err(|_| ProxyError::UpstreamUnavailable)?;
        write_slice(&mut cursor, hv.value).map_err(|_| ProxyError::UpstreamUnavailable)?;
        write_slice(&mut cursor, b"\r\n").map_err(|_| ProxyError::UpstreamUnavailable)?;
    }

    if is_tls {
        write_slice(&mut cursor, HSTS_HEADER_LINE.as_bytes())
            .map_err(|_| ProxyError::UpstreamUnavailable)?;
    }
    write_slice(&mut cursor, b"X-Content-Type-Options: nosniff\r\n")
        .map_err(|_| ProxyError::UpstreamUnavailable)?;
    write_slice(&mut cursor, b"X-Frame-Options: DENY\r\n")
        .map_err(|_| ProxyError::UpstreamUnavailable)?;
    write_slice(&mut cursor, b"Referrer-Policy: no-referrer\r\n")
        .map_err(|_| ProxyError::UpstreamUnavailable)?;
    if let Some(policy) = permissions_policy {
        write!(cursor, "Permissions-Policy: {policy}\r\n")
            .map_err(|_| ProxyError::UpstreamUnavailable)?;
    } else {
        write_slice(&mut cursor, PERMISSIONS_POLICY_HEADER_LINE.as_bytes())
            .map_err(|_| ProxyError::UpstreamUnavailable)?;
    }
    write_slice(&mut cursor, b"Connection: close\r\n\r\n")
        .map_err(|_| ProxyError::UpstreamUnavailable)?;

    Ok(cursor.position() as usize)
}

fn write_slice(cursor: &mut io::Cursor<&mut [u8]>, bytes: &[u8]) -> Result<(), ProxyError> {
    cursor
        .write_all(bytes)
        .map_err(|_| ProxyError::HeadersTooLarge)
}

fn parse_request_line(line: &[u8]) -> Result<(&str, &str, u8), ProxyError> {
    let sp1 = line
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ProxyError::BadRequest("malformed request line\n"))?;
    let method_bytes = &line[..sp1];
    let rest = &line[sp1 + 1..];
    let sp2 = rest
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ProxyError::BadRequest("malformed request line\n"))?;
    let target_bytes = &rest[..sp2];
    let version_bytes = &rest[sp2 + 1..];

    if method_bytes.is_empty() || !method_bytes.iter().all(|&b| is_tchar(b)) {
        return Err(ProxyError::BadRequest("invalid HTTP method\n"));
    }
    if target_bytes.is_empty()
        || target_bytes[0] != b'/'
        || !target_bytes
            .iter()
            .all(|&b| is_vchar(b) && b != b'#' && b != b'\\')
    {
        return Err(ProxyError::BadRequest("invalid request target\n"));
    }
    let version_minor = match version_bytes {
        b"HTTP/1.1" => 1,
        b"HTTP/1.0" => 0,
        _ => return Err(ProxyError::BadRequest("unsupported HTTP version\n")),
    };

    let method = std::str::from_utf8(method_bytes)
        .map_err(|_| ProxyError::BadRequest("non-ascii method\n"))?;
    let target = std::str::from_utf8(target_bytes)
        .map_err(|_| ProxyError::BadRequest("non-ascii target\n"))?;
    Ok((method, target, version_minor))
}

fn parse_status_line(line: &[u8]) -> Result<(u16, &str), ProxyError> {
    if line.len() < 12 {
        return Err(ProxyError::UpstreamUnavailable);
    }
    let version = &line[..8];
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(ProxyError::UpstreamUnavailable);
    }
    if line[8] != b' ' {
        return Err(ProxyError::UpstreamUnavailable);
    }
    let code_bytes = &line[9..12];
    if !code_bytes.iter().all(u8::is_ascii_digit) {
        return Err(ProxyError::UpstreamUnavailable);
    }
    let status_code = u16::from(code_bytes[0] - b'0') * 100
        + u16::from(code_bytes[1] - b'0') * 10
        + u16::from(code_bytes[2] - b'0');
    if !(100..=599).contains(&status_code) {
        return Err(ProxyError::UpstreamUnavailable);
    }
    let reason_bytes = if line.len() == 12 {
        b"" as &[u8]
    } else if line[12] == b' ' {
        &line[13..]
    } else {
        return Err(ProxyError::UpstreamUnavailable);
    };
    if !reason_bytes.iter().all(|&b| is_field_vchar_or_ows(b)) {
        return Err(ProxyError::UpstreamUnavailable);
    }
    let reason = std::str::from_utf8(reason_bytes).map_err(|_| ProxyError::UpstreamUnavailable)?;
    Ok((status_code, reason))
}

fn parse_header_line(line: &[u8]) -> Result<HeaderView<'_>, ProxyError> {
    if line.is_empty() || line[0] == b' ' || line[0] == b'\t' {
        return Err(ProxyError::BadRequest("obs-fold header rejected\n"));
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(ProxyError::BadRequest("header missing colon\n"))?;
    let name = &line[..colon];
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(ProxyError::BadRequest("invalid header name\n"));
    }
    let value = trim_ows(&line[colon + 1..]);
    if !value.iter().all(|&b| is_field_vchar_or_ows(b)) {
        return Err(ProxyError::BadRequest("invalid header value\n"));
    }
    Ok(HeaderView { name, value })
}

fn split_crlf(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    struct CrlfSplit<'a> {
        rem: &'a [u8],
        done: bool,
    }
    impl<'a> Iterator for CrlfSplit<'a> {
        type Item = &'a [u8];
        fn next(&mut self) -> Option<Self::Item> {
            if self.done {
                return None;
            }
            let mut i = 0;
            while i + 1 < self.rem.len() {
                if self.rem[i] == b'\r' && self.rem[i + 1] == b'\n' {
                    let line = &self.rem[..i];
                    self.rem = &self.rem[i + 2..];
                    return Some(line);
                }
                i += 1;
            }
            self.done = true;
            Some(self.rem)
        }
    }
    CrlfSplit {
        rem: data,
        done: data.is_empty(),
    }
}

fn parse_strict_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc = 0u64;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(acc)
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let Some(&b) = s.first() {
        if b == b' ' || b == b'\t' {
            s = &s[1..];
        } else {
            break;
        }
    }
    while let Some(&b) = s.last() {
        if b == b' ' || b == b'\t' {
            s = &s[..s.len() - 1];
        } else {
            break;
        }
    }
    s
}

#[inline]
const fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

#[inline]
const fn is_vchar(b: u8) -> bool {
    b >= 0x21 && b <= 0x7e
}

#[inline]
const fn is_field_vchar_or_ows(b: u8) -> bool {
    b == b'\t' || (b >= 0x20 && b <= 0x7e)
}

fn is_reserved_blindbind_header(name: &[u8]) -> bool {
    const PREFIX: &[u8] = b"x-blindbind";
    if name.len() < PREFIX.len() {
        return false;
    }
    let mut i = 0;
    while i < PREFIX.len() {
        let b = match name[i] {
            b'_' => b'-',
            other => other.to_ascii_lowercase(),
        };
        if b != PREFIX[i] {
            return false;
        }
        i += 1;
    }
    name.len() == PREFIX.len() || matches!(name[PREFIX.len()], b'-' | b'_')
}

fn is_hop_by_hop_request(name: &[u8], keep_chunked_te: bool) -> bool {
    if keep_chunked_te && name.eq_ignore_ascii_case(b"transfer-encoding") {
        return false;
    }
    is_hop_by_hop_common(name)
}

fn is_hop_by_hop_response(name: &[u8], keep_chunked_te: bool) -> bool {
    if keep_chunked_te && name.eq_ignore_ascii_case(b"transfer-encoding") {
        return false;
    }
    is_hop_by_hop_common(name)
}

fn is_hop_by_hop_common(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"connection")
        || name.eq_ignore_ascii_case(b"keep-alive")
        || name.eq_ignore_ascii_case(b"proxy-connection")
        || name.eq_ignore_ascii_case(b"proxy-authenticate")
        || name.eq_ignore_ascii_case(b"proxy-authorization")
        || name.eq_ignore_ascii_case(b"te")
        || name.eq_ignore_ascii_case(b"trailer")
        || name.eq_ignore_ascii_case(b"transfer-encoding")
        || name.eq_ignore_ascii_case(b"upgrade")
}

fn is_named_in_connection(headers: &[HeaderView<'_>], candidate: &[u8]) -> bool {
    for hv in headers {
        if hv.name.eq_ignore_ascii_case(b"connection") {
            for token in hv.value.split(|&b| b == b',') {
                let tok = trim_ows(token);
                if !tok.is_empty() && tok.eq_ignore_ascii_case(candidate) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_managed_security_header(name: &[u8]) -> bool {
    name.eq_ignore_ascii_case(b"x-content-type-options")
        || name.eq_ignore_ascii_case(b"x-frame-options")
        || name.eq_ignore_ascii_case(b"referrer-policy")
        || name.eq_ignore_ascii_case(b"strict-transport-security")
        || name.eq_ignore_ascii_case(b"permissions-policy")
        || name.eq_ignore_ascii_case(b"server")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn parse_valid_request_and_serialize_forwarded() {
        let raw = b"POST /api/post?id=7 HTTP/1.1\r\n\
                    Host: proxy.local\r\n\
                    Content-Length: 5\r\n\
                    X-Forwarded-For: 198.51.100.1\r\n\
                    Connection: keep-alive, X-Hop-Secret\r\n\
                    X-Hop-Secret: drop-me\r\n\
                    X-Custom: ok\r\n\r\nhello";
        let req = parse_request(raw, 1024, 64).expect("valid request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/api/post?id=7");
        assert_eq!(req.content_length, Some(5));
        assert!(!req.is_chunked);
        assert_eq!(&raw[req.header_end..], b"hello");

        let route = RouteMatch {
            upstream: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001),
            prepend_slash: false,
            tail: "/post?id=7",
        };
        let mut out = [0u8; 1024];
        let n = write_forwarded_request_head(
            &mut out,
            &req,
            route,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        )
        .expect("serialize request");
        let text = std::str::from_utf8(&out[..n]).expect("ascii");
        assert!(text.starts_with("POST /post?id=7 HTTP/1.1\r\n"));
        assert!(text.contains("X-Forwarded-For: 198.51.100.1, 203.0.113.9\r\n"));
        assert!(text.contains("X-Custom: ok\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(!text.contains("X-Hop-Secret"));
    }

    #[test]
    fn reject_smuggling_bare_crlf_and_oversized_body() {
        let cl_te = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(
            parse_request(cl_te, 1024, 64).unwrap_err().status_code(),
            400
        );

        let dup_cl = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nContent-Length: 4\r\n\r\n";
        assert_eq!(
            parse_request(dup_cl, 1024, 64).unwrap_err().status_code(),
            400
        );

        let bare_lf = b"GET /a HTTP/1.1\nHost: h\n\n";
        assert_eq!(
            parse_request(bare_lf, 1024, 64).unwrap_err().status_code(),
            400
        );

        let bare_cr = b"GET /a HTTP/1.1\rHost: h\r\n\r\n";
        assert_eq!(
            parse_request(bare_cr, 1024, 64).unwrap_err().status_code(),
            400
        );

        let space_before_colon = b"GET /a HTTP/1.1\r\nHost : h\r\n\r\n";
        assert_eq!(
            parse_request(space_before_colon, 1024, 64).unwrap_err().status_code(),
            400
        );

        let too_big = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 70001\r\n\r\n";
        assert_eq!(
            parse_request(too_big, 70_000, 64).unwrap_err(),
            ProxyError::PayloadTooLarge
        );

        let missing_host = b"GET /a HTTP/1.1\r\n\r\n";
        assert_eq!(
            parse_request(missing_host, 1024, 64).unwrap_err().status_code(),
            400
        );

        let too_many_headers = b"GET /a HTTP/1.1\r\nHost: h\r\nX-1: a\r\nX-2: b\r\n\r\n";
        assert_eq!(
            parse_request(too_many_headers, 1024, 2).unwrap_err(),
            ProxyError::HeadersTooLarge
        );
    }

    #[test]
    fn sanitize_response_and_inject_security_headers() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Content-Length: 2\r\n\
                    Server: leaky-upstream/1.0\r\n\
                    Strict-Transport-Security: max-age=0\r\n\
                    Permissions-Policy: geolocation=*\r\n\
                    X-Frame-Options: ALLOWALL\r\n\
                    Connection: keep-alive\r\n\r\nok";
        let resp = parse_response_head(raw, 64).expect("valid response");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length, Some(2));
        let mut out = [0u8; 512];
        let n = write_forwarded_response_head(&mut out, &resp).expect("serialize response");
        let text = std::str::from_utf8(&out[..n]).expect("ascii");
        assert!(text.contains("X-Content-Type-Options: nosniff\r\n"));
        assert!(text.contains("X-Frame-Options: DENY\r\n"));
        assert!(text.contains("Referrer-Policy: no-referrer\r\n"));
        assert!(text.contains(PERMISSIONS_POLICY_HEADER_LINE));
        assert!(!text.contains("Strict-Transport-Security"));
        assert!(!text.contains("leaky-upstream"));
        assert!(!text.contains("ALLOWALL"));
        assert!(!text.contains("keep-alive"));

        let n_tls =
            write_forwarded_response_head_tls(&mut out, &resp, true).expect("serialize tls resp");
        let text_tls = std::str::from_utf8(&out[..n_tls]).expect("ascii");
        assert!(text_tls.contains(HSTS_HEADER_LINE));
        assert!(text_tls.contains(PERMISSIONS_POLICY_HEADER_LINE));
        assert!(!text_tls.contains("max-age=0"));
        assert!(!text_tls.contains("Server:"));
    }

    #[test]
    fn mitm_hardening_headers_x_real_ip_static_integrity_and_308() {
        let raw = b"GET /api/check HTTP/1.1\r\n\
                    Host: example.com\r\n\
                    X-Real-IP: 1.2.3.4\r\n\r\n";
        let req = parse_request(raw, 1024, 64).expect("valid req");
        let route = RouteMatch {
            upstream: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3001),
            prepend_slash: false,
            tail: "/api/check",
        };
        let mut out = [0u8; 1024];
        let n = write_forwarded_request_head_proto(
            &mut out,
            &req,
            route,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            true,
        )
        .expect("forwarded req");
        let req_text = std::str::from_utf8(&out[..n]).expect("ascii");
        assert!(req_text.contains("X-Real-IP: 198.51.100.42\r\n"));
        assert!(!req_text.contains("1.2.3.4"));
        assert!(req_text.contains("X-Forwarded-Proto: https\r\n"));

        let n_st = write_static_response_head_full(
            &mut out,
            "text/html; charset=utf-8",
            123,
            Some("AAAA=="),
            Some("default-src 'none'"),
            true,
        )
        .expect("static head");
        let st_text = std::str::from_utf8(&out[..n_st]).expect("ascii");
        assert!(st_text.contains("Content-Digest: sha-256=:AAAA==:\r\n"));
        assert!(st_text.contains("Content-Security-Policy: default-src 'none'\r\n"));
        assert!(st_text.contains(HSTS_HEADER_LINE));
        assert!(st_text.contains(PERMISSIONS_POLICY_HEADER_LINE));

        let n_int = write_integrity_response_head(&mut out, 42, "BBBB==", true).expect("int head");
        let int_text = std::str::from_utf8(&out[..n_int]).expect("ascii");
        assert!(int_text.contains("Content-Type: application/json; charset=utf-8\r\n"));
        assert!(int_text.contains("Cache-Control: no-store\r\n"));
        assert!(int_text.contains("Content-Digest: sha-256=:BBBB==:\r\n"));
        assert!(int_text.contains(HSTS_HEADER_LINE));

        let mut redir_buf = Vec::new();
        write_path_redirect_response(&mut redir_buf, "/app/", "?a=1", true)
            .expect("308 redirect");
        let redir_text = std::str::from_utf8(&redir_buf).expect("ascii");
        assert!(redir_text.starts_with("HTTP/1.1 308 Permanent Redirect\r\n"));
        assert!(redir_text.contains("Location: /app/?a=1\r\n"));
        assert!(redir_text.contains(HSTS_HEADER_LINE));
        assert!(redir_text.contains(PERMISSIONS_POLICY_HEADER_LINE));
    }

    #[test]
    fn route_permissions_policy_override() {
        let raw_resp = b"HTTP/1.1 200 OK\r\n\
                         Content-Length: 2\r\n\
                         Permissions-Policy: camera=*\r\n\r\nok";
        let resp = parse_response_head(raw_resp, 64).expect("resp");
        let mut out = [0u8; 512];
        let custom_policy = "geolocation=(), microphone=(self), camera=(self), payment=()";
        let n = write_forwarded_response_head_with_policy(&mut out, &resp, true, Some(custom_policy))
            .expect("serialize override policy");
        let text = std::str::from_utf8(&out[..n]).expect("ascii");
        assert!(text.contains(&format!("Permissions-Policy: {custom_policy}\r\n")));
        assert!(!text.contains("camera=*"));
    }

    #[test]
    fn static_response_head_emits_cors_only_when_enabled() {
        let mut out_cdn = [0u8; 1024];
        let n_cdn = write_static_response_head_cors(
            &mut out_cdn,
            "application/javascript; charset=utf-8",
            42,
            Some("abc123"),
            Some("default-src 'none'"),
            true,
            true,
        )
        .expect("cdn head");
        let cdn_text = std::str::from_utf8(&out_cdn[..n_cdn]).expect("utf8");
        assert!(cdn_text.contains("Access-Control-Allow-Origin: *\r\n"));
        assert!(cdn_text.contains("Content-Digest: sha-256=:abc123:\r\n"));
        assert!(cdn_text.contains("X-Content-Type-Options: nosniff\r\n"));

        let mut out_root = [0u8; 1024];
        let n_root = write_static_response_head_full(
            &mut out_root,
            "text/html; charset=utf-8",
            42,
            Some("abc123"),
            Some("default-src 'none'"),
            true,
        )
        .expect("root head");
        let root_text = std::str::from_utf8(&out_root[..n_root]).expect("utf8");
        assert!(!root_text.contains("Access-Control-Allow-Origin:"));
    }
}
