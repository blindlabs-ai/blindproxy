use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use crate::config::ProxyConfig;
use crate::error::ProxyError;
use crate::tls::{
    cert_days_until_expiry, write_atomic_0600, EcP256Key, TlsCertStore, TlsClientStream,
};

/// RFC 8555 ACME v2 HTTP-01 well-known URL prefix.
pub const ACME_HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";

/// Concurrent in-memory HTTP-01 challenge map with a lock-free empty fast path.
#[derive(Default)]
pub struct AcmeChallengeStore {
    active_count: AtomicUsize,
    tokens: RwLock<HashMap<String, String>>,
}

impl AcmeChallengeStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a validated `(token, key_authorization)` pair for HTTP-01 serving.
    pub fn insert(&self, token: String, key_auth: String) -> Result<(), ProxyError> {
        if !is_valid_acme_token(&token) || key_auth.is_empty() || key_auth.len() > 512 {
            return Err(ProxyError::Acme("invalid ACME challenge token"));
        }
        let mut guard = self
            .tokens
            .write()
            .map_err(|_| ProxyError::Acme("challenge store lock poisoned"))?;
        guard.insert(token, key_auth);
        self.active_count.store(guard.len(), Ordering::Release);
        Ok(())
    }

    /// Removes a challenge token after authorization completes.
    pub fn remove(&self, token: &str) {
        if let Ok(mut guard) = self.tokens.write() {
            guard.remove(token);
            self.active_count.store(guard.len(), Ordering::Release);
        }
    }

    /// Looks up a challenge token. Lock-free (`O(1)` atomic load) when no challenges are active.
    pub fn get(&self, token: &str) -> Option<String> {
        if self.active_count.load(Ordering::Acquire) == 0 {
            return None;
        }
        if !is_valid_acme_token(token) {
            return None;
        }
        self.tokens.read().ok().and_then(|g| g.get(token).cloned())
    }
}

/// Validates an RFC 8555 HTTP-01 challenge token (base64url alphabet, bounded length).
pub fn is_valid_acme_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 128
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Extracts the challenge token if `target` matches `/.well-known/acme-challenge/<token>`.
pub fn extract_http01_token(target: &str) -> Option<&str> {
    let path_end = target.find('?').unwrap_or(target.len());
    let path = &target[..path_end];
    let token = path.strip_prefix(ACME_HTTP01_PREFIX)?;
    if is_valid_acme_token(token) {
        Some(token)
    } else {
        None
    }
}

/// RAII guard ensuring temporary HTTP-01 tokens are always cleaned up.
struct ChallengeGuard<'a> {
    store: &'a AcmeChallengeStore,
    tokens: Vec<String>,
}

impl<'a> ChallengeGuard<'a> {
    fn new(store: &'a AcmeChallengeStore) -> Self {
        Self {
            store,
            tokens: Vec::new(),
        }
    }

    fn register(&mut self, token: String, key_auth: String) -> Result<(), ProxyError> {
        self.store.insert(token.clone(), key_auth)?;
        self.tokens.push(token);
        Ok(())
    }
}

impl Drop for ChallengeGuard<'_> {
    fn drop(&mut self) {
        for tok in &self.tokens {
            self.store.remove(tok);
        }
    }
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
    0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
    0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
    0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

/// Pure-Rust incremental FIPS 180-4 SHA-256 streaming hasher (100% safe, zero heap allocation).
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                0x1f83d9ab, 0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if data.len() < need {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            self.compress_block(&block);
            self.buf_len = 0;
            data = &data[need..];
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress_block(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len_bytes = self.total_len.wrapping_mul(8).to_be_bytes();
        let pad_len = if self.buf_len < 56 {
            56 - self.buf_len
        } else {
            120 - self.buf_len
        };
        let mut pad = [0u8; 64];
        pad[0] = 0x80;
        self.update(&pad[..pad_len]);
        self.update(&bit_len_bytes);

        let mut out = [0u8; 32];
        for (dst, word) in out.chunks_exact_mut(4).zip(self.state.iter()) {
            dst.copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn compress_block(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for (word, chunk) in w.iter_mut().take(16).zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for idx in 0..48 {
            let i = idx + 16;
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut st = self.state;
        for (&k, &wi) in SHA256_K.iter().zip(w.iter()) {
            sha256_round(&mut st, k, wi);
        }
        for (dst, &delta) in self.state.iter_mut().zip(st.iter()) {
            *dst = dst.wrapping_add(delta);
        }
    }
}

#[inline]
fn sha256_round(st: &mut [u32; 8], k: u32, wi: u32) {
    let [a, b, c, d, e, f, g, hh] = *st;
    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
    let ch = (e & f) ^ ((!e) & g);
    let temp1 = hh
        .wrapping_add(s1)
        .wrapping_add(ch)
        .wrapping_add(k)
        .wrapping_add(wi);
    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let temp2 = s0.wrapping_add(maj);
    *st = [
        temp1.wrapping_add(temp2),
        a,
        b,
        c,
        d.wrapping_add(temp1),
        e,
        f,
        g,
    ];
}

/// Pure-Rust FIPS 180-4 SHA-256 implementation (100% safe, Miri-verified).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

fn encode_base64_with(input: &[u8], table: &[u8; 64], pad: bool) -> String {
    let cap = if pad {
        input.len().div_ceil(3) * 4
    } else {
        (input.len() / 3) * 4 + [0, 2, 3][input.len() % 3]
    };
    let mut out = String::with_capacity(cap);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = (u32::from(input[i]) << 16)
            | (u32::from(input[i + 1]) << 8)
            | u32::from(input[i + 2]);
        out.push(table[((n >> 18) & 0x3f) as usize] as char);
        out.push(table[((n >> 12) & 0x3f) as usize] as char);
        out.push(table[((n >> 6) & 0x3f) as usize] as char);
        out.push(table[(n & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = u32::from(input[i]) << 16;
        out.push(table[((n >> 18) & 0x3f) as usize] as char);
        out.push(table[((n >> 12) & 0x3f) as usize] as char);
        if pad {
            out.push('=');
            out.push('=');
        }
    } else if rem == 2 {
        let n = (u32::from(input[i]) << 16) | (u32::from(input[i + 1]) << 8);
        out.push(table[((n >> 18) & 0x3f) as usize] as char);
        out.push(table[((n >> 12) & 0x3f) as usize] as char);
        out.push(table[((n >> 6) & 0x3f) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

/// Encodes `input` using RFC 4648 Section 4 standard Base64 with `=` padding.
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    encode_base64_with(input, TABLE, true)
}

/// Encodes `input` as lowercase ASCII hexadecimal.
pub fn hex_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(input.len() * 2);
    for &b in input {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Encodes `input` using RFC 4648 Section 5 Base64url without padding (`=`).
pub fn base64url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    encode_base64_with(input, TABLE, false)
}

/// Builds canonical RFC 7638 JWK JSON for an EC P-256 public key `(x, y)`.
pub fn canonical_ec_jwk_json(x: &[u8; 32], y: &[u8; 32]) -> String {
    format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        base64url_encode(x),
        base64url_encode(y)
    )
}

/// Computes the RFC 7638 SHA-256 JWK thumbprint for an EC P-256 key.
pub fn jwk_thumbprint(x: &[u8; 32], y: &[u8; 32]) -> String {
    let jwk = canonical_ec_jwk_json(x, y);
    let digest = sha256(jwk.as_bytes());
    base64url_encode(&digest)
}

/// Computes an RFC 8555 Section 8.1 HTTP-01 `keyAuthorization` string (`token.thumbprint`).
pub fn http01_key_authorization(token: &str, thumbprint: &str) -> String {
    format!("{}.{}", token, thumbprint)
}

/// Escapes a string as a JSON string literal (including surrounding quotes).
pub fn json_escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for b in s.bytes() {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(b as char),
            _ => {
                out.push_str(&format!("\\u{:04x}", b));
            }
        }
    }
    out.push('"');
    out
}

/// Signer abstraction separating pure-Rust ACME protocol logic from OpenSSL P-256 FFI.
pub trait AcmeSigner {
    fn public_xy(&self) -> Result<([u8; 32], [u8; 32]), ProxyError>;
    fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64], ProxyError>;
    fn create_csr_der(&self, domains: &[String]) -> Result<Vec<u8>, ProxyError>;
}

impl AcmeSigner for EcP256Key {
    fn public_xy(&self) -> Result<([u8; 32], [u8; 32]), ProxyError> {
        EcP256Key::public_xy(self)
    }

    fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64], ProxyError> {
        EcP256Key::sign_es256(self, signing_input)
    }

    fn create_csr_der(&self, domains: &[String]) -> Result<Vec<u8>, ProxyError> {
        EcP256Key::create_csr_der(self, domains)
    }
}

/// Builds an RFC 8555 flattened JWS (`ES256`) request body.
///
/// Pass `payload_json = None` for RFC 8555 POST-as-GET requests (`"payload": ""`).
pub fn build_jws_body<S: AcmeSigner>(
    signer: &S,
    url: &str,
    nonce: &str,
    kid: Option<&str>,
    payload_json: Option<&str>,
) -> Result<String, ProxyError> {
    let protected_json = match kid {
        Some(account_url) => format!(
            "{{\"alg\":\"ES256\",\"kid\":{},\"nonce\":{},\"url\":{}}}",
            json_escape_str(account_url),
            json_escape_str(nonce),
            json_escape_str(url)
        ),
        None => {
            let (x, y) = signer.public_xy()?;
            let jwk = canonical_ec_jwk_json(&x, &y);
            format!(
                "{{\"alg\":\"ES256\",\"jwk\":{},\"nonce\":{},\"url\":{}}}",
                jwk,
                json_escape_str(nonce),
                json_escape_str(url)
            )
        }
    };

    let protected_b64 = base64url_encode(protected_json.as_bytes());
    let payload_b64 = match payload_json {
        Some(p) => base64url_encode(p.as_bytes()),
        None => String::new(),
    };

    let mut signing_input = String::with_capacity(protected_b64.len() + 1 + payload_b64.len());
    signing_input.push_str(&protected_b64);
    signing_input.push('.');
    signing_input.push_str(&payload_b64);

    let sig = signer.sign_es256(signing_input.as_bytes())?;
    let sig_b64 = base64url_encode(&sig);

    Ok(format!(
        "{{\"protected\":\"{}\",\"payload\":\"{}\",\"signature\":\"{}\"}}",
        protected_b64, payload_b64, sig_b64
    ))
}

/// Parsed HTTP/HTTPS URL components for ACME transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl ParsedUrl {
    pub fn parse(raw: &str) -> Result<Self, ProxyError> {
        let (https, rest) = if let Some(r) = raw.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = raw.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(ProxyError::Acme("ACME URL must be http:// or https://"));
        };
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err(ProxyError::Acme("ACME URL missing host"));
        }
        let default_port = if https { 443 } else { 80 };
        let (host, port) = if let Some(after_open) = authority.strip_prefix('[') {
            let close = after_open
                .find(']')
                .ok_or(ProxyError::Acme("malformed IPv6 URL host"))?;
            let h = &after_open[..close];
            let tail = &after_open[close + 1..];
            let p = if let Some(pstr) = tail.strip_prefix(':') {
                pstr.parse::<u16>()
                    .map_err(|_| ProxyError::Acme("invalid URL port"))?
            } else if tail.is_empty() {
                default_port
            } else {
                return Err(ProxyError::Acme("invalid IPv6 URL authority"));
            };
            (h.to_owned(), p)
        } else if let Some((h, pstr)) = authority.rsplit_once(':') {
            let p = pstr
                .parse::<u16>()
                .map_err(|_| ProxyError::Acme("invalid URL port"))?;
            (h.to_owned(), p)
        } else {
            (authority.to_owned(), default_port)
        };
        if host.is_empty() {
            return Err(ProxyError::Acme("ACME URL empty host"));
        }
        Ok(Self {
            https,
            host,
            port,
            path: path.to_owned(),
        })
    }

    pub fn host_header(&self) -> String {
        let default_port = if self.https { 443 } else { 80 };
        let is_v6 = self.host.contains(':');
        if self.port == default_port {
            if is_v6 {
                format!("[{}]", self.host)
            } else {
                self.host.clone()
            }
        } else if is_v6 {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Minimal HTTP response captured by an ACME transport.
#[derive(Debug, Clone)]
pub struct AcmeHttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl AcmeHttpResponse {
    pub fn header(&self, lower_name: &str) -> Option<&str> {
        self.headers.get(lower_name).map(String::as_str)
    }
}

/// Transport abstraction allowing both live OpenSSL HTTPS/HTTP calls and Miri unit tests.
pub trait AcmeTransport {
    fn request(
        &mut self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<AcmeHttpResponse, ProxyError>;
}

/// Live HTTP/1.1 + OpenSSL TLS 1.2+/1.3 ACME transport.
pub struct StdAcmeTransport {
    timeout: Duration,
    ca_cert_path: Option<std::path::PathBuf>,
}

impl StdAcmeTransport {
    pub fn new(timeout: Duration, ca_cert_path: Option<std::path::PathBuf>) -> Self {
        Self {
            timeout,
            ca_cert_path,
        }
    }
}

impl AcmeTransport for StdAcmeTransport {
    fn request(
        &mut self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        accept: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<AcmeHttpResponse, ProxyError> {
        let parsed = ParsedUrl::parse(url)?;
        let addr_str = if parsed.host.contains(':') {
            format!("[{}]:{}", parsed.host, parsed.port)
        } else {
            format!("{}:{}", parsed.host, parsed.port)
        };
        let sock_addr = addr_str
            .to_socket_addrs()
            .map_err(|_| ProxyError::Acme("failed to resolve ACME host"))?
            .next()
            .ok_or(ProxyError::Acme("ACME host resolved to no addresses"))?;

        let tcp = TcpStream::connect_timeout(&sock_addr, self.timeout)
            .map_err(|_| ProxyError::Acme("failed to connect to ACME server"))?;
        let _ = tcp.set_read_timeout(Some(self.timeout));
        let _ = tcp.set_write_timeout(Some(self.timeout));

        let payload = body.unwrap_or(&[]);
        let mut req_bytes = Vec::with_capacity(512 + payload.len());
        let _ = write!(
            req_bytes,
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: zero-proxy-acme/0.1\r\nConnection: close\r\n",
            method,
            parsed.path,
            parsed.host_header()
        );
        if let Some(ct) = content_type {
            let _ = write!(req_bytes, "Content-Type: {}\r\n", ct);
        }
        if let Some(ac) = accept {
            let _ = write!(req_bytes, "Accept: {}\r\n", ac);
        }
        if body.is_some() {
            let _ = write!(req_bytes, "Content-Length: {}\r\n", payload.len());
        }
        req_bytes.extend_from_slice(b"\r\n");
        req_bytes.extend_from_slice(payload);

        let raw_resp = if parsed.https {
            let mut tls =
                TlsClientStream::connect(tcp, &parsed.host, true, self.ca_cert_path.as_deref())?;
            tls.write_all(&req_bytes)
                .map_err(|_| ProxyError::Acme("failed to send HTTPS ACME request"))?;
            read_bounded_response(&mut tls)?
        } else {
            let mut stream = tcp;
            stream
                .write_all(&req_bytes)
                .map_err(|_| ProxyError::Acme("failed to send HTTP ACME request"))?;
            read_bounded_response(&mut stream)?
        };

        parse_acme_http_response(&raw_resp, method.eq_ignore_ascii_case("HEAD"))
    }
}

fn read_bounded_response<R: Read>(reader: &mut R) -> Result<Vec<u8>, ProxyError> {
    const MAX_ACME_RESP: usize = 2 * 1024 * 1024;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() + n > MAX_ACME_RESP {
                    return Err(ProxyError::Acme("ACME response exceeds 2 MiB limit"));
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(ProxyError::Acme("failed to read ACME response")),
        }
    }
    Ok(out)
}

/// Parses a raw HTTP/1.1 ACME server response (including `Transfer-Encoding: chunked`).
pub fn parse_acme_http_response(
    raw: &[u8],
    is_head: bool,
) -> Result<AcmeHttpResponse, ProxyError> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(ProxyError::Acme("malformed ACME HTTP response"))?;
    let head = std::str::from_utf8(&raw[..sep])
        .map_err(|_| ProxyError::Acme("non-utf8 ACME response headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or(ProxyError::Acme("missing ACME status line"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(ProxyError::Acme("invalid ACME status code"))?;

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }

    let body = if is_head {
        Vec::new()
    } else {
        let raw_body = &raw[sep + 4..];
        let is_chunked = headers
            .get("transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);
        if is_chunked {
            decode_chunked_body(raw_body)?
        } else {
            raw_body.to_vec()
        }
    };

    Ok(AcmeHttpResponse {
        status,
        headers,
        body,
    })
}

fn decode_chunked_body(mut src: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut out = Vec::new();
    while let Some(pos) = src.windows(2).position(|w| w == b"\r\n") {
        let hex_line = std::str::from_utf8(&src[..pos])
            .map_err(|_| ProxyError::Acme("invalid chunked header"))?;
        let hex_only = hex_line.split(';').next().unwrap_or("").trim();
        let len = usize::from_str_radix(hex_only, 16)
            .map_err(|_| ProxyError::Acme("invalid chunk size"))?;
        src = &src[pos + 2..];
        if len == 0 {
            break;
        }
        if src.len() < len {
            return Err(ProxyError::Acme("truncated chunked body"));
        }
        out.extend_from_slice(&src[..len]);
        src = &src[len..];
        if src.starts_with(b"\r\n") {
            src = &src[2..];
        }
    }
    Ok(out)
}

/// Minimal zero-dependency JSON value tree for RFC 8555 responses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(arr) => Some(arr.as_slice()),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            Self::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(Self::as_str)
    }
}

/// Parses strict JSON with bounded nesting depth (`<= 32`).
pub fn parse_json(input: &str) -> Result<JsonValue, ProxyError> {
    let mut parser = JsonParser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    let val = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(ProxyError::Acme("trailing data after JSON"));
    }
    Ok(val)
}

struct JsonParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> JsonParser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b' ' | b'\t' | b'\r' | b'\n' => self.pos += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ProxyError> {
        if depth > 32 {
            return Err(ProxyError::Acme("JSON nesting depth exceeded"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'"') => self.parse_string().map(JsonValue::Str),
            Some(b't') => {
                self.expect_bytes(b"true")?;
                Ok(JsonValue::Bool(true))
            }
            Some(b'f') => {
                self.expect_bytes(b"false")?;
                Ok(JsonValue::Bool(false))
            }
            Some(b'n') => {
                self.expect_bytes(b"null")?;
                Ok(JsonValue::Null)
            }
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(ProxyError::Acme("unexpected JSON token")),
        }
    }

    fn expect_bytes(&mut self, lit: &[u8]) -> Result<(), ProxyError> {
        if self.bytes[self.pos..].starts_with(lit) {
            self.pos += lit.len();
            Ok(())
        } else {
            Err(ProxyError::Acme("malformed JSON literal"))
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ProxyError> {
        self.pos += 1; // '{'
        self.skip_ws();
        let mut pairs = Vec::new();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(pairs));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(ProxyError::Acme("JSON object key must be string"));
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(ProxyError::Acme("JSON object missing ':'"));
            }
            self.pos += 1;
            let val = self.parse_value(depth)?;
            pairs.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(pairs));
                }
                _ => return Err(ProxyError::Acme("JSON object expected ',' or '}'")),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ProxyError> {
        self.pos += 1; // '['
        self.skip_ws();
        let mut items = Vec::new();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            let val = self.parse_value(depth)?;
            items.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(ProxyError::Acme("JSON array expected ',' or ']'")),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ProxyError> {
        self.pos += 1; // '"'
        let mut out = String::new();
        while self.pos < self.bytes.len() {
            let b = self.bytes[self.pos];
            self.pos += 1;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    if self.pos >= self.bytes.len() {
                        return Err(ProxyError::Acme("unterminated JSON escape"));
                    }
                    let esc = self.bytes[self.pos];
                    self.pos += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            if self.pos + 4 > self.bytes.len() {
                                return Err(ProxyError::Acme("short JSON unicode escape"));
                            }
                            let hex = std::str::from_utf8(&self.bytes[self.pos..self.pos + 4])
                                .map_err(|_| ProxyError::Acme("invalid unicode escape"))?;
                            let code = u32::from_str_radix(hex, 16)
                                .map_err(|_| ProxyError::Acme("invalid unicode hex"))?;
                            self.pos += 4;
                            if let Some(ch) = char::from_u32(code) {
                                out.push(ch);
                            }
                        }
                        _ => return Err(ProxyError::Acme("unknown JSON escape")),
                    }
                }
                0x00..=0x1f => return Err(ProxyError::Acme("unescaped control char in JSON")),
                _ => out.push(b as char),
            }
        }
        Err(ProxyError::Acme("unterminated JSON string"))
    }

    fn parse_number(&mut self) -> Result<JsonValue, ProxyError> {
        let start = self.pos;
        while self.pos < self.bytes.len() {
            match self.bytes[self.pos] {
                b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9' => self.pos += 1,
                _ => break,
            }
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| ProxyError::Acme("invalid JSON number"))?;
        Ok(JsonValue::Number(s.to_owned()))
    }
}

/// Issued certificate bundle returned by `AcmeClient::issue_certificate`.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

/// Pure-Rust RFC 8555 ACME v2 HTTP-01 client generic over transport and signer.
pub struct AcmeClient<T, S> {
    directory_url: String,
    email: Option<String>,
    transport: T,
    account_signer: S,
    poll_interval: Duration,
    max_polls: usize,
}

impl<T: AcmeTransport, S: AcmeSigner> AcmeClient<T, S> {
    pub fn new(
        directory_url: String,
        email: Option<String>,
        transport: T,
        account_signer: S,
    ) -> Self {
        Self {
            directory_url,
            email,
            transport,
            account_signer,
            poll_interval: Duration::from_millis(250),
            max_polls: 60,
        }
    }

    /// Executes the full RFC 8555 HTTP-01 issuance flow:
    /// `directory -> newNonce -> newAccount -> newOrder -> authorizations -> HTTP-01 challenge -> finalize(CSR) -> download PEM chain`.
    pub fn issue_certificate<D: AcmeSigner>(
        &mut self,
        domains: &[String],
        domain_signer: &D,
        challenges: &AcmeChallengeStore,
    ) -> Result<Vec<u8>, ProxyError> {
        if domains.is_empty() {
            return Err(ProxyError::Acme("no ACME domains requested"));
        }

        // 1. Fetch ACME directory.
        let dir_resp = self.transport.request(
            "GET",
            &self.directory_url,
            None,
            Some("application/json"),
            None,
        )?;
        if dir_resp.status != 200 {
            return Err(ProxyError::Acme("ACME directory request failed"));
        }
        let dir_text = std::str::from_utf8(&dir_resp.body)
            .map_err(|_| ProxyError::Acme("ACME directory non-utf8"))?;
        let dir_json = parse_json(dir_text)?;
        let new_nonce_url = dir_json
            .get_str("newNonce")
            .ok_or(ProxyError::Acme("ACME directory missing newNonce"))?
            .to_owned();
        let new_account_url = dir_json
            .get_str("newAccount")
            .ok_or(ProxyError::Acme("ACME directory missing newAccount"))?
            .to_owned();
        let new_order_url = dir_json
            .get_str("newOrder")
            .ok_or(ProxyError::Acme("ACME directory missing newOrder"))?
            .to_owned();

        // 2. Fetch initial Replay-Nonce.
        let mut nonce = self.fetch_nonce(&new_nonce_url)?;

        // 3. Register / lookup ACME account (`newAccount`).
        let acct_payload = match &self.email {
            Some(email) => format!(
                "{{\"termsOfServiceAgreed\":true,\"contact\":[{}]}}",
                json_escape_str(&format!("mailto:{}", email))
            ),
            None => "{\"termsOfServiceAgreed\":true}".to_owned(),
        };
        let acct_resp = self.signed_post(
            &new_account_url,
            &new_nonce_url,
            &mut nonce,
            None,
            Some(&acct_payload),
            None,
        )?;
        if acct_resp.status != 200 && acct_resp.status != 201 {
            return Err(ProxyError::Acme("ACME newAccount failed"));
        }
        let kid = acct_resp
            .header("location")
            .ok_or(ProxyError::Acme("ACME newAccount missing Location kid"))?
            .to_owned();

        let (x, y) = self.account_signer.public_xy()?;
        let thumbprint = jwk_thumbprint(&x, &y);

        // 4. Create new certificate order (`newOrder`).
        let mut ids_json = String::from("{\"identifiers\":[");
        for (idx, d) in domains.iter().enumerate() {
            if idx > 0 {
                ids_json.push(',');
            }
            ids_json.push_str("{\"type\":\"dns\",\"value\":");
            ids_json.push_str(&json_escape_str(d));
            ids_json.push('}');
        }
        ids_json.push_str("]}");

        let order_resp = self.signed_post(
            &new_order_url,
            &new_nonce_url,
            &mut nonce,
            Some(&kid),
            Some(&ids_json),
            None,
        )?;
        if order_resp.status != 201 && order_resp.status != 200 {
            return Err(ProxyError::Acme("ACME newOrder failed"));
        }
        let order_url = order_resp
            .header("location")
            .map(str::to_owned)
            .unwrap_or_else(|| new_order_url.clone());
        let order_text = std::str::from_utf8(&order_resp.body)
            .map_err(|_| ProxyError::Acme("ACME order non-utf8"))?;
        let order_json = parse_json(order_text)?;
        let finalize_url = order_json
            .get_str("finalize")
            .ok_or(ProxyError::Acme("ACME order missing finalize URL"))?
            .to_owned();
        let authz_urls: Vec<String> = order_json
            .get("authorizations")
            .and_then(JsonValue::as_array)
            .ok_or(ProxyError::Acme("ACME order missing authorizations"))?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();

        // 5. Fulfill HTTP-01 challenges for each authorization.
        {
            let mut guard = ChallengeGuard::new(challenges);
            let mut to_trigger = Vec::new();
            for authz_url in &authz_urls {
                let az_resp = self.signed_post(
                    authz_url,
                    &new_nonce_url,
                    &mut nonce,
                    Some(&kid),
                    None,
                    None,
                )?;
                if az_resp.status != 200 {
                    return Err(ProxyError::Acme("ACME authorization fetch failed"));
                }
                let az_text = std::str::from_utf8(&az_resp.body)
                    .map_err(|_| ProxyError::Acme("ACME authorization non-utf8"))?;
                let az_json = parse_json(az_text)?;
                if az_json.get_str("status") == Some("valid") {
                    continue;
                }
                let ch_arr = az_json
                    .get("challenges")
                    .and_then(JsonValue::as_array)
                    .ok_or(ProxyError::Acme("ACME authorization missing challenges"))?;
                let http01 = ch_arr
                    .iter()
                    .find(|c| c.get_str("type") == Some("http-01"))
                    .ok_or(ProxyError::Acme("ACME authorization missing http-01"))?;
                let token = http01
                    .get_str("token")
                    .ok_or(ProxyError::Acme("ACME http-01 missing token"))?
                    .to_owned();
                let ch_url = http01
                    .get_str("url")
                    .ok_or(ProxyError::Acme("ACME http-01 missing url"))?
                    .to_owned();
                let key_auth = http01_key_authorization(&token, &thumbprint);
                guard.register(token, key_auth)?;
                to_trigger.push((authz_url.clone(), ch_url));
            }

            // Trigger validation and poll until each authorization is valid.
            for (authz_url, ch_url) in to_trigger {
                let trig_resp = self.signed_post(
                    &ch_url,
                    &new_nonce_url,
                    &mut nonce,
                    Some(&kid),
                    Some("{}"),
                    None,
                )?;
                if trig_resp.status != 200 && trig_resp.status != 202 {
                    return Err(ProxyError::Acme("ACME challenge trigger failed"));
                }
                self.poll_status(&authz_url, &new_nonce_url, &mut nonce, &kid, "valid")?;
            }
        }

        // 6. Finalize order with DER CSR.
        let csr_der = domain_signer.create_csr_der(domains)?;
        let csr_payload = format!("{{\"csr\":\"{}\"}}", base64url_encode(&csr_der));
        let fin_resp = self.signed_post(
            &finalize_url,
            &new_nonce_url,
            &mut nonce,
            Some(&kid),
            Some(&csr_payload),
            None,
        )?;
        if fin_resp.status != 200 {
            return Err(ProxyError::Acme("ACME finalize failed"));
        }
        let fin_text = std::str::from_utf8(&fin_resp.body)
            .map_err(|_| ProxyError::Acme("ACME finalize non-utf8"))?;
        let fin_json = parse_json(fin_text)?;
        let cert_url = if let Some(url) = fin_json.get_str("certificate") {
            url.to_owned()
        } else {
            let final_order =
                self.poll_status(&order_url, &new_nonce_url, &mut nonce, &kid, "valid")?;
            final_order
                .get_str("certificate")
                .ok_or(ProxyError::Acme("ACME valid order missing certificate URL"))?
                .to_owned()
        };

        // 7. Download full PEM certificate chain.
        let cert_resp = self.signed_post(
            &cert_url,
            &new_nonce_url,
            &mut nonce,
            Some(&kid),
            None,
            Some("application/pem-certificate-chain"),
        )?;
        if cert_resp.status != 200 || cert_resp.body.is_empty() {
            return Err(ProxyError::Acme("ACME certificate download failed"));
        }
        Ok(cert_resp.body)
    }

    fn fetch_nonce(&mut self, new_nonce_url: &str) -> Result<String, ProxyError> {
        let resp = self
            .transport
            .request("HEAD", new_nonce_url, None, None, None)?;
        resp.header("replay-nonce")
            .map(str::to_owned)
            .ok_or(ProxyError::Acme("ACME newNonce missing Replay-Nonce"))
    }

    fn signed_post(
        &mut self,
        url: &str,
        new_nonce_url: &str,
        nonce: &mut String,
        kid: Option<&str>,
        payload_json: Option<&str>,
        accept: Option<&str>,
    ) -> Result<AcmeHttpResponse, ProxyError> {
        for attempt in 0..2 {
            let body = build_jws_body(&self.account_signer, url, nonce, kid, payload_json)?;
            let resp = self.transport.request(
                "POST",
                url,
                Some("application/jose+json"),
                accept,
                Some(body.as_bytes()),
            )?;
            if let Some(next_nonce) = resp.header("replay-nonce") {
                *nonce = next_nonce.to_owned();
            } else {
                *nonce = self.fetch_nonce(new_nonce_url)?;
            }
            if resp.status == 400
                && attempt == 0
                && std::str::from_utf8(&resp.body)
                    .map(|b| b.contains("badNonce"))
                    .unwrap_or(false)
            {
                continue;
            }
            return Ok(resp);
        }
        Err(ProxyError::Acme("ACME request retry exhausted"))
    }

    fn poll_status(
        &mut self,
        url: &str,
        new_nonce_url: &str,
        nonce: &mut String,
        kid: &str,
        desired: &str,
    ) -> Result<JsonValue, ProxyError> {
        for _ in 0..self.max_polls {
            let resp = self.signed_post(url, new_nonce_url, nonce, Some(kid), None, None)?;
            if resp.status != 200 {
                return Err(ProxyError::Acme("ACME poll failed"));
            }
            let text = std::str::from_utf8(&resp.body)
                .map_err(|_| ProxyError::Acme("ACME poll non-utf8"))?;
            let json = parse_json(text)?;
            match json.get_str("status") {
                Some(st) if st == desired => return Ok(json),
                Some("invalid") => return Err(ProxyError::Acme("ACME validation marked invalid")),
                _ => {
                    if !self.poll_interval.is_zero() {
                        thread::sleep(self.poll_interval);
                    }
                }
            }
        }
        Err(ProxyError::Acme("ACME poll timed out"))
    }
}

/// Returns true if a domain's on-disk certificate is missing, unreadable, or expires in
/// fewer than `renew_days` days.
pub fn cert_needs_renewal(cert_dir: &Path, domain: &str, renew_days: u32) -> bool {
    let dir = cert_dir.join(domain);
    let cert_path = dir.join("fullchain.pem");
    let key_path = dir.join("privkey.pem");
    if !cert_path.is_file() || !key_path.is_file() {
        return true;
    }
    let Ok(pem) = std::fs::read(&cert_path) else {
        return true;
    };
    match cert_days_until_expiry(&pem) {
        Ok(days) => days < i64::from(renew_days),
        Err(_) => true,
    }
}

/// Issues or renews a single domain via live RFC 8555 ACME v2, atomically persists
/// `fullchain.pem` & `privkey.pem` (`0600`), and hot-swaps into `cert_store`.
pub fn issue_and_install_domain(
    cfg: &ProxyConfig,
    domain: &str,
    cert_store: &TlsCertStore,
    challenges: &AcmeChallengeStore,
) -> Result<IssuedCert, ProxyError> {
    let cert_dir = cfg
        .cert_dir
        .as_ref()
        .ok_or(ProxyError::Acme("cert_dir required for ACME"))?;

    let acct_key_path = cert_dir.join("account.key");
    let account_key = if acct_key_path.is_file() {
        let pem = std::fs::read(&acct_key_path)
            .map_err(|_| ProxyError::Acme("failed to read ACME account key"))?;
        EcP256Key::from_pem(&pem)?
    } else {
        let fresh = EcP256Key::generate()?;
        let pem = fresh.to_pem()?;
        write_atomic_0600(&acct_key_path, &pem)?;
        fresh
    };

    let domain_key = EcP256Key::generate()?;
    let domain_key_pem = domain_key.to_pem()?;
    let transport = StdAcmeTransport::new(
        Duration::from_millis(cfg.upstream_timeout_ms),
        cfg.acme_ca_cert.clone(),
    );
    let mut client = AcmeClient::new(
        cfg.acme_directory.clone(),
        cfg.acme_email.clone(),
        transport,
        account_key,
    );
    let domains = vec![domain.to_owned()];
    let cert_pem = client.issue_certificate(&domains, &domain_key, challenges)?;

    let host_dir = cert_dir.join(domain);
    write_atomic_0600(&host_dir.join("privkey.pem"), &domain_key_pem)?;
    write_atomic_0600(&host_dir.join("fullchain.pem"), &cert_pem)?;

    let set_default = !cert_store.has_certs();
    cert_store.install_pem_bytes(Some(domain), &cert_pem, &domain_key_pem, set_default)?;

    Ok(IssuedCert {
        cert_pem,
        key_pem: domain_key_pem,
    })
}

/// Checks every ACME domain in `cfg` and renews any certificate missing or expiring in
/// `< cfg.acme_renew_days` days, returning how many certificates were renewed.
pub fn run_renewal_pass(
    cfg: &ProxyConfig,
    cert_store: &TlsCertStore,
    challenges: &AcmeChallengeStore,
) -> usize {
    let Some(cert_dir) = cfg.cert_dir.as_ref() else {
        return 0;
    };
    let mut renewed = 0usize;
    for domain in &cfg.acme_domains {
        if cert_needs_renewal(cert_dir, domain, cfg.acme_renew_days) {
            match issue_and_install_domain(cfg, domain, cert_store, challenges) {
                Ok(_) => {
                    renewed += 1;
                }
                Err(err) => {
                    eprintln!("zero-proxy acme renewal error for {}: {}", domain, err);
                }
            }
        }
    }
    renewed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_and_base64url_match_rfc_vectors() {
        let empty = sha256(b"");
        let empty_hex: String = empty.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            empty_hex,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        let abc = sha256(b"abc");
        let abc_hex: String = abc.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            abc_hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(&[0xfb, 0xff, 0xfe]), "-__-");

        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xfe]), "+//+");
        assert_eq!(
            base64_encode(&abc),
            "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        );
        assert_eq!(
            hex_encode(&abc),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // Verify streaming Sha256 across 55/56/64/128-byte block boundaries.
        for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128, 257] {
            let payload: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(31)).collect();
            let one_shot = sha256(&payload);
            let mut streamed = Sha256::new();
            for chunk in payload.chunks(7) {
                streamed.update(chunk);
            }
            assert_eq!(streamed.finalize(), one_shot);
        }
    }

    #[test]
    fn challenge_store_token_validation_and_url_parser() {
        let store = AcmeChallengeStore::new();
        assert_eq!(store.get("abc"), None);
        assert!(store.insert("../bad".to_owned(), "k".to_owned()).is_err());

        store
            .insert("tok_ABC-123".to_owned(), "tok_ABC-123.thumb".to_owned())
            .expect("valid token");
        assert_eq!(
            store.get("tok_ABC-123").as_deref(),
            Some("tok_ABC-123.thumb")
        );
        assert_eq!(
            extract_http01_token("/.well-known/acme-challenge/tok_ABC-123?x=1"),
            Some("tok_ABC-123")
        );
        assert_eq!(extract_http01_token("/.well-known/acme-challenge/a/b"), None);
        store.remove("tok_ABC-123");
        assert_eq!(store.get("tok_ABC-123"), None);

        let u1 = ParsedUrl::parse("https://acme.example.com/directory")
            .expect("parse https url");
        assert!(u1.https);
        assert_eq!(u1.host, "acme.example.com");
        assert_eq!(u1.port, 443);
        assert_eq!(u1.path, "/directory");
        assert_eq!(u1.host_header(), "acme.example.com");

        let u2 = ParsedUrl::parse("http://127.0.0.1:14000/dir").expect("parse http url");
        assert!(!u2.https);
        assert_eq!(u2.port, 14000);
        assert_eq!(u2.host_header(), "127.0.0.1:14000");
    }

    #[test]
    fn json_parser_and_jws_state_machine_under_miri() {
        struct MockSigner;
        impl AcmeSigner for MockSigner {
            fn public_xy(&self) -> Result<([u8; 32], [u8; 32]), ProxyError> {
                Ok(([0x11u8; 32], [0x22u8; 32]))
            }
            fn sign_es256(&self, signing_input: &[u8]) -> Result<[u8; 64], ProxyError> {
                let d = sha256(signing_input);
                let mut sig = [0u8; 64];
                sig[..32].copy_from_slice(&d);
                sig[32..].copy_from_slice(&d);
                Ok(sig)
            }
            fn create_csr_der(&self, _domains: &[String]) -> Result<Vec<u8>, ProxyError> {
                Ok(vec![0x30, 0x03, 0x02, 0x01, 0x00])
            }
        }

        struct MockTransport {
            challenges: Arc<AcmeChallengeStore>,
            validated_token: Option<String>,
        }
        impl AcmeTransport for MockTransport {
            fn request(
                &mut self,
                method: &str,
                url: &str,
                _ct: Option<&str>,
                _accept: Option<&str>,
                _body: Option<&[u8]>,
            ) -> Result<AcmeHttpResponse, ProxyError> {
                let mut headers = HashMap::new();
                headers.insert("replay-nonce".to_owned(), "nonce-next".to_owned());
                match (method, url) {
                    ("GET", "http://mock.acme/dir") => Ok(AcmeHttpResponse {
                        status: 200,
                        headers,
                        body: br#"{"newNonce":"http://mock.acme/nonce","newAccount":"http://mock.acme/acct","newOrder":"http://mock.acme/order"}"#.to_vec(),
                    }),
                    ("HEAD", "http://mock.acme/nonce") => Ok(AcmeHttpResponse {
                        status: 200,
                        headers,
                        body: Vec::new(),
                    }),
                    ("POST", "http://mock.acme/acct") => {
                        headers.insert("location".to_owned(), "http://mock.acme/acct/1".to_owned());
                        Ok(AcmeHttpResponse {
                            status: 201,
                            headers,
                            body: br#"{"status":"valid"}"#.to_vec(),
                        })
                    }
                    ("POST", "http://mock.acme/order") => {
                        headers.insert("location".to_owned(), "http://mock.acme/order/1".to_owned());
                        Ok(AcmeHttpResponse {
                            status: 201,
                            headers,
                            body: br#"{"status":"pending","authorizations":["http://mock.acme/authz/1"],"finalize":"http://mock.acme/finalize/1"}"#.to_vec(),
                        })
                    }
                    ("POST", "http://mock.acme/authz/1") => {
                        let st = if self.validated_token.is_some() {
                            "valid"
                        } else {
                            "pending"
                        };
                        let body = format!(
                            "{{\"status\":\"{}\",\"challenges\":[{{\"type\":\"http-01\",\"token\":\"tok42\",\"url\":\"http://mock.acme/ch/1\"}}]}}",
                            st
                        );
                        Ok(AcmeHttpResponse {
                            status: 200,
                            headers,
                            body: body.into_bytes(),
                        })
                    }
                    ("POST", "http://mock.acme/ch/1") => {
                        // Simulate CA validating HTTP-01 from the live challenge store!
                        let key_auth = self
                            .challenges
                            .get("tok42")
                            .ok_or(ProxyError::Acme("token missing in store"))?;
                        assert!(key_auth.starts_with("tok42."));
                        self.validated_token = Some(key_auth);
                        Ok(AcmeHttpResponse {
                            status: 200,
                            headers,
                            body: br#"{"status":"valid"}"#.to_vec(),
                        })
                    }
                    ("POST", "http://mock.acme/finalize/1") => Ok(AcmeHttpResponse {
                        status: 200,
                        headers,
                        body: br#"{"status":"valid","certificate":"http://mock.acme/cert/1"}"#
                            .to_vec(),
                    }),
                    ("POST", "http://mock.acme/cert/1") => Ok(AcmeHttpResponse {
                        status: 200,
                        headers,
                        body: b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n"
                            .to_vec(),
                    }),
                    _ => Err(ProxyError::Acme("unexpected mock ACME endpoint")),
                }
            }
        }

        let challenges = AcmeChallengeStore::new();
        let transport = MockTransport {
            challenges: Arc::clone(&challenges),
            validated_token: None,
        };
        let mut client = AcmeClient::new(
            "http://mock.acme/dir".to_owned(),
            Some("ops@example.com".to_owned()),
            transport,
            MockSigner,
        );
        client.poll_interval = Duration::ZERO;

        let pem = client
            .issue_certificate(&["example.com".to_owned()], &MockSigner, &challenges)
            .expect("full ACME v2 flow succeeds");
        assert!(std::str::from_utf8(&pem)
            .expect("ascii pem")
            .contains("BEGIN CERTIFICATE"));
        // Verify challenge token was cleaned up after completion.
        assert_eq!(challenges.get("tok42"), None);
    }
}
