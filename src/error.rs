use std::fmt;
use std::io::{self, Write};

/// Zero-allocation typed error enum for all proxy, parser, config, and I/O failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyError {
    HeaderTimeout,
    IdleTimeout,
    HeadersTooLarge,
    PayloadTooLarge,
    RateLimited,
    BadRequest(&'static str),
    Unauthorized(&'static str),
    Forbidden,
    NotFound,
    MethodNotAllowed,
    UpstreamUnavailable,
    UpstreamTimeout,
    TooManyConnections,
    Config(&'static str),
    Tls(&'static str),
    Acme(&'static str),
    Io(io::ErrorKind),
}

impl ProxyError {
    const fn http_spec(self) -> (u16, &'static str, &'static str) {
        match self {
            Self::HeaderTimeout => (408, "Request Timeout", "header read timeout\n"),
            Self::IdleTimeout => (408, "Request Timeout", "idle timeout\n"),
            Self::HeadersTooLarge => (
                431,
                "Request Header Fields Too Large",
                "request headers too large\n",
            ),
            Self::PayloadTooLarge => (413, "Payload Too Large", "payload too large\n"),
            Self::RateLimited => (429, "Too Many Requests", "rate limit exceeded\n"),
            Self::BadRequest(msg) => (400, "Bad Request", msg),
            Self::Unauthorized(msg) => (401, "Unauthorized", msg),
            Self::Forbidden => (403, "Forbidden", "forbidden\n"),
            Self::NotFound => (404, "Not Found", "no matching route\n"),
            Self::MethodNotAllowed => (405, "Method Not Allowed", "method not allowed\n"),
            Self::UpstreamUnavailable | Self::Tls(_) | Self::Io(_) => {
                (502, "Bad Gateway", "upstream unavailable\n")
            }
            Self::UpstreamTimeout => (504, "Gateway Timeout", "upstream timeout\n"),
            Self::TooManyConnections => (503, "Service Unavailable", "server busy\n"),
            Self::Config(msg) | Self::Acme(msg) => (500, "Internal Server Error", msg),
        }
    }

    /// Returns the HTTP status code corresponding to this error.
    pub const fn status_code(self) -> u16 {
        self.http_spec().0
    }

    /// Returns the static HTTP reason phrase for this error.
    pub const fn reason_phrase(self) -> &'static str {
        self.http_spec().1
    }

    /// Returns a static plain-text body suitable for wire responses without leaking internals.
    pub const fn public_body(self) -> &'static str {
        self.http_spec().2
    }

    /// Formats and writes a complete HTTP/1.1 error response using a fixed stack buffer
    /// with zero heap allocations.
    pub fn write_http_response<W: Write>(self, writer: &mut W) -> io::Result<()> {
        self.write_http_response_tls(writer, false)
    }

    /// Formats and writes a complete HTTP/1.1 error response, adding HSTS preload on TLS connections.
    pub fn write_http_response_tls<W: Write>(self, writer: &mut W, is_tls: bool) -> io::Result<()> {
        let mut stack_buf = [0u8; 768];
        let mut cursor = io::Cursor::new(&mut stack_buf[..]);
        let body = self.public_body();
        let extra_header = match self {
            Self::RateLimited => "Retry-After: 1\r\n",
            _ => "",
        };
        let hsts_header = if is_tls {
            "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload\r\n"
        } else {
            ""
        };
        write!(
            cursor,
            "HTTP/1.1 {} {}\r\n\
             Content-Type: text/plain; charset=ascii\r\n\
             Content-Length: {}\r\n\
             {}\
             {}\
             X-Content-Type-Options: nosniff\r\n\
             X-Frame-Options: DENY\r\n\
             Referrer-Policy: no-referrer\r\n\
             Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()\r\n\
             Connection: close\r\n\r\n\
             {}",
            self.status_code(),
            self.reason_phrase(),
            body.len(),
            extra_header,
            hsts_header,
            body
        )?;
        let written = cursor.position() as usize;
        writer.write_all(&stack_buf[..written])
    }
}

impl From<io::Error> for ProxyError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.kind())
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::HeaderTimeout => f.write_str("header read timeout"),
            Self::IdleTimeout => f.write_str("connection idle timeout"),
            Self::HeadersTooLarge => f.write_str("request headers exceed maximum size"),
            Self::PayloadTooLarge => f.write_str("request body exceeds maximum size"),
            Self::RateLimited => f.write_str("client rate limit exceeded"),
            Self::BadRequest(reason) => write!(f, "bad request: {}", reason),
            Self::Unauthorized(reason) => write!(f, "unauthorized: {}", reason),
            Self::Forbidden => f.write_str("forbidden"),
            Self::NotFound => f.write_str("no route matched request path"),
            Self::MethodNotAllowed => f.write_str("method not allowed"),
            Self::UpstreamUnavailable => f.write_str("upstream unavailable"),
            Self::UpstreamTimeout => f.write_str("upstream timed out"),
            Self::TooManyConnections => f.write_str("maximum concurrent connections reached"),
            Self::Config(reason) => write!(f, "configuration error: {}", reason),
            Self::Tls(reason) => write!(f, "tls error: {}", reason),
            Self::Acme(reason) => write!(f, "acme error: {}", reason),
            Self::Io(kind) => write!(f, "io error: {:?}", kind),
        }
    }
}

impl std::error::Error for ProxyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_status_codes_and_zero_alloc_formatting() {
        let cases = [
            (ProxyError::HeaderTimeout, 408u16, "408 Request Timeout"),
            (ProxyError::IdleTimeout, 408, "408 Request Timeout"),
            (ProxyError::HeadersTooLarge, 431, "431 Request Header Fields Too Large"),
            (ProxyError::PayloadTooLarge, 413, "413 Payload Too Large"),
            (ProxyError::RateLimited, 429, "429 Too Many Requests"),
            (ProxyError::BadRequest("bad line"), 400, "400 Bad Request"),
            (ProxyError::Unauthorized("missing auth\n"), 401, "401 Unauthorized"),
            (ProxyError::NotFound, 404, "404 Not Found"),
            (ProxyError::UpstreamUnavailable, 502, "502 Bad Gateway"),
            (ProxyError::UpstreamTimeout, 504, "504 Gateway Timeout"),
            (ProxyError::TooManyConnections, 503, "503 Service Unavailable"),
            (ProxyError::Io(io::ErrorKind::BrokenPipe), 502, "502 Bad Gateway"),
        ];
        for (err, expected_code, expected_line) in cases {
            assert_eq!(err.status_code(), expected_code);
            let mut out = Vec::new();
            err.write_http_response(&mut out).expect("write error response");
            let text = std::str::from_utf8(&out).expect("ascii response");
            assert!(text.starts_with(&format!("HTTP/1.1 {}\r\n", expected_line)));
            assert!(text.contains("X-Content-Type-Options: nosniff\r\n"));
            assert!(text.contains("X-Frame-Options: DENY\r\n"));
            assert!(text.contains("Referrer-Policy: no-referrer\r\n"));
            assert!(text.contains("Connection: close\r\n"));
            if err == ProxyError::RateLimited {
                assert!(text.contains("Retry-After: 1\r\n"));
            }
            assert!(!err.to_string().is_empty());
        }
    }
}
