#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zero_proxy::{CliAction, ProxyConfig, ProxyHandle, ProxyServer};

struct MockUpstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockUpstream {
    fn start(tag: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let hits_c = Arc::clone(&hits);
        let stop_c = Arc::clone(&stop);
        let join = thread::spawn(move || {
            for incoming in listener.incoming() {
                if stop_c.load(Ordering::Acquire) {
                    break;
                }
                let mut stream = match incoming {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                if stop_c.load(Ordering::Acquire) {
                    break;
                }
                hits_c.fetch_add(1, Ordering::AcqRel);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                handle_mock_upstream(&mut stream, tag);
            }
        });

        Self {
            addr,
            hits,
            stop,
            join: Some(join),
        }
    }

    fn hit_count(&self) -> usize {
        self.hits.load(Ordering::Acquire)
    }
}

impl Drop for MockUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn handle_mock_upstream(stream: &mut TcpStream, tag: &str) {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        raw.extend_from_slice(&tmp[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if raw.len() > 65_536 {
            return;
        }
    }

    let head = String::from_utf8_lossy(&raw[..header_end - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("").to_owned();
    let mut content_length = 0usize;
    let mut is_chunked = false;
    let mut xff = String::new();
    let mut xfp = String::new();

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let kl = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if kl == "content-length" {
                content_length = val.parse().unwrap_or(0);
            } else if kl == "transfer-encoding" && val.eq_ignore_ascii_case("chunked") {
                is_chunked = true;
            } else if kl == "x-forwarded-for" {
                xff = val.to_owned();
            } else if kl == "x-forwarded-proto" {
                xfp = val.to_owned();
            }
        }
    }

    let mut body = raw[header_end..].to_vec();
    if is_chunked {
        while !body.ends_with(b"0\r\n\r\n") {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        let decoded = decode_chunked(&body);
        body = decoded;
    } else {
        while body.len() < content_length {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => body.extend_from_slice(&tmp[..n]),
            }
        }
        body.truncate(content_length);
    }

    let checksum: u64 = body.iter().fold(0u64, |acc, &b| acc.wrapping_add(u64::from(b)));
    let resp_body = format!(
        "tag={}|req={}|xff={}|xfp={}|body_len={}|sum={}\n",
        tag,
        req_line,
        xff,
        xfp,
        body.len(),
        checksum
    );

    // Intentionally send a weak X-Frame-Options to prove zero_proxy overwrites it with DENY.
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         X-Frame-Options: ALLOWALL\r\n\
         X-Upstream-Tag: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        resp_body.len(),
        tag,
        resp_body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.shutdown(Shutdown::Both);
}

fn decode_chunked(mut src: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(pos) = src.windows(2).position(|w| w == b"\r\n") {
        let hex = std::str::from_utf8(&src[..pos]).unwrap_or("0").trim();
        let len = usize::from_str_radix(hex, 16).unwrap_or(0);
        src = &src[pos + 2..];
        if len == 0 {
            break;
        }
        let take = len.min(src.len());
        out.extend_from_slice(&src[..take]);
        src = &src[take..];
        if src.starts_with(b"\r\n") {
            src = &src[2..];
        }
    }
    out
}

struct RunningProxy {
    handle: ProxyHandle,
    join: Option<thread::JoinHandle<()>>,
}

impl RunningProxy {
    fn start(cfg: ProxyConfig) -> Self {
        let server = ProxyServer::bind(cfg).expect("bind proxy");
        let handle = server.handle();
        let join = thread::spawn(move || {
            let _ = server.run();
        });
        Self {
            handle,
            join: Some(join),
        }
    }

    fn addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        self.handle.stop();
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

fn send_raw_http(addr: SocketAddr, req: &[u8]) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).expect("connect proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    stream.write_all(req).expect("write request");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("read response");
    parse_test_response(&buf)
}

fn parse_test_response(buf: &[u8]) -> (u16, String, String) {
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("valid http response framing");
    let head = std::str::from_utf8(&buf[..sep]).expect("ascii head").to_owned();
    let body = std::str::from_utf8(&buf[sep + 4..]).expect("utf8 body").to_owned();
    let status_line = head.lines().next().expect("status line");
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (code, head, body)
}

fn base_config(routes: Vec<(&str, SocketAddr)>) -> ProxyConfig {
    let mut cfg = ProxyConfig {
        listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        rate_limit_rps: 0, // Disabled unless explicitly testing rate limit.
        ..ProxyConfig::default()
    };
    for (prefix, upstream) in routes {
        cfg.add_route_spec(&format!("{}={}", prefix, upstream))
            .expect("valid route");
    }
    cfg
}

#[test]
fn e2e_multi_route_stripping_streaming_and_security_headers() {
    let app = MockUpstream::start("app");
    let auth = MockUpstream::start("auth");
    let api = MockUpstream::start("api");
    let billing = MockUpstream::start("billing");

    let mut cfg = base_config(vec![
        ("/app/", app.addr),
        ("/auth/", auth.addr),
        ("/api/", api.addr),
        ("/billing/", billing.addr),
    ]);
    cfg.max_body_bytes = 256 * 1024;

    let proxy = RunningProxy::start(cfg);

    // 1. Path stripping with query string + security header enforcement + X-Forwarded-For.
    let (status, head, body) = send_raw_http(
        proxy.addr(),
        b"GET /app/feed?limit=10 HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(body.contains("tag=app|"));
    assert!(body.contains("req=GET /feed?limit=10 HTTP/1.1|"));
    assert!(body.contains("xff=127.0.0.1|"));
    assert!(body.contains("xfp=http|"));
    assert!(head.contains("X-Content-Type-Options: nosniff"));
    assert!(head.contains("X-Frame-Options: DENY"));
    assert!(head.contains("Referrer-Policy: no-referrer"));
    assert!(!head.contains("ALLOWALL"));

    // 2. Exact prefix `/auth` rewrites to `/` on the auth upstream.
    let (status_auth, _, body_auth) = send_raw_http(
        proxy.addr(),
        b"GET /auth HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_eq!(status_auth, 200);
    assert!(body_auth.contains("tag=auth|"));
    assert!(body_auth.contains("req=GET / HTTP/1.1|"));

    // 3. Large streaming body (> 64 KiB fixed buffer: 150,000 bytes) to /billing/.
    let payload: Vec<u8> = (0..150_000usize).map(|i| b'A' + (i % 26) as u8).collect();
    let expected_sum: u64 = payload.iter().fold(0u64, |acc, &b| acc.wrapping_add(u64::from(b)));
    let mut big_req = format!(
        "POST /billing/ledger HTTP/1.1\r\nHost: edge.local\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )
    .into_bytes();
    big_req.extend_from_slice(&payload);
    let (status_big, _, body_big) = send_raw_http(proxy.addr(), &big_req);
    assert_eq!(status_big, 200);
    assert!(body_big.contains("tag=billing|"));
    assert!(body_big.contains("req=POST /ledger HTTP/1.1|"));
    assert!(body_big.contains(&format!("body_len=150000|sum={}", expected_sum)));

    // 4. Chunked request body to /api/ succeeds within max_body_bytes.
    let (status_chunked, _, body_chunked) = send_raw_http(
        proxy.addr(),
        b"POST /api/send HTTP/1.1\r\nHost: edge.local\r\nTransfer-Encoding: chunked\r\n\r\n\
          5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
    );
    assert_eq!(status_chunked, 200);
    assert!(body_chunked.contains("tag=api|"));
    assert!(body_chunked.contains("body_len=11|"));

    // 5. Unknown path returns 404 Not Found.
    let (status_404, _, _) = send_raw_http(
        proxy.addr(),
        b"GET /unknown/path HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_eq!(status_404, 404);

    let stats = proxy.handle.stats();
    assert_eq!(stats.requests_ok, 4);
    assert_eq!(stats.not_found, 1);
    assert!(stats.bytes_in >= 150_000);
}

#[test]
fn counterfactual_slowloris_header_stall_returns_408() {
    let upstream = MockUpstream::start("app");
    let mut cfg = base_config(vec![("/app/", upstream.addr)]);
    cfg.header_timeout_ms = 250;
    let proxy = RunningProxy::start(cfg);

    // Control: complete request returns 200.
    let (ok_status, _, _) = send_raw_http(
        proxy.addr(),
        b"GET /app/ok HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_eq!(ok_status, 200);

    // Attack: Slowloris sends partial headers and drips slowly past the 250 ms absolute deadline.
    let start = Instant::now();
    let mut slow = TcpStream::connect(proxy.addr()).expect("connect slowloris");
    slow.set_read_timeout(Some(Duration::from_secs(3)))
        .expect("read timeout");
    slow.write_all(b"GET /app/stall HTTP/1.1\r\nHost: edge.local\r\n")
        .expect("write partial headers");
    thread::sleep(Duration::from_millis(80));
    let _ = slow.write_all(b"X-Drip: 1\r\n");

    let mut resp_buf = Vec::new();
    slow.read_to_end(&mut resp_buf).expect("read 408 response");
    let elapsed = start.elapsed();

    let (slow_status, _, _) = parse_test_response(&resp_buf);
    assert_ne!(slow_status, ok_status);
    assert_eq!(slow_status, 408);
    assert!(
        elapsed < Duration::from_millis(1500),
        "Slowloris connection hung too long: {:?}",
        elapsed
    );
    assert_eq!(upstream.hit_count(), 1, "Slowloris must never reach upstream");
}

#[test]
fn counterfactual_smuggling_and_oversized_headers_rejected() {
    let upstream = MockUpstream::start("auth");
    let mut cfg = base_config(vec![("/auth/", upstream.addr)]);
    cfg.max_header_bytes = 256;
    let proxy = RunningProxy::start(cfg);

    // Control: normal POST returns 200.
    let (ok_status, _, _) = send_raw_http(
        proxy.addr(),
        b"POST /auth/doc HTTP/1.1\r\nHost: edge.local\r\nContent-Length: 4\r\n\r\nabcd",
    );
    assert_eq!(ok_status, 200);
    assert_eq!(upstream.hit_count(), 1);

    // Attack 1: CL + TE request smuggling -> 400 Bad Request.
    let (smuggle_status, _, _) = send_raw_http(
        proxy.addr(),
        b"POST /auth/doc HTTP/1.1\r\n\
          Host: edge.local\r\n\
          Content-Length: 4\r\n\
          Transfer-Encoding: chunked\r\n\r\n\
          0\r\n\r\n",
    );
    assert_ne!(smuggle_status, ok_status);
    assert_eq!(smuggle_status, 400);

    // Attack 2: Bare LF framing -> 400 Bad Request immediately.
    let (lf_status, _, _) = send_raw_http(
        proxy.addr(),
        b"GET /auth/doc HTTP/1.1\nHost: edge.local\n\n",
    );
    assert_ne!(lf_status, ok_status);
    assert_eq!(lf_status, 400);

    // Attack 3: Oversized header block (> 256 B) -> 431 Request Header Fields Too Large.
    let pad = "a".repeat(300);
    let big_hdr = format!(
        "GET /auth/doc HTTP/1.1\r\nHost: edge.local\r\nX-Pad: {}\r\n\r\n",
        pad
    );
    let (hdr_status, _, _) = send_raw_http(proxy.addr(), big_hdr.as_bytes());
    assert_ne!(hdr_status, ok_status);
    assert_eq!(hdr_status, 431);

    assert_eq!(
        upstream.hit_count(),
        1,
        "none of the malformed/smuggled requests may reach upstream"
    );
}

#[test]
fn counterfactual_oversized_body_returns_413() {
    let upstream = MockUpstream::start("api");
    let mut cfg = base_config(vec![("/api/", upstream.addr)]);
    cfg.max_body_bytes = 1024;
    let proxy = RunningProxy::start(cfg);

    // Control: 512 B body succeeds with 200.
    let ok_body = "x".repeat(512);
    let ok_req = format!(
        "POST /api/upload HTTP/1.1\r\nHost: edge.local\r\nContent-Length: 512\r\n\r\n{}",
        ok_body
    );
    let (ok_status, _, _) = send_raw_http(proxy.addr(), ok_req.as_bytes());
    assert_eq!(ok_status, 200);
    assert_eq!(upstream.hit_count(), 1);

    // Attack 1: Content-Length > 1024 -> 413 Payload Too Large.
    let big_req = "POST /api/upload HTTP/1.1\r\nHost: edge.local\r\nContent-Length: 2048\r\n\r\n";
    let (big_status, _, _) = send_raw_http(proxy.addr(), big_req.as_bytes());
    assert_ne!(big_status, ok_status);
    assert_eq!(big_status, 413);
    assert_eq!(upstream.hit_count(), 1, "413 CL request must not hit upstream");

    // Attack 2: Chunked body exceeding 1024 B -> 413 Payload Too Large.
    let big_chunk = "z".repeat(1200);
    let chunked_req = format!(
        "POST /api/upload HTTP/1.1\r\nHost: edge.local\r\nTransfer-Encoding: chunked\r\n\r\n\
         {:x}\r\n{}\r\n0\r\n\r\n",
        big_chunk.len(),
        big_chunk
    );
    let (chunk_status, _, _) = send_raw_http(proxy.addr(), chunked_req.as_bytes());
    assert_ne!(chunk_status, ok_status);
    assert_eq!(chunk_status, 413);
}

#[test]
fn counterfactual_rate_limit_burst_returns_429_and_recovers() {
    let upstream = MockUpstream::start("billing");
    let mut cfg = base_config(vec![("/billing/", upstream.addr)]);
    cfg.rate_limit_rps = 5;
    cfg.rate_limit_burst = 3;
    let proxy = RunningProxy::start(cfg);

    let req = b"GET /billing/quote HTTP/1.1\r\nHost: edge.local\r\n\r\n";

    // First 3 requests consume the burst cleanly -> 200 OK.
    let mut ok_codes = Vec::new();
    for _ in 0..3 {
        let (code, _, _) = send_raw_http(proxy.addr(), req);
        ok_codes.push(code);
    }
    assert_eq!(ok_codes, vec![200, 200, 200]);

    // 4th immediate request exceeds burst -> 429 Too Many Requests with Retry-After.
    let (limited_status, limited_head, _) = send_raw_http(proxy.addr(), req);
    assert_ne!(limited_status, ok_codes[0]);
    assert_eq!(limited_status, 429);
    assert!(limited_head.contains("Retry-After: 1"));

    // After 250 ms at 5 rps (1 token every 200 ms), normal rate returns 200 OK again.
    thread::sleep(Duration::from_millis(260));
    let (recovered_status, _, _) = send_raw_http(proxy.addr(), req);
    assert_eq!(recovered_status, 200);
}

#[test]
fn cli_config_file_plus_override_works_end_to_end() {
    let upstream = MockUpstream::start("app");
    let tmp_path = std::env::temp_dir().join(format!(
        "zero_proxy_test_{}.conf",
        std::process::id()
    ));
    let conf_body = format!(
        "# test config\n\
         listen = 127.0.0.1:0\n\
         max_body = 500\n\
         rps = 0\n\
         route = /app/={}\n",
        upstream.addr
    );
    std::fs::write(&tmp_path, conf_body).expect("write temp config");

    let action = ProxyConfig::from_args([
        "--config",
        tmp_path.to_str().expect("utf8 path"),
        "--max-body",
        "70000",
    ])
    .expect("parse config + cli override");
    let _ = std::fs::remove_file(&tmp_path);

    let cfg = match action {
        CliAction::Run(c) => *c,
        CliAction::Help => panic!("expected Run"),
    };
    assert_eq!(cfg.max_body_bytes, 70_000);

    let proxy = RunningProxy::start(cfg);
    let (status, _, body) = send_raw_http(
        proxy.addr(),
        b"GET /app/health HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert!(body.contains("req=GET /health HTTP/1.1|"));
}

#[test]
fn per_ip_concurrent_connection_cap_counterfactual() {
    let upstream = MockUpstream::start("cap");
    let mut cfg = base_config(vec![("/cap/", upstream.addr)]);
    cfg.max_conns_per_ip = 2;
    cfg.header_timeout_ms = 5_000;
    let proxy = RunningProxy::start(cfg);
    let local_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let wait_for_ip_conns = |expected: u32| {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if proxy.handle.active_conns_for_ip(local_ip) == expected {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!(
            "timed out waiting for active_conns_for_ip == {}, got {}",
            expected,
            proxy.handle.active_conns_for_ip(local_ip)
        );
    };

    // Hold 2 concurrent live TCP sockets open against the proxy (partial HTTP headers).
    let mut s1 = TcpStream::connect(proxy.addr()).expect("connect s1");
    s1.write_all(b"GET /cap/hold1 HTTP/1.1\r\n").expect("partial s1");
    wait_for_ip_conns(1);

    let mut s2 = TcpStream::connect(proxy.addr()).expect("connect s2");
    s2.write_all(b"GET /cap/hold2 HTTP/1.1\r\n").expect("partial s2");
    wait_for_ip_conns(2);
    assert_eq!(proxy.handle.active_connections(), 2);

    // 3rd concurrent socket from same IP MUST be rejected with 429 before hitting upstream.
    let (rejected_code, rejected_head, _) = send_raw_http(
        proxy.addr(),
        b"GET /cap/third HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_eq!(rejected_code, 429);
    assert!(rejected_head.contains("Retry-After: 1"));
    assert_eq!(upstream.hit_count(), 0);
    assert_eq!(proxy.handle.active_conns_for_ip(local_ip), 2);
    assert!(proxy.handle.stats().rate_limited >= 1);

    // Dropping 1 socket immediately frees its RAII ConnGuard slot -> next request succeeds 200 OK.
    let _ = s1.shutdown(Shutdown::Both);
    drop(s1);
    wait_for_ip_conns(1);

    let (recovered_code, _, recovered_body) = send_raw_http(
        proxy.addr(),
        b"GET /cap/recovered HTTP/1.1\r\nHost: edge.local\r\n\r\n",
    );
    assert_ne!(rejected_code, recovered_code);
    assert_eq!(recovered_code, 200);
    assert!(recovered_body.contains("req=GET /recovered HTTP/1.1|"));
    assert_eq!(upstream.hit_count(), 1);

    // Closing the second held socket returns both per-IP and global counters cleanly to 0.
    let _ = s2.shutdown(Shutdown::Both);
    drop(s2);
    wait_for_ip_conns(0);
    assert_eq!(proxy.handle.active_connections(), 0);
}

#[test]
fn e2e_route_max_body_permissions_policy_and_static_cors() {
    let media = MockUpstream::start("media");
    let api = MockUpstream::start("api");
    let tmp_index = std::env::temp_dir().join(format!(
        "zero_proxy_static_index_{}.html",
        std::process::id()
    ));
    let tmp_asset = std::env::temp_dir().join(format!(
        "zero_proxy_static_asset_{}.js",
        std::process::id()
    ));
    std::fs::write(&tmp_index, b"<html>home</html>").expect("write temp static index");
    std::fs::write(&tmp_asset, b"console.log(1);").expect("write temp static asset");

    let mut cfg = base_config(vec![("/media/", media.addr), ("/api/", api.addr)]);
    cfg.max_body_bytes = 200_000;
    cfg.static_cors_prefix = Some("/static".to_owned());
    cfg.add_static_spec(&format!("/={}", tmp_index.display()))
        .expect("static /");
    cfg.add_static_spec(&format!("/static/app.js={}", tmp_asset.display()))
        .expect("static /static/app.js");
    cfg.add_route_max_body_spec("/media/=70000")
        .expect("route_max_body /media/");
    cfg.add_route_permissions_policy_spec(
        "/media/=geolocation=(), microphone=(self), camera=(self), payment=()",
    )
    .expect("route_permissions_policy /media/");

    let proxy = RunningProxy::start(cfg);

    // 1. Permissions-Policy override on /media/ vs locked-down policy on / and /api/.
    let (st_media, head_media, _) = send_raw_http(
        proxy.addr(),
        b"GET /media/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_media, 200);
    assert!(head_media.contains(
        "Permissions-Policy: geolocation=(), microphone=(self), camera=(self), payment=()"
    ));

    let (st_home, head_home, _) = send_raw_http(
        proxy.addr(),
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_home, 200);
    assert!(head_home.contains("Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()"));
    assert!(!head_home.contains("Access-Control-Allow-Origin: *"));

    let (st_asset, head_asset, _) = send_raw_http(
        proxy.addr(),
        b"GET /static/app.js HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_asset, 200);
    assert!(head_asset.contains("Access-Control-Allow-Origin: *"));

    let (st_api, head_api, _) = send_raw_http(
        proxy.addr(),
        b"GET /api/items HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_api, 200);
    assert!(head_api.contains("Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()"));

    // 2. Per-route max_body overrides global max_body cleanly (70000 on /media/ vs 200000 on /api/).
    let media_over =
        b"POST /media/api/v1/clips HTTP/1.1\r\nHost: example.com\r\nContent-Length: 70001\r\n\r\n";
    let (st_media_over, _, _) = send_raw_http(proxy.addr(), media_over);
    assert_eq!(st_media_over, 413);
    assert_eq!(media.hit_count(), 1, "oversized /media/ POST must not reach upstream");

    let api_big_body = vec![b'M'; 80_000];
    let mut api_big_req = format!(
        "POST /api/upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: {}\r\n\r\n",
        api_big_body.len()
    )
    .into_bytes();
    api_big_req.extend_from_slice(&api_big_body);
    let (st_api_big, _, body_api_big) = send_raw_http(proxy.addr(), &api_big_req);
    assert_eq!(st_api_big, 200);
    assert!(body_api_big.contains("body_len=80000|"));

    let _ = std::fs::remove_file(&tmp_index);
    let _ = std::fs::remove_file(&tmp_asset);
}
