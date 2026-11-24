#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use zero_proxy::acme::{base64_encode, hex_encode, parse_json, sha256, JsonValue};
use zero_proxy::tls::{cert_spki_sha256_b64, reset_signal_flags};
use zero_proxy::{
    CliAction, ProxyConfig, ProxyHandle, ProxyServer, TlsClientStream, TlsMinVersion,
};

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zero_proxy_{}_{}_{}_{}",
            label,
            std::process::id(),
            nanos,
            seq
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct MockUpstream {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockUpstream {
    fn start(tag: &'static str, delay_ms: u64, on_accept: Option<Arc<AtomicBool>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock upstream");
        let addr = listener.local_addr().expect("mock addr");
        let stop = Arc::new(AtomicBool::new(false));
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
                if let Some(flag) = &on_accept {
                    flag.store(true, Ordering::Release);
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                handle_mock_upstream(&mut stream, tag, delay_ms);
            }
        });

        Self {
            addr,
            stop,
            join: Some(join),
        }
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

fn handle_mock_upstream(stream: &mut TcpStream, tag: &str, delay_ms: u64) {
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

    if delay_ms > 0 {
        thread::sleep(Duration::from_millis(delay_ms));
    }

    let head = String::from_utf8_lossy(&raw[..header_end - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let req_line = lines.next().unwrap_or("").to_owned();
    let mut xfp = String::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("x-forwarded-proto") {
                xfp = v.trim().to_owned();
            }
        }
    }

    let body = format!("tag={}|req={}|xfp={}\n", tag, req_line, xfp);
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nX-Frame-Options: ALLOWALL\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.shutdown(Shutdown::Both);
}

struct RunningProxy {
    handle: ProxyHandle,
    join: Option<thread::JoinHandle<()>>,
}

impl RunningProxy {
    fn start(cfg: ProxyConfig, enable_signals: bool) -> Self {
        let server = ProxyServer::bind(cfg).expect("bind proxy");
        if enable_signals {
            server.enable_signal_handling();
        }
        let handle = server.handle();
        let join = thread::spawn(move || {
            server.run().expect("proxy run");
        });
        Self {
            handle,
            join: Some(join),
        }
    }

    fn stop_and_join(&mut self) {
        self.handle.stop();
        if let Some(j) = self.join.take() {
            j.join().expect("proxy thread join");
        }
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

fn generate_self_signed_cert(dir: &Path, name: &str, cn: &str, serial: &str) -> (PathBuf, PathBuf) {
    let cert_path = dir.join(format!("{}.crt", name));
    let key_path = dir.join(format!("{}.key", name));
    let san = format!("subjectAltName=DNS:{}", cn);
    let subj = format!("/CN={}", cn);
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            key_path.to_str().expect("key path"),
            "-out",
            cert_path.to_str().expect("cert path"),
            "-days",
            "30",
            "-set_serial",
            serial,
            "-subj",
            &subj,
            "-addext",
            &san,
        ])
        .output()
        .expect("spawn openssl req");
    assert!(
        status.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    (cert_path, key_path)
}

fn generate_ca_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let ca_cert = dir.join("ca.pem");
    let ca_key = dir.join("ca.key");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            ca_key.to_str().expect("ca key path"),
            "-out",
            ca_cert.to_str().expect("ca cert path"),
            "-days",
            "365",
            "-subj",
            "/CN=ZeroProxy Test Root CA",
        ])
        .output()
        .expect("spawn openssl ca req");
    assert!(
        status.status.success(),
        "openssl ca req failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    (ca_cert, ca_key)
}

fn parse_http_response(raw: &[u8]) -> (u16, String, String) {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("missing CRLFCRLF in HTTP response");
    let head = String::from_utf8_lossy(&raw[..sep]).into_owned();
    let body = String::from_utf8_lossy(&raw[sep + 4..]).into_owned();
    let first_line = head.lines().next().expect("status line");
    let status: u16 = first_line
        .split_whitespace()
        .nth(1)
        .expect("status code")
        .parse()
        .expect("numeric status");
    (status, head, body)
}

fn send_plain_http(addr: SocketAddr, req: &[u8]) -> (u16, String, String) {
    let mut s = TcpStream::connect(addr).expect("connect plain");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    s.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    s.write_all(req).expect("write plain req");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    parse_http_response(&buf)
}

fn send_tls_http(
    addr: SocketAddr,
    sni: &str,
    ca_cert: Option<&Path>,
    req: &[u8],
) -> (u16, String, String, Option<String>, Option<String>, Option<String>) {
    let tcp = TcpStream::connect(addr).expect("connect tls tcp");
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("tls read timeout");
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("tls write timeout");
    let mut tls = TlsClientStream::connect(tcp, sni, ca_cert.is_some(), ca_cert)
        .expect("tls client handshake");
    let proto = tls.protocol_version();
    let cn = tls.peer_cert_cn();
    let serial = tls.peer_cert_serial_hex();
    tls.write_all(req).expect("write tls req");
    let mut buf = Vec::new();
    let _ = tls.read_to_end(&mut buf);
    let (status, head, body) = parse_http_response(&buf);
    (status, head, body, proto, cn, serial)
}

fn base64url_decode(input: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4 + 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in input.bytes() {
        let val = match b {
            b'A'..=b'Z' => (b - b'A') as u32,
            b'a'..=b'z' => (b - b'a' + 26) as u32,
            b'0'..=b'9' => (b - b'0' + 52) as u32,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => panic!("invalid base64url byte"),
        };
        acc = (acc << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    out
}

#[test]
fn e2e_tls13_proxy_static_redirect_and_http80_upgrade() {
    let tmp = TempDir::new("tls13");
    let (cert_path, key_path) = generate_self_signed_cert(tmp.path(), "edge", "edge.test", "1001");

    let index_path = tmp.path().join("index.html");
    let js_path = tmp.path().join("app.js");
    fs::write(&index_path, b"<!doctype html><h1>zero-proxy</h1>").expect("write index.html");
    fs::write(&js_path, b"export const ok = true;\n").expect("write app.js");

    let upstream = MockUpstream::start("api", 0, None);

    let mut cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("listen"),
        http_listen: Some("127.0.0.1:0".parse().expect("http listen")),
        tls_cert: Some(cert_path.clone()),
        tls_key: Some(key_path),
        ..ProxyConfig::default()
    };
    cfg.add_route_spec(&format!("/api/={}", upstream.addr))
        .expect("route");
    cfg.add_static_spec(&format!("/={}", index_path.display()))
        .expect("static /");
    cfg.add_static_spec(&format!("/app.js={}", js_path.display()))
        .expect("static js");
    cfg.add_redirect_spec("www.edge.test -> https://edge.test")
        .expect("redirect");

    let proxy = RunningProxy::start(cfg, false);
    let tls_addr = proxy.handle.local_addr();
    let http_addr = proxy
        .handle
        .http_local_addr()
        .expect("http_listen bound");

    // 1. Live TLS 1.3 proxied HTTPS request with strict certificate verification.
    let (status, head, body, proto, cn, _) = send_tls_http(
        tls_addr,
        "edge.test",
        Some(&cert_path),
        b"GET /api/hello?x=1 HTTP/1.1\r\nHost: edge.test\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(proto.as_deref(), Some("TLSv1.3"));
    assert_eq!(cn.as_deref(), Some("edge.test"));
    assert!(body.contains("tag=api|req=GET /hello?x=1 HTTP/1.1|xfp=https"));
    assert!(head.contains("X-Frame-Options: DENY"));
    assert!(head.contains("X-Content-Type-Options: nosniff"));
    assert!(head.contains("Referrer-Policy: no-referrer"));

    // 2. Static file serving (HTML + JS + HEAD).
    let (status_html, head_html, body_html, _, _, _) = send_tls_http(
        tls_addr,
        "edge.test",
        Some(&cert_path),
        b"GET / HTTP/1.1\r\nHost: edge.test\r\n\r\n",
    );
    assert_eq!(status_html, 200);
    assert!(head_html.contains("Content-Type: text/html; charset=utf-8"));
    assert_eq!(body_html, "<!doctype html><h1>zero-proxy</h1>");

    let (status_js, head_js, body_js, _, _, _) = send_tls_http(
        tls_addr,
        "edge.test",
        Some(&cert_path),
        b"GET /app.js HTTP/1.1\r\nHost: edge.test\r\n\r\n",
    );
    assert_eq!(status_js, 200);
    assert!(head_js.contains("Content-Type: application/javascript; charset=utf-8"));
    assert_eq!(body_js, "export const ok = true;\n");

    let (status_head, head_only, body_only, _, _, _) = send_tls_http(
        tls_addr,
        "edge.test",
        Some(&cert_path),
        b"HEAD / HTTP/1.1\r\nHost: edge.test\r\n\r\n",
    );
    assert_eq!(status_head, 200);
    assert!(head_only.contains("Content-Length: 34"));
    assert!(body_only.is_empty());

    // 3. Per-host 301 redirect over TLS.
    let (status_redir, head_redir, _, _, _, _) = send_tls_http(
        tls_addr,
        "edge.test",
        Some(&cert_path),
        b"GET /docs?q=1 HTTP/1.1\r\nHost: www.edge.test\r\n\r\n",
    );
    assert_eq!(status_redir, 301);
    assert!(head_redir.contains("Location: https://edge.test/docs?q=1"));

    // 4. Plain HTTP :80 listener 301 -> https:// upgrade.
    let (status_80, head_80, _) = send_plain_http(
        http_addr,
        b"GET /pricing?plan=pro HTTP/1.1\r\nHost: edge.test:80\r\n\r\n",
    );
    assert_eq!(status_80, 301);
    assert!(head_80.contains("Location: https://edge.test/pricing?plan=pro"));
}

#[test]
fn e2e_tls_zero_downtime_hot_swap_cert_reload() {
    let tmp = TempDir::new("hotswap");
    let cert_dir = tmp.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");

    let (cert_a, key_a) = generate_self_signed_cert(tmp.path(), "a", "alpha.test", "0x111111");
    let (cert_b, key_b) = generate_self_signed_cert(tmp.path(), "b", "beta.test", "0x222222");

    let live_cert = cert_dir.join("fullchain.pem");
    let live_key = cert_dir.join("privkey.pem");
    fs::copy(&cert_a, &live_cert).expect("install cert A");
    fs::copy(&key_a, &live_key).expect("install key A");

    let upstream = MockUpstream::start("swap", 0, None);
    let mut cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("listen"),
        cert_dir: Some(cert_dir),
        ..ProxyConfig::default()
    };
    cfg.add_route_spec(&format!("/app/={}", upstream.addr))
        .expect("route");

    let proxy = RunningProxy::start(cfg, false);
    let addr = proxy.handle.local_addr();

    // Open TLS connection #1 BEFORE the hot-swap and keep it open across the swap.
    let tcp1 = TcpStream::connect(addr).expect("connect conn1");
    tcp1.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    tcp1.set_write_timeout(Some(Duration::from_secs(5)))
        .expect("write timeout");
    let mut tls1 =
        TlsClientStream::connect(tcp1, "alpha.test", true, Some(&cert_a)).expect("handshake A");
    assert_eq!(tls1.protocol_version().as_deref(), Some("TLSv1.3"));
    assert_eq!(tls1.peer_cert_cn().as_deref(), Some("alpha.test"));
    assert!(tls1
        .peer_cert_serial_hex()
        .unwrap_or_default()
        .contains("111111"));

    // Swap cert files on disk to Cert B and hot-reload atomically.
    fs::copy(&cert_b, &live_cert).expect("swap cert B");
    fs::copy(&key_b, &live_key).expect("swap key B");
    proxy.handle.reload().expect("zero-downtime reload");
    assert_eq!(proxy.handle.reload_count(), 1);

    // Pre-existing TLS connection #1 still completes cleanly with 0 dropped connections.
    tls1.write_all(b"GET /app/inflight HTTP/1.1\r\nHost: alpha.test\r\n\r\n")
        .expect("write conn1");
    let mut buf1 = Vec::new();
    let _ = tls1.read_to_end(&mut buf1);
    let (status1, _, body1) = parse_http_response(&buf1);
    assert_eq!(status1, 200);
    assert!(body1.contains("tag=swap|req=GET /inflight HTTP/1.1|xfp=https"));

    // New TLS connection #2 immediately presents Cert B with TLS 1.3.
    let (status2, _, body2, proto2, cn2, serial2) = send_tls_http(
        addr,
        "beta.test",
        Some(&cert_b),
        b"GET /app/after HTTP/1.1\r\nHost: beta.test\r\n\r\n",
    );
    assert_eq!(status2, 200);
    assert_eq!(proto2.as_deref(), Some("TLSv1.3"));
    assert_eq!(cn2.as_deref(), Some("beta.test"));
    assert!(serial2.unwrap_or_default().contains("222222"));
    assert!(body2.contains("tag=swap|req=GET /after HTTP/1.1|xfp=https"));
}

#[test]
fn e2e_tls_sni_multi_host_selection_and_mismatch_rejection() {
    let tmp = TempDir::new("sni");
    let cert_dir = tmp.path().join("certs");
    let alpha_dir = cert_dir.join("alpha.test");
    let beta_dir = cert_dir.join("beta.test");
    fs::create_dir_all(&alpha_dir).expect("create alpha dir");
    fs::create_dir_all(&beta_dir).expect("create beta dir");

    let (cert_a, key_a) = generate_self_signed_cert(tmp.path(), "sni_a", "alpha.test", "0x333333");
    let (cert_b, key_b) = generate_self_signed_cert(tmp.path(), "sni_b", "beta.test", "0x444444");
    fs::copy(&cert_a, alpha_dir.join("fullchain.pem")).expect("copy alpha cert");
    fs::copy(&key_a, alpha_dir.join("privkey.pem")).expect("copy alpha key");
    fs::copy(&cert_b, beta_dir.join("fullchain.pem")).expect("copy beta cert");
    fs::copy(&key_b, beta_dir.join("privkey.pem")).expect("copy beta key");

    let upstream = MockUpstream::start("sni", 0, None);
    let mut cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("listen"),
        cert_dir: Some(cert_dir),
        ..ProxyConfig::default()
    };
    cfg.add_route_spec(&format!("/app/={}", upstream.addr))
        .expect("route");

    let proxy = RunningProxy::start(cfg, false);
    let addr = proxy.handle.local_addr();

    let (sa, _, ba, proto_a, cn_a, ser_a) = send_tls_http(
        addr,
        "alpha.test",
        Some(&cert_a),
        b"GET /app/a HTTP/1.1\r\nHost: alpha.test\r\n\r\n",
    );
    assert_eq!(sa, 200);
    assert_eq!(proto_a.as_deref(), Some("TLSv1.3"));
    assert_eq!(cn_a.as_deref(), Some("alpha.test"));
    assert!(ser_a.unwrap_or_default().contains("333333"));
    assert!(ba.contains("tag=sni|req=GET /a HTTP/1.1|xfp=https"));

    let (sb, _, bb, proto_b, cn_b, ser_b) = send_tls_http(
        addr,
        "beta.test",
        Some(&cert_b),
        b"GET /app/b HTTP/1.1\r\nHost: beta.test\r\n\r\n",
    );
    assert_eq!(sb, 200);
    assert_eq!(proto_b.as_deref(), Some("TLSv1.3"));
    assert_eq!(cn_b.as_deref(), Some("beta.test"));
    assert!(ser_b.unwrap_or_default().contains("444444"));
    assert!(bb.contains("tag=sni|req=GET /b HTTP/1.1|xfp=https"));

    // Counterfactual: strict hostname verification fails closed when SNI does not match cert.
    let tcp = TcpStream::connect(addr).expect("connect mismatch");
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(3)));
    let mismatch = TlsClientStream::connect(tcp, "wrong.test", true, Some(&cert_a));
    assert!(mismatch.is_err(), "expected strict hostname verification failure");
}

#[test]
fn e2e_live_acme_v2_http01_issuance_and_tls13_serve() {
    let tmp = TempDir::new("acme");
    let cert_dir = tmp.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert_dir");
    let (ca_cert, ca_key) = generate_ca_cert(tmp.path());

    let upstream = MockUpstream::start("acme-app", 0, None);

    // Bind mock ACME v2 server first so its address is known for ProxyConfig.
    let acme_listener = TcpListener::bind("127.0.0.1:0").expect("bind mock acme");
    let acme_addr = acme_listener.local_addr().expect("acme addr");

    let mut cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("listen"),
        http_listen: Some("127.0.0.1:0".parse().expect("http_listen")),
        cert_dir: Some(cert_dir.clone()),
        acme_email: Some("ops@acme.test".to_owned()),
        acme_directory: format!("http://{}/directory", acme_addr),
        acme_check_interval_secs: 3600,
        ..ProxyConfig::default()
    };
    cfg.add_acme_domain("acme.test").expect("acme domain");
    cfg.add_route_spec(&format!("/ping/={}", upstream.addr))
        .expect("route");

    // Bind proxy before starting mock ACME so proxy's live HTTP :80 port is known.
    let server = ProxyServer::bind(cfg).expect("bind acme proxy");
    let tls_addr = server.local_addr();
    let http_addr = server.http_local_addr().expect("http_listen addr");
    let handle = server.handle();

    let acme_stop = Arc::new(AtomicBool::new(false));
    let acme_stop_c = Arc::clone(&acme_stop);
    let challenge_verified = Arc::new(AtomicUsize::new(0));
    let challenge_verified_c = Arc::clone(&challenge_verified);
    let bad_nonce_triggered = Arc::new(AtomicBool::new(false));
    let bad_nonce_c = Arc::clone(&bad_nonce_triggered);
    let work_dir = tmp.path().to_path_buf();
    let ca_cert_c = ca_cert.clone();
    let ca_key_c = ca_key.clone();

    let token = "AbCdEf0123456789_-AcmeHttp01LiveToken";
    let token_owned = token.to_owned();

    let acme_thread = thread::spawn(move || {
        let authz_valid = Arc::new(AtomicBool::new(false));
        let issued_pem: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let nonce_seq = AtomicU64::new(1);

        for incoming in acme_listener.incoming() {
            if acme_stop_c.load(Ordering::Acquire) {
                break;
            }
            let mut stream = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            if acme_stop_c.load(Ordering::Acquire) {
                break;
            }
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

            let Some((method, path, body)) = read_http_request(&mut stream) else {
                continue;
            };
            let next_nonce = format!("nonce-{}", nonce_seq.fetch_add(1, Ordering::Relaxed));
            let base = format!("http://{}", acme_addr);

            match (method.as_str(), path.as_str()) {
                ("GET", "/directory") => {
                    let json = format!(
                        "{{\"newNonce\":\"{b}/new-nonce\",\"newAccount\":\"{b}/new-acct\",\"newOrder\":\"{b}/new-order\"}}",
                        b = base
                    );
                    write_mock_acme_resp(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        &next_nonce,
                        None,
                        json.as_bytes(),
                    );
                }
                ("HEAD", "/new-nonce") => {
                    write_mock_acme_resp(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        &next_nonce,
                        None,
                        b"",
                    );
                }
                ("POST", "/new-acct") => {
                    let loc = format!("{}/acct/1", base);
                    write_mock_acme_resp(
                        &mut stream,
                        "201 Created",
                        "application/json",
                        &next_nonce,
                        Some(&loc),
                        b"{\"status\":\"valid\"}",
                    );
                }
                ("POST", "/new-order") => {
                    // Trigger one RFC 8555 badNonce error to exercise live retry logic.
                    if !bad_nonce_c.swap(true, Ordering::AcqRel) {
                        write_mock_acme_resp(
                            &mut stream,
                            "400 Bad Request",
                            "application/problem+json",
                            &next_nonce,
                            None,
                            b"{\"type\":\"urn:ietf:params:acme:error:badNonce\"}",
                        );
                    } else {
                        let loc = format!("{}/order/1", base);
                        let json = format!(
                            "{{\"status\":\"pending\",\"authorizations\":[\"{b}/authz/1\"],\"finalize\":\"{b}/finalize/1\"}}",
                            b = base
                        );
                        write_mock_acme_resp(
                            &mut stream,
                            "201 Created",
                            "application/json",
                            &next_nonce,
                            Some(&loc),
                            json.as_bytes(),
                        );
                    }
                }
                ("POST", "/authz/1") => {
                    let st = if authz_valid.load(Ordering::Acquire) {
                        "valid"
                    } else {
                        "pending"
                    };
                    let json = format!(
                        "{{\"status\":\"{}\",\"challenges\":[{{\"type\":\"http-01\",\"token\":\"{}\",\"url\":\"{}/chal/1\"}}]}}",
                        st, token_owned, base
                    );
                    write_mock_acme_resp(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        &next_nonce,
                        None,
                        json.as_bytes(),
                    );
                }
                ("POST", "/chal/1") => {
                    // Mock CA performs real HTTP-01 GET against zero-proxy's live HTTP :80 listener!
                    let req = format!(
                        "GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: acme.test\r\n\r\n",
                        token_owned
                    );
                    let (ch_status, ch_head, ch_body) =
                        send_plain_http(http_addr, req.as_bytes());
                    assert_eq!(ch_status, 200, "HTTP-01 challenge response status");
                    assert!(
                        ch_head.contains("Content-Type: application/octet-stream"),
                        "HTTP-01 content-type"
                    );
                    assert!(
                        ch_body.starts_with(&format!("{}.", token_owned)),
                        "HTTP-01 keyAuthorization prefix mismatch: {}",
                        ch_body
                    );
                    assert!(ch_body.len() > token_owned.len() + 20);
                    challenge_verified_c.fetch_add(1, Ordering::AcqRel);
                    authz_valid.store(true, Ordering::Release);
                    write_mock_acme_resp(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        &next_nonce,
                        None,
                        b"{\"status\":\"valid\"}",
                    );
                }
                ("POST", "/finalize/1") => {
                    let body_str = std::str::from_utf8(&body).expect("jws utf8");
                    let jws = parse_json(body_str).expect("parse jws json");
                    let payload_b64 = jws.get_str("payload").expect("jws payload");
                    let payload_bytes = base64url_decode(payload_b64);
                    let payload_json =
                        parse_json(std::str::from_utf8(&payload_bytes).expect("payload utf8"))
                            .expect("parse finalize payload");
                    let csr_b64 = payload_json.get_str("csr").expect("csr field");
                    let csr_der = base64url_decode(csr_b64);

                    let csr_path = work_dir.join("req.csr.der");
                    let leaf_path = work_dir.join("issued_leaf.pem");
                    fs::write(&csr_path, &csr_der).expect("write csr der");

                    let out = Command::new("openssl")
                        .args([
                            "x509",
                            "-req",
                            "-inform",
                            "DER",
                            "-in",
                            csr_path.to_str().expect("csr path"),
                            "-CA",
                            ca_cert_c.to_str().expect("ca cert"),
                            "-CAkey",
                            ca_key_c.to_str().expect("ca key"),
                            "-CAcreateserial",
                            "-days",
                            "90",
                            "-copy_extensions",
                            "copy",
                            "-out",
                            leaf_path.to_str().expect("leaf path"),
                        ])
                        .output()
                        .expect("spawn openssl x509 -req");
                    assert!(
                        out.status.success(),
                        "openssl x509 sign failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );

                    let mut chain = fs::read(&leaf_path).expect("read issued leaf");
                    chain.extend_from_slice(&fs::read(&ca_cert_c).expect("read ca pem"));
                    *issued_pem.lock().expect("lock issued_pem") = Some(chain);

                    let json = format!(
                        "{{\"status\":\"valid\",\"certificate\":\"{}/cert/1\"}}",
                        base
                    );
                    write_mock_acme_resp(
                        &mut stream,
                        "200 OK",
                        "application/json",
                        &next_nonce,
                        None,
                        json.as_bytes(),
                    );
                }
                ("POST", "/cert/1") => {
                    let pem = issued_pem
                        .lock()
                        .expect("lock issued_pem")
                        .clone()
                        .expect("issued cert must exist");
                    write_mock_acme_resp(
                        &mut stream,
                        "200 OK",
                        "application/pem-certificate-chain",
                        &next_nonce,
                        None,
                        &pem,
                    );
                }
                _ => {
                    write_mock_acme_resp(
                        &mut stream,
                        "404 Not Found",
                        "text/plain",
                        &next_nonce,
                        None,
                        b"not found",
                    );
                }
            }
        }
    });

    // Start the proxy (its background ACME thread immediately issues the missing cert).
    let proxy_join = thread::spawn(move || {
        server.run().expect("acme proxy run");
    });

    let tls_store = handle.tls_store().expect("tls_store present");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !tls_store.has_certs() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        tls_store.has_certs(),
        "ACME background renewal did not install certificate in time"
    );
    assert_eq!(challenge_verified.load(Ordering::Acquire), 1);
    assert!(bad_nonce_triggered.load(Ordering::Acquire));

    // Verify atomic 0600 key persistence on disk.
    let acct_key = cert_dir.join("account.key");
    let host_key = cert_dir.join("acme.test").join("privkey.pem");
    let host_cert = cert_dir.join("acme.test").join("fullchain.pem");
    assert!(acct_key.is_file());
    assert!(host_key.is_file());
    assert!(host_cert.is_file());
    assert_eq!(
        fs::metadata(&acct_key).expect("acct meta").permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&host_key).expect("key meta").permissions().mode() & 0o777,
        0o600
    );

    // Verify RAII cleaned up the HTTP-01 challenge token after issuance.
    let (post_ch_status, _, _) = send_plain_http(
        http_addr,
        format!(
            "GET /.well-known/acme-challenge/{} HTTP/1.1\r\nHost: acme.test\r\n\r\n",
            token
        )
        .as_bytes(),
    );
    assert_eq!(post_ch_status, 404);

    // Connect via live TLS 1.3 verifying the issued certificate against our test Root CA!
    let (status, _, body, proto, cn, _) = send_tls_http(
        tls_addr,
        "acme.test",
        Some(&ca_cert),
        b"GET /ping/ok HTTP/1.1\r\nHost: acme.test\r\n\r\n",
    );
    assert_eq!(status, 200);
    assert_eq!(proto.as_deref(), Some("TLSv1.3"));
    assert_eq!(cn.as_deref(), Some("acme.test"));
    assert!(body.contains("tag=acme-app|req=GET /ok HTTP/1.1|xfp=https"));

    handle.stop();
    proxy_join.join().expect("proxy join");
    acme_stop.store(true, Ordering::Release);
    let _ = TcpStream::connect_timeout(&acme_addr, Duration::from_millis(50));
    acme_thread.join().expect("acme thread join");
}

#[test]
fn e2e_os_sighup_hot_reload_and_sigterm_graceful_drain() {
    reset_signal_flags();
    let tmp = TempDir::new("signals");
    let cfg_path = tmp.path().join("zero_proxy.conf");

    let up_v1 = MockUpstream::start("v1", 0, None);
    let up_v2 = MockUpstream::start("v2", 0, None);
    let slow_started = Arc::new(AtomicBool::new(false));
    let up_slow = MockUpstream::start("slow", 200, Some(Arc::clone(&slow_started)));

    let initial_conf = format!(
        "listen = 127.0.0.1:0\ndrain_timeout_ms = 5000\nroute = /v1/={}\n",
        up_v1.addr
    );
    fs::write(&cfg_path, &initial_conf).expect("write initial conf");

    let action = ProxyConfig::from_args([
        "--config",
        cfg_path.to_str().expect("cfg path utf8"),
    ])
    .expect("parse conf");
    let cfg = match action {
        CliAction::Run(c) => *c,
        CliAction::Help => panic!("expected Run"),
    };

    let mut proxy = RunningProxy::start(cfg, true);
    let addr = proxy.handle.local_addr();

    // Before SIGHUP: /v1/ -> 200, /v2/ -> 404.
    let (s1, _, b1) = send_plain_http(addr, b"GET /v1/check HTTP/1.1\r\nHost: reload.test\r\n\r\n");
    assert_eq!(s1, 200);
    assert!(b1.contains("tag=v1|req=GET /check HTTP/1.1|xfp=http"));

    let (s2, _, _) = send_plain_http(addr, b"GET /v2/check HTTP/1.1\r\nHost: reload.test\r\n\r\n");
    assert_eq!(s2, 404);

    // Update config file with /v2/ and /slow/ routes, then send real OS SIGHUP.
    let updated_conf = format!(
        "listen = 127.0.0.1:0\ndrain_timeout_ms = 5000\nroute = /v1/={}\nroute = /v2/={}\nroute = /slow/={}\n",
        up_v1.addr, up_v2.addr, up_slow.addr
    );
    fs::write(&cfg_path, &updated_conf).expect("write updated conf");

    let pid = std::process::id().to_string();
    let hup_out = Command::new("kill")
        .args(["-HUP", &pid])
        .output()
        .expect("send SIGHUP");
    assert!(hup_out.status.success(), "kill -HUP failed");

    let deadline = Instant::now() + Duration::from_secs(3);
    while proxy.handle.reload_count() < 1 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(15));
    }
    assert!(
        proxy.handle.reload_count() >= 1,
        "SIGHUP did not trigger hot reload"
    );

    // After SIGHUP: /v2/ immediately returns 200 OK without restarting!
    let (s2_after, _, b2_after) =
        send_plain_http(addr, b"GET /v2/check HTTP/1.1\r\nHost: reload.test\r\n\r\n");
    assert_eq!(s2_after, 200);
    assert!(b2_after.contains("tag=v2|req=GET /check HTTP/1.1|xfp=http"));

    // Start an in-flight slow request, then send real OS SIGTERM to verify graceful drain.
    let slow_client = thread::spawn(move || {
        send_plain_http(addr, b"GET /slow/work HTTP/1.1\r\nHost: reload.test\r\n\r\n")
    });

    let start_wait = Instant::now() + Duration::from_secs(2);
    while !slow_started.load(Ordering::Acquire) && Instant::now() < start_wait {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        slow_started.load(Ordering::Acquire),
        "slow upstream never accepted in-flight request"
    );

    let term_out = Command::new("kill")
        .args(["-TERM", &pid])
        .output()
        .expect("send SIGTERM");
    assert!(term_out.status.success(), "kill -TERM failed");

    // In-flight request MUST finish 200 OK before the server exits!
    let (slow_status, _, slow_body) = slow_client.join().expect("slow client join");
    assert_eq!(slow_status, 200);
    assert!(slow_body.contains("tag=slow|req=GET /work HTTP/1.1|xfp=http"));

    // Proxy thread should exit cleanly after draining.
    if let Some(j) = proxy.join.take() {
        j.join().expect("proxy clean exit after SIGTERM drain");
    } else {
        proxy.stop_and_join();
    }
    reset_signal_flags();
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut raw = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = match stream.read(&mut tmp) {
            Ok(0) | Err(_) => return None,
            Ok(n) => n,
        };
        raw.extend_from_slice(&tmp[..n]);
        if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if raw.len() > 131_072 {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&raw[..header_end - 4]).into_owned();
    let mut lines = head.split("\r\n");
    let first = lines.next()?;
    let mut parts = first.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let mut content_len = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut body = raw[header_end..].to_vec();
    while body.len() < content_len {
        let n = match stream.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_len);
    Some((method, path, body))
}

fn write_mock_acme_resp(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    nonce: &str,
    location: Option<&str>,
    body: &[u8],
) {
    let mut resp = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nReplay-Nonce: {}\r\nConnection: close\r\n",
        status,
        content_type,
        body.len(),
        nonce
    );
    if let Some(loc) = location {
        resp.push_str(&format!("Location: {}\r\n", loc));
    }
    resp.push_str("\r\n");
    let _ = stream.write_all(resp.as_bytes());
    if !body.is_empty() {
        let _ = stream.write_all(body);
    }
    let _ = stream.shutdown(Shutdown::Both);
}

fn openssl_cli_spki_sha256_b64(cert_path: &Path) -> String {
    let pubkey_out = Command::new("openssl")
        .args([
            "x509",
            "-in",
            cert_path.to_str().expect("cert path utf8"),
            "-pubkey",
            "-noout",
        ])
        .output()
        .expect("openssl x509 -pubkey");
    assert!(
        pubkey_out.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&pubkey_out.stderr)
    );

    let mut pkey_child = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "der"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl pkey");
    pkey_child
        .stdin
        .take()
        .expect("pkey stdin")
        .write_all(&pubkey_out.stdout)
        .expect("write pubkey pem");
    let der_out = pkey_child.wait_with_output().expect("wait openssl pkey");
    assert!(
        der_out.status.success(),
        "openssl pkey failed: {}",
        String::from_utf8_lossy(&der_out.stderr)
    );

    let mut dgst_child = Command::new("openssl")
        .args(["dgst", "-sha256", "-binary"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl dgst");
    dgst_child
        .stdin
        .take()
        .expect("dgst stdin")
        .write_all(&der_out.stdout)
        .expect("write pubkey der");
    let dgst_out = dgst_child.wait_with_output().expect("wait openssl dgst");
    assert!(
        dgst_out.status.success(),
        "openssl dgst failed: {}",
        String::from_utf8_lossy(&dgst_out.stderr)
    );

    let mut b64_child = Command::new("openssl")
        .args(["base64", "-A"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn openssl base64");
    b64_child
        .stdin
        .take()
        .expect("base64 stdin")
        .write_all(&dgst_out.stdout)
        .expect("write sha256 binary");
    let b64_out = b64_child.wait_with_output().expect("wait openssl base64");
    assert!(
        b64_out.status.success(),
        "openssl base64 failed: {}",
        String::from_utf8_lossy(&b64_out.stderr)
    );
    String::from_utf8(b64_out.stdout)
        .expect("base64 utf8")
        .trim()
        .to_owned()
}

struct MitmEchoUpstream {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl MitmEchoUpstream {
    fn start(tag: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mitm upstream");
        let addr = listener.local_addr().expect("mitm upstream addr");
        let stop = Arc::new(AtomicBool::new(false));
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
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
                let mut raw = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end;
                loop {
                    let n = match stream.read(&mut tmp) {
                        Ok(0) | Err(_) => {
                            header_end = 0;
                            break;
                        }
                        Ok(n) => n,
                    };
                    raw.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = pos + 4;
                        break;
                    }
                    if raw.len() > 65_536 {
                        header_end = 0;
                        break;
                    }
                }
                if header_end == 0 {
                    continue;
                }
                let head = String::from_utf8_lossy(&raw[..header_end - 4]).into_owned();
                let mut lines = head.split("\r\n");
                let req_line = lines.next().unwrap_or("").to_owned();
                let mut xfp = String::new();
                let mut xri_vals = Vec::new();
                for line in lines {
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("x-forwarded-proto") {
                            xfp = v.trim().to_owned();
                        } else if k.trim().eq_ignore_ascii_case("x-real-ip") {
                            xri_vals.push(v.trim().to_owned());
                        }
                    }
                }
                let body = format!(
                    "tag={}|req={}|xfp={}|xri_count={}|xri={}\n",
                    tag,
                    req_line,
                    xfp,
                    xri_vals.len(),
                    xri_vals.join(",")
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain\r\n\
                     Content-Length: {}\r\n\
                     Server: SecretBackend/9.9\r\n\
                     Strict-Transport-Security: max-age=1\r\n\
                     Permissions-Policy: camera=*\r\n\
                     X-Frame-Options: ALLOWALL\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.shutdown(Shutdown::Both);
            }
        });

        Self {
            addr,
            stop,
            join: Some(join),
        }
    }
}

impl Drop for MitmEchoUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[test]
fn e2e_mitm_hardening_integrity_hsts_redirects_and_host_isolation() {
    let tmp = TempDir::new("mitm_harden");
    let (cert_path, key_path) =
        generate_self_signed_cert(tmp.path(), "example", "example.com", "0x55AA11");
    let expected_spki_b64 = openssl_cli_spki_sha256_b64(&cert_path);
    let cert_pem = fs::read(&cert_path).expect("read cert pem");
    assert_eq!(
        cert_spki_sha256_b64(&cert_pem).expect("rust spki b64"),
        expected_spki_b64,
        "Rust SPKI SHA-256 base64 must match openssl CLI exactly"
    );

    let index_bytes = b"<!doctype html><html><body>example hardened</body></html>\n";
    let index_path = tmp.path().join("index.html");
    fs::write(&index_path, index_bytes).expect("write index.html");
    let index_digest = sha256(index_bytes);
    let index_digest_b64 = base64_encode(&index_digest);
    let index_digest_hex = hex_encode(&index_digest);
    let expected_index_cd = format!("sha-256=:{}:", index_digest_b64);

    let other_path = tmp.path().join("other.txt");
    fs::write(&other_path, b"other-host-only\n").expect("write other.txt");

    let up_api = MitmEchoUpstream::start("api");
    let up_social = MitmEchoUpstream::start("app");

    let csp = "default-src 'self'; script-src 'self'";
    let hsts_expected = "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload";
    let perm_expected = "Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()";

    // Build shared route/static/redirect topology for TLS (1.3-only) and Plain HTTP verification.
    let build_cfg = |with_tls: bool| {
        let mut cfg = ProxyConfig {
            listen: "127.0.0.1:0".parse().expect("listen"),
            tls_cert: if with_tls {
                Some(cert_path.clone())
            } else {
                None
            },
            tls_key: if with_tls {
                Some(key_path.clone())
            } else {
                None
            },
            tls_min_version: TlsMinVersion::Tls13,
            static_csp: Some(csp.to_owned()),
            ..ProxyConfig::default()
        };
        cfg.add_static_spec(&format!("example.com /={}", index_path.display()))
            .expect("static example");
        cfg.add_static_spec(&format!("other.test /other={}", other_path.display()))
            .expect("static other");
        cfg.add_redirect_spec("www.example.com -> https://example.com")
            .expect("host redirect");
        cfg.add_path_redirect_spec("example.com /app -> /app/")
            .expect("path redirect");
        cfg.add_route_preserve_spec(&format!("example.com /app/={}", up_social.addr))
            .expect("route_preserve app");
        cfg.add_route_spec(&format!("example.com /api/={}", up_api.addr))
            .expect("route strip api");
        cfg
    };

    // Part A: TLS 1.3 hardened server checks.
    let tls_proxy = RunningProxy::start(build_cfg(true), false);
    let tls_addr = tls_proxy.handle.local_addr();

    // A1. Proxied strip-prefix route (/api/) over TLS: HSTS preload, Permissions-Policy,
    // upstream Server stripped, spoofed X-Real-IP overwritten with 127.0.0.1.
    let (st, head, body, proto, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET /api/v1/ping?a=1 HTTP/1.1\r\nHost: example.com\r\nX-Real-IP: 203.0.113.99\r\n\r\n",
    );
    assert_eq!(st, 200);
    assert_eq!(proto.as_deref(), Some("TLSv1.3"));
    assert!(head.contains(hsts_expected), "missing HSTS on TLS proxied: {}", head);
    assert!(head.contains(perm_expected), "missing Permissions-Policy: {}", head);
    assert!(!head.contains("Server:"), "upstream Server leaked: {}", head);
    assert!(!head.contains("max-age=1"), "upstream HSTS leaked: {}", head);
    assert!(!head.contains("camera=*"), "upstream Permissions-Policy leaked: {}", head);
    assert!(
        body.contains("tag=api|req=GET /v1/ping?a=1 HTTP/1.1|xfp=https|xri_count=1|xri=127.0.0.1"),
        "unexpected api body: {}",
        body
    );

    // A2. Proxied preserve-prefix route (/app/) keeps /app/ intact.
    let (st_soc, head_soc, body_soc, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET /app/posts?p=2 HTTP/1.1\r\nHost: example.com\r\nX-Real-IP: 198.51.100.7\r\n\r\n",
    );
    assert_eq!(st_soc, 200);
    assert!(head_soc.contains(hsts_expected));
    assert!(head_soc.contains(perm_expected));
    assert!(!head_soc.contains("Server:"));
    assert!(
        body_soc.contains(
            "tag=app|req=GET /app/posts?p=2 HTTP/1.1|xfp=https|xri_count=1|xri=127.0.0.1"
        ),
        "route_preserve failed: {}",
        body_soc
    );

    // A3. Static file on example.com /: RFC 9530 Content-Digest + static_csp + HSTS + Permissions-Policy.
    let (st_idx, head_idx, body_idx, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_idx, 200);
    assert_eq!(body_idx.as_bytes(), index_bytes);
    assert!(
        head_idx.contains(&format!("Content-Digest: {}", expected_index_cd)),
        "static Content-Digest mismatch: {}",
        head_idx
    );
    assert!(
        head_idx.contains(&format!("Content-Security-Policy: {}", csp)),
        "static CSP missing: {}",
        head_idx
    );
    assert!(head_idx.contains(hsts_expected));
    assert!(head_idx.contains(perm_expected));

    // A4. /.well-known/edge-integrity.json: exact SPKI match vs openssl CLI, static_assets, Content-Digest.
    let (st_int, head_int, body_int, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET /.well-known/edge-integrity.json?v=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_int, 200);
    assert!(head_int.contains("Content-Type: application/json; charset=utf-8"));
    assert!(head_int.contains("Cache-Control: no-store"));
    assert!(head_int.contains(hsts_expected));
    assert!(head_int.contains(perm_expected));
    let expected_int_cd = format!(
        "Content-Digest: sha-256=:{}:",
        base64_encode(&sha256(body_int.as_bytes()))
    );
    assert!(
        head_int.contains(&expected_int_cd),
        "integrity Content-Digest mismatch: {}",
        head_int
    );

    let json = parse_json(&body_int).expect("valid integrity JSON");
    assert_eq!(json.get_str("schema"), Some("zero-proxy.integrity.v1"));
    assert_eq!(json.get_str("host"), Some("example.com"));
    assert_eq!(json.get_str("tls_min_version"), Some("1.3"));
    assert_eq!(
        json.get_str("cert_spki_sha256"),
        Some(expected_spki_b64.as_str())
    );
    assert_eq!(json.get_str("cert_cn"), Some("example.com"));
    assert_eq!(json.get_str("cert_serial_hex"), Some("55aa11"));
    let assets = json
        .get("static_assets")
        .and_then(JsonValue::as_array)
        .expect("static_assets array");
    assert_eq!(assets.len(), 1, "must only list host-matching static assets");
    assert_eq!(assets[0].get_str("path"), Some("/"));
    assert_eq!(
        assets[0].get_str("sha256_hex"),
        Some(index_digest_hex.as_str())
    );
    assert_eq!(
        assets[0].get_str("content_digest"),
        Some(expected_index_cd.as_str())
    );

    // HEAD on integrity endpoint returns 200 + empty body.
    let (st_int_h, head_int_h, body_int_h, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"HEAD /.well-known/edge-integrity.json HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_int_h, 200);
    assert!(head_int_h.contains(&format!("Content-Length: {}", body_int.len())));
    assert!(body_int_h.is_empty());

    // A5. 308 path redirect preserving ?query.
    let (st_308, head_308, _, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET /app?tab=feed&x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(st_308, 308);
    assert!(
        head_308.contains("Location: /app/?tab=feed&x=1\r\n"),
        "308 location mismatch: {}",
        head_308
    );
    assert!(head_308.contains(hsts_expected));
    assert!(head_308.contains(perm_expected));

    // A6. Per-host isolation: other.example / -> 404 (with HSTS on TLS), www.example.com -> 301.
    let (st_iso, head_iso, _, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n",
    );
    assert_eq!(st_iso, 404);
    assert!(head_iso.contains(hsts_expected));
    assert!(head_iso.contains(perm_expected));

    let (st_www, head_www, _, _, _, _) = send_tls_http(
        tls_addr,
        "example.com",
        Some(&cert_path),
        b"GET /about?ref=1 HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
    );
    assert_eq!(st_www, 301);
    assert!(head_www.contains("Location: https://example.com/about?ref=1\r\n"));
    assert!(head_www.contains(hsts_expected));
    assert!(head_www.contains(perm_expected));

    // Part B: Plain HTTP listener must NOT emit HSTS, while keeping Permissions-Policy & Content-Digest.
    let plain_proxy = RunningProxy::start(build_cfg(false), false);
    let plain_addr = plain_proxy.handle.local_addr();

    let (pst_api, phead_api, _) = send_plain_http(
        plain_addr,
        b"GET /api/ping HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(pst_api, 200);
    assert!(!phead_api.contains("Strict-Transport-Security:"));
    assert!(phead_api.contains(perm_expected));
    assert!(!phead_api.contains("Server:"));

    let (pst_idx, phead_idx, _) =
        send_plain_http(plain_addr, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    assert_eq!(pst_idx, 200);
    assert!(!phead_idx.contains("Strict-Transport-Security:"));
    assert!(phead_idx.contains(&format!("Content-Digest: {}", expected_index_cd)));
    assert!(phead_idx.contains(perm_expected));

    let (pst_int, phead_int, pbody_int) = send_plain_http(
        plain_addr,
        b"GET /.well-known/edge-integrity.json HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(pst_int, 200);
    assert!(!phead_int.contains("Strict-Transport-Security:"));
    let pjson = parse_json(&pbody_int).expect("plain integrity json");
    assert_eq!(pjson.get("cert_spki_sha256"), Some(&JsonValue::Null));

    let (pst_404, phead_404, _) =
        send_plain_http(plain_addr, b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n");
    assert_eq!(pst_404, 404);
    assert!(!phead_404.contains("Strict-Transport-Security:"));
    assert!(phead_404.contains(perm_expected));
}
