#![forbid(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zero_proxy::acme::{
    base64_encode, base64url_encode, hex_encode, parse_json, sha256, JsonValue,
};
use zero_proxy::blindbind::{
    base64url_decode_exact, export_blindbind_secret, verify_binding, Error as BlindBindError,
    HybridBindingProof, HybridKeyPair, HybridPublicKey, Role, BLINDBIND_PROOF_B64URL_LEN,
    BLINDBIND_PUBKEY_B64URL_LEN, EXPORTER_LABEL, HYBRID_PROOF_LEN, HYBRID_PUBLIC_KEY_LEN,
};
use zero_proxy::{ProxyConfig, ProxyHandle, ProxyServer, TlsClientStream, TlsMinVersion};

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
            "zero_proxy_bb_{}_{}_{}_{}",
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

struct RecordingUpstream {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl RecordingUpstream {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind recording upstream");
        let addr = listener.local_addr().expect("upstream addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let hits_c = Arc::clone(&hits);
        let stop_c = Arc::clone(&stop);

        let join = thread::spawn(move || {
            for incoming in listener.incoming() {
                if stop_c.load(Ordering::Acquire) {
                    break;
                }
                let Ok(mut stream) = incoming else {
                    continue;
                };
                if stop_c.load(Ordering::Acquire) {
                    break;
                }
                hits_c.fetch_add(1, Ordering::SeqCst);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));

                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            raw.extend_from_slice(&buf[..n]);
                            if raw.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let head_end = raw
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(raw.len());
                let echoed = &raw[..head_end];
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    echoed.len()
                );
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.write_all(echoed);
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Both);
            }
        });

        Self {
            addr,
            hits,
            stop,
            join: Some(join),
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn reset_hits(&self) {
        self.hits.store(0, Ordering::SeqCst);
    }
}

impl Drop for RecordingUpstream {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
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
            server.run().expect("proxy run");
        });
        Self {
            handle,
            join: Some(join),
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

fn generate_self_signed_cert(dir: &Path, name: &str, cn: &str) -> (PathBuf, PathBuf) {
    let cert_path = dir.join(format!("{}.crt", name));
    let key_path = dir.join(format!("{}.key", name));
    let san = format!("subjectAltName=DNS:{}", cn);
    let subj = format!("/CN={}", cn);
    let out = Command::new("openssl")
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
            "-subj",
            &subj,
            "-addext",
            &san,
        ])
        .output()
        .expect("spawn openssl req");
    assert!(
        out.status.success(),
        "openssl req failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (cert_path, key_path)
}

fn send_http_exchange<S: Read + Write>(stream: &mut S, raw_req: &str) -> (String, String) {
    stream.write_all(raw_req.as_bytes()).expect("write request");
    stream.flush().expect("flush request");
    let mut resp = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => resp.extend_from_slice(&tmp[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(_) => break,
        }
    }
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http response header terminator");
    let head = String::from_utf8(resp[..split].to_vec()).expect("utf8 head");
    let body = String::from_utf8(resp[split + 4..].to_vec()).expect("utf8 body");
    (head, body)
}

fn base_tls_config(
    cert: &Path,
    key: &Path,
    upstream_addr: SocketAddr,
    min_version: TlsMinVersion,
) -> ProxyConfig {
    let mut cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        tls_cert: Some(cert.to_path_buf()),
        tls_key: Some(key.to_path_buf()),
        tls_min_version: min_version,
        rate_limit_rps: 0,
        ..Default::default()
    };
    cfg.add_route_spec(&format!("/api={}", upstream_addr))
        .expect("add route");
    cfg
}

#[test]
fn e2e_live_openssl_vs_pure_rust_exporter_parity_all_tls13_suites() {
    let dir = TempDir::new("parity");
    let (cert, key) = generate_self_signed_cert(dir.path(), "srv", "blindbind.test");
    let upstream = RecordingUpstream::start();
    let cfg = base_tls_config(&cert, &key, upstream.addr, TlsMinVersion::Tls13);
    let proxy = RunningProxy::start(cfg);
    let addr = proxy.handle.local_addr();

    let suites = [
        ("TLS_AES_256_GCM_SHA384", 48usize),
        ("TLS_AES_128_GCM_SHA256", 32usize),
        ("TLS_CHACHA20_POLY1305_SHA256", 32usize),
    ];

    for (suite, expected_ems_len) in suites {
        let tcp = TcpStream::connect(addr).expect("tcp connect");
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .expect("write timeout");

        let (tls, maybe_ems) =
            TlsClientStream::connect_with_keylog(tcp, "blindbind.test", true, Some(&cert), Some(suite))
                .expect("tls13 connect with keylog");
        assert_eq!(tls.protocol_version().as_deref(), Some("TLSv1.3"));

        let ems = maybe_ems.expect("OpenSSL keylog EXPORTER_SECRET captured");
        assert_eq!(
            ems.len(),
            expected_ems_len,
            "unexpected EXPORTER_SECRET length for {}",
            suite
        );

        let live_host = tls
            .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
            .expect("live openssl export host");
        let rust_host = export_blindbind_secret(&ems, b"blindbind.test")
            .expect("pure rust export host");
        assert_eq!(
            live_host, rust_host,
            "bit-exact OpenSSL <-> pure-Rust parity failed for {} with host context",
            suite
        );

        let live_empty = tls
            .export_tls13_keying_material(EXPORTER_LABEL, b"")
            .expect("live openssl export empty");
        let rust_empty = export_blindbind_secret(&ems, b"").expect("pure rust export empty");
        assert_eq!(
            live_empty, rust_empty,
            "bit-exact OpenSSL <-> pure-Rust parity failed for {} with empty context",
            suite
        );

        // Counterfactual knockout: different context and 1-bit flipped EMS must diverge.
        assert_ne!(live_host, live_empty);
        let mut bad_ems = ems.clone();
        bad_ems[0] ^= 0x01;
        let rust_bad = export_blindbind_secret(&bad_ems, b"blindbind.test").expect("bad ems");
        assert_ne!(live_host, rust_bad);
    }
}

#[test]
fn e2e_well_known_blindbind_tls13_plaintext_and_seed_persistence() {
    let dir = TempDir::new("well_known");
    let (cert, key) = generate_self_signed_cert(dir.path(), "srv", "blindbind.test");
    let upstream = RecordingUpstream::start();
    let seed_file = dir.path().join("blindbind.seed");

    // 1. Seed file creation (0600 perms) and persistence across server restart.
    let mut cfg1 = base_tls_config(&cert, &key, upstream.addr, TlsMinVersion::Tls13);
    cfg1.blindbind_seed_file = Some(seed_file.clone());
    let proxy1 = RunningProxy::start(cfg1);
    let pk1 = proxy1.handle.blindbind_public_key();
    let meta = fs::metadata(&seed_file).expect("seed file created");
    assert_eq!(meta.len(), 32);
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    drop(proxy1);

    let mut cfg2 = base_tls_config(&cert, &key, upstream.addr, TlsMinVersion::Tls13);
    cfg2.blindbind_seed_file = Some(seed_file.clone());
    let proxy2 = RunningProxy::start(cfg2);
    let pk2 = proxy2.handle.blindbind_public_key();
    assert_eq!(pk1, pk2, "seed file must reproduce identical hybrid keypair");

    // 2. Live TLS 1.3 GET /.well-known/blindbind with uppercase host + :port normalization.
    let tcp_a = TcpStream::connect(proxy2.handle.local_addr()).expect("tcp a");
    tcp_a
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut tls_a = TlsClientStream::connect(tcp_a, "blindbind.test", true, Some(&cert))
        .expect("tls a");
    let secret_a = tls_a
        .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
        .expect("export secret a");

    let (head, body) = send_http_exchange(
        &mut tls_a,
        "GET /.well-known/blindbind HTTP/1.1\r\nHost: BLINDBIND.TEST:8443\r\nConnection: close\r\n\r\n",
    );
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "head: {}", head);
    assert!(head.contains("Cache-Control: no-store\r\n"));
    let expected_digest = format!(
        "Content-Digest: sha-256=:{}:",
        base64_encode(&sha256(body.as_bytes()))
    );
    assert!(head.contains(&expected_digest));

    let json = parse_json(&body).expect("parse well-known json");
    assert_eq!(
        json.get("schema").and_then(|v| v.as_str()),
        Some("zero-proxy.blindbind.v1")
    );
    assert_eq!(
        json.get("host").and_then(|v| v.as_str()),
        Some("blindbind.test")
    );
    assert_eq!(json.get("tls13_bound"), Some(&JsonValue::Bool(true)));
    let pk_b64 = json
        .get("pubkey_b64url")
        .and_then(|v| v.as_str())
        .expect("pubkey_b64url");
    let proof_b64 = json
        .get("proof_b64url")
        .and_then(|v| v.as_str())
        .expect("proof_b64url");
    assert_eq!(pk_b64.len(), BLINDBIND_PUBKEY_B64URL_LEN);
    assert_eq!(proof_b64.len(), BLINDBIND_PROOF_B64URL_LEN);

    let pk_bytes = base64url_decode_exact::<HYBRID_PUBLIC_KEY_LEN>(pk_b64.as_bytes())
        .expect("decode pubkey");
    let proof_bytes = base64url_decode_exact::<HYBRID_PROOF_LEN>(proof_b64.as_bytes())
        .expect("decode proof");
    let server_pk = HybridPublicKey::from_bytes(&pk_bytes).expect("hybrid pk");
    let server_proof = HybridBindingProof::from_bytes(&proof_bytes).expect("hybrid proof");
    assert_eq!(server_pk, pk2);

    verify_binding(
        &server_pk,
        &secret_a,
        Role::Server,
        b"blindbind.test",
        &server_proof,
    )
    .expect("server blindbind proof must verify against live TLS 1.3 session A");

    // Counterfactual cross-session knockout for server proof.
    let tcp_b = TcpStream::connect(proxy2.handle.local_addr()).expect("tcp b");
    let tls_b = TlsClientStream::connect(tcp_b, "blindbind.test", true, Some(&cert))
        .expect("tls b");
    let secret_b = tls_b
        .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
        .expect("export secret b");
    assert_ne!(secret_a, secret_b);
    assert_eq!(
        verify_binding(
            &server_pk,
            &secret_b,
            Role::Server,
            b"blindbind.test",
            &server_proof
        ),
        Err(BlindBindError::ExporterMismatch)
    );

    // HEAD /.well-known/blindbind -> 200 OK with empty body; POST -> 405.
    let tcp_head = TcpStream::connect(proxy2.handle.local_addr()).expect("tcp head");
    let mut tls_head = TlsClientStream::connect(tcp_head, "blindbind.test", true, Some(&cert))
        .expect("tls head");
    let (h_head, h_body) = send_http_exchange(
        &mut tls_head,
        "HEAD /.well-known/blindbind HTTP/1.1\r\nHost: blindbind.test\r\nConnection: close\r\n\r\n",
    );
    assert!(h_head.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(h_body.is_empty());

    let tcp_post = TcpStream::connect(proxy2.handle.local_addr()).expect("tcp post");
    let mut tls_post = TlsClientStream::connect(tcp_post, "blindbind.test", true, Some(&cert))
        .expect("tls post");
    let (p_head, _) = send_http_exchange(
        &mut tls_post,
        "POST /.well-known/blindbind HTTP/1.1\r\nHost: blindbind.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    assert!(p_head.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"));
    drop(proxy2);

    // 3. Plaintext HTTP /.well-known/blindbind returns tls13_bound: false and proof_b64url: null.
    let mut plain_cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        rate_limit_rps: 0,
        ..Default::default()
    };
    plain_cfg
        .add_route_spec(&format!("/api={}", upstream.addr))
        .expect("route");
    let plain_proxy = RunningProxy::start(plain_cfg);
    let mut tcp_plain = TcpStream::connect(plain_proxy.handle.local_addr()).expect("tcp plain");
    let (pl_head, pl_body) = send_http_exchange(
        &mut tcp_plain,
        "GET /.well-known/blindbind HTTP/1.1\r\nHost: plain.test\r\nConnection: close\r\n\r\n",
    );
    assert!(pl_head.starts_with("HTTP/1.1 200 OK\r\n"));
    let pl_json = parse_json(&pl_body).expect("plain json");
    assert_eq!(pl_json.get("tls13_bound"), Some(&JsonValue::Bool(false)));
    assert!(
        pl_json.get("proof_b64url").is_some_and(|v| v.as_str().is_none()),
        "plaintext proof_b64url must be null"
    );

    // 4. Malformed seed file fails closed on bind.
    let bad_seed = dir.path().join("bad.seed");
    fs::write(&bad_seed, [0x11u8; 31]).expect("write bad seed");
    let mut bad_cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        blindbind_seed_file: Some(bad_seed),
        ..Default::default()
    };
    bad_cfg
        .add_route_spec(&format!("/api={}", upstream.addr))
        .expect("route");
    assert!(ProxyServer::bind(bad_cfg).is_err());
}

#[test]
fn e2e_client_proof_verification_and_cross_session_replay_knockout() {
    let dir = TempDir::new("client_proof");
    let (cert, key) = generate_self_signed_cert(dir.path(), "srv", "blindbind.test");
    let upstream = RecordingUpstream::start();
    let cfg = base_tls_config(&cert, &key, upstream.addr, TlsMinVersion::Tls13);
    let proxy = RunningProxy::start(cfg);
    let addr = proxy.handle.local_addr();

    let client_kp = HybridKeyPair::from_master_seed(&[0x7Cu8; 32]);
    let client_pk_bytes = client_kp.public_key().to_bytes();
    let expected_key_sha = hex_encode(&sha256(&client_pk_bytes));
    let client_pk_b64 = base64url_encode(&client_pk_bytes);

    // Session A: valid two-header client proof + attempted spoofed X-BlindBind-Verified overwrite.
    let tcp_a = TcpStream::connect(addr).expect("tcp a");
    tcp_a
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut tls_a = TlsClientStream::connect(tcp_a, "blindbind.test", true, Some(&cert))
        .expect("tls a");
    let secret_a = tls_a
        .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
        .expect("secret a");
    let proof_a = client_kp
        .bind(&secret_a, Role::Client, b"blindbind.test")
        .expect("bind a");
    let proof_a_b64 = base64url_encode(&proof_a.to_bytes());

    let req_a = format!(
        "GET /api/ping HTTP/1.1\r\n\
         Host: blindbind.test\r\n\
         X-BlindBind-PubKey: {}\r\n\
         X-BlindBind-Proof: {}\r\n\
         X-BlindBind-Verified: 0\r\n\
         X-BlindBind-Key-Sha256: deadbeef\r\n\
         Connection: close\r\n\r\n",
        client_pk_b64, proof_a_b64
    );
    let (head_a, body_a) = send_http_exchange(&mut tls_a, &req_a);
    assert!(head_a.starts_with("HTTP/1.1 200 OK\r\n"), "head_a: {}", head_a);
    assert_eq!(upstream.hits(), 1);
    assert!(body_a.contains("X-BlindBind-Verified: 1\r\n"), "body_a: {}", body_a);
    assert!(
        body_a.contains(&format!("X-BlindBind-Key-Sha256: {}\r\n", expected_key_sha)),
        "body_a: {}",
        body_a
    );
    assert!(!body_a.to_ascii_lowercase().contains("x-blindbind-proof"));
    assert!(!body_a.to_ascii_lowercase().contains("x-blindbind-pubkey"));
    assert!(!body_a.contains("deadbeef"));

    // Session B: COUNTERFACTUAL CROSS-SESSION REPLAY KNOCKOUT (assert_ne! secrets -> 401 + 0 upstream hits).
    upstream.reset_hits();
    let tcp_b = TcpStream::connect(addr).expect("tcp b");
    tcp_b
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut tls_b = TlsClientStream::connect(tcp_b, "blindbind.test", true, Some(&cert))
        .expect("tls b");
    let secret_b = tls_b
        .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
        .expect("secret b");
    assert_ne!(
        secret_a, secret_b,
        "distinct TLS 1.3 sessions must yield distinct exporter secrets"
    );
    let (head_b, _) = send_http_exchange(&mut tls_b, &req_a);
    assert!(
        head_b.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "cross-session replay must fail closed with 401, got: {}",
        head_b
    );
    assert_eq!(
        upstream.hits(),
        0,
        "replayed request must never reach upstream"
    );

    // Session C: single-header dotted format (`X-BlindBind-Proof: <pk>.<proof>`).
    let tcp_c = TcpStream::connect(addr).expect("tcp c");
    tcp_c
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut tls_c = TlsClientStream::connect(tcp_c, "blindbind.test", true, Some(&cert))
        .expect("tls c");
    let secret_c = tls_c
        .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
        .expect("secret c");
    let proof_c = client_kp
        .bind(&secret_c, Role::Client, b"blindbind.test")
        .expect("bind c");
    let req_c = format!(
        "GET /api/dotted HTTP/1.1\r\n\
         Host: blindbind.test\r\n\
         X-BlindBind-Proof: {}.{}\r\n\
         Connection: close\r\n\r\n",
        client_pk_b64,
        base64url_encode(&proof_c.to_bytes())
    );
    let (head_c, body_c) = send_http_exchange(&mut tls_c, &req_c);
    assert!(head_c.starts_with("HTTP/1.1 200 OK\r\n"));
    assert_eq!(upstream.hits(), 1);
    assert!(body_c.contains("X-BlindBind-Verified: 1\r\n"));
    assert!(body_c.contains(&format!("X-BlindBind-Key-Sha256: {}\r\n", expected_key_sha)));

    // Session D: tampered ML-DSA-87 sig, tampered Ed25519 sig, Server-role reflection, wrong host context.
    upstream.reset_hits();
    for attack in ["tamper_mldsa", "tamper_ed25519", "server_role", "wrong_host"] {
        let tcp_d = TcpStream::connect(addr).expect("tcp d");
        tcp_d
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        let mut tls_d = TlsClientStream::connect(tcp_d, "blindbind.test", true, Some(&cert))
            .expect("tls d");
        let secret_d = tls_d
            .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
            .expect("secret d");
        let mut proof_bytes = match attack {
            "server_role" => client_kp
                .bind(&secret_d, Role::Server, b"blindbind.test")
                .expect("bind role")
                .to_bytes(),
            "wrong_host" => client_kp
                .bind(&secret_d, Role::Client, b"evil.test")
                .expect("bind host")
                .to_bytes(),
            _ => client_kp
                .bind(&secret_d, Role::Client, b"blindbind.test")
                .expect("bind ok")
                .to_bytes(),
        };
        if attack == "tamper_ed25519" {
            proof_bytes[40] ^= 0x01;
        } else if attack == "tamper_mldsa" {
            proof_bytes[200] ^= 0x01;
        }
        let req_d = format!(
            "GET /api/attack HTTP/1.1\r\n\
             Host: blindbind.test\r\n\
             X-BlindBind-Proof: {}.{}\r\n\
             Connection: close\r\n\r\n",
            client_pk_b64,
            base64url_encode(&proof_bytes)
        );
        let (head_d, _) = send_http_exchange(&mut tls_d, &req_d);
        assert!(
            head_d.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "attack {} must return 401, got: {}",
            attack,
            head_d
        );
    }
    assert_eq!(upstream.hits(), 0, "no attacked request may reach upstream");
}

#[test]
fn e2e_browser_compat_spoof_strip_plaintext_and_tls12_rejection() {
    let dir = TempDir::new("browser_compat");
    let (cert, key) = generate_self_signed_cert(dir.path(), "srv", "blindbind.test");
    let upstream = RecordingUpstream::start();
    // Allow TLS 1.2 + TLS 1.3 so we can verify TLS 1.2 downgrade rejection live!
    let cfg = base_tls_config(&cert, &key, upstream.addr, TlsMinVersion::Tls12);
    let proxy = RunningProxy::start(cfg);
    let addr = proxy.handle.local_addr();

    // 1. Normal browser over TLS 1.3 (zero BlindBind headers) -> 200 OK unaffected.
    let tcp1 = TcpStream::connect(addr).expect("tcp1");
    let mut tls1 = TlsClientStream::connect(tcp1, "blindbind.test", true, Some(&cert))
        .expect("tls1");
    let (h1, b1) = send_http_exchange(
        &mut tls1,
        "GET /api/browser HTTP/1.1\r\nHost: blindbind.test\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
    );
    assert!(h1.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!b1.to_ascii_lowercase().contains("x-blindbind-verified"));
    assert!(!b1.to_ascii_lowercase().contains("x-blindbind-key-sha256"));

    // 2. Spoofed X-BlindBind-Verified: 1 without proof over TLS 1.3 -> stripped before upstream!
    let tcp2 = TcpStream::connect(addr).expect("tcp2");
    let mut tls2 = TlsClientStream::connect(tcp2, "blindbind.test", true, Some(&cert))
        .expect("tls2");
    let (h2, b2) = send_http_exchange(
        &mut tls2,
        "GET /api/spoof HTTP/1.1\r\nHost: blindbind.test\r\nX-BlindBind-Verified: 1\r\nX-BlindBind-Key-Sha256: 00112233\r\nX-BlindBind_Verified: 1\r\nX_BLINDBIND_KEY_SHA256: deadbeef\r\nConnection: close\r\n\r\n",
    );
    assert!(h2.starts_with("HTTP/1.1 200 OK\r\n"));
    let b2_lc = b2.to_ascii_lowercase();
    assert!(!b2_lc.contains("x-blindbind-verified"));
    assert!(!b2_lc.contains("x-blindbind_verified"));
    assert!(!b2_lc.contains("x-blindbind-key-sha256"));
    assert!(!b2_lc.contains("x_blindbind_key_sha256"));
    assert!(!b2.contains("00112233"));
    assert!(!b2.contains("deadbeef"));

    // 3. TLS 1.2 browser works, but TLS 1.2 with X-BlindBind-Proof is rejected 401 (no RFC 5705 downgrade)!
    let tcp3 = TcpStream::connect(addr).expect("tcp3");
    let mut tls12_ok = TlsClientStream::connect_tls12(tcp3, "blindbind.test", true, Some(&cert))
        .expect("tls12 connect");
    assert_eq!(tls12_ok.protocol_version().as_deref(), Some("TLSv1.2"));
    assert!(
        tls12_ok
            .export_tls13_keying_material(EXPORTER_LABEL, b"blindbind.test")
            .is_err(),
        "client exporter must refuse TLS 1.2"
    );
    let (h3, b3) = send_http_exchange(
        &mut tls12_ok,
        "GET /api/tls12 HTTP/1.1\r\nHost: blindbind.test\r\nX-BlindBind-Verified: 1\r\nConnection: close\r\n\r\n",
    );
    assert!(h3.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!b3.to_ascii_lowercase().contains("x-blindbind-verified"));

    upstream.reset_hits();
    let kp = HybridKeyPair::from_master_seed(&[0x91u8; 32]);
    let pk_b64 = base64url_encode(&kp.public_key().to_bytes());
    let dummy_proof = kp
        .bind(&[0x11u8; 32], Role::Client, b"blindbind.test")
        .expect("dummy bind");
    let proof_b64 = base64url_encode(&dummy_proof.to_bytes());

    let tcp4 = TcpStream::connect(addr).expect("tcp4");
    let mut tls12_proof =
        TlsClientStream::connect_tls12(tcp4, "blindbind.test", true, Some(&cert))
            .expect("tls12 proof connect");
    let req_with_proof = format!(
        "GET /api/downgrade HTTP/1.1\r\nHost: blindbind.test\r\nX-BlindBind-Proof: {}.{}\r\nConnection: close\r\n\r\n",
        pk_b64, proof_b64
    );
    let (h4, _) = send_http_exchange(&mut tls12_proof, &req_with_proof);
    assert!(
        h4.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "TLS 1.2 with BlindBind proof must fail closed with 401, got: {}",
        h4
    );
    assert_eq!(upstream.hits(), 0);
    drop(proxy);

    // 4. Plaintext HTTP: spoofed X-BlindBind-Verified stripped, X-BlindBind-Proof rejected 401.
    let mut plain_cfg = ProxyConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        rate_limit_rps: 0,
        ..Default::default()
    };
    plain_cfg
        .add_route_spec(&format!("/api={}", upstream.addr))
        .expect("route");
    let plain_proxy = RunningProxy::start(plain_cfg);

    let mut plain1 = TcpStream::connect(plain_proxy.handle.local_addr()).expect("plain1");
    let (hp1, bp1) = send_http_exchange(
        &mut plain1,
        "GET /api/plain HTTP/1.1\r\nHost: plain.test\r\nX-BlindBind-Verified: 1\r\nConnection: close\r\n\r\n",
    );
    assert!(hp1.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!bp1.to_ascii_lowercase().contains("x-blindbind-verified"));

    upstream.reset_hits();
    let mut plain2 = TcpStream::connect(plain_proxy.handle.local_addr()).expect("plain2");
    let (hp2, _) = send_http_exchange(&mut plain2, &req_with_proof);
    assert!(
        hp2.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "plaintext BlindBind proof must return 401, got: {}",
        hp2
    );
    assert_eq!(upstream.hits(), 0);
}
