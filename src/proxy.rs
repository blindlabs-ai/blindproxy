use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::acme::{
    base64_encode, base64url_encode, extract_http01_token, hex_encode, json_escape_str,
    run_renewal_pass, sha256, AcmeChallengeStore, Sha256,
};
use crate::blindbind::{
    normalize_blindbind_context, parse_blindbind_headers, verify_binding, zeroize_bytes,
    HybridKeyPair, HybridPublicKey, Role, EXPORTER_LABEL, HYBRID_PROOF_LEN, HYBRID_PUBLIC_KEY_LEN,
};
use crate::config::{strip_host_port, ProxyConfig, StaticRoute, STREAM_BUFFER_BYTES};
use crate::error::ProxyError;
use crate::http::{
    content_type_for_path, parse_request, parse_response_head, scan_header_terminator,
    write_acme_challenge_response, write_forwarded_request_head_blindbind,
    write_forwarded_response_head_with_policy, write_integrity_response_head,
    write_path_redirect_response, write_redirect_response, write_redirect_response_tls,
    write_static_response_head_cors, HeaderView,
};
use crate::ratelimit::{ConnGuard, IpConnLimiter, RateLimiter};
use crate::tls::{
    install_signal_handlers, shutdown_requested, take_sighup, write_atomic_0600, ClientTransport,
    TlsCertStore, TlsServerStream,
};

/// Lock-free atomic telemetry counters for a running proxy instance.
#[derive(Default)]
pub struct ProxyStats {
    pub requests_total: AtomicU64,
    pub requests_ok: AtomicU64,
    pub rate_limited: AtomicU64,
    pub bad_requests: AtomicU64,
    pub payload_too_large: AtomicU64,
    pub headers_too_large: AtomicU64,
    pub header_timeouts: AtomicU64,
    pub not_found: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

/// Point-in-time snapshot of proxy counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatsSnapshot {
    pub requests_total: u64,
    pub requests_ok: u64,
    pub rate_limited: u64,
    pub bad_requests: u64,
    pub payload_too_large: u64,
    pub headers_too_large: u64,
    pub header_timeouts: u64,
    pub not_found: u64,
    pub upstream_errors: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

impl ProxyStats {
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_ok: self.requests_ok.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            bad_requests: self.bad_requests.load(Ordering::Relaxed),
            payload_too_large: self.payload_too_large.load(Ordering::Relaxed),
            headers_too_large: self.headers_too_large.load(Ordering::Relaxed),
            header_timeouts: self.header_timeouts.load(Ordering::Relaxed),
            not_found: self.not_found.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }

    fn record_error(&self, err: ProxyError) {
        match err {
            ProxyError::RateLimited => {
                self.rate_limited.fetch_add(1, Ordering::Relaxed);
            }
            ProxyError::BadRequest(_)
            | ProxyError::Unauthorized(_)
            | ProxyError::Forbidden
            | ProxyError::MethodNotAllowed => {
                self.bad_requests.fetch_add(1, Ordering::Relaxed);
            }
            ProxyError::PayloadTooLarge => {
                self.payload_too_large.fetch_add(1, Ordering::Relaxed);
            }
            ProxyError::HeadersTooLarge => {
                self.headers_too_large.fetch_add(1, Ordering::Relaxed);
            }
            ProxyError::HeaderTimeout | ProxyError::IdleTimeout => {
                self.header_timeouts.fetch_add(1, Ordering::Relaxed);
            }
            ProxyError::NotFound => {
                self.not_found.fetch_add(1, Ordering::Relaxed);
            }
            ProxyError::UpstreamUnavailable
            | ProxyError::UpstreamTimeout
            | ProxyError::TooManyConnections
            | ProxyError::Config(_)
            | ProxyError::Tls(_)
            | ProxyError::Acme(_)
            | ProxyError::Io(_) => {
                self.upstream_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

struct ProxyState {
    config: RwLock<Arc<ProxyConfig>>,
    limiter: RwLock<Arc<RateLimiter>>,
    ip_conn_limiter: RwLock<Arc<IpConnLimiter>>,
    tls_store: Option<Arc<TlsCertStore>>,
    acme_challenges: Arc<AcmeChallengeStore>,
    blindbind_keypair: Arc<HybridKeyPair>,
    stats: ProxyStats,
    active_conns: AtomicUsize,
    shutdown: AtomicBool,
    watch_signals: AtomicBool,
    reload_count: AtomicU64,
    local_addr: SocketAddr,
    http_local_addr: Option<SocketAddr>,
}

fn read_arc_lock<T>(lock: &RwLock<Arc<T>>) -> Arc<T> {
    match lock.read() {
        Ok(g) => Arc::clone(&g),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    }
}

impl ProxyState {
    fn current_config(&self) -> Arc<ProxyConfig> {
        read_arc_lock(&self.config)
    }

    fn current_limiter(&self) -> Arc<RateLimiter> {
        read_arc_lock(&self.limiter)
    }

    fn current_ip_conn_limiter(&self) -> Arc<IpConnLimiter> {
        read_arc_lock(&self.ip_conn_limiter)
    }

    fn reload_all(&self) -> Result<(), ProxyError> {
        let cur = self.current_config();
        let next = cur.reload_from_file()?;
        let limiter_changed = next.rate_limit_rps != cur.rate_limit_rps
            || next.rate_limit_burst != cur.rate_limit_burst
            || next.rate_limit_shards != cur.rate_limit_shards;

        if limiter_changed {
            let new_lim = Arc::new(RateLimiter::new(
                next.rate_limit_shards,
                next.rate_limit_rps,
                next.rate_limit_burst,
            )?);
            if let Ok(mut guard) = self.limiter.write() {
                *guard = new_lim;
            }
        }

        let ip_conn_changed = next.max_conns_per_ip != cur.max_conns_per_ip
            || next.rate_limit_shards != cur.rate_limit_shards;
        if ip_conn_changed {
            let new_ip_lim = Arc::new(IpConnLimiter::new(
                next.rate_limit_shards,
                next.max_conns_per_ip,
            )?);
            if let Ok(mut guard) = self.ip_conn_limiter.write() {
                *guard = new_ip_lim;
            }
        }

        if let Some(store) = &self.tls_store {
            let _ = store.reload_from_config(&next)?;
        }

        if let Ok(mut guard) = self.config.write() {
            *guard = Arc::new(next);
        }
        self.reload_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn request_shutdown(&self) {
        if !self.shutdown.swap(true, Ordering::AcqRel) {
            let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(100));
            if let Some(http_addr) = self.http_local_addr {
                let _ = TcpStream::connect_timeout(&http_addr, Duration::from_millis(100));
            }
        }
    }
}

/// Cloneable control and telemetry handle for a bound `ProxyServer`.
#[derive(Clone)]
pub struct ProxyHandle {
    state: Arc<ProxyState>,
}

impl ProxyHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.state.local_addr
    }

    pub fn http_local_addr(&self) -> Option<SocketAddr> {
        self.state.http_local_addr
    }

    pub fn stats(&self) -> StatsSnapshot {
        self.state.stats.snapshot()
    }

    pub fn active_connections(&self) -> usize {
        self.state.active_conns.load(Ordering::Acquire)
    }

    pub fn active_conns_for_ip(&self, ip: IpAddr) -> u32 {
        self.state.current_ip_conn_limiter().active_for_ip(ip)
    }

    pub fn reload_count(&self) -> u64 {
        self.state.reload_count.load(Ordering::Acquire)
    }

    pub fn tls_store(&self) -> Option<Arc<TlsCertStore>> {
        self.state.tls_store.clone()
    }

    pub fn acme_challenges(&self) -> Arc<AcmeChallengeStore> {
        Arc::clone(&self.state.acme_challenges)
    }

    /// Returns the server's active hybrid BlindBind (Ed25519 + ML-DSA-87) public key.
    pub fn blindbind_public_key(&self) -> HybridPublicKey {
        self.state.blindbind_keypair.public_key()
    }

    /// Atomically reloads the config file (if configured) and TLS certificates with zero downtime.
    pub fn reload(&self) -> Result<(), ProxyError> {
        self.state.reload_all()
    }

    /// Signals the accept loop(s) to stop accepting new connections and begin graceful drain.
    pub fn stop(&self) {
        self.state.request_shutdown();
    }
}

/// Multi-threaded, lock-free, fixed-buffer HTTP/1.1 + TLS 1.3 + ACME v2 reverse proxy server.
pub struct ProxyServer {
    listener: TcpListener,
    http_listener: Option<TcpListener>,
    state: Arc<ProxyState>,
}

impl ProxyServer {
    /// Validates `config`, loads TLS certificates if configured, initializes the lock-free
    /// rate limiter, and binds primary (and optional HTTP `:80`) TCP listeners.
    pub fn bind(mut config: ProxyConfig) -> Result<Self, ProxyError> {
        config.finalize()?;
        let limiter = Arc::new(RateLimiter::new(
            config.rate_limit_shards,
            config.rate_limit_rps,
            config.rate_limit_burst,
        )?);
        let ip_conn_limiter = Arc::new(IpConnLimiter::new(
            config.rate_limit_shards,
            config.max_conns_per_ip,
        )?);

        let tls_store = if config.tls_enabled() {
            let store = TlsCertStore::new();
            let loaded = store.reload_from_config(&config)?;
            if loaded == 0 && config.acme_domains.is_empty() {
                return Err(ProxyError::Tls(
                    "TLS enabled but no certificate found and no acme_domain configured",
                ));
            }
            Some(store)
        } else {
            None
        };

        let blindbind_keypair = Arc::new(load_or_generate_blindbind_keypair(
            config.blindbind_seed_file.as_deref(),
        )?);

        let listener = TcpListener::bind(config.listen)?;
        let local_addr = listener.local_addr()?;

        let (http_listener, http_local_addr) = match config.http_listen {
            Some(addr) => {
                let l = TcpListener::bind(addr)?;
                let bound = l.local_addr()?;
                (Some(l), Some(bound))
            }
            None => (None, None),
        };

        let state = Arc::new(ProxyState {
            config: RwLock::new(Arc::new(config)),
            limiter: RwLock::new(limiter),
            ip_conn_limiter: RwLock::new(ip_conn_limiter),
            tls_store,
            acme_challenges: AcmeChallengeStore::new(),
            blindbind_keypair,
            stats: ProxyStats::default(),
            active_conns: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            watch_signals: AtomicBool::new(false),
            reload_count: AtomicU64::new(0),
            local_addr,
            http_local_addr,
        });

        Ok(Self {
            listener,
            http_listener,
            state,
        })
    }

    /// Enables OS `SIGHUP` (zero-downtime reload) and `SIGTERM`/`SIGINT` (graceful drain) handling.
    pub fn enable_signal_handling(&self) {
        install_signal_handlers();
        self.state.watch_signals.store(true, Ordering::Release);
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.state.local_addr
    }

    pub fn http_local_addr(&self) -> Option<SocketAddr> {
        self.state.http_local_addr
    }

    pub fn handle(&self) -> ProxyHandle {
        ProxyHandle {
            state: Arc::clone(&self.state),
        }
    }

    /// Runs accept loop(s), optional signal watcher, optional ACME renewal thread, and
    /// performs a graceful in-flight connection drain (up to `drain_timeout_ms`) on shutdown.
    pub fn run(&self) -> Result<(), ProxyError> {
        let http_thread = self.spawn_http_redirect_listener()?;
        let signal_thread = self.spawn_signal_watcher();
        let acme_thread = self.spawn_acme_renewal_thread();

        for incoming in self.listener.incoming() {
            if self.state.shutdown.load(Ordering::Acquire) {
                break;
            }
            let stream = match incoming {
                Ok(s) => s,
                Err(err) => {
                    if self.state.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    if err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    continue;
                }
            };
            if self.state.shutdown.load(Ordering::Acquire) {
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }

            let peer = match stream.peer_addr() {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            let guard = match try_acquire_conn(&self.state, peer.ip()) {
                Ok(g) => g,
                Err(err_kind) => {
                    let proxy_err = match err_kind {
                        AcquireError::PerIpLimit => ProxyError::RateLimited,
                        AcquireError::GlobalLimit => ProxyError::TooManyConnections,
                    };
                    self.state.stats.record_error(proxy_err);
                    if self.state.tls_store.is_none() {
                        let mut s = stream;
                        let _ = s.set_write_timeout(Some(Duration::from_millis(250)));
                        let _ = proxy_err.write_http_response(&mut s);
                        let _ = s.shutdown(Shutdown::Both);
                    } else {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    continue;
                }
            };

            let state = Arc::clone(&self.state);
            let spawn_res = thread::Builder::new()
                .name("bp-worker".to_owned())
                .spawn(move || {
                    let conn_guard = guard;
                    handle_primary_connection(stream, peer, &state);
                    drop(conn_guard);
                });
            if spawn_res.is_err() {
                self.state
                    .stats
                    .record_error(ProxyError::TooManyConnections);
            }
        }

        // Ensure helper listeners/threads observe shutdown and exit cleanly.
        self.state.request_shutdown();
        if let Some(h) = http_thread {
            let _ = h.join();
        }
        if let Some(h) = signal_thread {
            let _ = h.join();
        }
        if let Some(h) = acme_thread {
            let _ = h.join();
        }

        // Graceful SIGTERM/SIGINT drain: wait up to drain_timeout_ms for in-flight requests.
        let drain_ms = self.state.current_config().drain_timeout_ms;
        let drain_deadline = Instant::now() + Duration::from_millis(drain_ms);
        while self.state.active_conns.load(Ordering::Acquire) > 0
            && Instant::now() < drain_deadline
        {
            thread::sleep(Duration::from_millis(10));
        }

        Ok(())
    }

    fn spawn_http_redirect_listener(
        &self,
    ) -> Result<Option<thread::JoinHandle<()>>, ProxyError> {
        let Some(ref listener) = self.http_listener else {
            return Ok(None);
        };
        let cloned = listener.try_clone()?;
        let state = Arc::clone(&self.state);
        let handle = thread::Builder::new()
            .name("bp-http80".to_owned())
            .spawn(move || {
                for incoming in cloned.incoming() {
                    if state.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let stream = match incoming {
                        Ok(s) => s,
                        Err(_) => {
                            if state.shutdown.load(Ordering::Acquire) {
                                break;
                            }
                            continue;
                        }
                    };
                    if state.shutdown.load(Ordering::Acquire) {
                        let _ = stream.shutdown(Shutdown::Both);
                        break;
                    }
                    let peer = match stream.peer_addr() {
                        Ok(a) => a,
                        Err(_) => continue,
                    };
                    let guard = match try_acquire_conn(&state, peer.ip()) {
                        Ok(g) => g,
                        Err(err_kind) => {
                            let proxy_err = match err_kind {
                                AcquireError::PerIpLimit => ProxyError::RateLimited,
                                AcquireError::GlobalLimit => ProxyError::TooManyConnections,
                            };
                            state.stats.record_error(proxy_err);
                            let mut s = stream;
                            let _ = s.set_write_timeout(Some(Duration::from_millis(250)));
                            let _ = proxy_err.write_http_response(&mut s);
                            let _ = s.shutdown(Shutdown::Both);
                            continue;
                        }
                    };
                    let st = Arc::clone(&state);
                    let _ = thread::Builder::new()
                        .name("bp-http80-w".to_owned())
                        .spawn(move || {
                            let conn_guard = guard;
                            handle_http80_connection(stream, peer, &st);
                            drop(conn_guard);
                        });
                }
            })
            .map_err(|_| ProxyError::Io(io::ErrorKind::Other))?;
        Ok(Some(handle))
    }

    fn spawn_signal_watcher(&self) -> Option<thread::JoinHandle<()>> {
        if !self.state.watch_signals.load(Ordering::Acquire) {
            return None;
        }
        let state = Arc::clone(&self.state);
        thread::Builder::new()
            .name("bp-signals".to_owned())
            .spawn(move || {
                while !state.shutdown.load(Ordering::Acquire) {
                    if take_sighup() {
                        if let Err(err) = state.reload_all() {
                            eprintln!("zero-proxy SIGHUP reload failed (kept previous): {}", err);
                        } else {
                            eprintln!(
                                "zero-proxy reloaded config & certs (gen={})",
                                state.reload_count.load(Ordering::Acquire)
                            );
                        }
                    }
                    if shutdown_requested() {
                        state.request_shutdown();
                        break;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            })
            .ok()
    }

    fn spawn_acme_renewal_thread(&self) -> Option<thread::JoinHandle<()>> {
        let cfg = self.state.current_config();
        let store = self.state.tls_store.as_ref()?;
        if cfg.acme_domains.is_empty() || cfg.cert_dir.is_none() {
            return None;
        }
        let state = Arc::clone(&self.state);
        let cert_store = Arc::clone(store);
        thread::Builder::new()
            .name("bp-acme".to_owned())
            .spawn(move || {
                loop {
                    if state.shutdown.load(Ordering::Acquire) {
                        break;
                    }
                    let cur_cfg = state.current_config();
                    if !cur_cfg.acme_domains.is_empty() {
                        let _ = run_renewal_pass(&cur_cfg, &cert_store, &state.acme_challenges);
                    }
                    let interval = Duration::from_secs(cur_cfg.acme_check_interval_secs);
                    let wake_at = Instant::now() + interval;
                    while Instant::now() < wake_at && !state.shutdown.load(Ordering::Acquire) {
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            })
            .ok()
    }
}

enum AcquireError {
    GlobalLimit,
    PerIpLimit,
}

struct ConnectionGuard {
    counter: Arc<ProxyState>,
    _ip_guard: ConnGuard,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.active_conns.fetch_sub(1, Ordering::AcqRel);
    }
}

fn try_acquire_conn(state: &Arc<ProxyState>, peer_ip: IpAddr) -> Result<ConnectionGuard, AcquireError> {
    let Some(ip_guard) = state.current_ip_conn_limiter().try_acquire(peer_ip) else {
        return Err(AcquireError::PerIpLimit);
    };
    let max_conns = state.current_config().max_connections;
    if try_increment_bounded(&state.active_conns, max_conns) {
        Ok(ConnectionGuard {
            counter: Arc::clone(state),
            _ip_guard: ip_guard,
        })
    } else {
        Err(AcquireError::GlobalLimit)
    }
}

fn try_increment_bounded(counter: &AtomicUsize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return false;
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn handle_primary_connection(stream: TcpStream, peer: SocketAddr, state: &ProxyState) {
    let _ = stream.set_nodelay(true);
    let cfg = state.current_config();

    if !state.current_limiter().allow_ip(peer.ip()) {
        state.stats.requests_total.fetch_add(1, Ordering::Relaxed);
        state.stats.record_error(ProxyError::RateLimited);
        if state.tls_store.is_none() {
            let mut s = stream;
            let _ = s.set_write_timeout(Some(Duration::from_millis(250)));
            let _ = ProxyError::RateLimited.write_http_response(&mut s);
            let _ = s.shutdown(Shutdown::Both);
        } else {
            let _ = stream.shutdown(Shutdown::Both);
        }
        return;
    }

    let mut transport = match &state.tls_store {
        Some(store) => {
            let hs_timeout = Duration::from_millis(cfg.header_timeout_ms);
            match TlsServerStream::accept(stream, Arc::clone(store), hs_timeout) {
                Ok(tls_stream) => ClientTransport::Tls(tls_stream),
                Err(err) => {
                    state.stats.requests_total.fetch_add(1, Ordering::Relaxed);
                    state.stats.record_error(err);
                    return;
                }
            }
        }
        None => ClientTransport::Plain(stream),
    };

    let write_timeout = Duration::from_millis(cfg.idle_timeout_ms);
    let _ = transport.set_write_timeout(Some(write_timeout));

    state.stats.requests_total.fetch_add(1, Ordering::Relaxed);

    // Two fixed 64 KiB heap-allocated slices per worker; zero Vec growth for the entire exchange.
    let mut in_buf = vec![0u8; STREAM_BUFFER_BYTES].into_boxed_slice();
    let mut out_buf = vec![0u8; STREAM_BUFFER_BYTES].into_boxed_slice();

    let mut response_started = false;
    match handle_single_request(
        &mut transport,
        peer,
        &cfg,
        state,
        &mut in_buf,
        &mut out_buf,
        &mut response_started,
    ) {
        Ok(true) => {
            state.stats.requests_ok.fetch_add(1, Ordering::Relaxed);
        }
        Ok(false) => {
            // Client closed connection cleanly before sending any bytes.
        }
        Err(err) => {
            state.stats.record_error(err);
            if !response_started {
                let is_tls = transport.is_tls();
                let _ = err.write_http_response_tls(&mut transport, is_tls);
            }
        }
    }
    let _ = transport.shutdown(Shutdown::Both);
}

fn handle_http80_connection(stream: TcpStream, peer: SocketAddr, state: &ProxyState) {
    let _ = stream.set_nodelay(true);
    let cfg = state.current_config();
    let mut transport = ClientTransport::Plain(stream);
    let _ = transport.set_write_timeout(Some(Duration::from_millis(cfg.idle_timeout_ms)));

    if !state.current_limiter().allow_ip(peer.ip()) {
        state.stats.record_error(ProxyError::RateLimited);
        let _ = ProxyError::RateLimited.write_http_response(&mut transport);
        let _ = transport.shutdown(Shutdown::Both);
        return;
    }

    let mut in_buf = vec![0u8; cfg.max_header_bytes.min(STREAM_BUFFER_BYTES)].into_boxed_slice();
    let header_deadline = Instant::now() + Duration::from_millis(cfg.header_timeout_ms);
    let res = (|| -> Result<(), ProxyError> {
        let Some((filled, _)) =
            read_headers_with_deadline(&mut transport, &mut in_buf, header_deadline)?
        else {
            return Ok(());
        };
        let req = parse_request(&in_buf[..filled], cfg.max_body_bytes, cfg.max_headers)?;
        let is_head = req.method.eq_ignore_ascii_case("HEAD");

        if let Some(token) = extract_http01_token(req.target) {
            if !req.method.eq_ignore_ascii_case("GET") && !is_head {
                return Err(ProxyError::MethodNotAllowed);
            }
            let Some(key_auth) = state.acme_challenges.get(token) else {
                return Err(ProxyError::NotFound);
            };
            let n = write_acme_challenge_response(&mut transport, &key_auth, is_head)?;
            state.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            state.stats.requests_ok.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }

        let host_raw = req
            .host()
            .ok_or(ProxyError::BadRequest("missing Host header\n"))?;
        let host = strip_host_port(host_raw);
        if host.is_empty() {
            return Err(ProxyError::BadRequest("empty Host header\n"));
        }
        let mut base = String::with_capacity(8 + host.len());
        base.push_str("https://");
        base.push_str(host);
        let n = write_redirect_response(&mut transport, &base, req.target)?;
        state.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
        state.stats.requests_ok.fetch_add(1, Ordering::Relaxed);
        Ok(())
    })();

    if let Err(err) = res {
        state.stats.record_error(err);
        let _ = err.write_http_response(&mut transport);
    }
    let _ = transport.shutdown(Shutdown::Both);
}

fn handle_single_request(
    client: &mut ClientTransport,
    peer: SocketAddr,
    cfg: &ProxyConfig,
    state: &ProxyState,
    in_buf: &mut [u8],
    out_buf: &mut [u8],
    response_started: &mut bool,
) -> Result<bool, ProxyError> {
    let header_deadline = Instant::now() + Duration::from_millis(cfg.header_timeout_ms);

    let Some((filled, _header_end)) =
        read_headers_with_deadline(client, &mut in_buf[..cfg.max_header_bytes], header_deadline)?
    else {
        return Ok(false);
    };

    let req = parse_request(&in_buf[..filled], u64::MAX, cfg.max_headers)?;
    let is_head = req.method.eq_ignore_ascii_case("HEAD");
    let req_host = req.host();
    let effective_max_body = cfg.effective_max_body_bytes(req_host, req.target);
    if let Some(cl) = req.content_length {
        if cl > effective_max_body {
            return Err(ProxyError::PayloadTooLarge);
        }
    }
    let is_tls = client.is_tls();
    let path_end = req.target.find('?').unwrap_or(req.target.len());
    let req_path = &req.target[..path_end];

    // 1. Serve active ACME HTTP-01 challenge tokens if requested on primary listener too.
    if let Some(token) = extract_http01_token(req.target) {
        if let Some(key_auth) = state.acme_challenges.get(token) {
            if !req.method.eq_ignore_ascii_case("GET") && !is_head {
                return Err(ProxyError::MethodNotAllowed);
            }
            *response_started = true;
            let n = write_acme_challenge_response(client, &key_auth, is_head)?;
            state.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            return Ok(true);
        }
    }

    // 2. Per-host 301 redirect rules (e.g. www.example.com -> https://example.com).
    if let Some(host) = req_host {
        if let Some(redir) = cfg.match_redirect(host) {
            *response_started = true;
            let n = write_redirect_response_tls(client, &redir.target_base, req.target, is_tls)?;
            state.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
            return Ok(true);
        }
    }

    // 3. Cryptographic integrity manifest (/.well-known/edge-integrity.json).
    if req_path == "/.well-known/edge-integrity.json" {
        if !req.method.eq_ignore_ascii_case("GET") && !is_head {
            return Err(ProxyError::MethodNotAllowed);
        }
        serve_integrity_manifest(
            client,
            req_host,
            cfg,
            state,
            is_head,
            out_buf,
            response_started,
        )?;
        return Ok(true);
    }

    // 3b. Hybrid post-quantum TLS 1.3 channel binding manifest (/.well-known/blindbind).
    if req_path == "/.well-known/blindbind" {
        if !req.method.eq_ignore_ascii_case("GET") && !is_head {
            return Err(ProxyError::MethodNotAllowed);
        }
        serve_blindbind_manifest(client, req_host, state, is_head, out_buf, response_started)?;
        return Ok(true);
    }

    // 3c. Optional client BlindBind proof verification (RFC 8446 Section 7.5).
    let blindbind_key_sha256 = verify_optional_client_blindbind(client, req_host, req.headers())?;

    // 4. Per-path 308 Permanent Redirect rules (preserving ?query).
    if let Some(redir) = cfg.match_path_redirect(req_host, req.target) {
        let query = &req.target[path_end..];
        *response_started = true;
        let n = write_path_redirect_response(client, &redir.to, query, is_tls)?;
        state.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
        return Ok(true);
    }

    // 5. Static file serving (host-scoped or wildcard) with RFC 9530 Content-Digest.
    if let Some(static_route) = cfg.match_static_for_host(req_host, req.target) {
        if !req.method.eq_ignore_ascii_case("GET") && !is_head {
            return Err(ProxyError::MethodNotAllowed);
        }
        serve_static_file(
            client,
            static_route,
            cfg,
            state,
            is_head,
            out_buf,
            response_started,
        )?;
        return Ok(true);
    }

    // 6. Host-aware reverse proxy route matching and fixed-buffer streaming.
    let route = cfg
        .match_route_for_host(req_host, req.target)
        .ok_or(ProxyError::NotFound)?;
    let permissions_policy = cfg.effective_permissions_policy(req_host, req.target);
    let req_header_end = req.header_end;
    let req_is_chunked = req.is_chunked;
    let req_content_length = req.content_length;

    let req_head_len = write_forwarded_request_head_blindbind(
        out_buf,
        &req,
        route,
        peer.ip(),
        is_tls,
        blindbind_key_sha256.as_deref(),
    )?;

    let upstream_timeout = Duration::from_millis(cfg.upstream_timeout_ms);
    let mut upstream = TcpStream::connect_timeout(&route.upstream, upstream_timeout).map_err(|e| {
        if is_timeout(&e) {
            ProxyError::UpstreamTimeout
        } else {
            ProxyError::UpstreamUnavailable
        }
    })?;
    let _ = upstream.set_nodelay(true);
    let _ = upstream.set_write_timeout(Some(upstream_timeout));
    let _ = upstream.set_read_timeout(Some(upstream_timeout));

    upstream
        .write_all(&out_buf[..req_head_len])
        .map_err(map_upstream_io)?;
    state
        .stats
        .bytes_in
        .fetch_add(req_header_end as u64, Ordering::Relaxed);

    // Forward client request body (if any) using the fixed 64 KiB buffer.
    let idle_timeout = Duration::from_millis(cfg.idle_timeout_ms);
    let _ = client.set_read_timeout(Some(idle_timeout));

    let body_prefix = &in_buf[req_header_end..filled];
    if req_is_chunked {
        let body_bytes = stream_chunked_request_body(
            client,
            &mut upstream,
            body_prefix,
            effective_max_body,
            out_buf,
        )?;
        state
            .stats
            .bytes_in
            .fetch_add(body_bytes, Ordering::Relaxed);
    } else if let Some(cl) = req_content_length {
        if cl > 0 {
            let copied = stream_exact_bytes(
                client,
                &mut upstream,
                body_prefix,
                cl,
                out_buf,
                CopyErrors {
                    timeout: ProxyError::IdleTimeout,
                    eof: ProxyError::BadRequest("truncated request body\n"),
                    write: ProxyError::UpstreamUnavailable,
                },
            )?;
            state.stats.bytes_in.fetch_add(copied, Ordering::Relaxed);
        }
    }

    // Read upstream response headers into `in_buf` with upstream deadline.
    let resp_deadline = Instant::now() + upstream_timeout;
    let resp_hdr_cap = cfg.max_header_bytes.min(STREAM_BUFFER_BYTES);
    let mut upstream_transport = ClientTransport::Plain(upstream);
    let (resp_filled, _) = read_headers_with_deadline(
        &mut upstream_transport,
        &mut in_buf[..resp_hdr_cap],
        resp_deadline,
    )
    .map_err(|e| match e {
        ProxyError::HeaderTimeout => ProxyError::UpstreamTimeout,
        _ => ProxyError::UpstreamUnavailable,
    })?
    .ok_or(ProxyError::UpstreamUnavailable)?;

    let resp = parse_response_head(&in_buf[..resp_filled], cfg.max_headers)?;
    let resp_head_len =
        write_forwarded_response_head_with_policy(out_buf, &resp, is_tls, permissions_policy)?;

    *response_started = true;
    client.write_all(&out_buf[..resp_head_len])?;
    state
        .stats
        .bytes_out
        .fetch_add(resp_head_len as u64, Ordering::Relaxed);

    if !resp.has_no_body(is_head) {
        let resp_prefix = &in_buf[resp.header_end..resp_filled];
        if let Some(cl) = resp.content_length {
            if cl > 0 {
                let copied = stream_exact_bytes(
                    &mut upstream_transport,
                    client,
                    resp_prefix,
                    cl,
                    out_buf,
                    CopyErrors {
                        timeout: ProxyError::UpstreamTimeout,
                        eof: ProxyError::UpstreamUnavailable,
                        write: ProxyError::Io(io::ErrorKind::BrokenPipe),
                    },
                )?;
                state.stats.bytes_out.fetch_add(copied, Ordering::Relaxed);
            }
        } else {
            let copied = stream_until_eof(&mut upstream_transport, client, resp_prefix, out_buf)?;
            state.stats.bytes_out.fetch_add(copied, Ordering::Relaxed);
        }
    }

    Ok(true)
}

fn hash_file_streaming(path: &Path, buf: &mut [u8]) -> Result<(u64, [u8; 32]), ProxyError> {
    let mut file = File::open(path).map_err(|_| ProxyError::NotFound)?;
    let meta = file.metadata().map_err(|_| ProxyError::NotFound)?;
    if !meta.is_file() {
        return Err(ProxyError::Forbidden);
    }
    let file_len = meta.len();
    let digest = hash_open_file(&mut file, file_len, buf)?;
    Ok((file_len, digest))
}

fn hash_open_file(file: &mut File, file_len: u64, buf: &mut [u8]) -> Result<[u8; 32], ProxyError> {
    let mut hasher = Sha256::new();
    let mut remaining = file_len;
    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = match file.read(&mut buf[..want]) {
            Ok(0) => return Err(ProxyError::Io(io::ErrorKind::UnexpectedEof)),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProxyError::Io(e.kind())),
        };
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize())
}

fn serve_integrity_manifest(
    client: &mut ClientTransport,
    req_host: Option<&str>,
    cfg: &ProxyConfig,
    state: &ProxyState,
    is_head: bool,
    out_buf: &mut [u8],
    response_started: &mut bool,
) -> Result<(), ProxyError> {
    let is_tls = client.is_tls();
    let host_only = req_host.map(strip_host_port).unwrap_or("");
    let cert_info = state
        .tls_store
        .as_ref()
        .and_then(|store| store.leaf_cert_info(req_host.map(strip_host_port)));

    let mut body = String::with_capacity(512);
    let _ = write!(
        body,
        "{{\"schema\":\"zero-proxy.integrity.v1\",\"host\":{},\"tls_min_version\":{},",
        json_escape_str(host_only),
        json_escape_str(cfg.tls_min_version.as_str())
    );
    if let Some(info) = cert_info {
        let cn_json = match &info.cn {
            Some(cn) => json_escape_str(cn),
            None => "null".to_owned(),
        };
        let _ = write!(
            body,
            "\"cert_spki_sha256\":{},\"cert_spki_sha256_hex\":{},\"cert_sha256_hex\":{},\"cert_serial_hex\":{},\"cert_cn\":{},\"cert_days_remaining\":{},",
            json_escape_str(&info.spki_sha256_b64),
            json_escape_str(&info.spki_sha256_hex),
            json_escape_str(&info.cert_sha256_hex),
            json_escape_str(&info.serial_hex),
            cn_json,
            info.days_remaining
        );
    } else {
        body.push_str(
            "\"cert_spki_sha256\":null,\"cert_spki_sha256_hex\":null,\"cert_sha256_hex\":null,\"cert_serial_hex\":null,\"cert_cn\":null,\"cert_days_remaining\":null,",
        );
    }

    body.push_str("\"static_assets\":[");
    let mut first = true;
    for st in &cfg.static_routes {
        if !st.matches_host(req_host) {
            continue;
        }
        let Ok((size_bytes, digest)) = hash_file_streaming(&st.file_path, out_buf) else {
            continue;
        };
        if !first {
            body.push(',');
        }
        first = false;
        let digest_hex = hex_encode(&digest);
        let digest_b64 = base64_encode(&digest);
        let content_digest = format!("sha-256=:{}:", digest_b64);
        let _ = write!(
            body,
            "{{\"path\":{},\"size_bytes\":{},\"sha256_hex\":{},\"content_digest\":{}}}",
            json_escape_str(&st.path),
            size_bytes,
            json_escape_str(&digest_hex),
            json_escape_str(&content_digest)
        );
    }
    body.push_str("]}\n");

    write_json_manifest_response(
        client,
        &body,
        is_tls,
        is_head,
        state,
        out_buf,
        response_started,
    )
}

fn read_os_random_32() -> Result<[u8; 32], ProxyError> {
    #[cfg(miri)]
    {
        Ok([0x42u8; 32])
    }
    #[cfg(not(miri))]
    {
        let mut seed = [0u8; 32];
        let mut f = File::open("/dev/urandom")
            .map_err(|_| ProxyError::Config("failed to open /dev/urandom for blindbind seed"))?;
        f.read_exact(&mut seed)
            .map_err(|_| ProxyError::Config("failed to read blindbind seed from /dev/urandom"))?;
        Ok(seed)
    }
}

fn load_or_generate_blindbind_keypair(seed_file: Option<&Path>) -> Result<HybridKeyPair, ProxyError> {
    if let Some(path) = seed_file {
        if path.exists() {
            let mut raw = std::fs::read(path)
                .map_err(|_| ProxyError::Config("failed to read blindbind_seed_file"))?;
            if raw.len() != 32 {
                zeroize_bytes(&mut raw);
                return Err(ProxyError::Config(
                    "blindbind_seed_file must be exactly 32 bytes",
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            zeroize_bytes(&mut raw);
            let kp = HybridKeyPair::from_master_seed(&seed);
            zeroize_bytes(&mut seed);
            return Ok(kp);
        }
        let mut seed = read_os_random_32()?;
        let write_res = write_atomic_0600(path, &seed)
            .map_err(|_| ProxyError::Config("failed to persist blindbind_seed_file"));
        if let Err(err) = write_res {
            zeroize_bytes(&mut seed);
            return Err(err);
        }
        let kp = HybridKeyPair::from_master_seed(&seed);
        zeroize_bytes(&mut seed);
        return Ok(kp);
    }

    let mut seed = read_os_random_32()?;
    let kp = HybridKeyPair::from_master_seed(&seed);
    zeroize_bytes(&mut seed);
    Ok(kp)
}

fn verify_optional_client_blindbind(
    client: &ClientTransport,
    req_host: Option<&str>,
    headers: &[HeaderView<'_>],
) -> Result<Option<String>, ProxyError> {
    let Some((client_pk, proof)) = parse_blindbind_headers(headers)? else {
        return Ok(None);
    };
    let context = normalize_blindbind_context(req_host);
    let mut secret = match client.export_tls13_keying_material(EXPORTER_LABEL, context.as_bytes()) {
        Ok(Some(secret)) => secret,
        Ok(None) | Err(_) => {
            return Err(ProxyError::Unauthorized(
                "blindbind proof requires TLS 1.3\n",
            ));
        }
    };
    let verify_res = verify_binding(
        &client_pk,
        &secret,
        Role::Client,
        context.as_bytes(),
        &proof,
    );
    zeroize_bytes(&mut secret);
    verify_res.map_err(|_| ProxyError::Unauthorized("blindbind verification failed\n"))?;
    let pk_bytes = client_pk.to_bytes();
    Ok(Some(hex_encode(&sha256(&pk_bytes))))
}

fn serve_blindbind_manifest(
    client: &mut ClientTransport,
    req_host: Option<&str>,
    state: &ProxyState,
    is_head: bool,
    out_buf: &mut [u8],
    response_started: &mut bool,
) -> Result<(), ProxyError> {
    let is_tls = client.is_tls();
    let context = normalize_blindbind_context(req_host);
    let pk_bytes = state.blindbind_keypair.public_key().to_bytes();
    let pk_sha256_hex = hex_encode(&sha256(&pk_bytes));
    let pk_b64url = base64url_encode(&pk_bytes);

    let proof_b64url =
        match client.export_tls13_keying_material(EXPORTER_LABEL, context.as_bytes()) {
            Ok(Some(mut secret)) => {
                let bind_res = state
                    .blindbind_keypair
                    .bind(&secret, Role::Server, context.as_bytes());
                zeroize_bytes(&mut secret);
                let proof = bind_res
                    .map_err(|_| ProxyError::Tls("blindbind server signing failed"))?;
                Some(base64url_encode(&proof.to_bytes()))
            }
            Ok(None) | Err(_) => None,
        };

    let label_str = std::str::from_utf8(EXPORTER_LABEL).unwrap_or("");
    let mut body = String::with_capacity(10_500);
    let _ = write!(
        body,
        "{{\"schema\":\"zero-proxy.blindbind.v1\",\"host\":{},\"exporter_label\":{},\"role\":\"server\",\"pubkey_bytes\":{},\"proof_bytes\":{},\"pubkey_sha256_hex\":{},\"pubkey_b64url\":{},\"tls13_bound\":{},\"proof_b64url\":",
        json_escape_str(&context),
        json_escape_str(label_str),
        HYBRID_PUBLIC_KEY_LEN,
        HYBRID_PROOF_LEN,
        json_escape_str(&pk_sha256_hex),
        json_escape_str(&pk_b64url),
        if proof_b64url.is_some() { "true" } else { "false" },
    );
    match proof_b64url {
        Some(ref proof_tok) => body.push_str(&json_escape_str(proof_tok)),
        None => body.push_str("null"),
    }
    body.push_str("}\n");

    write_json_manifest_response(
        client,
        &body,
        is_tls,
        is_head,
        state,
        out_buf,
        response_started,
    )
}

fn write_json_manifest_response(
    client: &mut ClientTransport,
    body: &str,
    is_tls: bool,
    is_head: bool,
    state: &ProxyState,
    out_buf: &mut [u8],
    response_started: &mut bool,
) -> Result<(), ProxyError> {
    let body_digest = sha256(body.as_bytes());
    let body_digest_b64 = base64_encode(&body_digest);
    let head_len =
        write_integrity_response_head(out_buf, body.len() as u64, &body_digest_b64, is_tls)?;

    *response_started = true;
    client.write_all(&out_buf[..head_len])?;
    state
        .stats
        .bytes_out
        .fetch_add(head_len as u64, Ordering::Relaxed);
    if !is_head {
        client.write_all(body.as_bytes())?;
        state
            .stats
            .bytes_out
            .fetch_add(body.len() as u64, Ordering::Relaxed);
    }
    Ok(())
}

fn serve_static_file(
    client: &mut ClientTransport,
    route: &StaticRoute,
    cfg: &ProxyConfig,
    state: &ProxyState,
    is_head: bool,
    out_buf: &mut [u8],
    response_started: &mut bool,
) -> Result<(), ProxyError> {
    let mut file = File::open(&route.file_path).map_err(|_| ProxyError::NotFound)?;
    let meta = file.metadata().map_err(|_| ProxyError::NotFound)?;
    if !meta.is_file() {
        return Err(ProxyError::Forbidden);
    }
    let file_len = meta.len();
    let digest = hash_open_file(&mut file, file_len, out_buf)?;
    let digest_b64 = base64_encode(&digest);
    file.seek(SeekFrom::Start(0))?;

    let content_type = content_type_for_path(&route.file_path);
    let allow_cors = cfg.static_allows_cors(&route.path);
    let head_len = write_static_response_head_cors(
        out_buf,
        content_type,
        file_len,
        Some(&digest_b64),
        cfg.static_csp.as_deref(),
        client.is_tls(),
        allow_cors,
    )?;

    *response_started = true;
    client.write_all(&out_buf[..head_len])?;
    state
        .stats
        .bytes_out
        .fetch_add(head_len as u64, Ordering::Relaxed);

    if !is_head && file_len > 0 {
        let copied = stream_exact_bytes(
            &mut file,
            client,
            b"",
            file_len,
            out_buf,
            CopyErrors {
                timeout: ProxyError::IdleTimeout,
                eof: ProxyError::Io(io::ErrorKind::UnexpectedEof),
                write: ProxyError::Io(io::ErrorKind::BrokenPipe),
            },
        )?;
        state.stats.bytes_out.fetch_add(copied, Ordering::Relaxed);
    }
    Ok(())
}

fn read_headers_with_deadline(
    stream: &mut ClientTransport,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<Option<(usize, usize)>, ProxyError> {
    let mut filled = 0usize;
    loop {
        let now = Instant::now();
        let remaining = deadline.saturating_duration_since(now);
        if remaining.is_zero() {
            return Err(ProxyError::HeaderTimeout);
        }
        stream.set_read_timeout(Some(remaining))?;

        let n = match stream.read(&mut buf[filled..]) {
            Ok(n) => n,
            Err(e) if is_timeout(&e) => return Err(ProxyError::HeaderTimeout),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProxyError::Io(e.kind())),
        };

        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(ProxyError::BadRequest("truncated request headers\n"));
        }
        filled += n;

        if let Some(end) = scan_header_terminator(&buf[..filled])? {
            return Ok(Some((filled, end)));
        }

        if filled == buf.len() {
            return Err(ProxyError::HeadersTooLarge);
        }
    }
}

#[derive(Clone, Copy)]
struct CopyErrors {
    timeout: ProxyError,
    eof: ProxyError,
    write: ProxyError,
}

fn stream_exact_bytes<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    initial_prefix: &[u8],
    total_len: u64,
    copy_buf: &mut [u8],
    errs: CopyErrors,
) -> Result<u64, ProxyError> {
    let mut remaining = total_len;
    let mut copied = 0u64;

    if !initial_prefix.is_empty() && remaining > 0 {
        let take = initial_prefix.len().min(remaining as usize);
        writer
            .write_all(&initial_prefix[..take])
            .map_err(|_| errs.write)?;
        remaining -= take as u64;
        copied += take as u64;
    }

    while remaining > 0 {
        let want = copy_buf.len().min(remaining as usize);
        let n = match reader.read(&mut copy_buf[..want]) {
            Ok(0) => return Err(errs.eof),
            Ok(n) => n,
            Err(e) if is_timeout(&e) => return Err(errs.timeout),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProxyError::Io(e.kind())),
        };
        writer.write_all(&copy_buf[..n]).map_err(|_| errs.write)?;
        remaining -= n as u64;
        copied += n as u64;
    }

    Ok(copied)
}

fn stream_until_eof<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    initial_prefix: &[u8],
    copy_buf: &mut [u8],
) -> Result<u64, ProxyError> {
    let mut copied = 0u64;
    if !initial_prefix.is_empty() {
        writer.write_all(initial_prefix)?;
        copied += initial_prefix.len() as u64;
    }
    loop {
        let n = match reader.read(copy_buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if is_timeout(&e) => return Err(ProxyError::UpstreamTimeout),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProxyError::Io(e.kind())),
        };
        writer.write_all(&copy_buf[..n])?;
        copied += n as u64;
    }
    Ok(copied)
}

/// Streams a `Transfer-Encoding: chunked` request body while enforcing `max_body_bytes`
/// and strict CRLF chunk framing without dynamic allocations.
fn stream_chunked_request_body<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    initial_prefix: &[u8],
    max_body_bytes: u64,
    copy_buf: &mut [u8],
) -> Result<u64, ProxyError> {
    struct PrefixedReader<'a, R> {
        prefix: &'a [u8],
        pos: usize,
        inner: &'a mut R,
    }
    impl<R: Read> PrefixedReader<'_, R> {
        fn read_byte(&mut self) -> Result<u8, ProxyError> {
            if self.pos < self.prefix.len() {
                let b = self.prefix[self.pos];
                self.pos += 1;
                return Ok(b);
            }
            let mut single = [0u8; 1];
            loop {
                match self.inner.read(&mut single) {
                    Ok(0) => return Err(ProxyError::BadRequest("truncated chunked body\n")),
                    Ok(_) => return Ok(single[0]),
                    Err(e) if is_timeout(&e) => return Err(ProxyError::IdleTimeout),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(ProxyError::Io(e.kind())),
                }
            }
        }

        fn read_exact_chunk(
            &mut self,
            remaining: u64,
            writer: &mut impl Write,
            buf: &mut [u8],
        ) -> Result<(), ProxyError> {
            let rem_prefix = &self.prefix[self.pos..];
            let used_prefix = rem_prefix.len().min(remaining as usize);
            stream_exact_bytes(
                self.inner,
                writer,
                rem_prefix,
                remaining,
                buf,
                CopyErrors {
                    timeout: ProxyError::IdleTimeout,
                    eof: ProxyError::BadRequest("truncated chunk data\n"),
                    write: ProxyError::UpstreamUnavailable,
                },
            )?;
            self.pos += used_prefix;
            Ok(())
        }
    }

    let mut src = PrefixedReader {
        prefix: initial_prefix,
        pos: 0,
        inner: reader,
    };
    let mut total_decoded = 0u64;
    let mut line_buf = [0u8; 64];

    loop {
        let mut line_len = 0usize;
        loop {
            let b = src.read_byte()?;
            if b == b'\r' {
                let lf = src.read_byte()?;
                if lf != b'\n' {
                    return Err(ProxyError::BadRequest("bare CR in chunk size\n"));
                }
                break;
            }
            if b == b'\n' {
                return Err(ProxyError::BadRequest("bare LF in chunk size\n"));
            }
            if line_len >= line_buf.len() {
                return Err(ProxyError::BadRequest("chunk size line too long\n"));
            }
            line_buf[line_len] = b;
            line_len += 1;
        }

        let size_line = &line_buf[..line_len];
        let hex_part = match size_line.iter().position(|&b| b == b';') {
            Some(semi) => &size_line[..semi],
            None => size_line,
        };
        let chunk_size =
            parse_hex_u64(hex_part).ok_or(ProxyError::BadRequest("invalid chunk size\n"))?;

        if chunk_size == 0 {
            let cr = src.read_byte()?;
            let lf = src.read_byte()?;
            if cr != b'\r' || lf != b'\n' {
                return Err(ProxyError::BadRequest("invalid chunked terminator\n"));
            }
            writer
                .write_all(b"0\r\n\r\n")
                .map_err(|_| ProxyError::UpstreamUnavailable)?;
            return Ok(total_decoded);
        }

        total_decoded = total_decoded
            .checked_add(chunk_size)
            .ok_or(ProxyError::PayloadTooLarge)?;
        if total_decoded > max_body_bytes {
            return Err(ProxyError::PayloadTooLarge);
        }

        let mut hdr_buf = [0u8; 24];
        let mut hdr_cur = io::Cursor::new(&mut hdr_buf[..]);
        write!(hdr_cur, "{:x}\r\n", chunk_size).map_err(|_| ProxyError::UpstreamUnavailable)?;
        let hdr_n = hdr_cur.position() as usize;
        writer
            .write_all(&hdr_buf[..hdr_n])
            .map_err(|_| ProxyError::UpstreamUnavailable)?;

        src.read_exact_chunk(chunk_size, writer, copy_buf)?;

        let cr = src.read_byte()?;
        let lf = src.read_byte()?;
        if cr != b'\r' || lf != b'\n' {
            return Err(ProxyError::BadRequest("missing CRLF after chunk data\n"));
        }
        writer
            .write_all(b"\r\n")
            .map_err(|_| ProxyError::UpstreamUnavailable)?;
    }
}

fn parse_hex_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc = 0u64;
    for &b in bytes {
        let digit = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' => u64::from(b - b'a' + 10),
            b'A'..=b'F' => u64::from(b - b'A' + 10),
            _ => return None,
        };
        acc = acc.checked_mul(16)?.checked_add(digit)?;
    }
    Some(acc)
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn map_upstream_io(err: io::Error) -> ProxyError {
    if is_timeout(&err) {
        ProxyError::UpstreamTimeout
    } else {
        ProxyError::UpstreamUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_copy_errs(eof_msg: &'static str) -> CopyErrors {
        CopyErrors {
            timeout: ProxyError::IdleTimeout,
            eof: ProxyError::BadRequest(eof_msg),
            write: ProxyError::UpstreamUnavailable,
        }
    }

    #[test]
    fn stream_exact_bytes_prefix_and_truncation() {
        let mut reader = io::Cursor::new(b"world!EXTRA".to_vec());
        let mut writer = Vec::new();
        let mut buf = [0u8; 4];
        let copied = stream_exact_bytes(
            &mut reader,
            &mut writer,
            b"hello ",
            12,
            &mut buf,
            make_copy_errs("eof"),
        )
        .expect("exact copy");
        assert_eq!((copied, writer.as_slice()), (12, b"hello world!".as_slice()));

        let mut short_reader = io::Cursor::new(b"ab".to_vec());
        let mut out = Vec::new();
        let err = stream_exact_bytes(
            &mut short_reader,
            &mut out,
            b"",
            5,
            &mut buf,
            make_copy_errs("truncated"),
        )
        .unwrap_err();
        assert_eq!(err, ProxyError::BadRequest("truncated"));
    }

    #[test]
    fn stream_chunked_enforces_limit_and_crlf() {
        let mut reader = io::Cursor::new(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec());
        let mut writer = Vec::new();
        let mut buf = [0u8; 16];
        let decoded = stream_chunked_request_body(&mut reader, &mut writer, b"", 32, &mut buf)
            .expect("valid chunked body");
        assert_eq!(decoded, 11);
        assert_eq!(writer, b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n");

        // Enforce 413 PayloadTooLarge on chunked overflow.
        let mut big = io::Cursor::new(b"a\r\n0123456789\r\n0\r\n\r\n".to_vec());
        let mut out = Vec::new();
        let err = stream_chunked_request_body(&mut big, &mut out, b"", 8, &mut buf).unwrap_err();
        assert_eq!(err, ProxyError::PayloadTooLarge);

        // Reject bare LF in chunk framing.
        let mut bad = io::Cursor::new(b"1\na\r\n0\r\n\r\n".to_vec());
        let err2 = stream_chunked_request_body(&mut bad, &mut out, b"", 32, &mut buf).unwrap_err();
        assert_eq!(err2.status_code(), 400);
    }

    #[test]
    fn bounded_connection_counter_respects_cap() {
        let counter = AtomicUsize::new(0);
        assert!(try_increment_bounded(&counter, 2));
        assert!(try_increment_bounded(&counter, 2));
        assert!(!try_increment_bounded(&counter, 2));
        assert_eq!(counter.load(Ordering::Acquire), 2);
    }
}
