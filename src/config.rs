use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::error::ProxyError;
use crate::ratelimit::MAX_BURST_TOKENS;

/// Hard ceiling for the reusable fixed header/stream buffer (`64 KiB`).
pub const STREAM_BUFFER_BYTES: usize = 65_536;

/// Default maximum HTTP request header size (`16 KiB`).
pub const DEFAULT_MAX_HEADER_BYTES: usize = 16 * 1024;

/// Default maximum HTTP request body size (`1 MiB`).
pub const DEFAULT_MAX_BODY_BYTES: u64 = 1_048_576;

/// Default absolute Slowloris header-read deadline (`5 s`).
pub const DEFAULT_HEADER_TIMEOUT_MS: u64 = 5_000;

/// Default connection idle timeout during body streaming (`30 s`).
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// Default upstream connect/read timeout (`10 s`).
pub const DEFAULT_UPSTREAM_TIMEOUT_MS: u64 = 10_000;

/// Default per-IP token-bucket rate (`100 req/s`).
pub const DEFAULT_RATE_LIMIT_RPS: u64 = 100;

/// Default fixed power-of-2 atomic rate-limiter shards (`4096`).
pub const DEFAULT_RATE_LIMIT_SHARDS: usize = 4096;

/// Default maximum concurrent active client connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 1024;

/// Default maximum concurrent active client connections per IP shard.
pub const DEFAULT_MAX_CONNS_PER_IP: u32 = 64;

/// Maximum number of HTTP headers parsed without heap allocation.
pub const MAX_HEADERS_CAP: usize = 64;

/// Default ACME v2 directory URL (override with `--acme-directory` / `acme_directory`).
pub const DEFAULT_ACME_DIRECTORY: &str = "https://acme.example.com/directory";

/// Default certificate renewal threshold in days before expiration.
pub const DEFAULT_ACME_RENEW_DAYS: u32 = 30;

/// Default background ACME renewal check interval (`12 hours`).
pub const DEFAULT_ACME_CHECK_INTERVAL_SECS: u64 = 12 * 3600;

/// Default graceful `SIGTERM`/`SIGINT` connection drain timeout (`10 s`).
pub const DEFAULT_DRAIN_TIMEOUT_MS: u64 = 10_000;

/// Minimum TLS protocol version accepted on the TLS listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMinVersion {
    #[default]
    Tls12,
    Tls13,
}

impl TlsMinVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        }
    }
}

/// Single prefix-to-upstream routing rule (optionally host-scoped, strip or preserve prefix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub host: Option<String>,
    pub prefix: String,
    pub upstream: SocketAddr,
    pub strip_prefix: bool,
}

/// Static file serving rule mapping an exact request path (optionally host-scoped) to a local file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticRoute {
    pub host: Option<String>,
    pub path: String,
    pub file_path: PathBuf,
}

impl StaticRoute {
    /// Returns true if this static route applies to `host_header`.
    pub fn matches_host(&self, host_header: Option<&str>) -> bool {
        match (&self.host, host_header) {
            (None, _) => true,
            (Some(expected), Some(actual)) => {
                expected.eq_ignore_ascii_case(strip_host_port(actual))
            }
            (Some(_), None) => false,
        }
    }
}

/// Per-host `301 Moved Permanently` redirect rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRedirect {
    pub host: String,
    pub target_base: String,
}

/// Per-path `308 Permanent Redirect` rule (e.g. `/app -> /app/`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathRedirect {
    pub host: Option<String>,
    pub from: String,
    pub to: String,
}

/// Generic host-optional prefix-scoped rule sorted longest-prefix-first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixRule<T> {
    pub host: Option<String>,
    pub prefix: String,
    pub value: T,
}

/// Zero-allocation result of matching a request target against the route table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteMatch<'a> {
    pub upstream: SocketAddr,
    pub prepend_slash: bool,
    pub tail: &'a str,
}

/// Action returned by CLI parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    Help,
    Run(Box<ProxyConfig>),
}

/// Complete validated runtime configuration for `zero-proxy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub http_listen: Option<SocketAddr>,
    pub config_path: Option<PathBuf>,
    pub routes: Vec<Route>,
    pub route_max_bodies: Vec<PrefixRule<u64>>,
    pub route_permissions_policies: Vec<PrefixRule<String>>,
    pub static_routes: Vec<StaticRoute>,
    pub redirects: Vec<HostRedirect>,
    pub path_redirects: Vec<PathRedirect>,
    pub cert_dir: Option<PathBuf>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_min_version: TlsMinVersion,
    pub blindbind_seed_file: Option<PathBuf>,
    pub static_csp: Option<String>,
    pub static_cors_prefix: Option<String>,
    pub acme_domains: Vec<String>,
    pub acme_email: Option<String>,
    pub acme_directory: String,
    pub acme_ca_cert: Option<PathBuf>,
    pub acme_renew_days: u32,
    pub acme_check_interval_secs: u64,
    pub max_header_bytes: usize,
    pub max_body_bytes: u64,
    pub header_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub upstream_timeout_ms: u64,
    pub drain_timeout_ms: u64,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u64,
    pub rate_limit_shards: usize,
    pub max_connections: usize,
    pub max_conns_per_ip: u32,
    pub max_headers: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            http_listen: None,
            config_path: None,
            routes: Vec::new(),
            route_max_bodies: Vec::new(),
            route_permissions_policies: Vec::new(),
            static_routes: Vec::new(),
            redirects: Vec::new(),
            path_redirects: Vec::new(),
            cert_dir: None,
            tls_cert: None,
            tls_key: None,
            tls_min_version: TlsMinVersion::Tls12,
            blindbind_seed_file: None,
            static_csp: None,
            static_cors_prefix: None,
            acme_domains: Vec::new(),
            acme_email: None,
            acme_directory: DEFAULT_ACME_DIRECTORY.to_owned(),
            acme_ca_cert: None,
            acme_renew_days: DEFAULT_ACME_RENEW_DAYS,
            acme_check_interval_secs: DEFAULT_ACME_CHECK_INTERVAL_SECS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            header_timeout_ms: DEFAULT_HEADER_TIMEOUT_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            upstream_timeout_ms: DEFAULT_UPSTREAM_TIMEOUT_MS,
            drain_timeout_ms: DEFAULT_DRAIN_TIMEOUT_MS,
            rate_limit_rps: DEFAULT_RATE_LIMIT_RPS,
            rate_limit_burst: DEFAULT_RATE_LIMIT_RPS,
            rate_limit_shards: DEFAULT_RATE_LIMIT_SHARDS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            max_conns_per_ip: DEFAULT_MAX_CONNS_PER_IP,
            max_headers: MAX_HEADERS_CAP,
        }
    }
}

impl ProxyConfig {
    /// Returns true if TLS termination is enabled on the main listener.
    pub fn tls_enabled(&self) -> bool {
        self.cert_dir.is_some()
            || self.tls_cert.is_some()
            || self.tls_key.is_some()
            || !self.acme_domains.is_empty()
    }

    /// Parses CLI arguments (excluding argv[0]), loading `--config` first if provided,
    /// then applying CLI flag overrides and validating all invariants fail-closed.
    pub fn from_args<I, S>(args: I) -> Result<CliAction, ProxyError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let raw: Vec<String> = args.into_iter().map(|s| s.as_ref().to_owned()).collect();

        for arg in &raw {
            if arg == "-h" || arg == "--help" {
                return Ok(CliAction::Help);
            }
        }

        let mut cfg = Self::default();
        let mut burst_explicit = false;

        // First pass: load --config file(s) so subsequent CLI flags always override file values.
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == "--config" {
                let path = raw
                    .get(i + 1)
                    .ok_or(ProxyError::Config("missing value for --config"))?;
                let pb = PathBuf::from(path);
                cfg.load_config_file(&pb, &mut burst_explicit)?;
                cfg.config_path = Some(pb);
                i += 2;
            } else {
                i += 1;
            }
        }

        // Second pass: apply CLI flags.
        let mut j = 0;
        while j < raw.len() {
            let flag = raw[j].as_str();
            if flag == "--config" {
                j += 2;
                continue;
            }
            let val = raw
                .get(j + 1)
                .ok_or(ProxyError::Config("missing value for CLI flag"))?;
            match flag {
                "--listen" => cfg.listen = parse_socket_addr(val)?,
                "--http-listen" => cfg.http_listen = Some(parse_socket_addr(val)?),
                "--route" | "--upstream" => cfg.add_route_spec(val)?,
                "--route-preserve" => cfg.add_route_preserve_spec(val)?,
                "--route-max-body" => cfg.add_route_max_body_spec(val)?,
                "--route-permissions-policy" => cfg.add_route_permissions_policy_spec(val)?,
                "--static" => cfg.add_static_spec(val)?,
                "--redirect" => cfg.add_redirect_spec(val)?,
                "--path-redirect" => cfg.add_path_redirect_spec(val)?,
                "--cert-dir" => cfg.cert_dir = Some(PathBuf::from(val)),
                "--tls-cert" => cfg.tls_cert = Some(PathBuf::from(val)),
                "--tls-key" => cfg.tls_key = Some(PathBuf::from(val)),
                "--tls-min-version" => cfg.tls_min_version = parse_tls_min_version(val)?,
                "--blindbind-seed-file" => cfg.blindbind_seed_file = Some(PathBuf::from(val)),
                "--static-csp" => cfg.static_csp = Some(validate_header_value(val)?),
                "--static-cors-prefix" => cfg.static_cors_prefix = Some(normalize_prefix(val)?),
                "--acme-domain" => cfg.add_acme_domain(val)?,
                "--acme-email" => cfg.acme_email = Some(val.to_owned()),
                "--acme-directory" => cfg.acme_directory = validate_http_url(val)?,
                "--acme-ca-cert" => cfg.acme_ca_cert = Some(PathBuf::from(val)),
                "--acme-renew-days" => {
                    cfg.acme_renew_days = parse_u32(val, "invalid --acme-renew-days")?;
                }
                "--acme-check-interval-secs" => {
                    cfg.acme_check_interval_secs =
                        parse_u64(val, "invalid --acme-check-interval-secs")?;
                }
                "--max-body" => cfg.max_body_bytes = parse_u64(val, "invalid --max-body")?,
                "--max-header-bytes" => {
                    cfg.max_header_bytes = parse_usize(val, "invalid --max-header-bytes")?;
                }
                "--header-timeout-ms" => {
                    cfg.header_timeout_ms = parse_u64(val, "invalid --header-timeout-ms")?;
                }
                "--idle-timeout-ms" => {
                    cfg.idle_timeout_ms = parse_u64(val, "invalid --idle-timeout-ms")?;
                }
                "--upstream-timeout-ms" => {
                    cfg.upstream_timeout_ms = parse_u64(val, "invalid --upstream-timeout-ms")?;
                }
                "--drain-timeout-ms" => {
                    cfg.drain_timeout_ms = parse_u64(val, "invalid --drain-timeout-ms")?;
                }
                "--rps" => {
                    cfg.rate_limit_rps = parse_u64(val, "invalid --rps")?;
                    if !burst_explicit {
                        cfg.rate_limit_burst = cfg.rate_limit_rps;
                    }
                }
                "--burst" => {
                    cfg.rate_limit_burst = parse_u64(val, "invalid --burst")?;
                    burst_explicit = true;
                }
                "--shards" => cfg.rate_limit_shards = parse_usize(val, "invalid --shards")?,
                "--max-connections" => {
                    cfg.max_connections = parse_usize(val, "invalid --max-connections")?;
                }
                "--max-conns-per-ip" => {
                    cfg.max_conns_per_ip = parse_u32(val, "invalid --max-conns-per-ip")?;
                }
                "--max-headers" => {
                    cfg.max_headers = parse_usize(val, "invalid --max-headers")?;
                }
                _ => return Err(ProxyError::Config("unknown CLI flag")),
            }
            j += 2;
        }

        cfg.finalize()?;
        Ok(CliAction::Run(Box::new(cfg)))
    }

    /// Reloads configuration from `self.config_path`, keeping live listening addresses intact.
    pub fn reload_from_file(&self) -> Result<Self, ProxyError> {
        let Some(path) = self.config_path.as_ref() else {
            return Ok(self.clone());
        };
        let mut next = Self::default();
        let mut burst_explicit = false;
        next.load_config_file(path, &mut burst_explicit)?;
        next.listen = self.listen;
        next.http_listen = self.http_listen;
        next.config_path = Some(path.clone());
        if next.cert_dir.is_none() {
            next.cert_dir = self.cert_dir.clone();
        }
        if next.tls_cert.is_none() && next.tls_key.is_none() {
            next.tls_cert = self.tls_cert.clone();
            next.tls_key = self.tls_key.clone();
        }
        if next.blindbind_seed_file.is_none() {
            next.blindbind_seed_file = self.blindbind_seed_file.clone();
        }
        next.finalize()?;
        Ok(next)
    }

    /// Parses a `key=value` (plus `static <path>=<file>` / `redirect <host> -> <url>`)
    /// configuration string into `self`.
    pub fn apply_config_str(
        &mut self,
        contents: &str,
        burst_explicit: &mut bool,
    ) -> Result<(), ProxyError> {
        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "static") {
                self.add_static_spec(rest)?;
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "redirect") {
                self.add_redirect_spec(rest)?;
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "path_redirect") {
                self.add_path_redirect_spec(rest)?;
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "route_preserve") {
                self.add_route_preserve_spec(rest)?;
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "route_max_body") {
                self.add_route_max_body_spec(rest)?;
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "route_permissions_policy") {
                self.add_route_permissions_policy_spec(rest)?;
                continue;
            }
            if let Some(rest) = strip_directive_prefix(line, "route") {
                self.add_route_spec(rest)?;
                continue;
            }
            let (key, val) = line
                .split_once('=')
                .ok_or(ProxyError::Config("config line must be key=value"))?;
            let key = key.trim();
            let val = val.trim();
            if val.is_empty() {
                return Err(ProxyError::Config("config value cannot be empty"));
            }
            match key {
                "listen" => self.listen = parse_socket_addr(val)?,
                "http_listen" => self.http_listen = Some(parse_socket_addr(val)?),
                "route" | "upstream" => self.add_route_spec(val)?,
                "route_preserve" => self.add_route_preserve_spec(val)?,
                "route_max_body" => self.add_route_max_body_spec(val)?,
                "route_permissions_policy" => self.add_route_permissions_policy_spec(val)?,
                "static" => self.add_static_spec(val)?,
                "redirect" => self.add_redirect_spec(val)?,
                "path_redirect" => self.add_path_redirect_spec(val)?,
                "cert_dir" => self.cert_dir = Some(PathBuf::from(val)),
                "tls_cert" => self.tls_cert = Some(PathBuf::from(val)),
                "tls_key" => self.tls_key = Some(PathBuf::from(val)),
                "tls_min_version" => self.tls_min_version = parse_tls_min_version(val)?,
                "blindbind_seed_file" => self.blindbind_seed_file = Some(PathBuf::from(val)),
                "static_csp" => self.static_csp = Some(validate_header_value(val)?),
                "static_cors_prefix" => self.static_cors_prefix = Some(normalize_prefix(val)?),
                "acme_domain" => self.add_acme_domain(val)?,
                "acme_email" => self.acme_email = Some(val.to_owned()),
                "acme_directory" => self.acme_directory = validate_http_url(val)?,
                "acme_ca_cert" => self.acme_ca_cert = Some(PathBuf::from(val)),
                "acme_renew_days" => {
                    self.acme_renew_days = parse_u32(val, "invalid acme_renew_days")?;
                }
                "acme_check_interval_secs" => {
                    self.acme_check_interval_secs =
                        parse_u64(val, "invalid acme_check_interval_secs")?;
                }
                "max_body" => self.max_body_bytes = parse_u64(val, "invalid max_body")?,
                "max_header_bytes" => {
                    self.max_header_bytes = parse_usize(val, "invalid max_header_bytes")?;
                }
                "header_timeout_ms" => {
                    self.header_timeout_ms = parse_u64(val, "invalid header_timeout_ms")?;
                }
                "idle_timeout_ms" => {
                    self.idle_timeout_ms = parse_u64(val, "invalid idle_timeout_ms")?;
                }
                "upstream_timeout_ms" => {
                    self.upstream_timeout_ms = parse_u64(val, "invalid upstream_timeout_ms")?;
                }
                "drain_timeout_ms" => {
                    self.drain_timeout_ms = parse_u64(val, "invalid drain_timeout_ms")?;
                }
                "rps" => {
                    self.rate_limit_rps = parse_u64(val, "invalid rps")?;
                    if !*burst_explicit {
                        self.rate_limit_burst = self.rate_limit_rps;
                    }
                }
                "burst" => {
                    self.rate_limit_burst = parse_u64(val, "invalid burst")?;
                    *burst_explicit = true;
                }
                "shards" => self.rate_limit_shards = parse_usize(val, "invalid shards")?,
                "max_connections" => {
                    self.max_connections = parse_usize(val, "invalid max_connections")?;
                }
                "max_conns_per_ip" => {
                    self.max_conns_per_ip = parse_u32(val, "invalid max_conns_per_ip")?;
                }
                "max_headers" => self.max_headers = parse_usize(val, "invalid max_headers")?,
                _ => return Err(ProxyError::Config("unknown config key")),
            }
        }
        Ok(())
    }

    fn load_config_file(
        &mut self,
        path: &Path,
        burst_explicit: &mut bool,
    ) -> Result<(), ProxyError> {
        let contents =
            fs::read_to_string(path).map_err(|_| ProxyError::Config("failed to read config file"))?;
        self.apply_config_str(&contents, burst_explicit)
    }

    /// Parses and adds a single strip-prefix route specification `[host] <prefix>=<ip:port>`.
    pub fn add_route_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        self.add_route_with_mode(spec, true)
    }

    /// Parses and adds a preserve-prefix route specification `[host] <prefix>=<ip:port>`.
    pub fn add_route_preserve_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        self.add_route_with_mode(spec, false)
    }

    fn add_route_with_mode(&mut self, spec: &str, strip_prefix: bool) -> Result<(), ProxyError> {
        let (raw_lhs, raw_addr) = spec
            .split_once('=')
            .ok_or(ProxyError::Config("route must be [host] <prefix>=<ip:port>"))?;
        let (host, raw_prefix) = split_optional_host_and_path(raw_lhs.trim())?;
        let prefix = normalize_prefix(raw_prefix)?;
        let upstream = parse_socket_addr(raw_addr.trim())?;
        if self
            .routes
            .iter()
            .any(|r| r.host == host && r.prefix == prefix)
        {
            return Err(ProxyError::Config("duplicate route prefix"));
        }
        self.routes.push(Route {
            host,
            prefix,
            upstream,
            strip_prefix,
        });
        Ok(())
    }

    /// Parses and adds a per-route `max_body` override (`[host] <prefix>=<bytes>`).
    pub fn add_route_max_body_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        let (raw_lhs, raw_bytes) = spec
            .split_once('=')
            .ok_or(ProxyError::Config("route_max_body must be [host] <prefix>=<bytes>"))?;
        let (host, raw_prefix) = split_optional_host_and_path(raw_lhs.trim())?;
        let prefix = normalize_prefix(raw_prefix)?;
        let bytes = parse_u64(raw_bytes.trim(), "invalid route_max_body")?;
        push_prefix_rule(
            &mut self.route_max_bodies,
            host,
            prefix,
            bytes,
            "duplicate route_max_body prefix",
        )
    }

    /// Parses and adds a per-route `Permissions-Policy` override (`[host] <prefix>=<policy>`).
    pub fn add_route_permissions_policy_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        let (raw_lhs, raw_policy) = spec.split_once('=').ok_or(ProxyError::Config(
            "route_permissions_policy must be [host] <prefix>=<policy>",
        ))?;
        let (host, raw_prefix) = split_optional_host_and_path(raw_lhs.trim())?;
        let prefix = normalize_prefix(raw_prefix)?;
        let policy = validate_header_value(raw_policy)?;
        push_prefix_rule(
            &mut self.route_permissions_policies,
            host,
            prefix,
            policy,
            "duplicate route_permissions_policy prefix",
        )
    }

    /// Parses and adds a static file route of the form `[host] <path>=<file_path>`.
    pub fn add_static_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        let (raw_lhs, raw_file) = spec
            .split_once('=')
            .ok_or(ProxyError::Config("static route must be [host] <path>=<file>"))?;
        let (host, raw_path) = split_optional_host_and_path(raw_lhs.trim())?;
        let path = normalize_static_path(raw_path)?;
        let file = raw_file.trim();
        if file.is_empty() || file.bytes().any(|b| b == 0) {
            return Err(ProxyError::Config("invalid static file path"));
        }
        if self
            .static_routes
            .iter()
            .any(|r| r.host == host && r.path == path)
        {
            return Err(ProxyError::Config("duplicate static route path"));
        }
        self.static_routes.push(StaticRoute {
            host,
            path,
            file_path: PathBuf::from(file),
        });
        Ok(())
    }

    /// Parses and adds a per-host `301` redirect (`<host> -> <target_base>` or `<host>=<target_base>`).
    pub fn add_redirect_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        let (raw_host, raw_target) = if let Some(pair) = spec.split_once("->") {
            pair
        } else if let Some(pair) = spec.split_once('=') {
            pair
        } else {
            return Err(ProxyError::Config(
                "redirect must be <host> -> <https://target>",
            ));
        };
        let host = normalize_hostname(raw_host.trim())?;
        let target_base = validate_http_url(raw_target.trim())?
            .trim_end_matches('/')
            .to_owned();
        if self.redirects.iter().any(|r| r.host == host) {
            return Err(ProxyError::Config("duplicate redirect host"));
        }
        self.redirects.push(HostRedirect { host, target_base });
        Ok(())
    }

    /// Parses and adds a per-path `308 Permanent Redirect` (`[host] <from> -> <to>`).
    pub fn add_path_redirect_spec(&mut self, spec: &str) -> Result<(), ProxyError> {
        let (raw_lhs, raw_to) = if let Some(pair) = spec.split_once("->") {
            pair
        } else if let Some(pair) = spec.split_once('=') {
            pair
        } else {
            return Err(ProxyError::Config(
                "path_redirect must be [host] <from> -> <to>",
            ));
        };
        let (host, raw_from) = split_optional_host_and_path(raw_lhs.trim())?;
        let from = normalize_static_path(raw_from)?;
        let to = normalize_redirect_location(raw_to.trim())?;
        if self
            .path_redirects
            .iter()
            .any(|r| r.host == host && r.from == from)
        {
            return Err(ProxyError::Config("duplicate path_redirect source"));
        }
        self.path_redirects.push(PathRedirect { host, from, to });
        Ok(())
    }

    /// Adds a domain to the ACME auto-issuance list.
    pub fn add_acme_domain(&mut self, raw: &str) -> Result<(), ProxyError> {
        for part in raw.split(',') {
            let domain = normalize_hostname(part.trim())?;
            if !self.acme_domains.iter().any(|d| d == &domain) {
                self.acme_domains.push(domain);
            }
        }
        Ok(())
    }

    /// Sorts routes by longest-prefix-first and validates all configuration bounds fail-closed.
    pub fn finalize(&mut self) -> Result<(), ProxyError> {
        if self.routes.is_empty()
            && self.static_routes.is_empty()
            && self.redirects.is_empty()
            && self.path_redirects.is_empty()
        {
            return Err(ProxyError::Config(
                "at least one route, static file, or redirect must be configured",
            ));
        }
        if self.tls_cert.is_some() != self.tls_key.is_some() {
            return Err(ProxyError::Config(
                "tls_cert and tls_key must both be set together",
            ));
        }
        if !self.acme_domains.is_empty() && self.cert_dir.is_none() {
            return Err(ProxyError::Config(
                "cert_dir must be set when acme_domain is configured",
            ));
        }
        if self.acme_check_interval_secs == 0 {
            return Err(ProxyError::Config("acme_check_interval_secs must be > 0"));
        }
        if self.max_header_bytes < 64 || self.max_header_bytes > STREAM_BUFFER_BYTES {
            return Err(ProxyError::Config(
                "max_header_bytes must be between 64 and 65536",
            ));
        }
        if self.header_timeout_ms == 0
            || self.idle_timeout_ms == 0
            || self.upstream_timeout_ms == 0
            || self.drain_timeout_ms == 0
        {
            return Err(ProxyError::Config("timeouts must be > 0 ms"));
        }
        if self.rate_limit_shards == 0 || !self.rate_limit_shards.is_power_of_two() {
            return Err(ProxyError::Config("shards must be a power of 2"));
        }
        if self.rate_limit_rps > 0
            && (self.rate_limit_burst == 0 || self.rate_limit_burst > MAX_BURST_TOKENS)
        {
            return Err(ProxyError::Config(
                "burst must be in 1..=67108 when rps > 0",
            ));
        }
        if self.max_connections == 0 {
            return Err(ProxyError::Config("max_connections must be > 0"));
        }
        if self.max_conns_per_ip == 0 {
            return Err(ProxyError::Config("max_conns_per_ip must be > 0"));
        }
        if self.max_headers == 0 || self.max_headers > MAX_HEADERS_CAP {
            return Err(ProxyError::Config("max_headers must be in 1..=64"));
        }
        for route in &mut self.routes {
            route.prefix = normalize_prefix(&route.prefix)?;
        }
        // Sort longest prefix first, with host-scoped routes taking precedence over wildcard routes.
        self.routes.sort_by(|a, b| {
            b.prefix
                .len()
                .cmp(&a.prefix.len())
                .then_with(|| b.host.is_some().cmp(&a.host.is_some()))
                .then_with(|| a.host.cmp(&b.host))
                .then_with(|| a.prefix.cmp(&b.prefix))
        });
        for pair in self.routes.windows(2) {
            if pair[0].host == pair[1].host && pair[0].prefix == pair[1].prefix {
                return Err(ProxyError::Config("duplicate route prefix"));
            }
        }
        finalize_prefix_rules(
            &mut self.route_max_bodies,
            "duplicate route_max_body prefix",
        )?;
        finalize_prefix_rules(
            &mut self.route_permissions_policies,
            "duplicate route_permissions_policy prefix",
        )?;
        Ok(())
    }

    /// Matches a request `Host` header (stripping optional `:port`) against configured `301` redirects.
    pub fn match_redirect(&self, host_header: &str) -> Option<&HostRedirect> {
        let host_only = strip_host_port(host_header);
        self.redirects
            .iter()
            .find(|r| r.host.eq_ignore_ascii_case(host_only))
    }

    /// Matches a request target (ignoring `?query`) against configured `308` path redirects.
    pub fn match_path_redirect(
        &self,
        host_header: Option<&str>,
        target: &str,
    ) -> Option<&PathRedirect> {
        let path_end = target.find('?').unwrap_or(target.len());
        let path = &target[..path_end];
        if let Some(h) = host_header {
            let host_only = strip_host_port(h);
            if let Some(found) = self.path_redirects.iter().find(|r| {
                r.from == path
                    && r.host
                        .as_deref()
                        .map(|expected| expected.eq_ignore_ascii_case(host_only))
                        .unwrap_or(false)
            }) {
                return Some(found);
            }
        }
        self.path_redirects
            .iter()
            .find(|r| r.host.is_none() && r.from == path)
    }

    /// Matches a request target (ignoring `?query`) against configured static file routes.
    pub fn match_static(&self, target: &str) -> Option<&StaticRoute> {
        self.match_static_for_host(None, target)
    }

    /// Matches a request target (ignoring `?query`) against host-scoped or wildcard static routes.
    pub fn match_static_for_host(
        &self,
        host_header: Option<&str>,
        target: &str,
    ) -> Option<&StaticRoute> {
        let path_end = target.find('?').unwrap_or(target.len());
        let path = &target[..path_end];
        if let Some(h) = host_header {
            let host_only = strip_host_port(h);
            if let Some(found) = self.static_routes.iter().find(|s| {
                s.path == path
                    && s.host
                        .as_deref()
                        .map(|expected| expected.eq_ignore_ascii_case(host_only))
                        .unwrap_or(false)
            }) {
                return Some(found);
            }
        }
        self.static_routes
            .iter()
            .find(|s| s.host.is_none() && s.path == path)
    }

    /// Matches a request target (path + optional `?query`) using longest-prefix routing
    /// and returns a zero-allocation rewritten upstream target view.
    pub fn match_route<'a>(&self, target: &'a str) -> Option<RouteMatch<'a>> {
        self.match_route_for_host(None, target)
    }

    /// Matches a request target (path + optional `?query`) using host-aware longest-prefix routing.
    pub fn match_route_for_host<'a>(
        &self,
        host_header: Option<&str>,
        target: &'a str,
    ) -> Option<RouteMatch<'a>> {
        let path_end = target.find('?').unwrap_or(target.len());
        let path = &target[..path_end];
        let host_only = host_header.map(strip_host_port);

        for route in &self.routes {
            if let Some(ref expected) = route.host {
                match host_only {
                    Some(actual) if expected.eq_ignore_ascii_case(actual) => {}
                    _ => continue,
                }
            }
            if route.prefix == "/" {
                return Some(RouteMatch {
                    upstream: route.upstream,
                    prepend_slash: false,
                    tail: target,
                });
            }
            if let Some(rest_path) = path.strip_prefix(&route.prefix) {
                if rest_path.is_empty() {
                    if route.strip_prefix {
                        return Some(RouteMatch {
                            upstream: route.upstream,
                            prepend_slash: true,
                            tail: &target[path_end..],
                        });
                    }
                    return Some(RouteMatch {
                        upstream: route.upstream,
                        prepend_slash: false,
                        tail: target,
                    });
                }
                if rest_path.starts_with('/') {
                    if route.strip_prefix {
                        return Some(RouteMatch {
                            upstream: route.upstream,
                            prepend_slash: false,
                            tail: &target[route.prefix.len()..],
                        });
                    }
                    return Some(RouteMatch {
                        upstream: route.upstream,
                        prepend_slash: false,
                        tail: target,
                    });
                }
            }
        }
        None
    }

    /// Returns the effective `max_body` limit for `(host_header, target)`, falling back to global `max_body_bytes`.
    pub fn effective_max_body_bytes(&self, host_header: Option<&str>, target: &str) -> u64 {
        match_prefix_rule(&self.route_max_bodies, host_header, target)
            .copied()
            .unwrap_or(self.max_body_bytes)
    }

    /// Returns an optional per-route `Permissions-Policy` header override for `(host_header, target)`.
    pub fn effective_permissions_policy(
        &self,
        host_header: Option<&str>,
        target: &str,
    ) -> Option<&str> {
        match_prefix_rule(&self.route_permissions_policies, host_header, target).map(String::as_str)
    }

    /// Returns true if a static asset path falls under the configured `static_cors_prefix`.
    pub fn static_allows_cors(&self, path: &str) -> bool {
        let Some(prefix) = self.static_cors_prefix.as_deref() else {
            return false;
        };
        if prefix == "/" {
            return path.starts_with('/');
        }
        path == prefix
            || (path.starts_with(prefix)
                && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
    }

    /// Returns CLI usage text.
    pub const fn usage() -> &'static str {
        "zero-proxy - zero-dependency, zero-spill TLS 1.3 + ACME v2 HTTP/1.1 reverse proxy\n\n\
         USAGE:\n\
           zero-proxy [--config <file>] [--listen <ip:port>] [--route <prefix>=<ip:port>] [OPTIONS]\n\n\
         OPTIONS:\n\
           --config <path>                  Path to config file (reloaded on SIGHUP)\n\
           --listen <ip:port>               Primary HTTP/HTTPS bind address (default: 127.0.0.1:8080)\n\
           --http-listen <ip:port>          Optional HTTP :80 listener (ACME HTTP-01 + 301->HTTPS)\n\
           --route [host] <prefix>=<ip:port>          Strip-prefix reverse-proxy route (alias: --upstream)\n\
           --route-preserve [host] <prefix>=<ip:port> Preserve-path reverse-proxy route (repeatable)\n\
           --route-max-body [host] <prefix>=<bytes>   Per-route max_body override (repeatable)\n\
           --route-permissions-policy [host] <p>=<v>  Per-route Permissions-Policy override\n\
           --static [host] <path>=<file>              Static file route (optionally host-scoped)\n\
           --static-cors-prefix <prefix>              Static path prefix emitting Access-Control-Allow-Origin: *\n\
           --redirect <host>-><url>                   Per-host 301 redirect\n\
           --path-redirect [host] <from>-><to>        Per-path 308 redirect (e.g. /app->/app/)\n\
           --cert-dir <dir>                 PEM cert directory for SNI & ACME auto-renewal\n\
           --tls-cert <file>                Default PEM certificate chain file\n\
           --tls-key <file>                 Default PEM private key file\n\
           --tls-min-version <1.2|1.3>      Minimum TLS protocol version (default: 1.2)\n\
           --blindbind-seed-file <file>     Optional 32-byte BlindBind hybrid keypair seed file\n\
           --static-csp <policy>            Optional Content-Security-Policy for static files\n\
           --acme-domain <host>             ACME v2 managed domain (repeatable)\n\
           --acme-email <email>             ACME account contact email\n\
           --acme-directory <url>           ACME v2 directory URL (RFC 8555)\n\
           --acme-ca-cert <file>            Optional custom CA PEM for ACME directory HTTPS\n\
           --acme-renew-days <days>         Renew cert when < days remain (default: 30)\n\
           --acme-check-interval-secs <s>   Renewal check interval in secs (default: 43200)\n\
           --max-body <bytes>               Max request body bytes (default: 1048576)\n\
           --max-header-bytes <bytes>       Max request header bytes (default: 16384, max: 65536)\n\
           --header-timeout-ms <ms>         Slowloris header deadline in ms (default: 5000)\n\
           --idle-timeout-ms <ms>           Body streaming idle timeout in ms (default: 30000)\n\
           --upstream-timeout-ms <ms>       Upstream connect/read timeout in ms (default: 10000)\n\
           --drain-timeout-ms <ms>          Graceful SIGTERM drain timeout in ms (default: 10000)\n\
           --rps <n>                        Per-IP requests/sec, 0 disables (default: 100)\n\
           --burst <n>                      Per-IP token bucket burst (default: matches --rps)\n\
           --shards <pow2>                  Fixed atomic rate-limiter shards (default: 4096)\n\
           --max-connections <n>            Max concurrent active connections (default: 1024)\n\
           --max-conns-per-ip <n>           Max concurrent connections per IP (default: 64)\n\
           --max-headers <n>                Max parsed request headers (default: 64)\n\
           -h, --help                       Print this help message\n"
    }
}

fn push_prefix_rule<T>(
    rules: &mut Vec<PrefixRule<T>>,
    host: Option<String>,
    prefix: String,
    value: T,
    dup_err: &'static str,
) -> Result<(), ProxyError> {
    if rules.iter().any(|r| r.host == host && r.prefix == prefix) {
        return Err(ProxyError::Config(dup_err));
    }
    rules.push(PrefixRule {
        host,
        prefix,
        value,
    });
    Ok(())
}

fn finalize_prefix_rules<T>(
    rules: &mut [PrefixRule<T>],
    dup_err: &'static str,
) -> Result<(), ProxyError> {
    for rule in rules.iter_mut() {
        rule.prefix = normalize_prefix(&rule.prefix)?;
    }
    rules.sort_by(|a, b| {
        b.prefix
            .len()
            .cmp(&a.prefix.len())
            .then_with(|| b.host.is_some().cmp(&a.host.is_some()))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| a.prefix.cmp(&b.prefix))
    });
    for pair in rules.windows(2) {
        if pair[0].host == pair[1].host && pair[0].prefix == pair[1].prefix {
            return Err(ProxyError::Config(dup_err));
        }
    }
    Ok(())
}

fn match_prefix_rule<'a, T>(
    rules: &'a [PrefixRule<T>],
    host_header: Option<&str>,
    target: &str,
) -> Option<&'a T> {
    let path_end = target.find('?').unwrap_or(target.len());
    let path = &target[..path_end];
    let host_only = host_header.map(strip_host_port);
    for rule in rules {
        if let Some(ref expected) = rule.host {
            match host_only {
                Some(actual) if expected.eq_ignore_ascii_case(actual) => {}
                _ => continue,
            }
        }
        if prefix_matches_path(&rule.prefix, path) {
            return Some(&rule.value);
        }
    }
    None
}

fn prefix_matches_path(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

fn split_optional_host_and_path(raw: &str) -> Result<(Option<String>, &str), ProxyError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('/') {
        return Ok((None, trimmed));
    }
    let mut parts = trimmed.split_whitespace();
    let Some(raw_host) = parts.next() else {
        return Err(ProxyError::Config("missing route path"));
    };
    let Some(raw_path) = parts.next() else {
        return Err(ProxyError::Config("route path must start with '/'"));
    };
    if parts.next().is_some() {
        return Err(ProxyError::Config("unexpected extra token in host/path spec"));
    }
    let host = normalize_hostname(raw_host)?;
    Ok((Some(host), raw_path))
}

fn parse_tls_min_version(raw: &str) -> Result<TlsMinVersion, ProxyError> {
    match raw.trim() {
        "1.2" | "tls1.2" | "TLS1.2" => Ok(TlsMinVersion::Tls12),
        "1.3" | "tls1.3" | "TLS1.3" => Ok(TlsMinVersion::Tls13),
        _ => Err(ProxyError::Config("tls_min_version must be 1.2 or 1.3")),
    }
}

fn validate_header_value(raw: &str) -> Result<String, ProxyError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .bytes()
            .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b))
    {
        return Err(ProxyError::Config("invalid HTTP header value in config"));
    }
    Ok(trimmed.to_owned())
}

fn validate_ascii_target(
    raw: &str,
    allow_relative: bool,
    prefix_err: &'static str,
    char_err: &'static str,
) -> Result<String, ProxyError> {
    let trimmed = raw.trim();
    let ok_prefix = trimmed.starts_with("https://")
        || trimmed.starts_with("http://")
        || (allow_relative && trimmed.starts_with('/'));
    if trimmed.is_empty() || !ok_prefix {
        return Err(ProxyError::Config(prefix_err));
    }
    if trimmed.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return Err(ProxyError::Config(char_err));
    }
    Ok(trimmed.to_owned())
}

fn normalize_redirect_location(raw: &str) -> Result<String, ProxyError> {
    validate_ascii_target(
        raw,
        true,
        "path_redirect target must start with '/', https://, or http://",
        "path_redirect target contains invalid characters",
    )
}

fn strip_directive_prefix<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    let first = rest.bytes().next()?;
    if first != b' ' && first != b'\t' {
        return None;
    }
    let trimmed = rest.trim();
    if trimmed.starts_with('=') {
        return None;
    }
    Some(trimmed)
}

/// Strips optional `:port` from an HTTP `Host` header value (handling IPv6 brackets).
pub fn strip_host_port(host_header: &str) -> &str {
    let trimmed = host_header.trim();
    if let Some(after_open) = trimmed.strip_prefix('[') {
        if let Some(close) = after_open.find(']') {
            return &trimmed[..close + 2];
        }
        return trimmed;
    }
    match trimmed.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => trimmed,
    }
}

fn validate_slash_path<'a>(
    raw: &'a str,
    forbid_backslash: bool,
    slash_err: &'static str,
    char_err: &'static str,
) -> Result<&'a str, ProxyError> {
    if !raw.starts_with('/') {
        return Err(ProxyError::Config(slash_err));
    }
    if raw.bytes().any(|b| {
        b <= 0x20 || b >= 0x7f || b == b'?' || b == b'#' || (forbid_backslash && b == b'\\')
    }) {
        return Err(ProxyError::Config(char_err));
    }
    Ok(raw)
}

fn normalize_prefix(raw: &str) -> Result<String, ProxyError> {
    let valid = validate_slash_path(
        raw,
        false,
        "route prefix must start with '/'",
        "route prefix contains invalid characters",
    )?;
    let trimmed = valid.trim_end_matches('/');
    Ok(if trimmed.is_empty() {
        "/".to_owned()
    } else {
        trimmed.to_owned()
    })
}

fn normalize_static_path(raw: &str) -> Result<String, ProxyError> {
    let valid = validate_slash_path(
        raw,
        true,
        "static path must start with '/'",
        "static path contains invalid characters",
    )?;
    if valid.contains("..") {
        return Err(ProxyError::Config("static path cannot contain '..'"));
    }
    Ok(valid.to_owned())
}

fn normalize_hostname(raw: &str) -> Result<String, ProxyError> {
    if raw.is_empty() || raw.len() > 253 {
        return Err(ProxyError::Config("invalid hostname"));
    }
    if !raw
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(ProxyError::Config("hostname contains invalid characters"));
    }
    if raw.starts_with('.') || raw.ends_with('.') || raw.contains("..") {
        return Err(ProxyError::Config("malformed hostname"));
    }
    Ok(raw.to_ascii_lowercase())
}

fn validate_http_url(raw: &str) -> Result<String, ProxyError> {
    validate_ascii_target(
        raw,
        false,
        "URL must start with https:// or http://",
        "URL contains invalid characters",
    )
}

fn parse_socket_addr(val: &str) -> Result<SocketAddr, ProxyError> {
    val.parse::<SocketAddr>()
        .map_err(|_| ProxyError::Config("invalid socket address (expected ip:port)"))
}

fn parse_u32(val: &str, msg: &'static str) -> Result<u32, ProxyError> {
    val.parse::<u32>().map_err(|_| ProxyError::Config(msg))
}

fn parse_u64(val: &str, msg: &'static str) -> Result<u64, ProxyError> {
    val.parse::<u64>().map_err(|_| ProxyError::Config(msg))
}

fn parse_usize(val: &str, msg: &'static str) -> Result<usize, ProxyError> {
    val.parse::<usize>().map_err(|_| ProxyError::Config(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_and_longest_prefix_stripping() {
        let action = ProxyConfig::from_args([
            "--listen",
            "127.0.0.1:8080",
            "--route",
            "/app/=127.0.0.1:9002",
            "--upstream",
            "/app/v2/=127.0.0.1:9004",
            "--route",
            "/=127.0.0.1:9000",
            "--max-body",
            "70000",
            "--rps",
            "25",
        ])
        .expect("valid cli");

        let cfg = match action {
            CliAction::Run(c) => *c,
            CliAction::Help => panic!("expected Run"),
        };

        assert_eq!(cfg.max_body_bytes, 70_000);
        assert_eq!(cfg.rate_limit_rps, 25);
        assert_eq!(cfg.rate_limit_burst, 25);

        let m1 = cfg.match_route("/app/feed?limit=5").expect("match /app/");
        assert_eq!(m1.upstream.port(), 9002);
        assert!(!m1.prepend_slash);
        assert_eq!(m1.tail, "/feed?limit=5");

        let m2 = cfg.match_route("/app/v2/items").expect("match /app/v2/");
        assert_eq!(m2.upstream.port(), 9004);
        assert!(!m2.prepend_slash);
        assert_eq!(m2.tail, "/items");

        let m3 = cfg.match_route("/app?tab=1").expect("match exact /app");
        assert_eq!(m3.upstream.port(), 9002);
        assert!(m3.prepend_slash);
        assert_eq!(m3.tail, "?tab=1");

        // Must NOT falsely match `/app` prefix for `/apple`.
        let m4 = cfg.match_route("/apple").expect("fallback to /");
        assert_eq!(m4.upstream.port(), 9000);
        assert_eq!(m4.tail, "/apple");
    }

    #[test]
    fn parse_key_value_config_and_reject_invalid() {
        let mut cfg = ProxyConfig::default();
        let mut burst_explicit = false;
        cfg.apply_config_str(
            "\
            # zero-proxy route table\n\
            listen = 127.0.0.1:8080\n\
            max_body = 70000\n\
            rps = 100\n\
            burst = 150\n\
            route = /api/=127.0.0.1:9001\n\
            route = /app/=127.0.0.1:9002\n\
            route = /auth/=127.0.0.1:9003\n\
            route = /billing/=127.0.0.1:9004\n\
            ",
            &mut burst_explicit,
        )
        .expect("valid config");
        cfg.finalize().expect("valid finalize");
        assert_eq!(cfg.routes.len(), 4);
        assert_eq!(cfg.rate_limit_burst, 150);

        // Fail-closed on unknown key, duplicate prefix, non-pow2 shards, missing routes.
        let mut bad = ProxyConfig::default();
        let mut be = false;
        assert!(bad.apply_config_str("bogus=1", &mut be).is_err());
        assert!(ProxyConfig::from_args(["--rps", "10"]).is_err());
        assert!(ProxyConfig::from_args(["--route", "/a=127.0.0.1:80", "--shards", "3"]).is_err());
        assert!(
            ProxyConfig::from_args([
                "--route",
                "/a/=127.0.0.1:80",
                "--route",
                "/a=127.0.0.1:81"
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_static_redirects_tls_and_acme_directives() {
        let mut cfg = ProxyConfig::default();
        let mut burst_explicit = false;
        cfg.apply_config_str(
            "\
            listen = 0.0.0.0:443\n\
            http_listen = 0.0.0.0:80\n\
            cert_dir = /var/lib/zero-proxy/certs\n\
            acme_domain = example.com\n\
            acme_domain = www.example.com\n\
            acme_email = ops@example.com\n\
            static /=/srv/www/index.html\n\
            static /app.js=/srv/www/app.js\n\
            static_cors_prefix = /static\n\
            redirect www.example.com -> https://example.com\n\
            route = /api/=127.0.0.1:9001\n\
            ",
            &mut burst_explicit,
        )
        .expect("valid proxy config");
        cfg.finalize().expect("valid finalize");
        assert!(cfg.tls_enabled());
        assert_eq!(cfg.acme_domains, vec!["example.com", "www.example.com"]);
        assert_eq!(cfg.static_routes.len(), 2);
        assert!(cfg.static_allows_cors("/static/app.js"));
        assert!(!cfg.static_allows_cors("/static_other/app.js"));
        assert!(!cfg.static_allows_cors("/index.html"));
        assert_eq!(
            cfg.match_static("/app.js?v=1")
                .expect("static match")
                .file_path,
            PathBuf::from("/srv/www/app.js")
        );
        let redir = cfg
            .match_redirect("WWW.EXAMPLE.COM:443")
            .expect("redirect match");
        assert_eq!(redir.target_base, "https://example.com");
    }

    #[test]
    fn parse_host_isolation_preserve_path_and_tls13_options() {
        let mut cfg = ProxyConfig::default();
        let mut burst_explicit = false;
        cfg.apply_config_str(
            "\
            listen = 0.0.0.0:443\n\
            tls_min_version = 1.3\n\
            static_csp = default-src 'none'; script-src 'self'\n\
            static example.com /=/srv/www/index.html\n\
            static example.com /app.js=/srv/www/app.js\n\
            path_redirect /app -> /app/\n\
            route_preserve = /api/v1/pricing=127.0.0.1:3002\n\
            route_preserve = /api/=127.0.0.1:3001\n\
            route = /app/=127.0.0.1:9002\n\
            ",
            &mut burst_explicit,
        )
        .expect("valid host-isolated config");
        cfg.finalize().expect("valid finalize");

        assert_eq!(cfg.tls_min_version, TlsMinVersion::Tls13);
        assert_eq!(
            cfg.static_csp.as_deref(),
            Some("default-src 'none'; script-src 'self'")
        );
        assert!(cfg.match_static_for_host(Some("example.com"), "/").is_some());
        assert!(cfg.match_static_for_host(Some("other.example.net"), "/").is_none());
        assert_eq!(
            cfg.match_path_redirect(Some("example.com"), "/app?a=1")
                .expect("308 match")
                .to,
            "/app/"
        );

        let pricing = cfg
            .match_route_for_host(Some("example.com"), "/api/v1/pricing?x=1")
            .expect("pricing route");
        assert_eq!(pricing.upstream.port(), 3002);
        assert!(!pricing.prepend_slash);
        assert_eq!(pricing.tail, "/api/v1/pricing?x=1");

        let query = cfg
            .match_route_for_host(Some("example.com"), "/api/v1/query")
            .expect("api preserve route");
        assert_eq!(query.upstream.port(), 3001);
        assert_eq!(query.tail, "/api/v1/query");

        let app = cfg
            .match_route_for_host(Some("example.com"), "/app/feed")
            .expect("app strip route");
        assert_eq!(app.upstream.port(), 9002);
        assert_eq!(app.tail, "/feed");
    }

    #[test]
    fn parse_max_conns_per_ip_cli_config_and_fail_closed() {
        let def = ProxyConfig::default();
        assert_eq!(def.max_conns_per_ip, DEFAULT_MAX_CONNS_PER_IP);
        assert_eq!(def.max_conns_per_ip, 64);

        let action = ProxyConfig::from_args([
            "--route",
            "/=127.0.0.1:8080",
            "--max-conns-per-ip",
            "12",
        ])
        .expect("valid cli");
        let CliAction::Run(cfg) = action else {
            panic!("expected Run");
        };
        assert_eq!(cfg.max_conns_per_ip, 12);

        let mut file_cfg = ProxyConfig::default();
        let mut be = false;
        file_cfg
            .apply_config_str(
                "max_conns_per_ip = 32\nroute = /=127.0.0.1:8080\n",
                &mut be,
            )
            .expect("valid config file");
        file_cfg.finalize().expect("valid finalize");
        assert_eq!(file_cfg.max_conns_per_ip, 32);

        assert!(ProxyConfig::from_args([
            "--route",
            "/=127.0.0.1:8080",
            "--max-conns-per-ip",
            "0",
        ])
        .is_err());
        assert!(ProxyConfig::from_args([
            "--route",
            "/=127.0.0.1:8080",
            "--max-conns-per-ip",
            "abc",
        ])
        .is_err());
    }

    #[test]
    fn parse_route_max_body_and_permissions_policy_directives() {
        let mut cfg = ProxyConfig::default();
        let mut be = false;
        cfg.apply_config_str(
            "\
            max_body = 4194304\n\
            route /api/=127.0.0.1:9001\n\
            route /media/=127.0.0.1:9002\n\
            route_max_body /media/=70000\n\
            route_max_body /media/api/v1/clips=8192\n\
            route_permissions_policy /media/=geolocation=(), microphone=(self), camera=(self), payment=()\n\
            ",
            &mut be,
        )
        .expect("valid route directives");
        cfg.finalize().expect("valid finalize");

        assert_eq!(cfg.effective_max_body_bytes(None, "/media/upload"), 70_000);
        assert_eq!(
            cfg.effective_max_body_bytes(None, "/media/api/v1/clips?x=1"),
            8_192
        );
        assert_eq!(cfg.effective_max_body_bytes(None, "/api/send"), 4_194_304);
        assert_eq!(cfg.effective_max_body_bytes(None, "/median"), 4_194_304);

        assert_eq!(
            cfg.effective_permissions_policy(None, "/media/"),
            Some("geolocation=(), microphone=(self), camera=(self), payment=()")
        );
        assert_eq!(cfg.effective_permissions_policy(None, "/api/"), None);
        assert_eq!(cfg.effective_permissions_policy(None, "/median"), None);

        // CLI flag equivalents and fail-closed validation.
        let action = ProxyConfig::from_args([
            "--route",
            "/media/=127.0.0.1:9002",
            "--route-max-body",
            "example.com /media/=70000",
            "--route-permissions-policy",
            "example.com /media/=camera=(self), microphone=(self)",
            "--static-cors-prefix",
            "/static/",
        ])
        .expect("valid cli flags");
        let CliAction::Run(cli_cfg) = action else {
            panic!("expected Run");
        };
        assert_eq!(
            cli_cfg.effective_max_body_bytes(Some("example.com:443"), "/media/x"),
            70_000
        );
        assert_eq!(
            cli_cfg.effective_max_body_bytes(Some("other.example"), "/media/x"),
            DEFAULT_MAX_BODY_BYTES
        );
        assert_eq!(
            cli_cfg.effective_permissions_policy(Some("example.com"), "/media/"),
            Some("camera=(self), microphone=(self)")
        );
        assert!(cli_cfg.static_allows_cors("/static/bundle.js"));
        assert!(!cli_cfg.static_allows_cors("/assets/bundle.js"));

        // Fail closed on duplicate prefix, invalid header chars, invalid numbers.
        assert!(ProxyConfig::from_args([
            "--route",
            "/media/=127.0.0.1:9002",
            "--route-max-body",
            "/media/=abc",
        ])
        .is_err());
        assert!(ProxyConfig::from_args([
            "--route",
            "/media/=127.0.0.1:9002",
            "--route-permissions-policy",
            "/media/=camera=(self)\r\nX-Injected: 1",
        ])
        .is_err());
        assert!(ProxyConfig::from_args([
            "--route",
            "/media/=127.0.0.1:9002",
            "--route-max-body",
            "/media/=100",
            "--route-max-body",
            "/media=200",
        ])
        .is_err());
    }
}
