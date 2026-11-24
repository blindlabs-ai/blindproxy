#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

use zero_proxy::{CliAction, ProxyConfig, ProxyServer, TlsMinVersion};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let cfg = match ProxyConfig::from_args(args) {
        Ok(CliAction::Help) => {
            print!("{}", ProxyConfig::usage());
            return ExitCode::SUCCESS;
        }
        Ok(CliAction::Run(cfg)) => *cfg,
        Err(err) => {
            eprintln!("error: {}\n\n{}", err, ProxyConfig::usage());
            return ExitCode::FAILURE;
        }
    };

    let server = match ProxyServer::bind(cfg.clone()) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("error: failed to bind {}: {}", cfg.listen, err);
            return ExitCode::FAILURE;
        }
    };
    server.enable_signal_handling();

    let mode = if cfg.tls_enabled() {
        match cfg.tls_min_version {
            TlsMinVersion::Tls13 => "TLS 1.3",
            TlsMinVersion::Tls12 => "TLS 1.2+/1.3",
        }
    } else {
        "HTTP/1.1"
    };
    eprintln!(
        "zero-proxy listening on {} [{}] ({} routes, {} static, {} redirects, {} path_redirects, max_body={}B, rps={}, burst={}, max_conns_per_ip={}, drain={}ms)",
        server.local_addr(),
        mode,
        cfg.routes.len(),
        cfg.static_routes.len(),
        cfg.redirects.len(),
        cfg.path_redirects.len(),
        cfg.max_body_bytes,
        cfg.rate_limit_rps,
        cfg.rate_limit_burst,
        cfg.max_conns_per_ip,
        cfg.drain_timeout_ms
    );
    if let Some(http_addr) = server.http_local_addr() {
        eprintln!("  http acme+redirect listener on {}", http_addr);
    }
    for route in &cfg.routes {
        let kind = if route.strip_prefix {
            "route"
        } else {
            "route_preserve"
        };
        if let Some(ref host) = route.host {
            eprintln!("  {} {} {} -> {}", kind, host, route.prefix, route.upstream);
        } else {
            eprintln!("  {} {} -> {}", kind, route.prefix, route.upstream);
        }
    }
    for st in &cfg.static_routes {
        if let Some(ref host) = st.host {
            eprintln!("  static {} {} -> {}", host, st.path, st.file_path.display());
        } else {
            eprintln!("  static {} -> {}", st.path, st.file_path.display());
        }
    }
    for redir in &cfg.redirects {
        eprintln!("  redirect {} -> {}", redir.host, redir.target_base);
    }
    for predir in &cfg.path_redirects {
        if let Some(ref host) = predir.host {
            eprintln!("  path_redirect {} {} -> {}", host, predir.from, predir.to);
        } else {
            eprintln!("  path_redirect {} -> {}", predir.from, predir.to);
        }
    }
    if !cfg.acme_domains.is_empty() {
        eprintln!(
            "  acme domains: {} (dir={}, renew={}d)",
            cfg.acme_domains.join(", "),
            cfg.acme_directory,
            cfg.acme_renew_days
        );
    }

    if let Err(err) = server.run() {
        eprintln!("error: proxy exited: {}", err);
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
