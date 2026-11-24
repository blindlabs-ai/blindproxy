# Zero-Proxy

Zero-dependency, zero-spill, fixed-buffer `HTTP/1.1` + `TLS 1.3` + `ACME v2` reverse proxy, hybrid post-quantum channel binding (`blindbind`), and pure-Rust `XDP/eBPF` packet filter + 64-bit RFC 9669 eBPF ISA compiler/verifier/VM (`xdp`) written in Rust (`Cargo.lock` external crates == `0`) by Blind Labs.

| Property | Specification |
| :--- | :--- |
| **Repository** | https://github.com/blindlabs-ai/zero-proxy |
| **External Rust Crates** | `0` (`Cargo.lock` has zero third-party dependencies; Rust `std` + system OpenSSL 3.x) |
| **Zero-Spill Safety Model** | `#[forbid(unsafe_code)]` across all non-FFI modules; fixed `64 KiB` header buffers; `Copy` `ProxyError`; register-only DAG eBPF; Nightly Miri clean |
| **TLS, PQ & XDP Surface** | OpenSSL 3.x TLS 1.2+/1.3, SNI hot-swap, RFC 8555 ACME v2, hybrid Ed25519 + ML-DSA-87 RFC 8446 binding, pure-Rust XDP/eBPF compiler/verifier/VM |
| **License** | Apache License, Version 2.0 ([LICENSE](LICENSE) & [NOTICE](NOTICE)) |

---

## Why Zero-Proxy?

- **Zero External Crate Supply Chain:** `Cargo.toml` `[dependencies]` is empty (`Cargo.lock` external `"source ="` count == `0`), linking solely against Rust `std` and the host OS's FIPS/system-patched `libssl` and `libcrypto` 3.x.
- **Strictly Isolated FFI Boundary:** `#[forbid(unsafe_code)]` is enforced across `acme`, `blindbind`, `config`, `error`, `http`, `proxy`, `ratelimit`, `xdp`, `main`, `examples`, and every integration test. Direct OpenSSL 3.x and POSIX signal FFI lives exclusively in `src/tls.rs`, backed by `#[cfg(miri)]` stubs so `cargo +nightly miri test --lib` passes with `0` undefined behavior.
- **Pure-Rust XDP/eBPF Packet Filter, Bytecode Compiler, Verifier & VM (`src/xdp/`):**
  - `zero_proxy::xdp::filter_packet` parses Ethernet II (`14 B`) -> up to 2 stacked `802.1Q`/`802.1ad` QinQ VLAN tags -> IPv4 (variable IHL `5..=15`) or IPv6 -> configurable UDP port (default `:9000` via `UdpFilterConfig`) -> 32-byte `UdpPacketHdr` (configurable magic default `"ZPX1"`, erasure-coded data/parity slot/flag rules, frame offset + payload bounds, keyed SipHash-2-4 header MAC), passing all other traffic (`SSH`, `HTTPS`, `DNS`, `QUIC`, `ARP`, `ICMP`) untouched (`XdpAction::Pass`).
  - `zero_proxy::xdp::bpf_emit` compiles standalone 64-bit RFC 9669 / Linux eBPF bytecode directly from safe Rust (`0` C/Clang toolchain, `0` stack spills, `0` backward jumps), statically verifies `PTR_TO_PACKET` bounds + `[umin, umax]` ranges + DAG termination (`verify_bpf_program`), and executes a bounds-checked 64-bit eBPF VM (`execute_bpf_program`) with 100% verdict parity against `filter_packet`.
- **Hybrid Post-Quantum TLS 1.3 Channel Binding (`src/blindbind/`):**
  - Pure-Rust RFC 8446 Section 7.5 TLS 1.3 exporter channel binding combining RFC 8032 Ed25519 and NIST FIPS 204 ML-DSA-87 (`pk = 2592 B`, `sig = 4627 B`), unconditionally stripping spoofed inbound headers and emitting `X-BlindBind-Verified: 1` only for cryptographically verified peers.
- **Zero-Downtime TLS 1.3 + SNI Hot-Swap & Pure-Rust ACME v2 (`src/tls.rs`, `src/acme.rs`, `src/proxy.rs`):**
  - Enforces `SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE` with exact and wildcard SNI dispatch (`SSL_set_SSL_CTX`), async-signal-safe `SIGHUP` hot-reload, graceful `SIGTERM`/`SIGINT` drain, and a full RFC 8555 `HTTP-01` (`ES256` JWS) client with automatic 30-day renewal.
- **Zero-Spill Fixed-Buffer HTTP/1.1 & Lock-Free Rate Limiting (`src/http.rs`, `src/ratelimit.rs`):**
  - `ProxyError` is `Copy` (`0` heap allocations); headers parse into borrowed slices inside a fixed `64 KiB` buffer with strict bare-CR/LF, `CL`+`TE`, duplicate `Host`, and `obs-fold` smuggling rejection, configurable `static_cors_prefix` CORS for static assets, and lock-free sharded `AtomicU64` CAS token buckets + `AtomicU32` per-IP connection caps.
- **Independent Edge & Certificate Transparency Verifier (`scripts/verify_edge_integrity.py`):**
  - Zero-dependency Python 3 verifier auditing live TLS 1.3 enforcement, embedded RFC 6962 CT SCTs, leaf SPKI SHA-256 parity (`/.well-known/edge-integrity.json`), RFC 9530 `Content-Digest`, HSTS preload, and optional DNS `CAA`.

---

## Quickstart

### 1. Build Release Binary & Run End-to-End Example

```bash
env -u RUSTFLAGS cargo build --release --offline
env -u RUSTFLAGS cargo run --example reverse_proxy --release --offline
```

### 2. Run Reverse Proxy from CLI or Config File

Run directly from CLI flags:

```bash
./target/release/zero-proxy \
  --listen 127.0.0.1:8080 \
  --route /api/=127.0.0.1:9001 \
  --route /=127.0.0.1:9000
```

Or run from a configuration file (see [configs/example.conf](configs/example.conf)):

```bash
./target/release/zero-proxy --config configs/example.conf

# Zero-downtime config and TLS certificate hot-reload:
kill -HUP $(pidof zero-proxy)

# Graceful in-flight request drain and shutdown:
kill -TERM $(pidof zero-proxy)
```

### 3. Programmatic XDP/eBPF Compilation & Verification

```rust
use zero_proxy::xdp::bpf_emit::{emit_xdp_program, execute_bpf_program, verify_bpf_program};
use zero_proxy::xdp::{filter_packet, UdpFilterConfig};

let cfg = UdpFilterConfig::default();
let prog = emit_xdp_program(&cfg);
let summary = verify_bpf_program(&prog).expect("verifier-clean eBPF program");
assert!(summary.is_dag);

let frame: &[u8] = &[];
let rust_verdict = filter_packet(frame, &cfg);
let ebpf_action = execute_bpf_program(&prog, frame).expect("vm execution");
assert_eq!(rust_verdict.action.as_u32(), ebpf_action);
```

---

## Repository Layout

```text
Cargo.toml                       # Zero-dependency Rust crate manifest (Apache-2.0, LTO release profile)
Cargo.lock                       # Deterministic lockfile (0 external crates)
configs/example.conf             # General-purpose INI configuration template (HTTP + optional TLS/ACME)
examples/reverse_proxy.rs        # Runnable zero-dep HTTP reverse proxy + RFC 9669 eBPF filter demo
src/main.rs                      # CLI entrypoint and daemon lifecycle wiring
src/lib.rs                       # Crate module root (#[forbid(unsafe_code)] on all non-FFI modules)
src/config.rs                    # INI config & CLI flag parser with strict validation
src/error.rs                     # Zero-allocation Copy ProxyError & HTTP status mapping
src/http.rs                      # Fixed-64 KiB smuggling-resistant HTTP/1.1 parser & response writer
src/proxy.rs                     # Listener loops, upstream streaming, static files, SIGHUP/SIGTERM drain
src/ratelimit.rs                 # Lock-free sharded AtomicU64 token bucket & AtomicU32 per-IP conn cap
src/tls.rs                       # OpenSSL 3.x TLS 1.2+/1.3, SNI hot-swap store, and Miri FFI stubs
src/acme.rs                      # Pure-Rust RFC 8555 ACME v2 HTTP-01 client & ES256 JWS state machine
src/blindbind/                   # Hybrid Ed25519 + ML-DSA-87 RFC 8446 TLS 1.3 exporter channel binding
src/xdp/                         # Pure-Rust XDP/eBPF packet filter + 64-bit eBPF ISA compiler, verifier & VM
specs/zero_proxy.ntf1            # Formal function-level safety specification
tests/proxy_e2e.rs               # End-to-end HTTP routing, smuggling rejection, and rate-limit tests
tests/tls_acme_reload_e2e.rs     # End-to-end TLS 1.3, SNI, ACME HTTP-01, SIGHUP reload, and drain tests
tests/blindbind_e2e.rs           # End-to-end hybrid Ed25519 + ML-DSA-87 TLS 1.3 binding integration tests
tests/zipfian_blindbind_fuzz.rs  # Deterministic Zipfian fuzzing and counterfactual knockouts for blindbind
tests/xdp_zipfian_fuzz.rs        # 12,000-packet Zipfian s=1.2 Rust-vs-eBPF-VM parity & MAC/bounds knockouts
scripts/verify_edge_integrity.py # Zero-dep Python 3 TLS 1.3, CT SCT, SPKI, and Content-Digest verifier
LICENSE                          # Apache License, Version 2.0
NOTICE                           # Attribution and trademark notice
```

---

## Verification & Test Suite

```bash
env -u RUSTFLAGS cargo clippy --all-targets --offline -- -D warnings
env -u RUSTFLAGS cargo test --release --offline
env -u RUSTFLAGS cargo run --example reverse_proxy --release --offline
env -u RUSTFLAGS cargo +nightly miri test --lib
python3 scripts/verify_edge_integrity.py --host example.com
```

---

## Acknowledgments

Special thanks and a public shoutout to the **Ripwire** team for building fast, zero-dependency static code hygiene, AST lint verification (`0` findings across `src/`), structural clone detection, and ranked codebase mapping tooling.

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) and [NOTICE](NOTICE)).

Copyright 2026 Blind Labs.
