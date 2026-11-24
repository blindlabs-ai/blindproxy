use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::config::ProxyConfig;
use crate::error::ProxyError;

/// Cryptographic identity metadata extracted from a loaded leaf X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCertIntegrity {
    pub spki_sha256_b64: String,
    pub spki_sha256_hex: String,
    pub cert_sha256_hex: String,
    pub serial_hex: String,
    pub cn: Option<String>,
    pub days_remaining: i64,
}

static SIGHUP_RECEIVED: AtomicBool = AtomicBool::new(false);
static SHUTDOWN_RECEIVED: AtomicBool = AtomicBool::new(false);

/// Returns true (and clears the flag) if a `SIGHUP` reload signal has been received.
pub fn take_sighup() -> bool {
    SIGHUP_RECEIVED.swap(false, Ordering::AcqRel)
}

/// Returns true if `SIGTERM` or `SIGINT` has been received.
pub fn shutdown_requested() -> bool {
    SHUTDOWN_RECEIVED.load(Ordering::Acquire)
}

/// Clears pending signal flags (used during process startup or isolated tests).
pub fn reset_signal_flags() {
    SIGHUP_RECEIVED.store(false, Ordering::Release);
    SHUTDOWN_RECEIVED.store(false, Ordering::Release);
}

/// Normalizes a TLS SNI hostname to lowercase ASCII without trailing dots.
pub fn normalize_sni_host(raw: &str) -> String {
    raw.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Matches a normalized SNI hostname against an exact or wildcard (`*.example.com`) entry.
pub fn match_sni_key<'a, T>(map: &'a HashMap<String, T>, host: &str) -> Option<&'a T> {
    if let Some(exact) = map.get(host) {
        return Some(exact);
    }
    if let Some((_, parent)) = host.split_once('.') {
        if !parent.is_empty() {
            let mut wildcard = String::with_capacity(parent.len() + 2);
            wildcard.push_str("*.");
            wildcard.push_str(parent);
            if let Some(found) = map.get(&wildcard) {
                return Some(found);
            }
        }
    }
    None
}

#[cfg(not(miri))]
mod native {
    use super::{
        match_sni_key, normalize_sni_host, LeafCertIntegrity, ProxyConfig, ProxyError,
        SHUTDOWN_RECEIVED, SIGHUP_RECEIVED,
    };
    use crate::acme::{base64_encode, hex_encode, sha256};
    use crate::config::TlsMinVersion;
    use std::collections::HashMap;
    use std::ffi::{c_char, c_int, c_long, c_uchar, c_ulong, c_void, CStr, CString};
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::Ordering;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Duration;

    const SIGHUP: c_int = 1;
    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;

    const TLS1_2_VERSION: c_long = 0x0303;
    const TLS1_3_VERSION: c_long = 0x0304;
    const SSL_CTRL_EXTRA_CHAIN_CERT: c_int = 14;
    const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
    const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
    const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
    const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
    const SSL_CTRL_SET_MAX_PROTO_VERSION: c_int = 124;
    const TLSEXT_NAMETYPE_HOST_NAME: c_int = 0;
    const SSL_TLSEXT_ERR_OK: c_int = 0;
    const SSL_TLSEXT_ERR_NOACK: c_int = 3;
    const SSL_VERIFY_NONE: c_int = 0;
    const SSL_VERIFY_PEER: c_int = 1;
    const SSL_ERROR_WANT_READ: c_int = 2;
    const SSL_ERROR_WANT_WRITE: c_int = 3;
    const SSL_ERROR_SYSCALL: c_int = 5;
    const SSL_ERROR_ZERO_RETURN: c_int = 6;
    const SSL_OP_NO_COMPRESSION: u64 = 1u64 << 17;
    const SSL_OP_CIPHER_SERVER_PREFERENCE: u64 = 1u64 << 22;
    const SSL_OP_NO_RENEGOTIATION: u64 = 1u64 << 30;

    const BIO_CTRL_INFO: c_int = 3;
    const NID_COMMON_NAME: c_int = 13;
    const NID_SUBJECT_ALT_NAME: c_int = 85;
    const NID_X9_62_ID_EC_PUBLIC_KEY: c_int = 408;
    const NID_X9_62_PRIME256V1: c_int = 415;
    const MBSTRING_ASC: c_int = 0x1001;

    #[repr(C)]
    struct SSL_METHOD {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct SSL_CTX {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct Ssl {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct BIO_METHOD {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct Bio {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct X509 {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct X509_PUBKEY {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct X509_NAME {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct X509_REQ {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct X509_EXTENSION {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct ASN1_TIME {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct ASN1_INTEGER {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct EVP_PKEY {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct EVP_PKEY_CTX {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct EVP_MD {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct EVP_MD_CTX {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct Bignum {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct ECDSA_SIG {
        _private: [u8; 0],
    }
    #[repr(C)]
    struct OPENSSL_STACK {
        _private: [u8; 0],
    }

    extern "C" {
        fn signal(sig: c_int, handler: extern "C" fn(c_int)) -> usize;
    }

    #[link(name = "ssl")]
    extern "C" {
        fn TLS_server_method() -> *const SSL_METHOD;
        fn TLS_client_method() -> *const SSL_METHOD;
        fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
        fn SSL_CTX_free(ctx: *mut SSL_CTX);
        fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
        fn SSL_CTX_callback_ctrl(
            ctx: *mut SSL_CTX,
            cmd: c_int,
            cb: Option<unsafe extern "C" fn(*mut Ssl, *mut c_int, *mut c_void) -> c_int>,
        ) -> c_long;
        fn SSL_CTX_set_options(ctx: *mut SSL_CTX, op: u64) -> u64;
        fn SSL_CTX_set_ciphersuites(ctx: *mut SSL_CTX, str_: *const c_char) -> c_int;
        fn SSL_CTX_set_cipher_list(ctx: *mut SSL_CTX, str_: *const c_char) -> c_int;
        fn SSL_CTX_use_certificate(ctx: *mut SSL_CTX, x: *mut X509) -> c_int;
        fn SSL_CTX_use_PrivateKey(ctx: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> c_int;
        fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) -> c_int;
        fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
        fn SSL_CTX_load_verify_locations(
            ctx: *mut SSL_CTX,
            ca_file: *const c_char,
            ca_path: *const c_char,
        ) -> c_int;
        fn SSL_new(ctx: *mut SSL_CTX) -> *mut Ssl;
        fn SSL_free(ssl: *mut Ssl);
        fn SSL_set_fd(ssl: *mut Ssl, fd: c_int) -> c_int;
        fn SSL_set_SSL_CTX(ssl: *mut Ssl, ctx: *mut SSL_CTX) -> *mut SSL_CTX;
        fn SSL_get_servername(ssl: *const Ssl, name_type: c_int) -> *const c_char;
        fn SSL_ctrl(ssl: *mut Ssl, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
        fn SSL_set1_host(ssl: *mut Ssl, hostname: *const c_char) -> c_int;
        fn SSL_set_verify(ssl: *mut Ssl, mode: c_int, cb: *const c_void);
        fn SSL_accept(ssl: *mut Ssl) -> c_int;
        fn SSL_connect(ssl: *mut Ssl) -> c_int;
        fn SSL_read(ssl: *mut Ssl, buf: *mut c_void, num: c_int) -> c_int;
        fn SSL_write(ssl: *mut Ssl, buf: *const c_void, num: c_int) -> c_int;
        fn SSL_shutdown(ssl: *mut Ssl) -> c_int;
        fn SSL_get_error(ssl: *const Ssl, ret_code: c_int) -> c_int;
        fn SSL_get_version(ssl: *const Ssl) -> *const c_char;
        fn SSL_get1_peer_certificate(ssl: *const Ssl) -> *mut X509;
        fn SSL_CTX_set_keylog_callback(
            ctx: *mut SSL_CTX,
            cb: Option<unsafe extern "C" fn(*const Ssl, *const c_char)>,
        );
        fn SSL_export_keying_material(
            ssl: *mut Ssl,
            out: *mut c_uchar,
            olen: usize,
            label: *const c_char,
            llen: usize,
            context: *const c_uchar,
            contextlen: usize,
            use_context: c_int,
        ) -> c_int;
    }

    #[link(name = "crypto")]
    extern "C" {
        fn ERR_clear_error();
        fn BIO_s_mem() -> *const BIO_METHOD;
        fn BIO_new(method: *const BIO_METHOD) -> *mut Bio;
        fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut Bio;
        fn BIO_ctrl(bp: *mut Bio, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
        fn BIO_free(a: *mut Bio) -> c_int;
        fn PEM_read_bio_X509(
            bp: *mut Bio,
            x: *mut *mut X509,
            cb: *const c_void,
            u: *mut c_void,
        ) -> *mut X509;
        fn PEM_read_bio_PrivateKey(
            bp: *mut Bio,
            x: *mut *mut EVP_PKEY,
            cb: *const c_void,
            u: *mut c_void,
        ) -> *mut EVP_PKEY;
        fn PEM_write_bio_PrivateKey(
            bp: *mut Bio,
            x: *const EVP_PKEY,
            enc: *const c_void,
            kstr: *const c_uchar,
            klen: c_int,
            cb: *const c_void,
            u: *mut c_void,
        ) -> c_int;
        fn X509_free(a: *mut X509);
        fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509_PUBKEY;
        fn i2d_X509_PUBKEY(a: *const X509_PUBKEY, pp: *mut *mut c_uchar) -> c_int;
        fn i2d_X509(x: *const X509, out: *mut *mut c_uchar) -> c_int;
        fn X509_get0_notAfter(x: *const X509) -> *const ASN1_TIME;
        fn X509_get0_serialNumber(x: *const X509) -> *const ASN1_INTEGER;
        fn X509_get_subject_name(a: *const X509) -> *mut X509_NAME;
        fn X509_NAME_get_text_by_NID(
            name: *const X509_NAME,
            nid: c_int,
            buf: *mut c_char,
            len: c_int,
        ) -> c_int;
        fn ASN1_TIME_diff(
            pday: *mut c_int,
            psec: *mut c_int,
            from: *const ASN1_TIME,
            to: *const ASN1_TIME,
        ) -> c_int;
        fn ASN1_INTEGER_to_BN(ai: *const ASN1_INTEGER, bn: *mut Bignum) -> *mut Bignum;
        fn BN_bn2hex(a: *const Bignum) -> *mut c_char;
        fn BN_bn2binpad(a: *const Bignum, to: *mut c_uchar, tolen: c_int) -> c_int;
        fn BN_free(a: *mut Bignum);
        fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);

        fn EVP_PKEY_CTX_new_id(id: c_int, e: *mut c_void) -> *mut EVP_PKEY_CTX;
        fn EVP_PKEY_CTX_free(ctx: *mut EVP_PKEY_CTX);
        fn EVP_PKEY_keygen_init(ctx: *mut EVP_PKEY_CTX) -> c_int;
        fn EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: *mut EVP_PKEY_CTX, nid: c_int) -> c_int;
        fn EVP_PKEY_keygen(ctx: *mut EVP_PKEY_CTX, ppkey: *mut *mut EVP_PKEY) -> c_int;
        fn EVP_PKEY_get_bn_param(
            pkey: *const EVP_PKEY,
            key_name: *const c_char,
            bn: *mut *mut Bignum,
        ) -> c_int;
        fn EVP_PKEY_free(pkey: *mut EVP_PKEY);

        fn EVP_sha256() -> *const EVP_MD;
        fn EVP_MD_CTX_new() -> *mut EVP_MD_CTX;
        fn EVP_MD_CTX_free(ctx: *mut EVP_MD_CTX);
        fn EVP_DigestSignInit(
            ctx: *mut EVP_MD_CTX,
            pctx: *mut *mut EVP_PKEY_CTX,
            md: *const EVP_MD,
            e: *mut c_void,
            pkey: *mut EVP_PKEY,
        ) -> c_int;
        fn EVP_DigestSignUpdate(ctx: *mut EVP_MD_CTX, d: *const c_void, cnt: usize) -> c_int;
        fn EVP_DigestSignFinal(
            ctx: *mut EVP_MD_CTX,
            sigret: *mut c_uchar,
            siglen: *mut usize,
        ) -> c_int;

        fn d2i_ECDSA_SIG(
            sig: *mut *mut ECDSA_SIG,
            pp: *mut *const c_uchar,
            len: c_long,
        ) -> *mut ECDSA_SIG;
        fn ECDSA_SIG_get0(sig: *const ECDSA_SIG, pr: *mut *const Bignum, ps: *mut *const Bignum);
        fn ECDSA_SIG_free(sig: *mut ECDSA_SIG);

        fn X509_REQ_new() -> *mut X509_REQ;
        fn X509_REQ_free(a: *mut X509_REQ);
        fn X509_REQ_set_version(x: *mut X509_REQ, version: c_long) -> c_int;
        fn X509_REQ_get_subject_name(req: *const X509_REQ) -> *mut X509_NAME;
        fn X509_NAME_add_entry_by_txt(
            name: *mut X509_NAME,
            field: *const c_char,
            name_type: c_int,
            bytes: *const c_uchar,
            len: c_int,
            loc: c_int,
            set: c_int,
        ) -> c_int;
        fn X509_REQ_set_pubkey(x: *mut X509_REQ, pkey: *mut EVP_PKEY) -> c_int;
        fn X509V3_EXT_conf_nid(
            conf: *mut c_void,
            ctx: *mut c_void,
            ext_nid: c_int,
            value: *const c_char,
        ) -> *mut X509_EXTENSION;
        fn X509_EXTENSION_free(a: *mut X509_EXTENSION);
        fn OPENSSL_sk_new_null() -> *mut OPENSSL_STACK;
        fn OPENSSL_sk_push(st: *mut OPENSSL_STACK, data: *const c_void) -> c_int;
        fn OPENSSL_sk_pop_free(
            st: *mut OPENSSL_STACK,
            func: unsafe extern "C" fn(*mut c_void),
        );
        fn X509_REQ_add_extensions(req: *mut X509_REQ, exts: *const OPENSSL_STACK) -> c_int;
        fn X509_REQ_sign(x: *mut X509_REQ, pkey: *mut EVP_PKEY, md: *const EVP_MD) -> c_int;
        fn i2d_X509_REQ(a: *const X509_REQ, out: *mut *mut c_uchar) -> c_int;
    }

    extern "C" fn on_sighup(_sig: c_int) {
        SIGHUP_RECEIVED.store(true, Ordering::Release);
    }

    extern "C" fn on_shutdown(_sig: c_int) {
        SHUTDOWN_RECEIVED.store(true, Ordering::Release);
    }

    /// Installs async-signal-safe handlers for `SIGHUP`, `SIGTERM`, and `SIGINT`.
    pub fn install_signal_handlers() {
        unsafe {
            let _ = signal(SIGHUP, on_sighup);
            let _ = signal(SIGTERM, on_shutdown);
            let _ = signal(SIGINT, on_shutdown);
        }
    }

    struct SslCtxHolder {
        raw: *mut SSL_CTX,
    }

    // SAFETY: OpenSSL 3.0 SSL_CTX is immutable after setup and internally refcounted.
    unsafe impl Send for SslCtxHolder {}
    unsafe impl Sync for SslCtxHolder {}

    impl Drop for SslCtxHolder {
        fn drop(&mut self) {
            unsafe {
                SSL_CTX_free(self.raw);
            }
        }
    }

    struct CertSnapshot {
        default_ctx: Option<Arc<SslCtxHolder>>,
        by_host: HashMap<String, Arc<SslCtxHolder>>,
        default_info: Option<LeafCertIntegrity>,
        info_by_host: HashMap<String, LeafCertIntegrity>,
        min_version: TlsMinVersion,
        generation: u64,
    }

    struct StoreCore {
        inner: RwLock<CertSnapshot>,
    }

    /// Atomic, SNI-aware OpenSSL 3.x TLS 1.2+/1.3 certificate store supporting zero-downtime hot-swap.
    pub struct TlsCertStore {
        core: Box<StoreCore>,
    }

    // SAFETY: StoreCore is protected by RwLock and SslCtxHolder is Send+Sync.
    unsafe impl Send for TlsCertStore {}
    unsafe impl Sync for TlsCertStore {}

    impl TlsCertStore {
        /// Creates an empty TLS certificate store ready to load or hot-swap PEM certificates.
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                core: Box::new(StoreCore {
                    inner: RwLock::new(CertSnapshot {
                        default_ctx: None,
                        by_host: HashMap::new(),
                        default_info: None,
                        info_by_host: HashMap::new(),
                        min_version: TlsMinVersion::Tls12,
                        generation: 0,
                    }),
                }),
            })
        }

        fn core_ptr(&self) -> *mut c_void {
            (&*self.core as *const StoreCore) as *mut c_void
        }

        /// Returns the current certificate reload generation counter.
        pub fn generation(&self) -> u64 {
            self.core.inner.read().map(|g| g.generation).unwrap_or(0)
        }

        /// Returns true if at least one certificate is currently loaded.
        pub fn has_certs(&self) -> bool {
            self.core
                .inner
                .read()
                .map(|g| g.default_ctx.is_some() || !g.by_host.is_empty())
                .unwrap_or(false)
        }

        /// Returns the loaded leaf certificate integrity metadata for `host` (or default).
        pub fn leaf_cert_info(&self, host: Option<&str>) -> Option<LeafCertIntegrity> {
            let guard = self.core.inner.read().ok()?;
            match host {
                Some(h) => {
                    let norm = normalize_sni_host(h);
                    match_sni_key(&guard.info_by_host, &norm)
                        .or(guard.default_info.as_ref())
                        .cloned()
                }
                None => guard.default_info.clone(),
            }
        }

        /// Installs or atomically hot-swaps a host certificate from PEM bytes.
        pub fn install_pem_bytes(
            &self,
            host: Option<&str>,
            cert_pem: &[u8],
            key_pem: &[u8],
            set_default: bool,
        ) -> Result<(), ProxyError> {
            let min_version = self
                .core
                .inner
                .read()
                .map(|g| g.min_version)
                .unwrap_or(TlsMinVersion::Tls12);
            let (raw_holder, info) =
                build_server_ctx_from_pem(cert_pem, key_pem, self.core_ptr(), min_version)?;
            let holder = Arc::new(raw_holder);
            let mut guard = self
                .core
                .inner
                .write()
                .map_err(|_| ProxyError::Tls("cert store lock poisoned"))?;
            if let Some(h) = host {
                let norm = normalize_sni_host(h);
                guard.by_host.insert(norm.clone(), Arc::clone(&holder));
                guard.info_by_host.insert(norm, info.clone());
            }
            if set_default || guard.default_ctx.is_none() {
                guard.default_ctx = Some(holder);
                guard.default_info = Some(info);
            }
            guard.generation = guard.generation.saturating_add(1);
            Ok(())
        }

        /// Installs or atomically hot-swaps a host certificate from PEM files on disk.
        pub fn install_pem_files(
            &self,
            host: Option<&str>,
            cert_path: &Path,
            key_path: &Path,
            set_default: bool,
        ) -> Result<(), ProxyError> {
            let cert_pem =
                fs::read(cert_path).map_err(|_| ProxyError::Tls("failed to read tls cert file"))?;
            let key_pem =
                fs::read(key_path).map_err(|_| ProxyError::Tls("failed to read tls key file"))?;
            self.install_pem_bytes(host, &cert_pem, &key_pem, set_default)
        }

        /// Reloads all certificates configured in `cfg` (`tls_cert`/`tls_key` and `cert_dir`)
        /// atomically so active connections keep their old `SSL_CTX` refcount with zero drops.
        pub fn reload_from_config(&self, cfg: &ProxyConfig) -> Result<usize, ProxyError> {
            let min_version = cfg.tls_min_version;
            let mut new_default: Option<Arc<SslCtxHolder>> = None;
            let mut new_map: HashMap<String, Arc<SslCtxHolder>> = HashMap::new();
            let mut new_default_info: Option<LeafCertIntegrity> = None;
            let mut new_info_map: HashMap<String, LeafCertIntegrity> = HashMap::new();
            let mut loaded = 0usize;

            if let (Some(cert_path), Some(key_path)) = (&cfg.tls_cert, &cfg.tls_key) {
                let cert_pem = fs::read(cert_path)
                    .map_err(|_| ProxyError::Tls("failed to read tls_cert file"))?;
                let key_pem = fs::read(key_path)
                    .map_err(|_| ProxyError::Tls("failed to read tls_key file"))?;
                let (raw_holder, info) =
                    build_server_ctx_from_pem(&cert_pem, &key_pem, self.core_ptr(), min_version)?;
                let holder = Arc::new(raw_holder);
                if let Some(ref cn) = info.cn {
                    let norm = normalize_sni_host(cn);
                    new_map.insert(norm.clone(), Arc::clone(&holder));
                    new_info_map.insert(norm, info.clone());
                }
                new_default = Some(holder);
                new_default_info = Some(info);
                loaded += 1;
            }

            if let Some(cert_dir) = &cfg.cert_dir {
                if cert_dir.exists() {
                    let top_cert = cert_dir.join("fullchain.pem");
                    let top_key = cert_dir.join("privkey.pem");
                    if top_cert.is_file() && top_key.is_file() {
                        let cert_pem = fs::read(&top_cert)
                            .map_err(|_| ProxyError::Tls("failed to read fullchain.pem"))?;
                        let key_pem = fs::read(&top_key)
                            .map_err(|_| ProxyError::Tls("failed to read privkey.pem"))?;
                        let (raw_holder, info) = build_server_ctx_from_pem(
                            &cert_pem,
                            &key_pem,
                            self.core_ptr(),
                            min_version,
                        )?;
                        let holder = Arc::new(raw_holder);
                        if new_default.is_none() {
                            new_default = Some(Arc::clone(&holder));
                            new_default_info = Some(info.clone());
                        }
                        if let Some(ref cn) = info.cn {
                            let norm = normalize_sni_host(cn);
                            new_map.insert(norm.clone(), holder);
                            new_info_map.insert(norm, info);
                        }
                        loaded += 1;
                    }

                    let entries = fs::read_dir(cert_dir)
                        .map_err(|_| ProxyError::Tls("failed to read cert_dir"))?;
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let host = match entry.file_name().to_str() {
                                Some(name) if !name.starts_with('.') => normalize_sni_host(name),
                                _ => continue,
                            };
                            let cert_file = path.join("fullchain.pem");
                            let key_file = path.join("privkey.pem");
                            if cert_file.is_file() && key_file.is_file() {
                                let cert_pem = fs::read(&cert_file).map_err(|_| {
                                    ProxyError::Tls("failed to read host fullchain.pem")
                                })?;
                                let key_pem = fs::read(&key_file).map_err(|_| {
                                    ProxyError::Tls("failed to read host privkey.pem")
                                })?;
                                let (raw_holder, info) = build_server_ctx_from_pem(
                                    &cert_pem,
                                    &key_pem,
                                    self.core_ptr(),
                                    min_version,
                                )?;
                                let holder = Arc::new(raw_holder);
                                if new_default.is_none() {
                                    new_default = Some(Arc::clone(&holder));
                                    new_default_info = Some(info.clone());
                                }
                                new_map.insert(host.clone(), holder);
                                new_info_map.insert(host, info);
                                loaded += 1;
                            }
                        }
                    }
                }
            }

            {
                let mut guard = self
                    .core
                    .inner
                    .write()
                    .map_err(|_| ProxyError::Tls("cert store lock poisoned"))?;
                guard.min_version = min_version;
                if loaded > 0 {
                    guard.default_ctx = new_default;
                    guard.by_host = new_map;
                    guard.default_info = new_default_info;
                    guard.info_by_host = new_info_map;
                    guard.generation = guard.generation.saturating_add(1);
                }
            }
            Ok(loaded)
        }

        fn current_default_ctx(&self) -> Result<Arc<SslCtxHolder>, ProxyError> {
            let guard = self
                .core
                .inner
                .read()
                .map_err(|_| ProxyError::Tls("cert store lock poisoned"))?;
            if let Some(ctx) = &guard.default_ctx {
                return Ok(Arc::clone(ctx));
            }
            guard
                .by_host
                .values()
                .next()
                .map(Arc::clone)
                .ok_or(ProxyError::Tls("no TLS certificate loaded"))
        }
    }

    unsafe extern "C" fn sni_callback(
        ssl: *mut Ssl,
        _ad: *mut c_int,
        arg: *mut c_void,
    ) -> c_int {
        if ssl.is_null() || arg.is_null() {
            return SSL_TLSEXT_ERR_NOACK;
        }
        let core = &*(arg as *const StoreCore);
        let name_ptr = SSL_get_servername(ssl, TLSEXT_NAMETYPE_HOST_NAME);
        let host_opt = if name_ptr.is_null() {
            None
        } else {
            CStr::from_ptr(name_ptr)
                .to_str()
                .ok()
                .map(normalize_sni_host)
        };
        let guard = match core.inner.read() {
            Ok(g) => g,
            Err(_) => return SSL_TLSEXT_ERR_NOACK,
        };
        let chosen = match host_opt.as_deref() {
            Some(host) => match_sni_key(&guard.by_host, host).or(guard.default_ctx.as_ref()),
            None => guard.default_ctx.as_ref(),
        };
        if let Some(ctx) = chosen {
            let _ = SSL_set_SSL_CTX(ssl, ctx.raw);
            SSL_TLSEXT_ERR_OK
        } else {
            SSL_TLSEXT_ERR_NOACK
        }
    }

    fn build_server_ctx_from_pem(
        cert_pem: &[u8],
        key_pem: &[u8],
        store_ptr: *mut c_void,
        min_version: TlsMinVersion,
    ) -> Result<(SslCtxHolder, LeafCertIntegrity), ProxyError> {
        if cert_pem.is_empty() || key_pem.is_empty() {
            return Err(ProxyError::Tls("empty PEM certificate or key"));
        }
        unsafe {
            ERR_clear_error();
            let method = TLS_server_method();
            if method.is_null() {
                return Err(ProxyError::Tls("TLS_server_method failed"));
            }
            let ctx = SSL_CTX_new(method);
            if ctx.is_null() {
                return Err(ProxyError::Tls("SSL_CTX_new failed"));
            }
            let holder = SslCtxHolder { raw: ctx };

            let min_proto = match min_version {
                TlsMinVersion::Tls12 => TLS1_2_VERSION,
                TlsMinVersion::Tls13 => TLS1_3_VERSION,
            };
            if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, min_proto, null_mut()) != 1 {
                return Err(ProxyError::Tls("failed to enforce TLS minimum protocol version"));
            }
            if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, TLS1_3_VERSION, null_mut()) != 1 {
                return Err(ProxyError::Tls("failed to configure TLS 1.3 maximum"));
            }
            let _ = SSL_CTX_set_options(
                ctx,
                SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE,
            );
            if SSL_CTX_set_ciphersuites(
                ctx,
                c"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
                    .as_ptr(),
            ) != 1
            {
                return Err(ProxyError::Tls("failed to configure TLS 1.3 ciphersuites"));
            }
            if SSL_CTX_set_cipher_list(
                ctx,
                c"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
                    .as_ptr(),
            ) != 1
            {
                return Err(ProxyError::Tls("failed to configure TLS 1.2 AEAD cipher list"));
            }

            // Load certificate chain from PEM memory BIO.
            let cert_bio = BIO_new_mem_buf(cert_pem.as_ptr() as *const c_void, cert_pem.len() as c_int);
            if cert_bio.is_null() {
                return Err(ProxyError::Tls("BIO_new_mem_buf cert failed"));
            }
            let leaf = PEM_read_bio_X509(cert_bio, null_mut(), null(), null_mut());
            if leaf.is_null() {
                BIO_free(cert_bio);
                return Err(ProxyError::Tls("failed to parse leaf X509 PEM"));
            }
            let leaf_info = match extract_leaf_cert_integrity(leaf) {
                Ok(info) => info,
                Err(err) => {
                    X509_free(leaf);
                    BIO_free(cert_bio);
                    return Err(err);
                }
            };
            let use_ok = SSL_CTX_use_certificate(ctx, leaf);
            X509_free(leaf);
            if use_ok != 1 {
                BIO_free(cert_bio);
                return Err(ProxyError::Tls("SSL_CTX_use_certificate failed"));
            }
            loop {
                let extra = PEM_read_bio_X509(cert_bio, null_mut(), null(), null_mut());
                if extra.is_null() {
                    ERR_clear_error();
                    break;
                }
                if SSL_CTX_ctrl(ctx, SSL_CTRL_EXTRA_CHAIN_CERT, 0, extra as *mut c_void) != 1 {
                    X509_free(extra);
                    BIO_free(cert_bio);
                    return Err(ProxyError::Tls("SSL_CTX_add_extra_chain_cert failed"));
                }
            }
            BIO_free(cert_bio);

            // Load private key from PEM memory BIO.
            let key_bio = BIO_new_mem_buf(key_pem.as_ptr() as *const c_void, key_pem.len() as c_int);
            if key_bio.is_null() {
                return Err(ProxyError::Tls("BIO_new_mem_buf key failed"));
            }
            let pkey = PEM_read_bio_PrivateKey(key_bio, null_mut(), null(), null_mut());
            BIO_free(key_bio);
            if pkey.is_null() {
                return Err(ProxyError::Tls("failed to parse private key PEM"));
            }
            let key_ok = SSL_CTX_use_PrivateKey(ctx, pkey);
            EVP_PKEY_free(pkey);
            if key_ok != 1 {
                return Err(ProxyError::Tls("SSL_CTX_use_PrivateKey failed"));
            }
            if SSL_CTX_check_private_key(ctx) != 1 {
                return Err(ProxyError::Tls("certificate and private key mismatch"));
            }

            // Register SNI callback pointing to the pinned StoreCore.
            let _ = SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, Some(sni_callback));
            let _ = SSL_CTX_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG, 0, store_ptr);

            Ok((holder, leaf_info))
        }
    }

    /// Server-side OpenSSL 3.x TLS stream wrapping a `TcpStream`.
    ///
    /// Field drop order is strictly `ssl` -> `_store` -> `stream` so `SSL_free` always runs
    /// before the underlying socket and `TlsCertStore` drop.
    pub struct TlsServerStream {
        ssl: *mut Ssl,
        _store: Arc<TlsCertStore>,
        stream: TcpStream,
    }

    // SAFETY: TlsServerStream has exclusive ownership of its SSL* and TcpStream.
    unsafe impl Send for TlsServerStream {}

    impl TlsServerStream {
        /// Performs a blocking TLS 1.2+/1.3 server handshake on `stream` with SNI lookup.
        pub fn accept(
            stream: TcpStream,
            store: Arc<TlsCertStore>,
            handshake_timeout: Duration,
        ) -> Result<Self, ProxyError> {
            let _ = stream.set_read_timeout(Some(handshake_timeout));
            let _ = stream.set_write_timeout(Some(handshake_timeout));
            let default_ctx = store.current_default_ctx()?;

            unsafe {
                ERR_clear_error();
                let ssl = SSL_new(default_ctx.raw);
                if ssl.is_null() {
                    return Err(ProxyError::Tls("SSL_new failed"));
                }
                let fd = stream.as_raw_fd();
                if SSL_set_fd(ssl, fd) != 1 {
                    SSL_free(ssl);
                    return Err(ProxyError::Tls("SSL_set_fd failed"));
                }
                let ret = SSL_accept(ssl);
                if ret != 1 {
                    let err_code = SSL_get_error(ssl, ret);
                    SSL_free(ssl);
                    if err_code == SSL_ERROR_WANT_READ || err_code == SSL_ERROR_WANT_WRITE {
                        return Err(ProxyError::HeaderTimeout);
                    }
                    return Err(ProxyError::Tls("TLS server handshake failed"));
                }
                Ok(Self {
                    ssl,
                    _store: store,
                    stream,
                })
            }
        }

        pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            self.stream.set_read_timeout(dur)
        }

        pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            self.stream.set_write_timeout(dur)
        }

        pub fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
            unsafe {
                let _ = SSL_shutdown(self.ssl);
            }
            self.stream.shutdown(how)
        }

        /// Exports 32 bytes of RFC 8446 Section 7.5 TLS 1.3 keying material.
        pub fn export_tls13_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> Result<[u8; 32], ProxyError> {
            export_tls13_keying_material_raw(self.ssl, label, context)
        }
    }

    impl Drop for TlsServerStream {
        fn drop(&mut self) {
            unsafe {
                let _ = SSL_shutdown(self.ssl);
                SSL_free(self.ssl);
            }
        }
    }

    impl Read for TlsServerStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            ssl_read_impl(self.ssl, buf)
        }
    }

    impl Write for TlsServerStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            ssl_write_impl(self.ssl, buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    static KEYLOG_LOCK: Mutex<()> = Mutex::new(());
    static KEYLOG_EXPORTER_SECRET: Mutex<Option<Vec<u8>>> = Mutex::new(None);

    const fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    fn decode_hex_bytes(hex: &str) -> Option<Vec<u8>> {
        let bytes = hex.as_bytes();
        if (bytes.len() & 1) != 0 {
            return None;
        }
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i])?;
            let lo = hex_nibble(bytes[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Some(out)
    }

    unsafe extern "C" fn keylog_exporter_cb(_ssl: *const Ssl, line: *const c_char) {
        if line.is_null() {
            return;
        }
        let Ok(text) = CStr::from_ptr(line).to_str() else {
            return;
        };
        let mut parts = text.split_ascii_whitespace();
        if parts.next() != Some("EXPORTER_SECRET") {
            return;
        }
        let _ = parts.next();
        let Some(secret_hex) = parts.next() else {
            return;
        };
        if let Some(secret) = decode_hex_bytes(secret_hex) {
            if let Ok(mut guard) = KEYLOG_EXPORTER_SECRET.lock() {
                *guard = Some(secret);
            }
        }
    }

    fn export_tls13_keying_material_raw(
        ssl: *mut Ssl,
        label: &[u8],
        context: &[u8],
    ) -> Result<[u8; 32], ProxyError> {
        if label.is_empty() || label.len() > 249 {
            return Err(ProxyError::Tls("invalid TLS 1.3 exporter label length"));
        }
        unsafe {
            let ver_ptr = SSL_get_version(ssl);
            if ver_ptr.is_null() {
                return Err(ProxyError::Tls("TLS protocol version unavailable"));
            }
            let ver = CStr::from_ptr(ver_ptr)
                .to_str()
                .map_err(|_| ProxyError::Tls("invalid TLS protocol version"))?;
            if ver != "TLSv1.3" {
                return Err(ProxyError::Tls("TLS 1.3 required for BlindBind exporter"));
            }

            let mut out = [0u8; 32];
            let ctx_ptr = if context.is_empty() {
                null()
            } else {
                context.as_ptr()
            };
            let rc = SSL_export_keying_material(
                ssl,
                out.as_mut_ptr(),
                out.len(),
                label.as_ptr() as *const c_char,
                label.len(),
                ctx_ptr,
                context.len(),
                1,
            );
            if rc != 1 {
                return Err(ProxyError::Tls("SSL_export_keying_material failed"));
            }
            Ok(out)
        }
    }

    /// Client-side OpenSSL 3.x TLS stream for HTTPS ACME calls and E2E verification.
    pub struct TlsClientStream {
        ssl: *mut Ssl,
        ctx: *mut SSL_CTX,
        stream: TcpStream,
    }

    // SAFETY: TlsClientStream owns its SSL*, SSL_CTX*, and TcpStream exclusively.
    unsafe impl Send for TlsClientStream {}

    struct ClientConnectOpts<'a> {
        min_proto: c_long,
        max_proto: c_long,
        tls13_ciphersuite: Option<&'a str>,
        capture_keylog: bool,
    }

    impl ClientConnectOpts<'_> {
        const fn with_max_proto(max_proto: c_long) -> Self {
            Self {
                min_proto: TLS1_2_VERSION,
                max_proto,
                tls13_ciphersuite: None,
                capture_keylog: false,
            }
        }
    }

    impl TlsClientStream {
        /// Connects TLS over an already-connected `TcpStream` with SNI and optional cert verification.
        pub fn connect(
            stream: TcpStream,
            server_name: &str,
            verify_peer: bool,
            ca_cert_path: Option<&Path>,
        ) -> Result<Self, ProxyError> {
            Self::connect_inner(
                stream,
                server_name,
                verify_peer,
                ca_cert_path,
                ClientConnectOpts::with_max_proto(TLS1_3_VERSION),
            )
            .map(|(s, _)| s)
        }

        /// Connects forcing TLS 1.2 (for protocol-downgrade rejection verification).
        pub fn connect_tls12(
            stream: TcpStream,
            server_name: &str,
            verify_peer: bool,
            ca_cert_path: Option<&Path>,
        ) -> Result<Self, ProxyError> {
            let (s, _) = Self::connect_inner(
                stream,
                server_name,
                verify_peer,
                ca_cert_path,
                ClientConnectOpts::with_max_proto(TLS1_2_VERSION),
            )?;
            Ok(s)
        }

        /// Connects over TLS 1.3 with optional ciphersuite pin and captures the negotiated
        /// RFC 8446 `EXPORTER_SECRET` via OpenSSL's keylog callback.
        pub fn connect_with_keylog(
            stream: TcpStream,
            server_name: &str,
            verify_peer: bool,
            ca_cert_path: Option<&Path>,
            tls13_ciphersuite: Option<&str>,
        ) -> Result<(Self, Option<Vec<u8>>), ProxyError> {
            Self::connect_inner(
                stream,
                server_name,
                verify_peer,
                ca_cert_path,
                ClientConnectOpts {
                    min_proto: TLS1_3_VERSION,
                    max_proto: TLS1_3_VERSION,
                    tls13_ciphersuite,
                    capture_keylog: true,
                },
            )
        }

        fn connect_inner(
            stream: TcpStream,
            server_name: &str,
            verify_peer: bool,
            ca_cert_path: Option<&Path>,
            opts: ClientConnectOpts<'_>,
        ) -> Result<(Self, Option<Vec<u8>>), ProxyError> {
            let sni_c = CString::new(server_name)
                .map_err(|_| ProxyError::Tls("invalid SNI server name"))?;
            let cs_c = match opts.tls13_ciphersuite {
                Some(cs) => Some(
                    CString::new(cs)
                        .map_err(|_| ProxyError::Tls("invalid TLS 1.3 ciphersuite"))?,
                ),
                None => None,
            };
            let keylog_guard = if opts.capture_keylog {
                let g = KEYLOG_LOCK
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if let Ok(mut slot) = KEYLOG_EXPORTER_SECRET.lock() {
                    *slot = None;
                }
                Some(g)
            } else {
                None
            };

            let res = (|| -> Result<(Self, Option<Vec<u8>>), ProxyError> {
                unsafe {
                ERR_clear_error();
                let method = TLS_client_method();
                if method.is_null() {
                    return Err(ProxyError::Tls("TLS_client_method failed"));
                }
                let ctx = SSL_CTX_new(method);
                if ctx.is_null() {
                    return Err(ProxyError::Tls("SSL_CTX_new client failed"));
                }
                if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, opts.min_proto, null_mut())
                    != 1
                {
                    SSL_CTX_free(ctx);
                    return Err(ProxyError::Tls("failed to set client TLS min version"));
                }
                if SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, opts.max_proto, null_mut())
                    != 1
                {
                    SSL_CTX_free(ctx);
                    return Err(ProxyError::Tls("failed to set client TLS max version"));
                }
                if let Some(cs) = cs_c.as_ref() {
                    if SSL_CTX_set_ciphersuites(ctx, cs.as_ptr()) != 1 {
                        SSL_CTX_free(ctx);
                        return Err(ProxyError::Tls("failed to set client TLS 1.3 ciphersuite"));
                    }
                }
                if opts.capture_keylog {
                    SSL_CTX_set_keylog_callback(ctx, Some(keylog_exporter_cb));
                }

                if verify_peer {
                    if let Some(ca_path) = ca_cert_path {
                        let ca_c = match ca_path.to_str().and_then(|s| CString::new(s).ok()) {
                            Some(c) => c,
                            None => {
                                SSL_CTX_free(ctx);
                                return Err(ProxyError::Tls("invalid ca_cert path"));
                            }
                        };
                        if SSL_CTX_load_verify_locations(ctx, ca_c.as_ptr(), null()) != 1 {
                            SSL_CTX_free(ctx);
                            return Err(ProxyError::Tls("failed to load ACME CA cert"));
                        }
                    } else if SSL_CTX_set_default_verify_paths(ctx) != 1 {
                        SSL_CTX_free(ctx);
                        return Err(ProxyError::Tls("failed to load system trust store"));
                    }
                }

                let ssl = SSL_new(ctx);
                if ssl.is_null() {
                    SSL_CTX_free(ctx);
                    return Err(ProxyError::Tls("SSL_new client failed"));
                }
                if SSL_set_fd(ssl, stream.as_raw_fd()) != 1 {
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return Err(ProxyError::Tls("SSL_set_fd client failed"));
                }
                let _ = SSL_ctrl(
                    ssl,
                    SSL_CTRL_SET_TLSEXT_HOSTNAME,
                    c_long::from(TLSEXT_NAMETYPE_HOST_NAME),
                    sni_c.as_ptr() as *mut c_void,
                );
                if verify_peer {
                    SSL_set_verify(ssl, SSL_VERIFY_PEER, null());
                    if SSL_set1_host(ssl, sni_c.as_ptr()) != 1 {
                        SSL_free(ssl);
                        SSL_CTX_free(ctx);
                        return Err(ProxyError::Tls("SSL_set1_host failed"));
                    }
                } else {
                    SSL_set_verify(ssl, SSL_VERIFY_NONE, null());
                }

                if SSL_connect(ssl) != 1 {
                    if opts.capture_keylog {
                        SSL_CTX_set_keylog_callback(ctx, None);
                    }
                    SSL_free(ssl);
                    SSL_CTX_free(ctx);
                    return Err(ProxyError::Tls("TLS client handshake failed"));
                }

                let exporter_secret = if opts.capture_keylog {
                    SSL_CTX_set_keylog_callback(ctx, None);
                    KEYLOG_EXPORTER_SECRET
                        .lock()
                        .ok()
                        .and_then(|mut g| g.take())
                } else {
                    None
                };

                Ok((Self { ssl, ctx, stream }, exporter_secret))
            }
            })();
            drop(keylog_guard);
            res
        }

        /// Exports 32 bytes of RFC 8446 Section 7.5 TLS 1.3 keying material.
        pub fn export_tls13_keying_material(
            &self,
            label: &[u8],
            context: &[u8],
        ) -> Result<[u8; 32], ProxyError> {
            export_tls13_keying_material_raw(self.ssl, label, context)
        }

        /// Returns the negotiated TLS protocol string (e.g. `"TLSv1.3"`).
        pub fn protocol_version(&self) -> Option<String> {
            unsafe {
                let ptr = SSL_get_version(self.ssl);
                if ptr.is_null() {
                    return None;
                }
                CStr::from_ptr(ptr).to_str().ok().map(str::to_owned)
            }
        }

        fn with_peer_cert<T>(&self, extract: unsafe fn(*const X509) -> Option<T>) -> Option<T> {
            unsafe {
                let x509 = SSL_get1_peer_certificate(self.ssl);
                if x509.is_null() {
                    return None;
                }
                let out = extract(x509);
                X509_free(x509);
                out
            }
        }

        /// Returns the peer certificate's Common Name (CN), if present.
        pub fn peer_cert_cn(&self) -> Option<String> {
            self.with_peer_cert(extract_x509_cn)
        }

        /// Returns the peer certificate's hexadecimal serial number.
        pub fn peer_cert_serial_hex(&self) -> Option<String> {
            self.with_peer_cert(|x509| unsafe { extract_x509_serial_hex_case(x509, false) })
        }
    }

    impl Drop for TlsClientStream {
        fn drop(&mut self) {
            unsafe {
                let _ = SSL_shutdown(self.ssl);
                SSL_free(self.ssl);
                SSL_CTX_free(self.ctx);
            }
        }
    }

    impl Read for TlsClientStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            ssl_read_impl(self.ssl, buf)
        }
    }

    impl Write for TlsClientStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            ssl_write_impl(self.ssl, buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    unsafe fn finish_ssl_io(ssl: *mut Ssl, ret: c_int, is_write: bool) -> io::Result<usize> {
        if ret > 0 {
            return Ok(ret as usize);
        }
        match SSL_get_error(ssl, ret) {
            SSL_ERROR_ZERO_RETURN if !is_write => Ok(0),
            SSL_ERROR_ZERO_RETURN => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "tls peer closed write",
            )),
            SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                if is_write {
                    "tls write timeout"
                } else {
                    "tls read timeout"
                },
            )),
            SSL_ERROR_SYSCALL => {
                let os_err = io::Error::last_os_error();
                if os_err.raw_os_error() == Some(0) {
                    if is_write {
                        Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "tls connection closed",
                        ))
                    } else {
                        Ok(0)
                    }
                } else {
                    Err(os_err)
                }
            }
            _ => Err(io::Error::new(
                if is_write {
                    io::ErrorKind::BrokenPipe
                } else {
                    io::ErrorKind::InvalidData
                },
                if is_write {
                    "tls write error"
                } else {
                    "tls read error"
                },
            )),
        }
    }

    fn ssl_io_op(
        ssl: *mut Ssl,
        buf_len: usize,
        is_write: bool,
        op: impl FnOnce(c_int) -> c_int,
    ) -> io::Result<usize> {
        if buf_len == 0 {
            return Ok(0);
        }
        let max_len = buf_len.min(c_int::MAX as usize) as c_int;
        unsafe {
            ERR_clear_error();
            let ret = op(max_len);
            finish_ssl_io(ssl, ret, is_write)
        }
    }

    fn ssl_read_impl(ssl: *mut Ssl, buf: &mut [u8]) -> io::Result<usize> {
        ssl_io_op(ssl, buf.len(), false, |max_len| unsafe {
            SSL_read(ssl, buf.as_mut_ptr() as *mut c_void, max_len)
        })
    }

    fn ssl_write_impl(ssl: *mut Ssl, buf: &[u8]) -> io::Result<usize> {
        ssl_io_op(ssl, buf.len(), true, |max_len| unsafe {
            SSL_write(ssl, buf.as_ptr() as *const c_void, max_len)
        })
    }

    unsafe fn extract_x509_cn(x509: *const X509) -> Option<String> {
        let name = X509_get_subject_name(x509);
        if name.is_null() {
            return None;
        }
        let mut buf = [0u8; 256];
        let n = X509_NAME_get_text_by_NID(
            name,
            NID_COMMON_NAME,
            buf.as_mut_ptr() as *mut c_char,
            buf.len() as c_int,
        );
        if n <= 0 {
            return None;
        }
        let len = (n as usize).min(buf.len() - 1);
        std::str::from_utf8(&buf[..len]).ok().map(str::to_owned)
    }

    unsafe fn extract_x509_serial_hex_case(x509: *const X509, lowercase: bool) -> Option<String> {
        let serial = X509_get0_serialNumber(x509);
        if serial.is_null() {
            return None;
        }
        let bn = ASN1_INTEGER_to_BN(serial, null_mut());
        if bn.is_null() {
            return None;
        }
        let hptr = BN_bn2hex(bn);
        let res = if hptr.is_null() {
            None
        } else {
            let s = CStr::from_ptr(hptr).to_str().ok().map(|v| {
                if lowercase {
                    v.to_ascii_lowercase()
                } else {
                    v.to_owned()
                }
            });
            CRYPTO_free(hptr as *mut c_void, c"tls.rs".as_ptr(), 0);
            s
        };
        BN_free(bn);
        res
    }

    unsafe fn extract_x509_serial_hex(x509: *const X509) -> Option<String> {
        extract_x509_serial_hex_case(x509, true)
    }

    unsafe fn extract_x509_days_remaining(x509: *const X509) -> Result<i64, ProxyError> {
        let not_after = X509_get0_notAfter(x509);
        if not_after.is_null() {
            return Err(ProxyError::Tls("missing X509 notAfter"));
        }
        let mut pday: c_int = 0;
        let mut psec: c_int = 0;
        if ASN1_TIME_diff(&mut pday, &mut psec, null(), not_after) != 1 {
            return Err(ProxyError::Tls("ASN1_TIME_diff failed"));
        }
        if pday == 0 && psec < 0 {
            Ok(-1)
        } else {
            Ok(i64::from(pday))
        }
    }

    unsafe fn extract_leaf_cert_integrity(x509: *const X509) -> Result<LeafCertIntegrity, ProxyError> {
        let pubkey = X509_get_X509_PUBKEY(x509);
        if pubkey.is_null() {
            return Err(ProxyError::Tls("X509_get_X509_PUBKEY failed"));
        }
        let spki_len = i2d_X509_PUBKEY(pubkey, null_mut());
        if spki_len <= 0 {
            return Err(ProxyError::Tls("i2d_X509_PUBKEY sizing failed"));
        }
        let mut spki_der = vec![0u8; spki_len as usize];
        let mut spki_ptr = spki_der.as_mut_ptr();
        if i2d_X509_PUBKEY(pubkey, &mut spki_ptr) != spki_len {
            return Err(ProxyError::Tls("i2d_X509_PUBKEY encoding failed"));
        }
        let spki_hash = sha256(&spki_der);

        let cert_len = i2d_X509(x509, null_mut());
        if cert_len <= 0 {
            return Err(ProxyError::Tls("i2d_X509 sizing failed"));
        }
        let mut cert_der = vec![0u8; cert_len as usize];
        let mut cert_ptr = cert_der.as_mut_ptr();
        if i2d_X509(x509, &mut cert_ptr) != cert_len {
            return Err(ProxyError::Tls("i2d_X509 encoding failed"));
        }
        let cert_hash = sha256(&cert_der);

        let serial_hex = extract_x509_serial_hex(x509).unwrap_or_default();
        let cn = extract_x509_cn(x509);
        let days_remaining = extract_x509_days_remaining(x509)?;

        Ok(LeafCertIntegrity {
            spki_sha256_b64: base64_encode(&spki_hash),
            spki_sha256_hex: hex_encode(&spki_hash),
            cert_sha256_hex: hex_encode(&cert_hash),
            serial_hex,
            cn,
            days_remaining,
        })
    }

    unsafe fn pem_read_x509(bio: *mut Bio) -> *mut X509 {
        PEM_read_bio_X509(bio, null_mut(), null(), null_mut())
    }

    unsafe fn pem_read_pkey(bio: *mut Bio) -> *mut EVP_PKEY {
        PEM_read_bio_PrivateKey(bio, null_mut(), null(), null_mut())
    }

    fn read_pem_ptr<P>(
        pem: &[u8],
        make_err: fn(&'static str) -> ProxyError,
        empty_msg: &'static str,
        parse_msg: &'static str,
        read_obj: unsafe fn(*mut Bio) -> *mut P,
    ) -> Result<*mut P, ProxyError> {
        if pem.is_empty() {
            return Err(make_err(empty_msg));
        }
        unsafe {
            ERR_clear_error();
            let bio = BIO_new_mem_buf(pem.as_ptr() as *const c_void, pem.len() as c_int);
            if bio.is_null() {
                return Err(make_err("BIO_new_mem_buf failed"));
            }
            let obj = read_obj(bio);
            BIO_free(bio);
            if obj.is_null() {
                return Err(make_err(parse_msg));
            }
            Ok(obj)
        }
    }

    fn with_pem_x509<T>(
        cert_pem: &[u8],
        extract: unsafe fn(*const X509) -> Result<T, ProxyError>,
    ) -> Result<T, ProxyError> {
        let x509 = read_pem_ptr(
            cert_pem,
            ProxyError::Tls,
            "empty cert pem",
            "failed to parse X509 cert",
            pem_read_x509,
        )?;
        unsafe {
            let res = extract(x509);
            X509_free(x509);
            res
        }
    }

    /// Computes the standard Base64 SHA-256 digest of a PEM leaf certificate's SPKI DER.
    pub fn cert_spki_sha256_b64(cert_pem: &[u8]) -> Result<String, ProxyError> {
        with_pem_x509(cert_pem, |x509| unsafe {
            extract_leaf_cert_integrity(x509).map(|info| info.spki_sha256_b64)
        })
    }

    /// Extracts the Common Name (CN) from a PEM-encoded X.509 certificate.
    pub fn cert_common_name(cert_pem: &[u8]) -> Option<String> {
        with_pem_x509(cert_pem, |x509| unsafe { Ok(extract_x509_cn(x509)) })
            .ok()
            .flatten()
    }

    /// Returns the number of full days remaining until a PEM X.509 certificate expires
    /// (negative if already expired).
    pub fn cert_days_until_expiry(cert_pem: &[u8]) -> Result<i64, ProxyError> {
        with_pem_x509(cert_pem, extract_x509_days_remaining)
    }

    /// OpenSSL 3.x ECDSA P-256 (`prime256v1`) key pair for ACME ES256 JWS & PKCS#10 CSR signing.
    pub struct EcP256Key {
        pkey: *mut EVP_PKEY,
    }

    // SAFETY: EcP256Key owns its EVP_PKEY exclusively.
    unsafe impl Send for EcP256Key {}

    impl Drop for EcP256Key {
        fn drop(&mut self) {
            unsafe {
                EVP_PKEY_free(self.pkey);
            }
        }
    }

    unsafe extern "C" fn free_x509_ext_void(ptr: *mut c_void) {
        X509_EXTENSION_free(ptr as *mut X509_EXTENSION);
    }

    impl EcP256Key {
        /// Generates a fresh ECDSA P-256 private key using OpenSSL CSPRNG.
        pub fn generate() -> Result<Self, ProxyError> {
            unsafe {
                ERR_clear_error();
                let pctx = EVP_PKEY_CTX_new_id(NID_X9_62_ID_EC_PUBLIC_KEY, null_mut());
                if pctx.is_null() {
                    return Err(ProxyError::Acme("EVP_PKEY_CTX_new_id failed"));
                }
                let mut pkey: *mut EVP_PKEY = null_mut();
                let ok = EVP_PKEY_keygen_init(pctx) == 1
                    && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_PRIME256V1) == 1
                    && EVP_PKEY_keygen(pctx, &mut pkey) == 1;
                EVP_PKEY_CTX_free(pctx);
                if !ok || pkey.is_null() {
                    if !pkey.is_null() {
                        EVP_PKEY_free(pkey);
                    }
                    return Err(ProxyError::Acme("EC P-256 key generation failed"));
                }
                Ok(Self { pkey })
            }
        }

        /// Loads an ECDSA P-256 private key from PEM bytes.
        pub fn from_pem(pem: &[u8]) -> Result<Self, ProxyError> {
            let pkey = read_pem_ptr(
                pem,
                ProxyError::Acme,
                "empty private key PEM",
                "failed to parse private key PEM",
                pem_read_pkey,
            )?;
            Ok(Self { pkey })
        }

        /// Serializes this private key to PKCS#8 PEM bytes.
        pub fn to_pem(&self) -> Result<Vec<u8>, ProxyError> {
            unsafe {
                ERR_clear_error();
                let bio = BIO_new(BIO_s_mem());
                if bio.is_null() {
                    return Err(ProxyError::Acme("BIO_new failed"));
                }
                let ok = PEM_write_bio_PrivateKey(
                    bio,
                    self.pkey,
                    null(),
                    null(),
                    0,
                    null(),
                    null_mut(),
                );
                if ok != 1 {
                    BIO_free(bio);
                    return Err(ProxyError::Acme("PEM_write_bio_PrivateKey failed"));
                }
                let mut data_ptr: *mut c_char = null_mut();
                let len = BIO_ctrl(
                    bio,
                    BIO_CTRL_INFO,
                    0,
                    (&mut data_ptr as *mut *mut c_char) as *mut c_void,
                );
                if len <= 0 || data_ptr.is_null() {
                    BIO_free(bio);
                    return Err(ProxyError::Acme("BIO_get_mem_data failed"));
                }
                let slice = std::slice::from_raw_parts(data_ptr as *const u8, len as usize);
                let out = slice.to_vec();
                BIO_free(bio);
                Ok(out)
            }
        }

        /// Extracts the 32-byte big-endian affine `(x, y)` public key coordinates for JWK.
        pub fn public_xy(&self) -> Result<([u8; 32], [u8; 32]), ProxyError> {
            unsafe {
                ERR_clear_error();
                let mut bx: *mut Bignum = null_mut();
                let mut by: *mut Bignum = null_mut();
                let ok_x = EVP_PKEY_get_bn_param(
                    self.pkey,
                    c"qx".as_ptr(),
                    &mut bx,
                );
                let ok_y = EVP_PKEY_get_bn_param(
                    self.pkey,
                    c"qy".as_ptr(),
                    &mut by,
                );
                if ok_x != 1 || ok_y != 1 || bx.is_null() || by.is_null() {
                    if !bx.is_null() {
                        BN_free(bx);
                    }
                    if !by.is_null() {
                        BN_free(by);
                    }
                    return Err(ProxyError::Acme("failed to extract EC P-256 public coords"));
                }
                let mut x = [0u8; 32];
                let mut y = [0u8; 32];
                let rx = BN_bn2binpad(bx, x.as_mut_ptr(), 32);
                let ry = BN_bn2binpad(by, y.as_mut_ptr(), 32);
                BN_free(bx);
                BN_free(by);
                if rx != 32 || ry != 32 {
                    return Err(ProxyError::Acme("BN_bn2binpad failed for EC coords"));
                }
                Ok((x, y))
            }
        }

        /// Signs `data` with ECDSA P-256 + SHA-256 and returns the 64-byte IEEE P1363 `(r || s)`
        /// signature required by JWS `ES256` (RFC 7515).
        pub fn sign_es256(&self, data: &[u8]) -> Result<[u8; 64], ProxyError> {
            unsafe {
                ERR_clear_error();
                let md_ctx = EVP_MD_CTX_new();
                if md_ctx.is_null() {
                    return Err(ProxyError::Acme("EVP_MD_CTX_new failed"));
                }
                let init_ok =
                    EVP_DigestSignInit(md_ctx, null_mut(), EVP_sha256(), null_mut(), self.pkey)
                        == 1;
                let upd_ok = init_ok
                    && EVP_DigestSignUpdate(md_ctx, data.as_ptr() as *const c_void, data.len())
                        == 1;
                let mut sig_len = 0usize;
                let len_ok = upd_ok && EVP_DigestSignFinal(md_ctx, null_mut(), &mut sig_len) == 1;
                let mut der = vec![0u8; sig_len];
                let fin_ok =
                    len_ok && EVP_DigestSignFinal(md_ctx, der.as_mut_ptr(), &mut sig_len) == 1;
                EVP_MD_CTX_free(md_ctx);
                if !fin_ok || sig_len == 0 {
                    return Err(ProxyError::Acme("EVP_DigestSignFinal failed"));
                }

                let mut der_ptr = der.as_ptr();
                let sig = d2i_ECDSA_SIG(null_mut(), &mut der_ptr, sig_len as c_long);
                if sig.is_null() {
                    return Err(ProxyError::Acme("d2i_ECDSA_SIG failed"));
                }
                let mut r: *const Bignum = null();
                let mut s: *const Bignum = null();
                ECDSA_SIG_get0(sig, &mut r, &mut s);
                let mut out = [0u8; 64];
                let ok_r = !r.is_null() && BN_bn2binpad(r, out[..32].as_mut_ptr(), 32) == 32;
                let ok_s = !s.is_null() && BN_bn2binpad(s, out[32..].as_mut_ptr(), 32) == 32;
                ECDSA_SIG_free(sig);
                if !ok_r || !ok_s {
                    return Err(ProxyError::Acme("failed to encode ES256 r||s"));
                }
                Ok(out)
            }
        }

        /// Builds a DER-encoded PKCS#10 Certificate Signing Request with `CN` and `SAN` extensions.
        pub fn create_csr_der(&self, domains: &[String]) -> Result<Vec<u8>, ProxyError> {
            if domains.is_empty() {
                return Err(ProxyError::Acme("CSR requires at least one domain"));
            }
            let cn = &domains[0];
            let mut san_list = String::new();
            for (idx, d) in domains.iter().enumerate() {
                if idx > 0 {
                    san_list.push(',');
                }
                san_list.push_str("DNS:");
                san_list.push_str(d);
            }
            let san_c = CString::new(san_list)
                .map_err(|_| ProxyError::Acme("invalid domain in CSR SAN"))?;

            unsafe {
                ERR_clear_error();
                let req = X509_REQ_new();
                if req.is_null() {
                    return Err(ProxyError::Acme("X509_REQ_new failed"));
                }
                let mut ok = X509_REQ_set_version(req, 0) == 1;
                if ok {
                    let subj = X509_REQ_get_subject_name(req);
                    ok = !subj.is_null()
                        && X509_NAME_add_entry_by_txt(
                            subj,
                            c"CN".as_ptr(),
                            MBSTRING_ASC,
                            cn.as_ptr(),
                            cn.len() as c_int,
                            -1,
                            0,
                        ) == 1;
                }
                if ok {
                    ok = X509_REQ_set_pubkey(req, self.pkey) == 1;
                }
                if ok {
                    let ext = X509V3_EXT_conf_nid(
                        null_mut(),
                        null_mut(),
                        NID_SUBJECT_ALT_NAME,
                        san_c.as_ptr(),
                    );
                    if ext.is_null() {
                        ok = false;
                    } else {
                        let exts = OPENSSL_sk_new_null();
                        if exts.is_null() {
                            X509_EXTENSION_free(ext);
                            ok = false;
                        } else {
                            let push_ok = OPENSSL_sk_push(exts, ext as *const c_void) > 0;
                            if !push_ok {
                                X509_EXTENSION_free(ext);
                                OPENSSL_sk_pop_free(exts, free_x509_ext_void);
                                ok = false;
                            } else {
                                ok = X509_REQ_add_extensions(req, exts) == 1;
                                OPENSSL_sk_pop_free(exts, free_x509_ext_void);
                            }
                        }
                    }
                }
                if ok {
                    ok = X509_REQ_sign(req, self.pkey, EVP_sha256()) > 0;
                }
                if !ok {
                    X509_REQ_free(req);
                    return Err(ProxyError::Acme("failed to construct signed CSR"));
                }
                let der_len = i2d_X509_REQ(req, null_mut());
                if der_len <= 0 {
                    X509_REQ_free(req);
                    return Err(ProxyError::Acme("i2d_X509_REQ sizing failed"));
                }
                let mut der = vec![0u8; der_len as usize];
                let mut out_ptr = der.as_mut_ptr();
                let written = i2d_X509_REQ(req, &mut out_ptr);
                X509_REQ_free(req);
                if written != der_len {
                    return Err(ProxyError::Acme("i2d_X509_REQ encoding failed"));
                }
                Ok(der)
            }
        }
    }

    // Keep unused-import-free verification of c_ulong compatibility on Linux.
    pub fn openssl_abi_sanity() -> usize {
        std::mem::size_of::<c_ulong>()
    }
}

#[cfg(miri)]
mod native {
    use super::{LeafCertIntegrity, ProxyConfig, ProxyError};
    use std::io::{self, Read, Write};
    use std::net::{Shutdown, TcpStream};
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    pub fn install_signal_handlers() {}

    pub struct TlsCertStore;

    impl TlsCertStore {
        pub fn new() -> Arc<Self> {
            Arc::new(Self)
        }

        pub fn generation(&self) -> u64 {
            0
        }

        pub fn has_certs(&self) -> bool {
            false
        }

        pub fn leaf_cert_info(&self, _host: Option<&str>) -> Option<LeafCertIntegrity> {
            None
        }

        pub fn install_pem_bytes(
            &self,
            _host: Option<&str>,
            _cert_pem: &[u8],
            _key_pem: &[u8],
            _set_default: bool,
        ) -> Result<(), ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn install_pem_files(
            &self,
            _host: Option<&str>,
            _cert_path: &Path,
            _key_path: &Path,
            _set_default: bool,
        ) -> Result<(), ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn reload_from_config(&self, _cfg: &ProxyConfig) -> Result<usize, ProxyError> {
            Ok(0)
        }
    }

    pub struct TlsServerStream {
        stream: TcpStream,
    }

    impl TlsServerStream {
        pub fn accept(
            _stream: TcpStream,
            _store: Arc<TlsCertStore>,
            _handshake_timeout: Duration,
        ) -> Result<Self, ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            self.stream.set_read_timeout(dur)
        }

        pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
            self.stream.set_write_timeout(dur)
        }

        pub fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
            self.stream.shutdown(how)
        }

        pub fn export_tls13_keying_material(
            &self,
            _label: &[u8],
            _context: &[u8],
        ) -> Result<[u8; 32], ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }
    }

    impl Read for TlsServerStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "miri stub"))
        }
    }

    impl Write for TlsServerStream {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "miri stub"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub struct TlsClientStream;

    impl TlsClientStream {
        pub fn connect(
            _stream: TcpStream,
            _server_name: &str,
            _verify_peer: bool,
            _ca_cert_path: Option<&Path>,
        ) -> Result<Self, ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn connect_tls12(
            _stream: TcpStream,
            _server_name: &str,
            _verify_peer: bool,
            _ca_cert_path: Option<&Path>,
        ) -> Result<Self, ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn connect_with_keylog(
            _stream: TcpStream,
            _server_name: &str,
            _verify_peer: bool,
            _ca_cert_path: Option<&Path>,
            _tls13_ciphersuite: Option<&str>,
        ) -> Result<(Self, Option<Vec<u8>>), ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn export_tls13_keying_material(
            &self,
            _label: &[u8],
            _context: &[u8],
        ) -> Result<[u8; 32], ProxyError> {
            Err(ProxyError::Tls("tls disabled under miri"))
        }

        pub fn protocol_version(&self) -> Option<String> {
            None
        }

        pub fn peer_cert_cn(&self) -> Option<String> {
            None
        }

        pub fn peer_cert_serial_hex(&self) -> Option<String> {
            None
        }
    }

    impl Read for TlsClientStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "miri stub"))
        }
    }

    impl Write for TlsClientStream {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "miri stub"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    pub fn cert_common_name(_cert_pem: &[u8]) -> Option<String> {
        None
    }

    pub fn cert_days_until_expiry(_cert_pem: &[u8]) -> Result<i64, ProxyError> {
        Err(ProxyError::Tls("tls disabled under miri"))
    }

    pub fn cert_spki_sha256_b64(_cert_pem: &[u8]) -> Result<String, ProxyError> {
        Err(ProxyError::Tls("tls disabled under miri"))
    }

    pub struct EcP256Key;

    impl EcP256Key {
        pub fn generate() -> Result<Self, ProxyError> {
            Err(ProxyError::Acme("crypto disabled under miri"))
        }

        pub fn from_pem(_pem: &[u8]) -> Result<Self, ProxyError> {
            Err(ProxyError::Acme("crypto disabled under miri"))
        }

        pub fn to_pem(&self) -> Result<Vec<u8>, ProxyError> {
            Err(ProxyError::Acme("crypto disabled under miri"))
        }

        pub fn public_xy(&self) -> Result<([u8; 32], [u8; 32]), ProxyError> {
            Err(ProxyError::Acme("crypto disabled under miri"))
        }

        pub fn sign_es256(&self, _data: &[u8]) -> Result<[u8; 64], ProxyError> {
            Err(ProxyError::Acme("crypto disabled under miri"))
        }

        pub fn create_csr_der(&self, _domains: &[String]) -> Result<Vec<u8>, ProxyError> {
            Err(ProxyError::Acme("crypto disabled under miri"))
        }
    }

    pub fn openssl_abi_sanity() -> usize {
        std::mem::size_of::<usize>()
    }
}

pub use native::{
    cert_common_name, cert_days_until_expiry, cert_spki_sha256_b64, install_signal_handlers,
    openssl_abi_sanity, EcP256Key, TlsCertStore, TlsClientStream, TlsServerStream,
};

/// Unified client stream abstraction over plaintext TCP and OpenSSL TLS 1.2+/1.3.
pub enum ClientTransport {
    Plain(TcpStream),
    Tls(TlsServerStream),
}

impl ClientTransport {
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// Exports 32 bytes of RFC 8446 Section 7.5 TLS 1.3 keying material.
    ///
    /// Returns `Ok(None)` on plaintext TCP, `Ok(Some(secret))` on TLS 1.3, and `Err` on TLS < 1.3.
    pub fn export_tls13_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
    ) -> Result<Option<[u8; 32]>, ProxyError> {
        match self {
            Self::Plain(_) => Ok(None),
            Self::Tls(s) => s.export_tls13_keying_material(label, context).map(Some),
        }
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.set_read_timeout(dur),
            Self::Tls(s) => s.set_read_timeout(dur),
        }
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.set_write_timeout(dur),
            Self::Tls(s) => s.set_write_timeout(dur),
        }
    }

    pub fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.shutdown(how),
            Self::Tls(s) => s.shutdown(how),
        }
    }
}

impl Read for ClientTransport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ClientTransport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

/// Ensures `0600` file permissions atomically when writing private keys or certs on Unix.
pub fn write_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), ProxyError> {
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ProxyError::Acme("failed to create cert dir"))?;
    }
    let tmp_name = format!(
        ".{}.tmp.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("cert"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|_| ProxyError::Acme("failed to create temp cert file"))?;
        f.write_all(bytes)
            .map_err(|_| ProxyError::Acme("failed to write temp cert file"))?;
        f.sync_all()
            .map_err(|_| ProxyError::Acme("failed to sync temp cert file"))?;
    }
    fs::rename(&tmp_path, path).map_err(|_| ProxyError::Acme("failed to atomically rename cert"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_host_normalization_and_wildcard_matching() {
        assert_eq!(normalize_sni_host("EXAMPLE.COM."), "example.com");
        let mut map = HashMap::new();
        map.insert("example.com".to_owned(), 1u32);
        map.insert("*.example.com".to_owned(), 2u32);

        assert_eq!(match_sni_key(&map, "example.com"), Some(&1));
        assert_eq!(match_sni_key(&map, "www.example.com"), Some(&2));
        assert_eq!(match_sni_key(&map, "api.example.com"), Some(&2));
        assert_eq!(match_sni_key(&map, "other.example.net"), None);
        assert!(openssl_abi_sanity() >= 4);
    }

    #[cfg(not(miri))]
    #[test]
    fn openssl_ec_p256_keygen_sign_and_csr_roundtrip() {
        let key = EcP256Key::generate().expect("generate P-256 key");
        let pem = key.to_pem().expect("export PEM");
        let reloaded = EcP256Key::from_pem(&pem).expect("reload PEM");
        let xy1 = key.public_xy().expect("xy1");
        let xy2 = reloaded.public_xy().expect("xy2");
        assert_eq!(xy1, xy2);

        let sig = key.sign_es256(b"acme-jws-signing-input").expect("es256 sign");
        assert_eq!(sig.len(), 64);
        assert!(sig.iter().any(|&b| b != 0));

        let csr = key
            .create_csr_der(&["example.com".to_owned(), "www.example.com".to_owned()])
            .expect("create CSR DER");
        assert!(csr.len() > 100);
        // DER SEQUENCE tag = 0x30.
        assert_eq!(csr[0], 0x30);
    }
}
