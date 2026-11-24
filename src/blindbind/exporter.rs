//! Pure-Rust IETF RFC 8446 Section 7.5 TLS 1.3 Keying Material Exporter.
//!
//! Supports both SHA-256 (`32 B` `EXPORTER_SECRET`) and SHA-384 (`48 B` `EXPORTER_SECRET`)
//! TLS 1.3 cipher suites with fixed-stack `HkdfLabel` serialization and zero external crates.

use crate::acme::Sha256;
use crate::error::ProxyError;

use super::ed25519::Sha512;
use super::{zeroize_bytes, EXPORTER_LABEL, EXPORTER_SECRET_LEN};

const TLS13_PREFIX: &[u8; 6] = b"tls13 ";
const MAX_LABEL_LEN: usize = 249;
const MAX_CONTEXT_LEN: usize = 255;
/// Maximum serialized RFC 8446 `HkdfLabel` wire length (`2 + 1 + 6 + 249 + 1 + 255 = 514`,
/// padded to `515` bytes).
pub const HKDF_LABEL_BUF_LEN: usize = 515;

/// Serializes an RFC 8446 Section 7.1 `HkdfLabel` structure onto a fixed stack buffer.
///
/// Enforces `1 <= label.len() <= 249` (so `"tls13 " || label` fits in `7..=255`) and
/// `context.len() <= 255`.
pub fn build_hkdf_label(
    out_len: u16,
    label: &[u8],
    context: &[u8],
) -> Result<([u8; HKDF_LABEL_BUF_LEN], usize), ProxyError> {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return Err(ProxyError::Tls("invalid TLS 1.3 HKDF label length"));
    }
    if context.len() > MAX_CONTEXT_LEN {
        return Err(ProxyError::Tls("invalid TLS 1.3 HKDF context length"));
    }

    let full_label_len = TLS13_PREFIX.len() + label.len();
    let total = 2 + 1 + full_label_len + 1 + context.len();
    let mut buf = [0u8; HKDF_LABEL_BUF_LEN];
    buf[0..2].copy_from_slice(&out_len.to_be_bytes());
    buf[2] = full_label_len as u8;
    buf[3..9].copy_from_slice(TLS13_PREFIX);
    let label_end = 9 + label.len();
    buf[9..label_end].copy_from_slice(label);
    buf[label_end] = context.len() as u8;
    let ctx_start = label_end + 1;
    buf[ctx_start..ctx_start + context.len()].copy_from_slice(context);
    Ok((buf, total))
}

trait Tls13Hash {
    const BLOCK_LEN: usize;
    const HASH_LEN: usize;
    const IS_SHA384: bool;

    fn hash_parts(parts: &[&[u8]], out: &mut [u8; 48]) {
        if Self::IS_SHA384 {
            let mut h = Sha512::new_sha384();
            for part in parts {
                h.update(part);
            }
            out[..48].copy_from_slice(&h.finalize_sha384());
        } else {
            let mut h = Sha256::new();
            for part in parts {
                h.update(part);
            }
            out[..32].copy_from_slice(&h.finalize());
        }
    }
}

struct Sha256Hash;

impl Tls13Hash for Sha256Hash {
    const BLOCK_LEN: usize = 64;
    const HASH_LEN: usize = 32;
    const IS_SHA384: bool = false;
}

struct Sha384Hash;

impl Tls13Hash for Sha384Hash {
    const BLOCK_LEN: usize = 128;
    const HASH_LEN: usize = 48;
    const IS_SHA384: bool = true;
}

fn hmac_parts<H: Tls13Hash>(key: &[u8], data_parts: &[&[u8]]) -> [u8; 48] {
    let mut key_block = [0u8; 128];
    if key.len() > H::BLOCK_LEN {
        let mut hashed = [0u8; 48];
        H::hash_parts(&[key], &mut hashed);
        key_block[..H::HASH_LEN].copy_from_slice(&hashed[..H::HASH_LEN]);
        zeroize_bytes(&mut hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 128];
    let mut opad = [0u8; 128];
    for i in 0..H::BLOCK_LEN {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner_parts: [&[u8]; 5] = [&[]; 5];
    inner_parts[0] = &ipad[..H::BLOCK_LEN];
    let count = data_parts.len().min(4);
    inner_parts[1..=count].copy_from_slice(&data_parts[..count]);

    let mut inner_hash = [0u8; 48];
    H::hash_parts(&inner_parts[..=count], &mut inner_hash);

    let mut mac = [0u8; 48];
    H::hash_parts(
        &[&opad[..H::BLOCK_LEN], &inner_hash[..H::HASH_LEN]],
        &mut mac,
    );

    zeroize_bytes(&mut key_block);
    zeroize_bytes(&mut ipad);
    zeroize_bytes(&mut opad);
    zeroize_bytes(&mut inner_hash);
    mac
}

/// Computes RFC 2104 `HMAC-SHA256` using the crate's existing `Sha256`.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let full = hmac_parts::<Sha256Hash>(key, &[data]);
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Computes RFC 2104 `HMAC-SHA384` using `Sha512::new_sha384()`.
#[must_use]
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> [u8; 48] {
    hmac_parts::<Sha384Hash>(key, &[data])
}

fn hkdf_expand_label<H: Tls13Hash>(
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, ProxyError> {
    let max_out = (255 * H::HASH_LEN).min(usize::from(u16::MAX));
    if out_len == 0 || out_len > max_out {
        return Err(ProxyError::Tls("invalid TLS 1.3 exporter output length"));
    }

    let (info_buf, info_len) = build_hkdf_label(out_len as u16, label, context)?;
    let info = &info_buf[..info_len];

    let blocks = out_len.div_ceil(H::HASH_LEN);
    let mut out = Vec::with_capacity(out_len);
    let mut prev = [0u8; 48];
    let mut prev_len = 0usize;

    for block_idx in 1..=blocks {
        let counter = [block_idx as u8];
        let mut t = hmac_parts::<H>(secret, &[&prev[..prev_len], info, &counter]);
        let need = (out_len - out.len()).min(H::HASH_LEN);
        out.extend_from_slice(&t[..need]);
        prev[..H::HASH_LEN].copy_from_slice(&t[..H::HASH_LEN]);
        prev_len = H::HASH_LEN;
        zeroize_bytes(&mut t);
    }
    zeroize_bytes(&mut prev);
    Ok(out)
}

fn export_with_hash<H: Tls13Hash>(
    ems: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, ProxyError> {
    let mut empty_hash = [0u8; 48];
    H::hash_parts(&[], &mut empty_hash);

    let mut derived = hkdf_expand_label::<H>(ems, label, &empty_hash[..H::HASH_LEN], H::HASH_LEN)?;

    let mut ctx_hash = [0u8; 48];
    H::hash_parts(&[context], &mut ctx_hash);

    let result = hkdf_expand_label::<H>(
        &derived,
        b"exporter",
        &ctx_hash[..H::HASH_LEN],
        out_len,
    );
    zeroize_bytes(&mut derived);
    result
}

/// Computes IETF RFC 8446 Section 7.5 `TLS-Exporter(label, context, out_len)` from a
/// TLS 1.3 `exporter_master_secret` (`32 B` for SHA-256 suites or `48 B` for SHA-384 suites).
pub fn export_keying_material(
    ems: &[u8],
    label: &[u8],
    context: &[u8],
    out_len: usize,
) -> Result<Vec<u8>, ProxyError> {
    match ems.len() {
        32 => export_with_hash::<Sha256Hash>(ems, label, context, out_len),
        48 => export_with_hash::<Sha384Hash>(ems, label, context, out_len),
        _ => Err(ProxyError::Tls(
            "TLS 1.3 exporter_master_secret must be 32 or 48 bytes",
        )),
    }
}

/// Derives the 32-byte BlindBind RFC 8446 Section 7.5 exporter secret using [`EXPORTER_LABEL`].
pub fn export_blindbind_secret(
    ems: &[u8],
    context: &[u8],
) -> Result<[u8; EXPORTER_SECRET_LEN], ProxyError> {
    let raw = export_keying_material(ems, EXPORTER_LABEL, context, EXPORTER_SECRET_LEN)?;
    let mut out = [0u8; EXPORTER_SECRET_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::hex_encode;
    use crate::blindbind::ed25519::sha384;

    #[test]
    fn nist_sha384_and_rfc4231_hmac_vectors() {
        // NIST FIPS 180-4 SHA-384("abc")
        assert_eq!(
            hex_encode(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        // NIST FIPS 180-4 SHA-384("")
        assert_eq!(
            hex_encode(&sha384(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        assert_eq!(
            hex_encode(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        assert_eq!(
            hex_encode(&hmac_sha384(b"Jefe", b"what do ya want for nothing?")),
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"
        );
        // Long key (> block size) exercises key-hashing branch for both SHA-256 and SHA-384.
        let long_key = [0xaau8; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hex_encode(&hmac_sha256(&long_key, msg)),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        assert_eq!(
            hex_encode(&hmac_sha384(&long_key, msg)),
            "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
        );
    }

    #[test]
    fn exporter_supports_sha256_and_sha384_and_rejects_bad_lengths() {
        let ems256 = [0x11u8; 32];
        let ems384 = [0x22u8; 48];
        let s1 = export_blindbind_secret(&ems256, b"example.com").expect("sha256 export");
        let s2 = export_blindbind_secret(&ems256, b"other.example").expect("sha256 export ctx2");
        assert_ne!(s1, s2);

        let s3 = export_blindbind_secret(&ems384, b"example.com").expect("sha384 export");
        let s4 = export_blindbind_secret(&ems384, b"").expect("sha384 empty ctx");
        assert_ne!(s3, s4);

        assert!(export_keying_material(&[0u8; 31], EXPORTER_LABEL, b"", 32).is_err());
        assert!(export_keying_material(&ems256, b"", b"", 32).is_err());
        assert!(export_keying_material(&ems256, &[b'a'; 250], b"", 32).is_err());
        assert!(export_keying_material(&ems256, EXPORTER_LABEL, b"", 0).is_err());
        assert!(build_hkdf_label(32, b"ok", &[0u8; 256]).is_err());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn proof_exporter_label_no_panic() {
        let out_len: u16 = kani::any();
        let label_len: usize = kani::any();
        let ctx_len: usize = kani::any();
        kani::assume(label_len <= 260);
        kani::assume(ctx_len <= 260);

        let label_buf = [b'x'; 260];
        let ctx_buf = [0x5Au8; 260];
        let res = build_hkdf_label(out_len, &label_buf[..label_len], &ctx_buf[..ctx_len]);
        if (1..=MAX_LABEL_LEN).contains(&label_len) && ctx_len <= MAX_CONTEXT_LEN {
            let (wire, total) = res.expect("valid hkdf label must succeed");
            assert_eq!(total, 2 + 1 + 6 + label_len + 1 + ctx_len);
            assert!(total <= HKDF_LABEL_BUF_LEN);
            assert_eq!(&wire[0..2], &out_len.to_be_bytes());
            assert_eq!(wire[2], (6 + label_len) as u8);
            assert_eq!(&wire[3..9], b"tls13 ");
            assert_eq!(wire[9 + label_len], ctx_len as u8);
        } else {
            assert!(res.is_err());
        }
    }
}
