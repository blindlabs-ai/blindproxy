//! Zero-dependency hybrid Ed25519 (IETF RFC 8032) + NIST FIPS 204 ML-DSA-87
//! post-quantum channel binding for TLS 1.3 exporter secrets (IETF RFC 8446 Section 7.5).
//!
//! # Standards Implemented
//! - NIST FIPS 202: `SHA3-256`, `SHA3-512`, `SHAKE128`, `SHAKE256`
//! - NIST FIPS 180-4: `SHA-256`, `SHA-384`, `SHA-512`
//! - IETF RFC 8032: `Ed25519` digital signatures
//! - NIST FIPS 204: `ML-DSA-87` lattice-based digital signatures (`pk = 2592 B`, `sk = 4896 B`, `sig = 4627 B`)
//! - IETF RFC 8446 Section 7.5: TLS 1.3 exporter secret channel binding (`EXPORTER-zero-proxy-hybrid-bind-v1`)

use core::fmt;

pub mod binding;
pub mod ed25519;
pub mod exporter;
pub mod header;
pub mod mldsa87;
pub mod sha3;

pub use binding::{
    evaluate_strict_conjunction, verify_binding, HybridBindingProof, HybridKeyPair,
    HybridPublicKey, Role, EXPORTER_LABEL, EXPORTER_SECRET_LEN, HYBRID_PROOF_LEN,
    HYBRID_PUBLIC_KEY_LEN,
};
pub use exporter::{build_hkdf_label, export_blindbind_secret, export_keying_material};
pub use header::{
    base64url_decode_exact, base64url_encoded_len, normalize_blindbind_context,
    parse_blindbind_header_tokens, parse_blindbind_headers, BLINDBIND_PROOF_B64URL_LEN,
    BLINDBIND_PUBKEY_B64URL_LEN,
};

/// Unified fail-closed error type for cryptographic parsing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input byte slice did not match the expected fixed wire length.
    InvalidLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length supplied.
        actual: usize,
    },
    /// Encoded public key, secret key, or signature failed canonical decoding checks.
    InvalidEncoding,
    /// ML-DSA context string exceeded the NIST FIPS 204 maximum of 255 bytes.
    ContextTooLong,
    /// Binding proof role byte was neither client (`0x01`) nor server (`0x02`).
    InvalidRole,
    /// Proof role did not match the expected peer role.
    RoleMismatch,
    /// Exporter commitment tag did not match the supplied TLS 1.3 exporter secret and context.
    ExporterMismatch,
    /// Classical RFC 8032 Ed25519 signature verification failed.
    Ed25519VerificationFailed,
    /// Post-quantum NIST FIPS 204 ML-DSA-87 signature verification failed.
    MlDsa87VerificationFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "invalid length: expected {expected} bytes, got {actual}")
            }
            Self::InvalidEncoding => write!(f, "invalid canonical cryptographic encoding"),
            Self::ContextTooLong => write!(f, "ml-dsa context exceeds 255 bytes"),
            Self::InvalidRole => write!(f, "invalid channel binding role byte"),
            Self::RoleMismatch => write!(f, "channel binding role mismatch"),
            Self::ExporterMismatch => write!(f, "tls 1.3 exporter secret binding mismatch"),
            Self::Ed25519VerificationFailed => write!(f, "ed25519 signature verification failed"),
            Self::MlDsa87VerificationFailed => write!(f, "ml-dsa-87 signature verification failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Copy a byte slice into a fixed-size array, failing closed on length mismatch.
pub(crate) fn copy_fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::InvalidLength {
        expected: N,
        actual: bytes.len(),
    })
}

/// Constant-time equality comparison for equal-length byte slices.
#[must_use]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= core::hint::black_box(x ^ y);
    }
    core::hint::black_box(diff) == 0
}

/// Safe best-effort zeroization barrier for secret byte slices under `#![forbid(unsafe_code)]`.
pub(crate) fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    core::hint::black_box(buf);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_bind_and_verify_roundtrip_and_tamper_knockout() {
        let kp = HybridKeyPair::from_master_seed(&[0x37u8; 32]);
        let pk = kp.public_key();
        let secret_a = [0xA5u8; EXPORTER_SECRET_LEN];
        let mut secret_b = secret_a;
        secret_b[0] ^= 0x01;
        assert_ne!(secret_a, secret_b);

        let proof = kp
            .bind(&secret_a, Role::Client, b"example.com")
            .expect("bind");
        assert_eq!(pk.to_bytes().len(), HYBRID_PUBLIC_KEY_LEN);
        assert_eq!(proof.to_bytes().len(), HYBRID_PROOF_LEN);

        verify_binding(&pk, &secret_a, Role::Client, b"example.com", &proof)
            .expect("valid proof verifies");
        assert_eq!(
            verify_binding(&pk, &secret_b, Role::Client, b"example.com", &proof),
            Err(Error::ExporterMismatch)
        );
        assert_eq!(
            verify_binding(&pk, &secret_a, Role::Server, b"example.com", &proof),
            Err(Error::RoleMismatch)
        );
        assert_eq!(
            verify_binding(&pk, &secret_a, Role::Client, b"other.example", &proof),
            Err(Error::ExporterMismatch)
        );
    }
}
