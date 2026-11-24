//! Hybrid Ed25519 + NIST FIPS 204 ML-DSA-87 channel binding to TLS 1.3 exporter secrets
//! (IETF RFC 8446 Section 7.5).
//!
//! Both signatures and the explicit exporter commitment tag are verified in strict
//! fail-closed AND conjunction: tampering with the 32-byte TLS 1.3 exporter secret,
//! the peer role, the transcript context, the Ed25519 signature, or the ML-DSA-87
//! signature causes verification to fail.

use super::ed25519;
use super::mldsa87;
use super::sha3::{shake256_parts, Sha3_256, Sha3_512};
use super::{ct_eq, Error};

/// IETF RFC 8446 Section 7.5 exporter label and FIPS 204 domain context string.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-zero-proxy-hybrid-bind-v1";
/// Required byte length of the TLS 1.3 exporter secret derived per RFC 8446 Section 7.5.
pub const EXPORTER_SECRET_LEN: usize = 32;
/// Serialized byte length of [`HybridPublicKey`] (`32 + 2592 = 2624`).
pub const HYBRID_PUBLIC_KEY_LEN: usize = ed25519::PUBLIC_KEY_LEN + mldsa87::PUBLIC_KEY_LEN;
/// Serialized byte length of [`HybridBindingProof`] (`1 + 32 + 64 + 4627 = 4724`).
pub const HYBRID_PROOF_LEN: usize = 1 + 32 + ed25519::SIGNATURE_LEN + mldsa87::SIGNATURE_LEN;

const PROTOCOL_VERSION: u8 = 0x01;
const TAG_DOMAIN: &[u8] = b"zero-proxy-hybrid-bind-tag-v1";
const KDF_ED25519_DOMAIN: &[u8] = b"zero-proxy-hybrid-keygen-ed25519-v1";
const KDF_MLDSA87_DOMAIN: &[u8] = b"zero-proxy-hybrid-keygen-mldsa87-v1";

/// Authenticated TLS endpoint role bound into every proof to prevent reflection attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    /// TLS 1.3 client endpoint (`0x01`).
    Client = 0x01,
    /// TLS 1.3 server endpoint (`0x02`).
    Server = 0x02,
}

impl Role {
    /// Return the canonical 1-byte wire representation.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Decode a canonical role byte (`0x01` or `0x02`).
    ///
    /// # Errors
    /// Returns [`Error::InvalidRole`] for any unrecognized byte.
    pub const fn from_byte(byte: u8) -> Result<Self, Error> {
        match byte {
            0x01 => Ok(Self::Client),
            0x02 => Ok(Self::Server),
            _ => Err(Error::InvalidRole),
        }
    }
}

/// Composite hybrid public key combining Ed25519 (`32 B`) and ML-DSA-87 (`2592 B`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    ed25519: ed25519::PublicKey,
    mldsa87: mldsa87::PublicKey,
}

impl HybridPublicKey {
    /// Construct a hybrid public key from its constituent Ed25519 and ML-DSA-87 keys.
    #[must_use]
    pub const fn new(ed25519: ed25519::PublicKey, mldsa87: mldsa87::PublicKey) -> Self {
        Self { ed25519, mldsa87 }
    }

    /// Return the classical Ed25519 public key.
    #[must_use]
    pub const fn ed25519(&self) -> ed25519::PublicKey {
        self.ed25519
    }

    /// Borrow the post-quantum ML-DSA-87 public key.
    #[must_use]
    pub const fn mldsa87(&self) -> &mldsa87::PublicKey {
        &self.mldsa87
    }

    /// Serialize to canonical 2624-byte wire representation (`ed25519_pk || mldsa87_pk`).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PUBLIC_KEY_LEN);
        out.extend_from_slice(self.ed25519.as_bytes());
        out.extend_from_slice(self.mldsa87.as_bytes());
        out
    }

    /// Deserialize a canonical 2624-byte hybrid public key.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 2624` or [`Error::InvalidEncoding`]
    /// if the Ed25519 component is not a valid compressed Edwards25519 point.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HYBRID_PUBLIC_KEY_LEN {
            return Err(Error::InvalidLength {
                expected: HYBRID_PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        let ed = ed25519::PublicKey::from_bytes(&bytes[0..ed25519::PUBLIC_KEY_LEN])?;
        let ml = mldsa87::PublicKey::from_bytes(&bytes[ed25519::PUBLIC_KEY_LEN..])?;
        Ok(Self {
            ed25519: ed,
            mldsa87: ml,
        })
    }
}

/// Composite hybrid signing keypair holding both Ed25519 and ML-DSA-87 secret keys.
#[derive(Debug, Clone)]
pub struct HybridKeyPair {
    ed25519: ed25519::KeyPair,
    mldsa87: mldsa87::KeyPair,
}

impl HybridKeyPair {
    /// Construct a hybrid keypair from independent 32-byte Ed25519 and ML-DSA-87 seeds.
    #[must_use]
    pub fn from_seeds(
        ed25519_seed: [u8; ed25519::SECRET_KEY_LEN],
        mldsa87_seed: [u8; mldsa87::SEED_LEN],
    ) -> Self {
        Self {
            ed25519: ed25519::KeyPair::from_seed(ed25519_seed),
            mldsa87: mldsa87::KeyPair::from_seed(mldsa87_seed),
        }
    }

    /// Deterministically derive independent Ed25519 and ML-DSA-87 keypairs from a single
    /// 32-byte master seed using domain-separated `SHAKE256`.
    #[must_use]
    pub fn from_master_seed(master_seed: &[u8; 32]) -> Self {
        let ed_seed = derive_subseed(KDF_ED25519_DOMAIN, master_seed);
        let ml_seed = derive_subseed(KDF_MLDSA87_DOMAIN, master_seed);
        Self::from_seeds(ed_seed, ml_seed)
    }

    /// Return the corresponding [`HybridPublicKey`].
    #[must_use]
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ed25519: self.ed25519.public_key(),
            mldsa87: self.mldsa87.public_key().clone(),
        }
    }

    /// Create a deterministic hybrid channel-binding proof over `exporter_secret`, `role`,
    /// and application transcript `context`.
    ///
    /// # Errors
    /// Returns an [`Error`] if ML-DSA-87 signing fails.
    pub fn bind(
        &self,
        exporter_secret: &[u8; EXPORTER_SECRET_LEN],
        role: Role,
        context: &[u8],
    ) -> Result<HybridBindingProof, Error> {
        self.bind_hedged(exporter_secret, role, context, &[0u8; 32])
    }

    /// Create a hedged hybrid channel-binding proof supplying 32 bytes of caller randomness
    /// `mldsa_rnd` to NIST FIPS 204 ML-DSA-87 signing.
    ///
    /// # Errors
    /// Returns an [`Error`] if ML-DSA-87 signing fails.
    pub fn bind_hedged(
        &self,
        exporter_secret: &[u8; EXPORTER_SECRET_LEN],
        role: Role,
        context: &[u8],
        mldsa_rnd: &[u8; 32],
    ) -> Result<HybridBindingProof, Error> {
        let pk = self.public_key();
        let digest = compute_binding_digest(&pk, exporter_secret, role, context);
        let binding_tag = compute_binding_tag(&digest);
        let ed25519_sig = self.ed25519.sign(&digest);
        let mldsa87_sig = self.mldsa87.sign_hedged(&digest, EXPORTER_LABEL, mldsa_rnd)?;
        Ok(HybridBindingProof {
            role,
            binding_tag,
            ed25519_sig,
            mldsa87_sig,
        })
    }
}

/// Wire-serializable hybrid channel-binding proof (`4724` bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridBindingProof {
    role: Role,
    binding_tag: [u8; 32],
    ed25519_sig: ed25519::Signature,
    mldsa87_sig: mldsa87::Signature,
}

impl HybridBindingProof {
    /// Return the bound endpoint role.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// Borrow the 32-byte exporter commitment tag.
    #[must_use]
    pub const fn binding_tag(&self) -> &[u8; 32] {
        &self.binding_tag
    }

    /// Return the 64-byte Ed25519 signature component.
    #[must_use]
    pub const fn ed25519_signature(&self) -> ed25519::Signature {
        self.ed25519_sig
    }

    /// Borrow the 4627-byte ML-DSA-87 signature component.
    #[must_use]
    pub const fn mldsa87_signature(&self) -> &mldsa87::Signature {
        &self.mldsa87_sig
    }

    /// Serialize to canonical 4724-byte wire layout:
    /// `role (1 B) || binding_tag (32 B) || ed25519_sig (64 B) || mldsa87_sig (4627 B)`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HYBRID_PROOF_LEN);
        out.push(self.role.as_byte());
        out.extend_from_slice(&self.binding_tag);
        out.extend_from_slice(self.ed25519_sig.as_bytes());
        out.extend_from_slice(self.mldsa87_sig.as_bytes());
        out
    }

    /// Deserialize a canonical 4724-byte hybrid binding proof.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 4724` or [`Error::InvalidRole`]
    /// if the leading role byte is invalid.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != HYBRID_PROOF_LEN {
            return Err(Error::InvalidLength {
                expected: HYBRID_PROOF_LEN,
                actual: bytes.len(),
            });
        }
        let role = Role::from_byte(bytes[0])?;
        let mut binding_tag = [0u8; 32];
        binding_tag.copy_from_slice(&bytes[1..33]);
        let ed_end = 33 + ed25519::SIGNATURE_LEN;
        let ed25519_sig = ed25519::Signature::from_bytes(&bytes[33..ed_end])?;
        let mldsa87_sig = mldsa87::Signature::from_bytes(&bytes[ed_end..])?;
        Ok(Self {
            role,
            binding_tag,
            ed25519_sig,
            mldsa87_sig,
        })
    }
}

/// Strict fail-closed AND conjunction predicate for hybrid channel binding verification.
pub const fn evaluate_strict_conjunction(
    role_ok: bool,
    tag_ok: bool,
    ed25519_ok: bool,
    mldsa87_ok: bool,
) -> Result<(), Error> {
    if !role_ok {
        return Err(Error::RoleMismatch);
    }
    if !tag_ok {
        return Err(Error::ExporterMismatch);
    }
    if !ed25519_ok {
        return Err(Error::Ed25519VerificationFailed);
    }
    if !mldsa87_ok {
        return Err(Error::MlDsa87VerificationFailed);
    }
    Ok(())
}

/// Verify a hybrid channel-binding proof strictly fail-closed:
/// role match AND exporter commitment match AND valid Ed25519 AND valid ML-DSA-87.
///
/// # Errors
/// Returns:
/// - [`Error::RoleMismatch`] if `proof.role() != expected_role`
/// - [`Error::ExporterMismatch`] if the exporter commitment tag fails constant-time equality
/// - [`Error::Ed25519VerificationFailed`] if the Ed25519 signature does not verify
/// - [`Error::MlDsa87VerificationFailed`] if the ML-DSA-87 signature does not verify
pub fn verify_binding(
    public_key: &HybridPublicKey,
    exporter_secret: &[u8; EXPORTER_SECRET_LEN],
    expected_role: Role,
    context: &[u8],
    proof: &HybridBindingProof,
) -> Result<(), Error> {
    let role_ok = proof.role == expected_role;
    if !role_ok {
        return evaluate_strict_conjunction(false, false, false, false);
    }

    let digest = compute_binding_digest(public_key, exporter_secret, expected_role, context);
    let expected_tag = compute_binding_tag(&digest);
    let tag_ok = ct_eq(&proof.binding_tag, &expected_tag);
    if !tag_ok {
        return evaluate_strict_conjunction(true, false, false, false);
    }

    let ed25519_ok = ed25519::verify(&public_key.ed25519, &digest, &proof.ed25519_sig).is_ok();
    let mldsa87_ok = if ed25519_ok {
        mldsa87::verify(
            &public_key.mldsa87,
            &digest,
            EXPORTER_LABEL,
            &proof.mldsa87_sig,
        )
        .is_ok()
    } else {
        false
    };

    evaluate_strict_conjunction(role_ok, tag_ok, ed25519_ok, mldsa87_ok)
}

fn derive_subseed(domain: &[u8], master_seed: &[u8; 32]) -> [u8; 32] {
    shake256_parts(&[domain, master_seed])
}

fn compute_binding_digest(
    public_key: &HybridPublicKey,
    exporter_secret: &[u8; EXPORTER_SECRET_LEN],
    role: Role,
    context: &[u8],
) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(EXPORTER_LABEL);
    h.update(&[PROTOCOL_VERSION, role.as_byte()]);
    h.update(exporter_secret);
    h.update(public_key.ed25519.as_bytes());
    h.update(public_key.mldsa87.as_bytes());
    h.update(&(context.len() as u64).to_le_bytes());
    h.update(context);
    h.finalize()
}

fn compute_binding_tag(digest: &[u8; 64]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(TAG_DOMAIN);
    h.update(digest);
    h.finalize()
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn proof_strict_conjunction() {
        let role_ok: bool = kani::any();
        let tag_ok: bool = kani::any();
        let ed25519_ok: bool = kani::any();
        let mldsa87_ok: bool = kani::any();
        let res = evaluate_strict_conjunction(role_ok, tag_ok, ed25519_ok, mldsa87_ok);
        assert_eq!(res.is_ok(), role_ok && tag_ok && ed25519_ok && mldsa87_ok);
        if !role_ok {
            assert_eq!(res, Err(Error::RoleMismatch));
        } else if !tag_ok {
            assert_eq!(res, Err(Error::ExporterMismatch));
        } else if !ed25519_ok {
            assert_eq!(res, Err(Error::Ed25519VerificationFailed));
        } else if !mldsa87_ok {
            assert_eq!(res, Err(Error::MlDsa87VerificationFailed));
        }
    }
}
