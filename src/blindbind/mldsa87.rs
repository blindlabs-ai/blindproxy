//! NIST FIPS 204 ML-DSA-87 (Category 5) lattice-based digital signatures.
//!
//! Parameters (FIPS 204 Table 1 and Table 2):
//! `q = 8380417`, `n = 256`, `d = 13`, `k = 8`, `l = 7`, `eta = 2`,
//! `tau = 60`, `beta = 120`, `gamma1 = 2^19`, `gamma2 = (q - 1) / 32`, `omega = 75`.
//!
//! Exact serialized wire sizes:
//! - Public key: `2592` bytes
//! - Secret key: `4896` bytes
//! - Signature: `4627` bytes

use core::fmt;

use super::sha3::{shake256_parts, Shake128, Shake256};
use super::{copy_fixed, ct_eq, zeroize_bytes, Error};

/// ML-DSA-87 seed length in bytes.
pub const SEED_LEN: usize = 32;
/// ML-DSA-87 public key length in bytes (FIPS 204 Table 2).
pub const PUBLIC_KEY_LEN: usize = 2592;
/// ML-DSA-87 secret key length in bytes (FIPS 204 Table 2).
pub const SECRET_KEY_LEN: usize = 4896;
/// ML-DSA-87 signature length in bytes (FIPS 204 Table 2).
pub const SIGNATURE_LEN: usize = 4627;
/// Maximum FIPS 204 domain context length in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

const Q: i32 = 8_380_417;
const Q_I64: i64 = 8_380_417;
const N: usize = 256;
const D: usize = 13;
const K: usize = 8;
const L: usize = 7;
const ETA: i32 = 2;
const TAU: usize = 60;
const BETA: i32 = 120;
const GAMMA1: i32 = 1 << 19;
const GAMMA2: i32 = (Q - 1) / 32;
const OMEGA: usize = 75;
const C_TILDE_LEN: usize = 64;
const INV_N: i64 = 8_347_681;

const T1_BYTES: usize = N * 10 / 8;
const S_BYTES: usize = N * 3 / 8;
const T0_BYTES: usize = N * 13 / 8;
const Z_BYTES: usize = N * 20 / 8;
const W1_BYTES: usize = N * 4 / 8;
const HINT_BYTES: usize = OMEGA + K;

type Poly = [i32; N];

const fn bitrev8(mut x: u8) -> u8 {
    let mut r = 0u8;
    let mut i = 0;
    while i < 8 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn mod_pow_q(mut base: i64, mut exp: u32) -> i32 {
    let mut acc = 1i64;
    while exp > 0 {
        if (exp & 1) == 1 {
            acc = (acc * base) % Q_I64;
        }
        base = (base * base) % Q_I64;
        exp >>= 1;
    }
    acc as i32
}

const fn build_zetas() -> [i32; N] {
    let mut table = [0i32; N];
    let mut i = 0usize;
    while i < N {
        table[i] = mod_pow_q(1753, bitrev8(i as u8) as u32);
        i += 1;
    }
    table
}

const ZETAS: [i32; N] = build_zetas();

#[inline]
fn mod_q(x: i64) -> i32 {
    x.rem_euclid(Q_I64) as i32
}

#[inline]
fn center_q(x: i32) -> i32 {
    let r = mod_q(i64::from(x));
    if r > (Q - 1) / 2 {
        r - Q
    } else {
        r
    }
}

fn ntt(a: &mut Poly) {
    for coeff in a.iter_mut() {
        *coeff = mod_q(i64::from(*coeff));
    }
    let mut m = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let zeta = i64::from(ZETAS[m]);
            for j in start..start + len {
                let t = mod_q(zeta * i64::from(a[j + len]));
                let u = a[j];
                let diff = u - t;
                a[j + len] = if diff < 0 { diff + Q } else { diff };
                let sum = u + t;
                a[j] = if sum >= Q { sum - Q } else { sum };
            }
            start += 2 * len;
        }
        len >>= 1;
    }
}

fn inv_ntt(a: &mut Poly) {
    for coeff in a.iter_mut() {
        *coeff = mod_q(i64::from(*coeff));
    }
    let mut m = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let zeta = i64::from(Q - ZETAS[m]);
            for j in start..start + len {
                let t = a[j];
                let sum = t + a[j + len];
                a[j] = if sum >= Q { sum - Q } else { sum };
                let diff = t - a[j + len];
                let diff_pos = if diff < 0 { diff + Q } else { diff };
                a[j + len] = mod_q(zeta * i64::from(diff_pos));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for coeff in a.iter_mut() {
        *coeff = mod_q(INV_N * i64::from(*coeff));
    }
}

fn poly_binop(a: &Poly, b: &Poly, op: fn(i64, i64) -> i64) -> Poly {
    core::array::from_fn(|i| mod_q(op(i64::from(a[i]), i64::from(b[i]))))
}

#[inline]
fn poly_pointwise_mul(a: &Poly, b: &Poly) -> Poly {
    poly_binop(a, b, |x, y| x * y)
}

#[inline]
fn poly_add_mod_q(a: &Poly, b: &Poly) -> Poly {
    poly_binop(a, b, |x, y| x + y)
}

#[inline]
fn poly_sub_mod_q(a: &Poly, b: &Poly) -> Poly {
    poly_binop(a, b, |x, y| x - y)
}

fn poly_inf_norm(a: &Poly) -> i32 {
    let mut max_abs = 0i32;
    for &c in a {
        let v = center_q(c).abs();
        if v > max_abs {
            max_abs = v;
        }
    }
    max_abs
}

fn mat_vec_mul_ntt(a_hat: &[[Poly; L]; K], v_hat: &[Poly; L]) -> [Poly; K] {
    let mut out = [[0i32; N]; K];
    for r in 0..K {
        let mut acc = [0i32; N];
        for s in 0..L {
            let prod = poly_pointwise_mul(&a_hat[r][s], &v_hat[s]);
            acc = poly_add_mod_q(&acc, &prod);
        }
        inv_ntt(&mut acc);
        out[r] = acc;
    }
    out
}

// ---------------------------------------------------------------------------
// Unified LSB-first bit packing and unpacking (FIPS 204 Algorithms 16-19)
// ---------------------------------------------------------------------------

fn pack_bits(vals: &[u32; N], bits: usize, out: &mut [u8]) {
    let mut acc = 0u64;
    let mut acc_bits = 0usize;
    let mut pos = 0usize;
    for &v in vals {
        acc |= u64::from(v) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            out[pos] = (acc & 0xFF) as u8;
            acc >>= 8;
            acc_bits -= 8;
            pos += 1;
        }
    }
}

fn unpack_bits(bytes: &[u8], bits: usize) -> [u32; N] {
    let mask = (1u64 << bits) - 1;
    let mut vals = [0u32; N];
    let mut acc = 0u64;
    let mut acc_bits = 0usize;
    let mut byte_idx = 0usize;
    for slot in &mut vals {
        while acc_bits < bits {
            acc |= u64::from(bytes[byte_idx]) << acc_bits;
            acc_bits += 8;
            byte_idx += 1;
        }
        *slot = (acc & mask) as u32;
        acc >>= bits;
        acc_bits -= bits;
    }
    vals
}

fn pack_poly(poly: &Poly, upper: Option<i32>, bits: usize, out: &mut [u8]) {
    let vals: [u32; N] = match upper {
        Some(b) => core::array::from_fn(|i| (b - poly[i]) as u32),
        None => core::array::from_fn(|i| poly[i] as u32),
    };
    pack_bits(&vals, bits, out);
}

fn bit_unpack_signed(bytes: &[u8], upper: i32, max_raw: u32, bits: usize) -> Result<Poly, Error> {
    let vals = unpack_bits(bytes, bits);
    let mut poly = [0i32; N];
    for i in 0..N {
        if vals[i] > max_raw {
            return Err(Error::InvalidEncoding);
        }
        poly[i] = upper - (vals[i] as i32);
    }
    Ok(poly)
}

fn simple_bit_unpack(bytes: &[u8], bits: usize) -> Poly {
    let vals = unpack_bits(bytes, bits);
    core::array::from_fn(|i| vals[i] as i32)
}

// ---------------------------------------------------------------------------
// Rounding and hints (FIPS 204 Algorithms 20-21 and 35-40)
// ---------------------------------------------------------------------------

#[inline]
fn power2round(r: i32) -> (i32, i32) {
    let r_plus = mod_q(i64::from(r));
    let r1 = (r_plus + (1 << (D - 1)) - 1) >> D;
    let r0 = r_plus - (r1 << D);
    (r1, r0)
}

#[inline]
fn decompose(r: i32) -> (i32, i32) {
    let r_plus = mod_q(i64::from(r));
    let two_g2 = 2 * GAMMA2;
    let rem = r_plus % two_g2;
    let r0 = if rem > GAMMA2 { rem - two_g2 } else { rem };
    if r_plus - r0 == Q - 1 {
        (0, r0 - 1)
    } else {
        ((r_plus - r0) / two_g2, r0)
    }
}

#[inline]
fn make_hint(z: i32, r: i32) -> u8 {
    let (r1, _) = decompose(r);
    let (v1, _) = decompose(mod_q(i64::from(r) + i64::from(z)));
    u8::from(r1 != v1)
}

#[inline]
fn use_hint(h: u8, r: i32) -> i32 {
    const M: i32 = (Q - 1) / (2 * GAMMA2);
    let (r1, r0) = decompose(r);
    if h == 1 {
        if r0 > 0 {
            (r1 + 1).rem_euclid(M)
        } else {
            (r1 - 1).rem_euclid(M)
        }
    } else {
        r1
    }
}

fn hint_bit_pack(h: &[[u8; N]; K], out: &mut [u8]) {
    out.fill(0);
    let mut index = 0usize;
    for (i, poly) in h.iter().enumerate() {
        for (j, &bit) in poly.iter().enumerate() {
            if bit != 0 {
                out[index] = j as u8;
                index += 1;
            }
        }
        out[OMEGA + i] = index as u8;
    }
}

fn hint_bit_unpack(bytes: &[u8]) -> Option<[[u8; N]; K]> {
    let mut h = [[0u8; N]; K];
    let mut index = 0usize;
    for i in 0..K {
        let limit = usize::from(bytes[OMEGA + i]);
        if limit < index || limit > OMEGA {
            return None;
        }
        let first = index;
        while index < limit {
            if index > first && bytes[index - 1] >= bytes[index] {
                return None;
            }
            h[i][usize::from(bytes[index])] = 1;
            index += 1;
        }
    }
    for &pad in &bytes[index..OMEGA] {
        if pad != 0 {
            return None;
        }
    }
    Some(h)
}

// ---------------------------------------------------------------------------
// Sampling (FIPS 204 Algorithms 29-34)
// ---------------------------------------------------------------------------

fn rej_ntt_poly(rho: &[u8; 32], col_s: u8, row_r: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[col_s, row_r]);
    let mut poly = [0i32; N];
    let mut j = 0usize;
    let mut buf = [0u8; 3];
    while j < N {
        xof.squeeze(&mut buf);
        let val = i32::from(buf[0])
            | (i32::from(buf[1]) << 8)
            | (i32::from(buf[2] & 0x7F) << 16);
        if val < Q {
            poly[j] = val;
            j += 1;
        }
    }
    poly
}

fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
    let mut mat = [[[0i32; N]; L]; K];
    for (r, row) in mat.iter_mut().enumerate() {
        for (s, cell) in row.iter_mut().enumerate() {
            *cell = rej_ntt_poly(rho, s as u8, r as u8);
        }
    }
    mat
}

fn rej_bounded_poly(rho_prime: &[u8; 64], nonce: u16) -> Poly {
    let mut xof = Shake256::new();
    xof.update(rho_prime);
    xof.update(&nonce.to_le_bytes());
    let mut poly = [0i32; N];
    let mut j = 0usize;
    let mut b = [0u8; 1];
    while j < N {
        xof.squeeze(&mut b);
        let z0 = b[0] & 0x0F;
        let z1 = b[0] >> 4;
        if z0 < 15 {
            poly[j] = ETA - i32::from(z0 % 5);
            j += 1;
        }
        if z1 < 15 && j < N {
            poly[j] = ETA - i32::from(z1 % 5);
            j += 1;
        }
    }
    poly
}

fn expand_s(rho_prime: &[u8; 64]) -> ([Poly; L], [Poly; K]) {
    let mut s1 = [[0i32; N]; L];
    for (r, poly) in s1.iter_mut().enumerate() {
        *poly = rej_bounded_poly(rho_prime, r as u16);
    }
    let mut s2 = [[0i32; N]; K];
    for (r, poly) in s2.iter_mut().enumerate() {
        *poly = rej_bounded_poly(rho_prime, (r + L) as u16);
    }
    (s1, s2)
}

fn expand_mask(rho_dp: &[u8; 64], kappa: u16) -> [Poly; L] {
    let mut y = [[0i32; N]; L];
    let mut buf = [0u8; Z_BYTES];
    for (r, poly) in y.iter_mut().enumerate() {
        let mut xof = Shake256::new();
        xof.update(rho_dp);
        xof.update(&(kappa.wrapping_add(r as u16)).to_le_bytes());
        xof.squeeze(&mut buf);
        let raw = unpack_bits(&buf, 20);
        for (slot, raw_v) in poly.iter_mut().zip(raw.iter()) {
            *slot = GAMMA1 - (*raw_v as i32);
        }
    }
    y
}

fn sample_in_ball(c_tilde: &[u8; C_TILDE_LEN]) -> Poly {
    let mut xof = Shake256::new();
    xof.update(c_tilde);
    let mut sign_bytes = [0u8; 8];
    xof.squeeze(&mut sign_bytes);
    let mut signs = u64::from_le_bytes(sign_bytes);

    let mut c = [0i32; N];
    let mut jb = [0u8; 1];
    for i in (N - TAU)..N {
        let j = loop {
            xof.squeeze(&mut jb);
            let cand = usize::from(jb[0]);
            if cand <= i {
                break cand;
            }
        };
        c[i] = c[j];
        c[j] = if (signs & 1) == 1 { -1 } else { 1 };
        signs >>= 1;
    }
    c
}

fn w1_encode(w1: &[Poly; K]) -> [u8; K * W1_BYTES] {
    let mut out = [0u8; K * W1_BYTES];
    for (i, poly) in w1.iter().enumerate() {
        pack_poly(poly, None, 4, &mut out[i * W1_BYTES..(i + 1) * W1_BYTES]);
    }
    out
}

fn compute_challenge_hash(mu: &[u8; 64], w1: &[Poly; K]) -> [u8; C_TILDE_LEN] {
    let w1_bytes = w1_encode(w1);
    shake256_parts(&[mu, &w1_bytes])
}

fn compute_mu_external(tr: &[u8; 64], context: &[u8], message: &[u8]) -> Result<[u8; 64], Error> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(Error::ContextTooLong);
    }
    let header = [0u8, context.len() as u8];
    Ok(shake256_parts(&[tr, &header, context, message]))
}

fn compute_mu_internal(tr: &[u8; 64], message: &[u8]) -> [u8; 64] {
    shake256_parts(&[tr, message])
}

// ---------------------------------------------------------------------------
// Encoded key and signature wire containers
// ---------------------------------------------------------------------------

/// Serialized 2592-byte NIST FIPS 204 ML-DSA-87 public key (`rho || t1`).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Box<[u8; PUBLIC_KEY_LEN]>);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87PublicKey")
            .field("len", &PUBLIC_KEY_LEN)
            .finish()
    }
}

impl PublicKey {
    /// Parse a 2592-byte ML-DSA-87 public key.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 2592`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Box::new(copy_fixed(bytes)?)))
    }

    /// Borrow the raw 2592-byte public key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    fn decode(&self) -> ([u8; 32], [Poly; K]) {
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&self.0[0..32]);
        let mut t1 = [[0i32; N]; K];
        for (i, poly) in t1.iter_mut().enumerate() {
            let start = 32 + i * T1_BYTES;
            *poly = simple_bit_unpack(&self.0[start..start + T1_BYTES], 10);
        }
        (rho, t1)
    }

    fn tr_hash(&self) -> [u8; 64] {
        shake256_parts(&[self.as_bytes()])
    }
}

/// Serialized 4896-byte NIST FIPS 204 ML-DSA-87 secret key (`rho || K || tr || s1 || s2 || t0`).
#[derive(Clone)]
pub struct SecretKey(Box<[u8; SECRET_KEY_LEN]>);

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87SecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.0[..]);
    }
}

struct DecodedSecretKey {
    rho: [u8; 32],
    k_seed: [u8; 32],
    tr: [u8; 64],
    s1: [Poly; L],
    s2: [Poly; K],
    t0: [Poly; K],
}

impl SecretKey {
    /// Parse and validate a 4896-byte ML-DSA-87 secret key.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 4896` or [`Error::InvalidEncoding`]
    /// if any `s1` or `s2` coefficient exceeds `[-eta, eta]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sk = Self(Box::new(copy_fixed(bytes)?));
        let _ = sk.decode()?;
        Ok(sk)
    }

    /// Borrow the raw 4896-byte secret key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SECRET_KEY_LEN] {
        &self.0
    }

    fn decode(&self) -> Result<DecodedSecretKey, Error> {
        let b = self.as_bytes();
        let mut rho = [0u8; 32];
        let mut k_seed = [0u8; 32];
        let mut tr = [0u8; 64];
        rho.copy_from_slice(&b[0..32]);
        k_seed.copy_from_slice(&b[32..64]);
        tr.copy_from_slice(&b[64..128]);

        let mut off = 128;
        let mut s1 = [[0i32; N]; L];
        for poly in &mut s1 {
            *poly = bit_unpack_signed(&b[off..off + S_BYTES], ETA, (2 * ETA) as u32, 3)?;
            off += S_BYTES;
        }
        let mut s2 = [[0i32; N]; K];
        for poly in &mut s2 {
            *poly = bit_unpack_signed(&b[off..off + S_BYTES], ETA, (2 * ETA) as u32, 3)?;
            off += S_BYTES;
        }
        let mut t0 = [[0i32; N]; K];
        for poly in &mut t0 {
            *poly = bit_unpack_signed(&b[off..off + T0_BYTES], 1 << (D - 1), (1 << D) - 1, 13)?;
            off += T0_BYTES;
        }
        Ok(DecodedSecretKey {
            rho,
            k_seed,
            tr,
            s1,
            s2,
            t0,
        })
    }
}

/// Serialized 4627-byte NIST FIPS 204 ML-DSA-87 signature (`c_tilde || z || h`).
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(Box<[u8; SIGNATURE_LEN]>);

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87Signature")
            .field("len", &SIGNATURE_LEN)
            .finish()
    }
}

impl Signature {
    /// Parse a 4627-byte ML-DSA-87 signature.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 4627`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(Box::new(copy_fixed(bytes)?)))
    }

    /// Borrow the raw 4627-byte signature.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

/// NIST FIPS 204 ML-DSA-87 signing keypair.
#[derive(Clone)]
pub struct KeyPair {
    public: PublicKey,
    secret: SecretKey,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MlDsa87KeyPair")
            .field("public", &self.public)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl KeyPair {
    /// Deterministically generate an ML-DSA-87 keypair from a 32-byte seed `xi`
    /// per NIST FIPS 204 Algorithm 6 (`ML-DSA.KeyGen_internal`).
    #[must_use]
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        let mut xof = Shake256::new();
        xof.update(&seed);
        xof.update(&[K as u8, L as u8]);
        let mut expanded = [0u8; 128];
        xof.squeeze(&mut expanded);

        let mut rho = [0u8; 32];
        let mut rho_prime = [0u8; 64];
        let mut k_seed = [0u8; 32];
        rho.copy_from_slice(&expanded[0..32]);
        rho_prime.copy_from_slice(&expanded[32..96]);
        k_seed.copy_from_slice(&expanded[96..128]);
        zeroize_bytes(&mut expanded);

        let a_hat = expand_a(&rho);
        let (s1, s2) = expand_s(&rho_prime);
        zeroize_bytes(&mut rho_prime);

        let mut s1_hat = s1;
        for poly in &mut s1_hat {
            ntt(poly);
        }
        let a_s1 = mat_vec_mul_ntt(&a_hat, &s1_hat);

        let mut t1 = [[0i32; N]; K];
        let mut t0 = [[0i32; N]; K];
        for r in 0..K {
            let t_r = poly_add_mod_q(&a_s1[r], &s2[r]);
            for j in 0..N {
                let (hi, lo) = power2round(t_r[j]);
                t1[r][j] = hi;
                t0[r][j] = lo;
            }
        }

        let mut pk_bytes = Box::new([0u8; PUBLIC_KEY_LEN]);
        pk_bytes[0..32].copy_from_slice(&rho);
        for (i, poly) in t1.iter().enumerate() {
            let start = 32 + i * T1_BYTES;
            pack_poly(poly, None, 10, &mut pk_bytes[start..start + T1_BYTES]);
        }
        let public = PublicKey(pk_bytes);
        let tr = public.tr_hash();

        let mut sk_bytes = Box::new([0u8; SECRET_KEY_LEN]);
        sk_bytes[0..32].copy_from_slice(&rho);
        sk_bytes[32..64].copy_from_slice(&k_seed);
        sk_bytes[64..128].copy_from_slice(&tr);
        let mut off = 128;
        for poly in &s1 {
            pack_poly(poly, Some(ETA), 3, &mut sk_bytes[off..off + S_BYTES]);
            off += S_BYTES;
        }
        for poly in &s2 {
            pack_poly(poly, Some(ETA), 3, &mut sk_bytes[off..off + S_BYTES]);
            off += S_BYTES;
        }
        for poly in &t0 {
            pack_poly(
                poly,
                Some(1 << (D - 1)),
                13,
                &mut sk_bytes[off..off + T0_BYTES],
            );
            off += T0_BYTES;
        }
        zeroize_bytes(&mut k_seed);

        Self {
            public,
            secret: SecretKey(sk_bytes),
        }
    }

    /// Borrow the 2592-byte public key.
    #[must_use]
    pub const fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Borrow the 4896-byte secret key.
    #[must_use]
    pub const fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Sign `message` deterministically (`rnd = 0^32`) with domain `context`
    /// per NIST FIPS 204 Algorithm 2 (`ML-DSA.Sign`).
    ///
    /// # Errors
    /// Returns [`Error::ContextTooLong`] if `context.len() > 255`.
    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<Signature, Error> {
        sign(&self.secret, message, context, &[0u8; 32])
    }

    /// Sign `message` in hedged mode with caller-supplied 32-byte randomness `rnd`
    /// and domain `context` per NIST FIPS 204 Algorithm 2 (`ML-DSA.Sign`).
    ///
    /// # Errors
    /// Returns [`Error::ContextTooLong`] if `context.len() > 255`.
    pub fn sign_hedged(
        &self,
        message: &[u8],
        context: &[u8],
        rnd: &[u8; 32],
    ) -> Result<Signature, Error> {
        sign(&self.secret, message, context, rnd)
    }
}

// ---------------------------------------------------------------------------
// Core FIPS 204 Sign and Verify algorithms (Algorithms 2, 3, 7, 8)
// ---------------------------------------------------------------------------

fn sign_from_mu(sk: &DecodedSecretKey, mu: &[u8; 64], rnd: &[u8; 32]) -> Signature {
    let a_hat = expand_a(&sk.rho);

    let mut s1_hat = sk.s1;
    for p in &mut s1_hat {
        ntt(p);
    }
    let mut s2_hat = sk.s2;
    for p in &mut s2_hat {
        ntt(p);
    }
    let mut t0_hat = sk.t0;
    for p in &mut t0_hat {
        ntt(p);
    }

    let mut xof = Shake256::new();
    xof.update(&sk.k_seed);
    xof.update(rnd);
    xof.update(mu);
    let mut rho_dp = [0u8; 64];
    xof.squeeze(&mut rho_dp);

    let mut kappa = 0u16;
    let sig = loop {
        let y = expand_mask(&rho_dp, kappa);
        kappa = kappa.wrapping_add(L as u16);

        let mut y_hat = y;
        for p in &mut y_hat {
            ntt(p);
        }
        let w = mat_vec_mul_ntt(&a_hat, &y_hat);

        let mut w1 = [[0i32; N]; K];
        for r in 0..K {
            for j in 0..N {
                let (hi, _) = decompose(w[r][j]);
                w1[r][j] = hi;
            }
        }

        let c_tilde = compute_challenge_hash(mu, &w1);
        let mut c_hat = sample_in_ball(&c_tilde);
        ntt(&mut c_hat);

        let mut z = [[0i32; N]; L];
        let mut z_ok = true;
        for s in 0..L {
            let mut cs1 = poly_pointwise_mul(&c_hat, &s1_hat[s]);
            inv_ntt(&mut cs1);
            for j in 0..N {
                z[s][j] = center_q(mod_q(i64::from(y[s][j]) + i64::from(center_q(cs1[j]))));
            }
            if poly_inf_norm(&z[s]) >= GAMMA1 - BETA {
                z_ok = false;
                break;
            }
        }
        if !z_ok {
            continue;
        }

        let mut w_minus_cs2 = [[0i32; N]; K];
        let mut r0_ok = true;
        for r in 0..K {
            let mut cs2 = poly_pointwise_mul(&c_hat, &s2_hat[r]);
            inv_ntt(&mut cs2);
            w_minus_cs2[r] = poly_sub_mod_q(&w[r], &cs2);
            for &coeff in &w_minus_cs2[r] {
                let (_, r0) = decompose(coeff);
                if r0.abs() >= GAMMA2 - BETA {
                    r0_ok = false;
                    break;
                }
            }
            if !r0_ok {
                break;
            }
        }
        if !r0_ok {
            continue;
        }

        let mut hints = [[0u8; N]; K];
        let mut hint_weight = 0usize;
        let mut ct0_ok = true;
        for r in 0..K {
            let mut ct0 = poly_pointwise_mul(&c_hat, &t0_hat[r]);
            inv_ntt(&mut ct0);
            if poly_inf_norm(&ct0) >= GAMMA2 {
                ct0_ok = false;
                break;
            }
            let r_arg = poly_add_mod_q(&w_minus_cs2[r], &ct0);
            for j in 0..N {
                let neg_ct0 = mod_q(-i64::from(ct0[j]));
                let bit = make_hint(neg_ct0, r_arg[j]);
                hints[r][j] = bit;
                hint_weight += usize::from(bit);
            }
            if hint_weight > OMEGA {
                ct0_ok = false;
                break;
            }
        }
        if !ct0_ok {
            continue;
        }

        let mut out = Box::new([0u8; SIGNATURE_LEN]);
        out[0..C_TILDE_LEN].copy_from_slice(&c_tilde);
        let mut off = C_TILDE_LEN;
        for poly in &z {
            pack_poly(poly, Some(GAMMA1), 20, &mut out[off..off + Z_BYTES]);
            off += Z_BYTES;
        }
        hint_bit_pack(&hints, &mut out[off..off + HINT_BYTES]);
        break Signature(out);
    };

    zeroize_bytes(&mut rho_dp);
    sig
}

fn verify_from_mu(public_key: &PublicKey, mu: &[u8; 64], signature: &Signature) -> Result<(), Error> {
    let (rho, t1) = public_key.decode();
    let sig_bytes = signature.as_bytes();

    let mut c_tilde = [0u8; C_TILDE_LEN];
    c_tilde.copy_from_slice(&sig_bytes[0..C_TILDE_LEN]);

    let mut z = [[0i32; N]; L];
    let mut off = C_TILDE_LEN;
    for poly in &mut z {
        *poly = bit_unpack_signed(&sig_bytes[off..off + Z_BYTES], GAMMA1, (1 << 20) - 1, 20)
            .map_err(|_| Error::MlDsa87VerificationFailed)?;
        if poly_inf_norm(poly) >= GAMMA1 - BETA {
            return Err(Error::MlDsa87VerificationFailed);
        }
        off += Z_BYTES;
    }

    let hints = hint_bit_unpack(&sig_bytes[off..off + HINT_BYTES])
        .ok_or(Error::MlDsa87VerificationFailed)?;

    let a_hat = expand_a(&rho);
    let mut z_hat = z;
    for p in &mut z_hat {
        ntt(p);
    }
    let a_z = mat_vec_mul_ntt(&a_hat, &z_hat);

    let mut c_hat = sample_in_ball(&c_tilde);
    ntt(&mut c_hat);

    let mut w1_prime = [[0i32; N]; K];
    for r in 0..K {
        let mut t1_scaled = [0i32; N];
        for j in 0..N {
            t1_scaled[j] = t1[r][j] << D;
        }
        ntt(&mut t1_scaled);
        let mut c_t1 = poly_pointwise_mul(&c_hat, &t1_scaled);
        inv_ntt(&mut c_t1);
        let w_approx = poly_sub_mod_q(&a_z[r], &c_t1);
        for j in 0..N {
            w1_prime[r][j] = use_hint(hints[r][j], w_approx[j]);
        }
    }

    let expected_c_tilde = compute_challenge_hash(mu, &w1_prime);
    if ct_eq(&c_tilde, &expected_c_tilde) {
        Ok(())
    } else {
        Err(Error::MlDsa87VerificationFailed)
    }
}

/// Sign `message` with `context` and 32-byte `rnd` per NIST FIPS 204 Algorithm 2 (`ML-DSA.Sign`).
///
/// # Errors
/// Returns [`Error::ContextTooLong`] if `context.len() > 255` or [`Error::InvalidEncoding`]
/// if `secret_key` fails decoding.
pub fn sign(
    secret_key: &SecretKey,
    message: &[u8],
    context: &[u8],
    rnd: &[u8; 32],
) -> Result<Signature, Error> {
    let decoded = secret_key.decode()?;
    let mu = compute_mu_external(&decoded.tr, context, message)?;
    Ok(sign_from_mu(&decoded, &mu, rnd))
}

/// Sign pre-formatted `message` per NIST FIPS 204 Algorithm 7 (`ML-DSA.Sign_internal`).
///
/// # Errors
/// Returns [`Error::InvalidEncoding`] if `secret_key` fails decoding.
pub fn sign_internal(
    secret_key: &SecretKey,
    message: &[u8],
    rnd: &[u8; 32],
) -> Result<Signature, Error> {
    let decoded = secret_key.decode()?;
    let mu = compute_mu_internal(&decoded.tr, message);
    Ok(sign_from_mu(&decoded, &mu, rnd))
}

/// Sign a precomputed 64-byte message representative `mu` per NIST FIPS 204 external-mu mode.
///
/// # Errors
/// Returns [`Error::InvalidEncoding`] if `secret_key` fails decoding.
pub fn sign_external_mu(
    secret_key: &SecretKey,
    mu: &[u8; 64],
    rnd: &[u8; 32],
) -> Result<Signature, Error> {
    let decoded = secret_key.decode()?;
    Ok(sign_from_mu(&decoded, mu, rnd))
}

/// Verify an ML-DSA-87 signature with `context` per NIST FIPS 204 Algorithm 3 (`ML-DSA.Verify`).
///
/// # Errors
/// Returns [`Error::ContextTooLong`] if `context.len() > 255`, or
/// [`Error::MlDsa87VerificationFailed`] if any norm, hint, or commitment check fails.
pub fn verify(
    public_key: &PublicKey,
    message: &[u8],
    context: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    let tr = public_key.tr_hash();
    let mu = compute_mu_external(&tr, context, message)?;
    verify_from_mu(public_key, &mu, signature)
}

/// Verify a signature against pre-formatted `message` per NIST FIPS 204 Algorithm 8 (`ML-DSA.Verify_internal`).
///
/// # Errors
/// Returns [`Error::MlDsa87VerificationFailed`] if verification fails.
pub fn verify_internal(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), Error> {
    let tr = public_key.tr_hash();
    let mu = compute_mu_internal(&tr, message);
    verify_from_mu(public_key, &mu, signature)
}

/// Verify a signature against a precomputed 64-byte message representative `mu`.
///
/// # Errors
/// Returns [`Error::MlDsa87VerificationFailed`] if verification fails.
pub fn verify_external_mu(
    public_key: &PublicKey,
    mu: &[u8; 64],
    signature: &Signature,
) -> Result<(), Error> {
    verify_from_mu(public_key, mu, signature)
}
