//! IETF RFC 8032 Ed25519 digital signatures and NIST FIPS 180-4 SHA-512.
//!
//! Secret-key operations (key derivation and signing) use constant-time
//! field arithmetic, scalar reduction, and conditional-select point multiplication.

use core::fmt;

use super::{copy_fixed, ct_eq, zeroize_bytes, Error};

/// Ed25519 seed (private key) length in bytes.
pub const SECRET_KEY_LEN: usize = 32;
/// Ed25519 compressed public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

// ---------------------------------------------------------------------------
// NIST FIPS 180-4 SHA-512
// ---------------------------------------------------------------------------

const SHA512_IV: [u64; 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

const SHA384_IV: [u64; 8] = [
    0xCBBB_9D5D_C105_9ED8,
    0x629A_292A_367C_D507,
    0x9159_015A_3070_DD17,
    0x152F_ECD8_F70E_5939,
    0x6733_2667_FFC0_0B31,
    0x8EB4_4A87_6858_1511,
    0xDB0C_2E0D_64F9_8FA7,
    0x47B5_481D_BEFA_4FA4,
];

const SHA512_K: [u64; 80] = [
    0x428A_2F98_D728_AE22,
    0x7137_4491_23EF_65CD,
    0xB5C0_FBCF_EC4D_3B2F,
    0xE9B5_DBA5_8189_DBBC,
    0x3956_C25B_F348_B538,
    0x59F1_11F1_B605_D019,
    0x923F_82A4_AF19_4F9B,
    0xAB1C_5ED5_DA6D_8118,
    0xD807_AA98_A303_0242,
    0x1283_5B01_4570_6FBE,
    0x2431_85BE_4EE4_B28C,
    0x550C_7DC3_D5FF_B4E2,
    0x72BE_5D74_F27B_896F,
    0x80DE_B1FE_3B16_96B1,
    0x9BDC_06A7_25C7_1235,
    0xC19B_F174_CF69_2694,
    0xE49B_69C1_9EF1_4AD2,
    0xEFBE_4786_384F_25E3,
    0x0FC1_9DC6_8B8C_D5B5,
    0x240C_A1CC_77AC_9C65,
    0x2DE9_2C6F_592B_0275,
    0x4A74_84AA_6EA6_E483,
    0x5CB0_A9DC_BD41_FBD4,
    0x76F9_88DA_8311_53B5,
    0x983E_5152_EE66_DFAB,
    0xA831_C66D_2DB4_3210,
    0xB003_27C8_98FB_213F,
    0xBF59_7FC7_BEEF_0EE4,
    0xC6E0_0BF3_3DA8_8FC2,
    0xD5A7_9147_930A_A725,
    0x06CA_6351_E003_826F,
    0x1429_2967_0A0E_6E70,
    0x27B7_0A85_46D2_2FFC,
    0x2E1B_2138_5C26_C926,
    0x4D2C_6DFC_5AC4_2AED,
    0x5338_0D13_9D95_B3DF,
    0x650A_7354_8BAF_63DE,
    0x766A_0ABB_3C77_B2A8,
    0x81C2_C92E_47ED_AEE6,
    0x9272_2C85_1482_353B,
    0xA2BF_E8A1_4CF1_0364,
    0xA81A_664B_BC42_3001,
    0xC24B_8B70_D0F8_9791,
    0xC76C_51A3_0654_BE30,
    0xD192_E819_D6EF_5218,
    0xD699_0624_5565_A910,
    0xF40E_3585_5771_202A,
    0x106A_A070_32BB_D1B8,
    0x19A4_C116_B8D2_D0C8,
    0x1E37_6C08_5141_AB53,
    0x2748_774C_DF8E_EB99,
    0x34B0_BCB5_E19B_48A8,
    0x391C_0CB3_C5C9_5A63,
    0x4ED8_AA4A_E341_8ACB,
    0x5B9C_CA4F_7763_E373,
    0x682E_6FF3_D6B2_B8A3,
    0x748F_82EE_5DEF_B2FC,
    0x78A5_636F_4317_2F60,
    0x84C8_7814_A1F0_AB72,
    0x8CC7_0208_1A64_39EC,
    0x90BE_FFFA_2363_1E28,
    0xA450_6CEB_DE82_BDE9,
    0xBEF9_A3F7_B2C6_7915,
    0xC671_78F2_E372_532B,
    0xCA27_3ECE_EA26_619C,
    0xD186_B8C7_21C0_C207,
    0xEADA_7DD6_CDE0_EB1E,
    0xF57D_4F7F_EE6E_D178,
    0x06F0_67AA_7217_6FBA,
    0x0A63_7DC5_A2C8_98A6,
    0x113F_9804_BEF9_0DAE,
    0x1B71_0B35_131C_471B,
    0x28DB_77F5_2304_7D84,
    0x32CA_AB7B_40C7_2493,
    0x3C9E_BE0A_15C9_BEBC,
    0x431D_67C4_9C10_0D4C,
    0x4CC5_D4BE_CB3E_42B6,
    0x597F_299C_FC65_7E2A,
    0x5FCB_6FAB_3AD6_FAEC,
    0x6C44_198C_4A47_5817,
];

/// Incremental NIST FIPS 180-4 `SHA-512` hasher.
#[derive(Clone)]
pub struct Sha512 {
    state: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Create a new `SHA-512` state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SHA512_IV,
            buf: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Create a new NIST FIPS 180-4 `SHA-384` state sharing the `SHA-512` compression function.
    #[must_use]
    pub const fn new_sha384() -> Self {
        Self {
            state: SHA384_IV,
            buf: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut w = [0u64; 80];
        for (slot, chunk) in w.iter_mut().take(16).zip(block.chunks_exact(8)) {
            *slot = u64::from_be_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
        }
        for idx in 0..64 {
            let i = idx + 16;
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA512_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        let vals = [a, b, c, d, e, f, g, h];
        for (s, v) in state.iter_mut().zip(vals.iter()) {
            *s = s.wrapping_add(*v);
        }
    }

    /// Absorb input bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);
        let mut idx = 0;
        while idx < data.len() {
            let take = (128 - self.buf_len).min(data.len() - idx);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[idx..idx + take]);
            self.buf_len += take;
            idx += take;
            if self.buf_len == 128 {
                let block = self.buf;
                Self::compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
    }

    /// Finalize the hash and return the 64-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 112 {
            self.buf[self.buf_len..128].fill(0);
            let block = self.buf;
            Self::compress(&mut self.state, &block);
            self.buf_len = 0;
        }
        self.buf[self.buf_len..112].fill(0);
        self.buf[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buf;
        Self::compress(&mut self.state, &block);

        let mut out = [0u8; 64];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Finalize a `SHA-384` state and return the truncated 48-byte digest.
    #[must_use]
    pub fn finalize_sha384(self) -> [u8; 48] {
        let full = self.finalize();
        let mut out = [0u8; 48];
        out.copy_from_slice(&full[..48]);
        out
    }
}

/// One-shot NIST FIPS 180-4 `SHA-512`.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

/// One-shot NIST FIPS 180-4 `SHA-384`.
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha512::new_sha384();
    h.update(data);
    h.finalize_sha384()
}

// ---------------------------------------------------------------------------
// Field arithmetic modulo p = 2^255 - 19 (5 x 51-bit limbs)
// ---------------------------------------------------------------------------

const MASK51: u64 = (1u64 << 51) - 1;
const TWO_P0: u64 = 2 * (MASK51 - 18);
const TWO_PI: u64 = 2 * MASK51;

const FE_ZERO: Fe = Fe([0, 0, 0, 0, 0]);
const FE_ONE: Fe = Fe([1, 0, 0, 0, 0]);
const FE_D: Fe = Fe([
    0x3_4DCA_1359_78A3,
    0x1_A828_3B15_6EBD,
    0x5_E7A2_6001_C029,
    0x7_39C6_63A0_3CBB,
    0x5_2036_CEE2_B6FF,
]);
const FE_D2: Fe = Fe([
    0x6_9B94_26B2_F159,
    0x3_5050_762A_DD7A,
    0x3_CF44_C003_8052,
    0x6_738C_C740_7977,
    0x2_406D_9DC5_6DFF,
]);
const FE_SQRT_M1: Fe = Fe([
    0x6_1B27_4A0E_A0B0,
    0x0_D5A5_FC8F_189D,
    0x7_EF5E_9CBD_0C60,
    0x7_8595_A680_4C9E,
    0x2_B832_4804_FC1D,
]);

#[derive(Clone, Copy)]
struct Fe([u64; 5]);

impl Fe {
    fn carry_u64(mut l: [u64; 5]) -> Self {
        let mut c = l[0] >> 51;
        l[0] &= MASK51;
        for limb in l.iter_mut().skip(1) {
            *limb += c;
            c = *limb >> 51;
            *limb &= MASK51;
        }
        l[0] += c * 19;
        let c0 = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c0;
        Self(l)
    }

    fn add(self, rhs: Self) -> Self {
        let mut out = self.0;
        for (a, b) in out.iter_mut().zip(rhs.0) {
            *a += b;
        }
        Self::carry_u64(out)
    }

    fn sub(self, rhs: Self) -> Self {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = rhs.0;
        Self::carry_u64([
            a0 + TWO_P0 - b0,
            a1 + TWO_PI - b1,
            a2 + TWO_PI - b2,
            a3 + TWO_PI - b3,
            a4 + TWO_PI - b4,
        ])
    }

    fn neg(self) -> Self {
        FE_ZERO.sub(self)
    }

    fn mul(self, rhs: Self) -> Self {
        let a: [u128; 5] = self.0.map(u128::from);
        let b: [u128; 5] = rhs.0.map(u128::from);
        let b19 = [b[0], b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19];

        let mut t = [
            a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1],
            a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2],
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3],
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4],
            a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
        ];

        let m51 = u128::from(MASK51);
        for _ in 0..2 {
            let mut c = t[0] >> 51;
            t[0] &= m51;
            for limb in t.iter_mut().skip(1) {
                *limb += c;
                c = *limb >> 51;
                *limb &= m51;
            }
            t[0] += c * 19;
        }
        let c0 = t[0] >> 51;
        t[0] &= m51;
        t[1] += c0;
        Self(t.map(|v| v as u64))
    }

    fn sq(self) -> Self {
        self.mul(self)
    }

    fn sq_n(mut self, n: usize) -> Self {
        for _ in 0..n {
            self = self.sq();
        }
        self
    }

    fn pow_2_250_minus_1(self) -> (Self, Self) {
        let z2 = self.sq();
        let z9 = z2.sq().sq().mul(self);
        let z11 = z2.mul(z9);
        let z_5_0 = z11.sq().mul(z9);
        let z_10_0 = z_5_0.sq_n(5).mul(z_5_0);
        let z_20_0 = z_10_0.sq_n(10).mul(z_10_0);
        let z_40_0 = z_20_0.sq_n(20).mul(z_20_0);
        let z_50_0 = z_40_0.sq_n(10).mul(z_10_0);
        let z_100_0 = z_50_0.sq_n(50).mul(z_50_0);
        let z_200_0 = z_100_0.sq_n(100).mul(z_100_0);
        let z_250_0 = z_200_0.sq_n(50).mul(z_50_0);
        (z_250_0, z11)
    }

    fn invert(self) -> Self {
        let (z_250_0, z11) = self.pow_2_250_minus_1();
        z_250_0.sq_n(5).mul(z11)
    }

    fn pow22523(self) -> Self {
        let (z_250_0, _) = self.pow_2_250_minus_1();
        z_250_0.sq_n(2).mul(self)
    }

    fn to_bytes(self) -> [u8; 32] {
        let h = Self::carry_u64(self.0).0;
        let mut t = h;
        t[0] += 19;
        let mut c = t[0] >> 51;
        t[0] &= MASK51;
        for limb in t.iter_mut().skip(1) {
            *limb += c;
            c = *limb >> 51;
            *limb &= MASK51;
        }
        let mask = 0u64.wrapping_sub(c);
        let mut l = [0u64; 5];
        for i in 0..5 {
            l[i] = (t[i] & mask) | (h[i] & !mask);
        }

        let w0 = l[0] | (l[1] << 51);
        let w1 = (l[1] >> 13) | (l[2] << 38);
        let w2 = (l[2] >> 26) | (l[3] << 25);
        let w3 = (l[3] >> 39) | (l[4] << 12);

        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&w0.to_le_bytes());
        out[8..16].copy_from_slice(&w1.to_le_bytes());
        out[16..24].copy_from_slice(&w2.to_le_bytes());
        out[24..32].copy_from_slice(&w3.to_le_bytes());
        out
    }

    fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Self> {
        let w0 = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
        let w1 = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
        let w2 = u64::from_le_bytes(bytes[16..24].try_into().ok()?);
        let w3 = u64::from_le_bytes(bytes[24..32].try_into().ok()?) & ((1u64 << 63) - 1);

        let l = [
            w0 & MASK51,
            ((w0 >> 51) | (w1 << 13)) & MASK51,
            ((w1 >> 38) | (w2 << 26)) & MASK51,
            ((w2 >> 25) | (w3 << 39)) & MASK51,
            w3 >> 12,
        ];
        if l[4] == MASK51
            && l[3] == MASK51
            && l[2] == MASK51
            && l[1] == MASK51
            && l[0] >= MASK51 - 18
        {
            return None;
        }
        Some(Self(l))
    }

    fn ct_eq(self, other: Self) -> bool {
        ct_eq(&self.to_bytes(), &other.to_bytes())
    }

    fn ct_select(self, other: Self, choose_other: u64) -> Self {
        let mask = 0u64.wrapping_sub(choose_other & 1);
        let mut out = [0u64; 5];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = (other.0[i] & mask) | (self.0[i] & !mask);
        }
        Self(out)
    }
}

// ---------------------------------------------------------------------------
// Extended twisted Edwards curve points (X : Y : Z : T)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct ExtPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const BASE_POINT: ExtPoint = ExtPoint {
    x: Fe([
        0x6_2D60_8F25_D51A,
        0x4_12A4_B4F6_592A,
        0x7_5B71_71A4_B31D,
        0x1_FF60_5271_18FE,
        0x2_1693_6D3C_D6E5,
    ]),
    y: Fe([
        0x6_6666_6666_6658,
        0x4_CCCC_CCCC_CCCC,
        0x1_9999_9999_9999,
        0x3_3333_3333_3333,
        0x6_6666_6666_6666,
    ]),
    z: FE_ONE,
    t: Fe([
        0x6_8AB3_A5B7_DDA3,
        0x0_0EEA_2A5E_ADBB,
        0x2_AF8D_F483_C27E,
        0x3_32B3_7527_4732,
        0x6_7875_F0FD_78B7,
    ]),
};

impl ExtPoint {
    const fn identity() -> Self {
        Self {
            x: FE_ZERO,
            y: FE_ONE,
            z: FE_ONE,
            t: FE_ZERO,
        }
    }

    fn add(self, rhs: Self) -> Self {
        let a = self.y.sub(self.x).mul(rhs.y.sub(rhs.x));
        let b = self.y.add(self.x).mul(rhs.y.add(rhs.x));
        let c = self.t.mul(FE_D2).mul(rhs.t);
        let d = self.z.add(self.z).mul(rhs.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Self {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn ct_select(self, other: Self, choose_other: u64) -> Self {
        Self {
            x: self.x.ct_select(other.x, choose_other),
            y: self.y.ct_select(other.y, choose_other),
            z: self.z.ct_select(other.z, choose_other),
            t: self.t.ct_select(other.t, choose_other),
        }
    }

    fn scalar_mul(self, scalar: &[u8; 32]) -> Self {
        let mut acc = Self::identity();
        let mut addend = self;
        for &byte in scalar {
            for bit_idx in 0..8 {
                let bit = u64::from((byte >> bit_idx) & 1);
                let sum = acc.add(addend);
                acc = acc.ct_select(sum, bit);
                addend = addend.add(addend);
            }
        }
        acc
    }

    fn encode(self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(z_inv).to_bytes();
        let mut y = self.y.mul(z_inv).to_bytes();
        y[31] |= (x[0] & 1) << 7;
        y
    }

    fn decode(bytes: &[u8; 32]) -> Option<Self> {
        let x_sign = bytes[31] >> 7;
        let y = Fe::from_bytes_canonical(bytes)?;
        let y2 = y.sq();
        let u = y2.sub(FE_ONE);
        let v = FE_D.mul(y2).add(FE_ONE);
        let v3 = v.sq().mul(v);
        let v7 = v3.sq().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow22523());

        let vx2 = v.mul(x.sq());
        if !vx2.ct_eq(u) {
            if vx2.ct_eq(u.neg()) {
                x = x.mul(FE_SQRT_M1);
            } else {
                return None;
            }
        }

        let x_bytes = x.to_bytes();
        if ct_eq(&x_bytes, &[0u8; 32]) && x_sign == 1 {
            return None;
        }
        if (x_bytes[0] & 1) != x_sign {
            x = x.neg();
        }
        Some(Self {
            x,
            y,
            z: FE_ONE,
            t: x.mul(y),
        })
    }

    fn ct_eq_projective(self, other: Self) -> bool {
        let xz = self.x.mul(other.z).ct_eq(other.x.mul(self.z));
        let yz = self.y.mul(other.z).ct_eq(other.y.mul(self.z));
        xz && yz
    }
}

// ---------------------------------------------------------------------------
// Scalar arithmetic modulo L = 2^252 + 27742317777372353535851937790883648493
// ---------------------------------------------------------------------------

const L_LIMBS: [u64; 4] = [
    0x5812_631A_5CF5_D3ED,
    0x14DE_F9DE_A2F7_9CD6,
    0x0000_0000_0000_0000,
    0x1000_0000_0000_0000,
];

fn sub_l_if_ge(acc: &mut [u64; 5]) {
    let mut diff = [0u64; 5];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d1, b1) = acc[i].overflowing_sub(L_LIMBS[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        diff[i] = d2;
        borrow = u64::from(b1) + u64::from(b2);
    }
    let (d4, b4) = acc[4].overflowing_sub(borrow);
    diff[4] = d4;
    let use_diff = 0u64.wrapping_sub(u64::from(!b4));
    for i in 0..5 {
        acc[i] = (diff[i] & use_diff) | (acc[i] & !use_diff);
    }
}

fn reduce_64_mod_l(wide: &[u8; 64]) -> [u8; 32] {
    let mut acc = [0u64; 5];
    for &byte in wide.iter().rev() {
        for bit_idx in (0..8).rev() {
            let mut carry = u64::from((byte >> bit_idx) & 1);
            for limb in &mut acc {
                let next_carry = *limb >> 63;
                *limb = (*limb << 1) | carry;
                carry = next_carry;
            }
            sub_l_if_ge(&mut acc);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&acc[i].to_le_bytes());
    }
    out
}

fn bytes_to_u64x4(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
        u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]),
        u64::from_le_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]),
    ]
}

fn mul_add_mod_l(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let al = bytes_to_u64x4(a);
    let bl = bytes_to_u64x4(b);
    let cl = bytes_to_u64x4(c);
    let mut prod = [0u64; 8];

    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let acc = u128::from(prod[i + j]) + u128::from(al[i]) * u128::from(bl[j]) + carry;
            prod[i + j] = acc as u64;
            carry = acc >> 64;
        }
        prod[i + 4] = carry as u64;
    }

    let mut carry = 0u128;
    for i in 0..8 {
        let addend = if i < 4 { u128::from(cl[i]) } else { 0 };
        let acc = u128::from(prod[i]) + addend + carry;
        prod[i] = acc as u64;
        carry = acc >> 64;
    }

    let mut wide = [0u8; 64];
    for i in 0..8 {
        wide[i * 8..(i + 1) * 8].copy_from_slice(&prod[i].to_le_bytes());
    }
    reduce_64_mod_l(&wide)
}

fn is_canonical_scalar(s: &[u8; 32]) -> bool {
    let sl = bytes_to_u64x4(s);
    for i in (0..4).rev() {
        if sl[i] < L_LIMBS[i] {
            return true;
        }
        if sl[i] > L_LIMBS[i] {
            return false;
        }
    }
    false
}

fn prune_scalar_buffer(buf: &mut [u8; 32]) {
    buf[0] &= 248;
    buf[31] &= 127;
    buf[31] |= 64;
}

// ---------------------------------------------------------------------------
// Public Ed25519 types and operations (RFC 8032 Section 5.1)
// ---------------------------------------------------------------------------

/// Compressed 32-byte RFC 8032 Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    /// Parse a 32-byte compressed Ed25519 public key and validate curve membership.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 32` or [`Error::InvalidEncoding`]
    /// if the bytes do not decode to a valid point on Edwards25519.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let raw = copy_fixed(bytes)?;
        if ExtPoint::decode(&raw).is_none() {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self(raw))
    }

    /// Borrow the raw 32-byte compressed public key.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }
}

/// 64-byte RFC 8032 Ed25519 signature (`R || S`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Parse a 64-byte Ed25519 signature.
    ///
    /// # Errors
    /// Returns [`Error::InvalidLength`] if `bytes.len() != 64`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(copy_fixed(bytes)?))
    }

    /// Borrow the raw 64-byte signature.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

/// RFC 8032 Ed25519 signing keypair derived from a 32-byte secret seed.
#[derive(Clone)]
pub struct KeyPair {
    seed: [u8; SECRET_KEY_LEN],
    scalar: [u8; 32],
    prefix: [u8; 32],
    public: PublicKey,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public", &self.public)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.seed);
        zeroize_bytes(&mut self.scalar);
        zeroize_bytes(&mut self.prefix);
    }
}

impl KeyPair {
    /// Derive an Ed25519 keypair from a 32-byte RFC 8032 seed.
    #[must_use]
    pub fn from_seed(seed: [u8; SECRET_KEY_LEN]) -> Self {
        let h = sha512(&seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&h[0..32]);
        prune_scalar_buffer(&mut scalar);

        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..64]);

        let pub_bytes = BASE_POINT.scalar_mul(&scalar).encode();
        Self {
            seed,
            scalar,
            prefix,
            public: PublicKey(pub_bytes),
        }
    }

    /// Return the corresponding 32-byte compressed public key.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Sign `message` deterministically per RFC 8032 Section 5.1.6.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut h_r = Sha512::new();
        h_r.update(&self.prefix);
        h_r.update(message);
        let r = reduce_64_mod_l(&h_r.finalize());

        let r_enc = BASE_POINT.scalar_mul(&r).encode();

        let mut h_k = Sha512::new();
        h_k.update(&r_enc);
        h_k.update(self.public.as_bytes());
        h_k.update(message);
        let k = reduce_64_mod_l(&h_k.finalize());

        let s = mul_add_mod_l(&k, &self.scalar, &r);
        let mut sig = [0u8; SIGNATURE_LEN];
        sig[0..32].copy_from_slice(&r_enc);
        sig[32..64].copy_from_slice(&s);
        Signature(sig)
    }
}

/// Verify an RFC 8032 Ed25519 signature strictly (`S < L`, canonical point encodings, `[S]B == R + [k]A`).
///
/// # Errors
/// Returns [`Error::Ed25519VerificationFailed`] if any decoding check or the group equation fails.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> Result<(), Error> {
    let sig_bytes = signature.as_bytes();
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[0..32]);
    s_bytes.copy_from_slice(&sig_bytes[32..64]);

    if !is_canonical_scalar(&s_bytes) {
        return Err(Error::Ed25519VerificationFailed);
    }
    let a_pt = ExtPoint::decode(public_key.as_bytes()).ok_or(Error::Ed25519VerificationFailed)?;
    let r_pt = ExtPoint::decode(&r_bytes).ok_or(Error::Ed25519VerificationFailed)?;

    let mut h_k = Sha512::new();
    h_k.update(&r_bytes);
    h_k.update(public_key.as_bytes());
    h_k.update(message);
    let k = reduce_64_mod_l(&h_k.finalize());

    let lhs = BASE_POINT.scalar_mul(&s_bytes);
    let rhs = r_pt.add(a_pt.scalar_mul(&k));
    if lhs.ct_eq_projective(rhs) {
        Ok(())
    } else {
        Err(Error::Ed25519VerificationFailed)
    }
}
