//! NIST FIPS 202 Keccak-f[1600] sponge primitives:
//! `SHA3-256`, `SHA3-512`, `SHAKE128`, and `SHAKE256`.

const SHA3_256_RATE: usize = 136;
const SHA3_512_RATE: usize = 72;
const SHAKE128_RATE: usize = 168;
const SHAKE256_RATE: usize = 136;

const SHA3_DOMAIN: u8 = 0x06;
const SHAKE_DOMAIN: u8 = 0x1F;

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const PI_LANES: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const RHO_ROT: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }

        let mut cur = state[1];
        for i in 0..24 {
            let next_lane = PI_LANES[i];
            let tmp = state[next_lane];
            state[next_lane] = cur.rotate_left(RHO_ROT[i]);
            cur = tmp;
        }

        for row in (0..25).step_by(5) {
            let t = [
                state[row],
                state[row + 1],
                state[row + 2],
                state[row + 3],
                state[row + 4],
            ];
            for x in 0..5 {
                state[row + x] = t[x] ^ ((!t[(x + 1) % 5]) & t[(x + 2) % 5]);
            }
        }

        state[0] ^= rc;
    }
}

#[derive(Clone)]
struct Sponge {
    state: [u64; 25],
    rate: usize,
    pos: usize,
    domain: u8,
    finalized: bool,
}

impl Sponge {
    const fn new(rate: usize, domain: u8) -> Self {
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
            domain,
            finalized: false,
        }
    }

    fn xor_byte(&mut self, idx: usize, byte: u8) {
        let lane = idx / 8;
        let shift = (idx % 8) * 8;
        if let Some(slot) = self.state.get_mut(lane) {
            *slot ^= u64::from(byte) << shift;
        }
    }

    fn read_byte(&self, idx: usize) -> u8 {
        let lane = idx / 8;
        let shift = (idx % 8) * 8;
        self.state
            .get(lane)
            .map_or(0, |&w| ((w >> shift) & 0xFF) as u8)
    }

    fn absorb(&mut self, data: &[u8]) {
        debug_assert!(!self.finalized);
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    fn pad_and_permute(&mut self) {
        if !self.finalized {
            self.xor_byte(self.pos, self.domain);
            self.xor_byte(self.rate - 1, 0x80);
            keccak_f1600(&mut self.state);
            self.pos = 0;
            self.finalized = true;
        }
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        self.pad_and_permute();
        for dst in out.iter_mut() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            *dst = self.read_byte(self.pos);
            self.pos += 1;
        }
    }
}

/// Incremental NIST FIPS 202 `SHA3-256` hasher.
#[derive(Clone)]
pub struct Sha3_256(Sponge);

impl Default for Sha3_256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256 {
    /// Create a new `SHA3-256` state.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sponge::new(SHA3_256_RATE, SHA3_DOMAIN))
    }

    /// Absorb additional input bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    /// Finalize the hash and return the 32-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.squeeze(&mut out);
        out
    }
}

/// Incremental NIST FIPS 202 `SHA3-512` hasher.
#[derive(Clone)]
pub struct Sha3_512(Sponge);

impl Default for Sha3_512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_512 {
    /// Create a new `SHA3-512` state.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sponge::new(SHA3_512_RATE, SHA3_DOMAIN))
    }

    /// Absorb additional input bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    /// Finalize the hash and return the 64-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.0.squeeze(&mut out);
        out
    }
}

/// Incremental NIST FIPS 202 `SHAKE128` extendable-output function (XOF).
#[derive(Clone)]
pub struct Shake128(Sponge);

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake128 {
    /// Create a new `SHAKE128` XOF state.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sponge::new(SHAKE128_RATE, SHAKE_DOMAIN))
    }

    /// Absorb additional input bytes prior to squeezing.
    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    /// Squeeze arbitrary output bytes from the XOF stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }
}

/// Incremental NIST FIPS 202 `SHAKE256` extendable-output function (XOF).
#[derive(Clone)]
pub struct Shake256(Sponge);

impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Shake256 {
    /// Create a new `SHAKE256` XOF state.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sponge::new(SHAKE256_RATE, SHAKE_DOMAIN))
    }

    /// Absorb additional input bytes prior to squeezing.
    pub fn update(&mut self, data: &[u8]) {
        self.0.absorb(data);
    }

    /// Squeeze arbitrary output bytes from the XOF stream.
    pub fn squeeze(&mut self, out: &mut [u8]) {
        self.0.squeeze(out);
    }
}

/// One-shot NIST FIPS 202 `SHA3-256`.
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize()
}

/// One-shot NIST FIPS 202 `SHA3-512`.
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finalize()
}

/// One-shot NIST FIPS 202 `SHAKE128`.
pub fn shake128(data: &[u8], out: &mut [u8]) {
    let mut xof = Shake128::new();
    xof.update(data);
    xof.squeeze(out);
}

/// One-shot NIST FIPS 202 `SHAKE256`.
pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut xof = Shake256::new();
    xof.update(data);
    xof.squeeze(out);
}

/// Absorb multiple byte slices into `SHAKE256` and squeeze a fixed-size output array.
#[must_use]
pub(crate) fn shake256_parts<const OUT: usize>(parts: &[&[u8]]) -> [u8; OUT] {
    let mut xof = Shake256::new();
    for part in parts {
        xof.update(part);
    }
    let mut out = [0u8; OUT];
    xof.squeeze(&mut out);
    out
}
