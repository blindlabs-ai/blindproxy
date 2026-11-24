//! Zero-dependency pure-Rust XDP/eBPF packet filter and Linux
//! 64-bit eBPF ISA bytecode compiler for authenticated UDP shard datagrams.
//!
//! Safety invariant:
//! - All traffic not targeting the configured UDP destination port (SSH `:22/tcp`,
//!   HTTPS `:443/tcp`, DNS `:53/udp`, QUIC `:443/udp`, ARP, ICMP, non-first IPv4
//!   fragments, IPv6 non-UDP, and truncated pre-UDP frames) immediately returns
//!   [`XdpAction::Pass`] with [`XdpStat::RxPassOther`].
//! - All packets targeting `cfg.udp_port` must carry a complete, unfragmented,
//!   well-formed 32-byte [`UdpPacketHdr`] matching `cfg.magic_be`, valid
//!   `(data_slots + parity_slots)` shard slot and flag parity rules, non-zero
//!   `stream_id`, exact payload bounds, and a valid keyed SipHash-2-4 header MAC,
//!   or they are dropped with [`XdpAction::Drop`].

pub mod bpf_emit;

/// Default authenticated UDP destination port (`9000`).
pub const DEFAULT_UDP_PORT: u16 = 9000;

/// Default big-endian 4-byte wire magic `"ZPX1"` (`0x5A505831`).
pub const DEFAULT_MAGIC_BE: u32 = 0x5A50_5831;

/// Default reassembly frame size in bytes (`64 KiB`).
pub const DEFAULT_MAX_FRAME_BYTES: u32 = 65_536;

/// Default number of data shard slots per stripe (`0..=7`).
pub const DEFAULT_DATA_SLOTS: u8 = 8;

/// Default number of parity shard slots per stripe (`8..=9`).
pub const DEFAULT_PARITY_SLOTS: u8 = 2;

/// Default total shard slots per stripe (`10`).
pub const DEFAULT_STRIPE_SLOTS: u8 = DEFAULT_DATA_SLOTS + DEFAULT_PARITY_SLOTS;

/// Flag bit 0: Compressed payload (forbidden on parity shards).
pub const FLAG_COMPRESSED: u8 = 0x01;

/// Flag bit 1: End-to-end encrypted payload.
pub const FLAG_ENCRYPTED: u8 = 0x02;

/// Flag bit 2: Parity shard (`slot >= data_slots` requires it; `slot < data_slots` forbids it).
pub const FLAG_PARITY: u8 = 0x04;

/// Bitmask of valid header flag bits (`0..=2`); bits `3..=7` must be zero.
pub const VALID_FLAGS_MASK: u8 = 0x07;

/// Exact wire size of [`UdpPacketHdr`] in bytes (`32`).
pub const UDP_PACKET_HDR_BYTES: usize = 32;

/// Default maximum MTU-safe slice payload length in bytes (`1440`).
pub const DEFAULT_MAX_PAYLOAD_BYTES: u16 = 1440;

/// Verifier-safe upper bound on UDP datagram length (`16384`).
pub const MAX_UDP_DATAGRAM_BYTES: u16 = 16_384;

/// Default public SipHash-2-4 key word 0 (`"ZPX1XDP1"`).
pub const DEFAULT_MAC_K0: u64 = 0x5A50_5831_5844_5031;

/// Default public SipHash-2-4 key word 1 (`"GF28PQ82"`).
pub const DEFAULT_MAC_K1: u64 = 0x4746_3238_5051_3832;

/// Default 128-bit SipHash-2-4 key used when an all-zero key `[0, 0]` is given.
pub const DEFAULT_MAC_KEY: [u64; 2] = [DEFAULT_MAC_K0, DEFAULT_MAC_K1];

/// Configurable parameters for the authenticated UDP XDP/eBPF packet filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpFilterConfig {
    /// Target UDP destination port inspected by the filter (other ports pass untouched).
    pub udp_port: u16,
    /// Expected big-endian 4-byte protocol magic at header offset `0..4`.
    pub magic_be: u32,
    /// Maximum reassembled frame size in bytes (`frag_offset + payload_len <= max_frame_bytes`).
    pub max_frame_bytes: u32,
    /// Maximum slice payload length in bytes (`1..=max_payload_bytes`).
    pub max_payload_bytes: u16,
    /// Number of data shard slots per stripe (`0..data_slots`).
    pub data_slots: u8,
    /// Number of parity shard slots per stripe (`data_slots..total_slots()`).
    pub parity_slots: u8,
    /// 128-bit SipHash-2-4 header MAC key (`[0, 0]` resolves to [`DEFAULT_MAC_KEY`]).
    pub mac_key: [u64; 2],
}

impl UdpFilterConfig {
    /// Returns the default filter configuration (port `9000`, magic `"ZPX1"`, `8+2` slots).
    #[inline]
    pub const fn default_config() -> Self {
        Self {
            udp_port: DEFAULT_UDP_PORT,
            magic_be: DEFAULT_MAGIC_BE,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            data_slots: DEFAULT_DATA_SLOTS,
            parity_slots: DEFAULT_PARITY_SLOTS,
            mac_key: DEFAULT_MAC_KEY,
        }
    }

    /// Returns the total number of valid shard slots (`data_slots + parity_slots`).
    #[inline]
    pub const fn total_slots(&self) -> u8 {
        self.data_slots.saturating_add(self.parity_slots)
    }

    /// Returns a default configuration using the supplied 128-bit SipHash-2-4 key.
    #[inline]
    pub const fn with_key(mac_key: [u64; 2]) -> Self {
        let mut cfg = Self::default_config();
        cfg.mac_key = mac_key;
        cfg
    }

    /// Returns a configuration with custom UDP destination port, 4-byte magic, and MAC key.
    #[inline]
    pub const fn with_port_and_magic(udp_port: u16, magic_be: u32, mac_key: [u64; 2]) -> Self {
        let mut cfg = Self::default_config();
        cfg.udp_port = udp_port;
        cfg.magic_be = magic_be;
        cfg.mac_key = mac_key;
        cfg
    }
}

impl Default for UdpFilterConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// Ethernet II header length in bytes.
pub const ETH_HDR_BYTES: usize = 14;

/// IEEE 802.1Q / 802.1ad VLAN tag length in bytes.
pub const VLAN_HDR_BYTES: usize = 4;

/// Minimum IPv4 header length in bytes (`ihl == 5`).
pub const IPV4_MIN_HDR_BYTES: usize = 20;

/// Fixed IPv6 base header length in bytes.
pub const IPV6_HDR_BYTES: usize = 40;

/// UDP header length in bytes.
pub const UDP_HDR_BYTES: usize = 8;

/// EtherType for IPv4.
pub const ETH_P_IP: u16 = 0x0800;

/// EtherType for ARP.
pub const ETH_P_ARP: u16 = 0x0806;

/// EtherType for IEEE 802.1Q VLAN tag.
pub const ETH_P_8021Q: u16 = 0x8100;

/// EtherType for IPv6.
pub const ETH_P_IPV6: u16 = 0x86DD;

/// EtherType for IEEE 802.1ad QinQ outer VLAN tag.
pub const ETH_P_8021AD: u16 = 0x88A8;

/// IP protocol number for ICMP.
pub const IPPROTO_ICMP: u8 = 1;

/// IP protocol number for TCP.
pub const IPPROTO_TCP: u8 = 6;

/// IP protocol number for UDP.
pub const IPPROTO_UDP: u8 = 17;

/// IPv4 More Fragments (MF) bit in host-order `frag_off`.
pub const IPV4_MF_FLAG: u16 = 0x2000;

/// IPv4 13-bit fragment offset mask in host-order `frag_off`.
pub const IPV4_FRAG_OFF_MASK: u16 = 0x1FFF;

/// Linux `XDP_ABORTED` return code.
pub const XDP_ABORTED: u32 = 0;

/// Linux `XDP_DROP` return code.
pub const XDP_DROP: u32 = 1;

/// Linux `XDP_PASS` return code.
pub const XDP_PASS: u32 = 2;

/// Linux `XDP_TX` return code.
pub const XDP_TX: u32 = 3;

/// Linux `XDP_REDIRECT` return code.
pub const XDP_REDIRECT: u32 = 4;

/// Kernel XDP action verdict returned by the filter.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpAction {
    /// Drop packet at NIC/XDP layer (`XDP_DROP = 1`).
    Drop = XDP_DROP,
    /// Pass packet up the host network stack (`XDP_PASS = 2`).
    Pass = XDP_PASS,
}

impl XdpAction {
    /// Returns the Linux UAPI integer code (`1` for Drop, `2` for Pass).
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// Per-verdict counter index for XDP filter telemetry.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpStat {
    /// Non-target traffic or pre-UDP frames passed untouched.
    RxPassOther = 0,
    /// Authenticated, well-formed target UDP frame passed.
    RxAuthPass = 1,
    /// Dropped target UDP frame due to truncation or length mismatch.
    RxDropTrunc = 2,
    /// Dropped target UDP frame due to invalid protocol magic.
    RxDropMagic = 3,
    /// Dropped target UDP frame due to shard, flag, MF, or payload bounds.
    RxDropBounds = 4,
    /// Dropped target UDP frame due to SipHash-2-4 header MAC mismatch.
    RxDropMac = 5,
}

impl XdpStat {
    /// Total number of per-CPU statistics slots (`6`).
    pub const COUNT: usize = 6;

    /// Returns the zero-based map index (`0..6`).
    #[inline]
    pub const fn as_index(self) -> usize {
        self as usize
    }

    /// Returns the canonical ASCII counter name.
    #[inline]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RxPassOther => "rx_pass_other",
            Self::RxAuthPass => "rx_auth_pass",
            Self::RxDropTrunc => "rx_drop_trunc",
            Self::RxDropMagic => "rx_drop_magic",
            Self::RxDropBounds => "rx_drop_bounds",
            Self::RxDropMac => "rx_drop_mac",
        }
    }
}

/// Combined XDP action and diagnostic counter bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct XdpVerdict {
    /// Final XDP disposition (`Pass` or `Drop`).
    pub action: XdpAction,
    /// Exact diagnostic counter bucket.
    pub stat: XdpStat,
}

impl XdpVerdict {
    /// Constructs a `Pass` verdict for the given counter bucket.
    #[inline]
    pub const fn pass(stat: XdpStat) -> Self {
        Self {
            action: XdpAction::Pass,
            stat,
        }
    }

    /// Constructs a `Drop` verdict for the given counter bucket.
    #[inline]
    pub const fn drop_with(stat: XdpStat) -> Self {
        Self {
            action: XdpAction::Drop,
            stat,
        }
    }
}

/// Fixed-size counter table (`[u64; 6]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XdpCounters {
    counts: [u64; XdpStat::COUNT],
}

impl XdpCounters {
    /// Creates an all-zero counter table.
    #[inline]
    pub const fn new() -> Self {
        Self {
            counts: [0u64; XdpStat::COUNT],
        }
    }

    /// Increments the counter associated with `verdict.stat` (saturating).
    #[inline]
    pub fn record(&mut self, verdict: XdpVerdict) {
        let idx = verdict.stat.as_index();
        if let Some(slot) = self.counts.get_mut(idx) {
            *slot = slot.saturating_add(1);
        }
    }

    /// Reads the counter value for a specific [`XdpStat`] bucket.
    #[inline]
    pub const fn get(&self, stat: XdpStat) -> u64 {
        let idx = stat.as_index();
        if idx < self.counts.len() {
            self.counts[idx]
        } else {
            0
        }
    }

    /// Returns the total packets observed across all 6 buckets.
    #[inline]
    pub const fn total(&self) -> u64 {
        self.counts[0]
            .saturating_add(self.counts[1])
            .saturating_add(self.counts[2])
            .saturating_add(self.counts[3])
            .saturating_add(self.counts[4])
            .saturating_add(self.counts[5])
    }

    /// Returns `rx_pass_other`.
    #[inline]
    pub const fn rx_pass_other(&self) -> u64 {
        self.get(XdpStat::RxPassOther)
    }

    /// Returns `rx_auth_pass`.
    #[inline]
    pub const fn rx_auth_pass(&self) -> u64 {
        self.get(XdpStat::RxAuthPass)
    }

    /// Returns `rx_drop_trunc`.
    #[inline]
    pub const fn rx_drop_trunc(&self) -> u64 {
        self.get(XdpStat::RxDropTrunc)
    }

    /// Returns `rx_drop_magic`.
    #[inline]
    pub const fn rx_drop_magic(&self) -> u64 {
        self.get(XdpStat::RxDropMagic)
    }

    /// Returns `rx_drop_bounds`.
    #[inline]
    pub const fn rx_drop_bounds(&self) -> u64 {
        self.get(XdpStat::RxDropBounds)
    }

    /// Returns `rx_drop_mac`.
    #[inline]
    pub const fn rx_drop_mac(&self) -> u64 {
        self.get(XdpStat::RxDropMac)
    }
}

/// Exact 32-byte authenticated UDP shard wire header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPacketHdr {
    /// Big-endian 4-byte protocol magic (default `0x5A505831` = `"ZPX1"`).
    pub magic: u32,
    /// Stripe/group identifier.
    pub gid: u32,
    /// Shard slot (`0..data_slots` data, `data_slots..total_slots` parity).
    pub slot: u8,
    /// Header flags (`FLAG_COMPRESSED=1`, `FLAG_ENCRYPTED=2`, `FLAG_PARITY=4`).
    pub flags: u8,
    /// Reserved field (must be `0`).
    pub reserved: u16,
    /// CRC32 of the reassembled frame.
    pub frame_crc32: u32,
    /// Non-zero stream identifier hash.
    pub stream_id: u32,
    /// Byte offset inside the reassembled frame.
    pub frag_offset: u16,
    /// Slice payload length (`1..=max_payload_bytes`).
    pub payload_len: u16,
    /// Big-endian SipHash-2-4 MAC over bytes `[0..24]`.
    pub hdr_mac: u64,
}

impl UdpPacketHdr {
    /// Constructs an unsigned `UdpPacketHdr` with [`DEFAULT_MAGIC_BE`] and `reserved = 0`.
    pub const fn new(
        gid: u32,
        slot: u8,
        flags: u8,
        frame_crc32: u32,
        stream_id: u32,
        frag_offset: u16,
        payload_len: u16,
    ) -> Self {
        Self {
            magic: DEFAULT_MAGIC_BE,
            gid,
            slot,
            flags,
            reserved: 0,
            frame_crc32,
            stream_id,
            frag_offset,
            payload_len,
            hdr_mac: 0,
        }
    }

    /// Overrides the big-endian 4-byte protocol magic before signing.
    pub const fn with_magic(mut self, magic: u32) -> Self {
        self.magic = magic;
        self
    }

    /// Computes and stores the keyed SipHash-2-4 header MAC over bytes `[0..24]`.
    pub const fn sign(mut self, mac_key: [u64; 2]) -> Self {
        let prefix = self.prefix24();
        let [k0, k1] = effective_mac_key(mac_key);
        self.hdr_mac = siphash24_24b(k0, k1, &prefix);
        self
    }

    /// Encodes the authenticated 24-byte header prefix `[0..24]`.
    pub const fn prefix24(&self) -> [u8; 24] {
        let magic = self.magic.to_be_bytes();
        let gid = self.gid.to_be_bytes();
        let res = self.reserved.to_be_bytes();
        let crc = self.frame_crc32.to_be_bytes();
        let sid = self.stream_id.to_be_bytes();
        let foff = self.frag_offset.to_be_bytes();
        let plen = self.payload_len.to_be_bytes();
        [
            magic[0], magic[1], magic[2], magic[3],
            gid[0], gid[1], gid[2], gid[3],
            self.slot, self.flags, res[0], res[1],
            crc[0], crc[1], crc[2], crc[3],
            sid[0], sid[1], sid[2], sid[3],
            foff[0], foff[1], plen[0], plen[1],
        ]
    }

    /// Serializes the full 32-byte wire header in big-endian network order.
    pub const fn to_bytes(&self) -> [u8; UDP_PACKET_HDR_BYTES] {
        let p = self.prefix24();
        let m = self.hdr_mac.to_be_bytes();
        [
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
            p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
            m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7],
        ]
    }

    /// Decodes a 32-byte wire header from the start of `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < UDP_PACKET_HDR_BYTES {
            return None;
        }
        Some(Self {
            magic: u32::from_be_bytes(read_array(bytes, 0)?),
            gid: u32::from_be_bytes(read_array(bytes, 4)?),
            slot: read_u8(bytes, 8)?,
            flags: read_u8(bytes, 9)?,
            reserved: u16::from_be_bytes(read_array(bytes, 10)?),
            frame_crc32: u32::from_be_bytes(read_array(bytes, 12)?),
            stream_id: u32::from_be_bytes(read_array(bytes, 16)?),
            frag_offset: u16::from_be_bytes(read_array(bytes, 20)?),
            payload_len: u16::from_be_bytes(read_array(bytes, 22)?),
            hdr_mac: u64::from_be_bytes(read_array(bytes, 24)?),
        })
    }
}

/// Resolves the effective 128-bit SipHash-2-4 key.
///
/// An all-zero key `[0, 0]` falls back to [`DEFAULT_MAC_KEY`], while any
/// non-zero key is used verbatim.
#[inline]
pub const fn effective_mac_key(mac_key: [u64; 2]) -> [u64; 2] {
    if mac_key[0] == 0 && mac_key[1] == 0 {
        DEFAULT_MAC_KEY
    } else {
        mac_key
    }
}

#[inline]
const fn sipround(mut v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> (u64, u64, u64, u64) {
    v0 = v0.wrapping_add(v1);
    v1 = v1.rotate_left(13);
    v1 ^= v0;
    v0 = v0.rotate_left(32);
    v2 = v2.wrapping_add(v3);
    v3 = v3.rotate_left(16);
    v3 ^= v2;
    v0 = v0.wrapping_add(v3);
    v3 = v3.rotate_left(21);
    v3 ^= v0;
    v2 = v2.wrapping_add(v1);
    v1 = v1.rotate_left(17);
    v1 ^= v2;
    v2 = v2.rotate_left(32);
    (v0, v1, v2, v3)
}

#[inline]
const fn sip_absorb_word(
    mut v0: u64,
    mut v1: u64,
    mut v2: u64,
    mut v3: u64,
    m: u64,
) -> (u64, u64, u64, u64) {
    v3 ^= m;
    (v0, v1, v2, v3) = sipround(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sipround(v0, v1, v2, v3);
    v0 ^= m;
    (v0, v1, v2, v3)
}

#[inline]
const fn sip_finalize(mut v0: u64, mut v1: u64, mut v2: u64, mut v3: u64) -> u64 {
    v2 ^= 0xFF;
    (v0, v1, v2, v3) = sipround(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sipround(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sipround(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sipround(v0, v1, v2, v3);
    v0 ^ v1 ^ v2 ^ v3
}

#[inline]
const fn le64_from_24(hdr24: &[u8; 24], off: usize) -> u64 {
    if off + 8 > hdr24.len() {
        return 0;
    }
    u64::from_le_bytes([
        hdr24[off],
        hdr24[off + 1],
        hdr24[off + 2],
        hdr24[off + 3],
        hdr24[off + 4],
        hdr24[off + 5],
        hdr24[off + 6],
        hdr24[off + 7],
    ])
}

/// Straight-line SipHash-2-4 over the fixed 24-byte `UdpPacketHdr` `[0..24]` prefix.
#[inline]
pub const fn siphash24_24b(k0: u64, k1: u64, hdr24: &[u8; 24]) -> u64 {
    let mut v0 = 0x736f_6d65_7073_6575u64 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6du64 ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261u64 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573u64 ^ k1;

    let m0 = le64_from_24(hdr24, 0);
    let m1 = le64_from_24(hdr24, 8);
    let m2 = le64_from_24(hdr24, 16);
    let b = 24u64 << 56;

    (v0, v1, v2, v3) = sip_absorb_word(v0, v1, v2, v3, m0);
    (v0, v1, v2, v3) = sip_absorb_word(v0, v1, v2, v3, m1);
    (v0, v1, v2, v3) = sip_absorb_word(v0, v1, v2, v3, m2);
    (v0, v1, v2, v3) = sip_absorb_word(v0, v1, v2, v3, b);

    sip_finalize(v0, v1, v2, v3)
}

/// General-length SipHash-2-4 (Aumasson-Bernstein 2012) for KAT verification.
pub fn siphash24(k0: u64, k1: u64, msg: &[u8]) -> u64 {
    let mut v0 = 0x736f_6d65_7073_6575u64 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6du64 ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261u64 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573u64 ^ k1;

    let full_blocks = msg.len() / 8;
    let mut idx = 0usize;
    while idx < full_blocks {
        let off = idx * 8;
        let m = read_array::<8>(msg, off).map_or(0, u64::from_le_bytes);
        (v0, v1, v2, v3) = sip_absorb_word(v0, v1, v2, v3, m);
        idx += 1;
    }

    let rem_start = full_blocks * 8;
    let mut b = ((msg.len() & 0xFF) as u64) << 56;
    let mut rem_idx = 0usize;
    while let Some(byte) = msg.get(rem_start + rem_idx) {
        b |= (*byte as u64) << (rem_idx * 8);
        rem_idx += 1;
    }

    (v0, v1, v2, v3) = sip_absorb_word(v0, v1, v2, v3, b);
    sip_finalize(v0, v1, v2, v3)
}

#[inline]
fn read_u8(buf: &[u8], off: usize) -> Option<u8> {
    buf.get(off).copied()
}

#[inline]
fn read_array<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    let end = off.checked_add(N)?;
    let s = buf.get(off..end)?;
    let mut out = [0u8; N];
    out.copy_from_slice(s);
    Some(out)
}

struct ParsedL4 {
    udp_off: usize,
    l4_avail: u32,
    is_ipv4_mf: bool,
}

#[inline]
fn parse_l2_l3(frame: &[u8]) -> Option<ParsedL4> {
    if frame.len() < ETH_HDR_BYTES {
        return None;
    }

    let mut eth_proto = u16::from_be_bytes(read_array(frame, 12)?);
    let mut cursor = ETH_HDR_BYTES;

    // Unwrap up to 2 stacked 802.1Q / 802.1ad VLAN tags.
    let mut vlan_step = 0u8;
    while vlan_step < 2 {
        if eth_proto == ETH_P_8021Q || eth_proto == ETH_P_8021AD {
            let next_cursor = cursor.checked_add(VLAN_HDR_BYTES)?;
            if next_cursor > frame.len() {
                return None;
            }
            eth_proto = u16::from_be_bytes(read_array(frame, cursor + 2)?);
            cursor = next_cursor;
        }
        vlan_step += 1;
    }

    if eth_proto == ETH_P_IP {
        let ipv4_min_end = cursor.checked_add(IPV4_MIN_HDR_BYTES)?;
        if ipv4_min_end > frame.len() {
            return None;
        }
        let ver_ihl = read_u8(frame, cursor)?;
        let version = ver_ihl >> 4;
        let ihl = ver_ihl & 0x0F;
        if version != 4 || ihl < 5 {
            return None;
        }
        if read_u8(frame, cursor + 9)? != IPPROTO_UDP {
            return None;
        }

        let frag_field = u16::from_be_bytes(read_array(frame, cursor + 6)?);
        if (frag_field & IPV4_FRAG_OFF_MASK) != 0 {
            return None;
        }
        let is_ipv4_mf = (frag_field & IPV4_MF_FLAG) != 0;

        let ihl_bytes = (ihl as usize) * 4;
        let ip_tot_len = u16::from_be_bytes(read_array(frame, cursor + 2)?) as usize;
        if ip_tot_len < ihl_bytes + UDP_HDR_BYTES {
            return None;
        }

        let udp_off = cursor.checked_add(ihl_bytes)?;
        let udp_end = udp_off.checked_add(UDP_HDR_BYTES)?;
        if udp_end > frame.len() {
            return None;
        }

        let l4_avail = (ip_tot_len - ihl_bytes) as u32;
        Some(ParsedL4 {
            udp_off,
            l4_avail,
            is_ipv4_mf,
        })
    } else if eth_proto == ETH_P_IPV6 {
        let ipv6_end = cursor.checked_add(IPV6_HDR_BYTES)?;
        if ipv6_end > frame.len() {
            return None;
        }
        let version = read_u8(frame, cursor)? >> 4;
        if version != 6 {
            return None;
        }
        if read_u8(frame, cursor + 6)? != IPPROTO_UDP {
            return None;
        }

        let udp_off = ipv6_end;
        let udp_end = udp_off.checked_add(UDP_HDR_BYTES)?;
        if udp_end > frame.len() {
            return None;
        }

        let l4_avail = u16::from_be_bytes(read_array(frame, cursor + 4)?) as u32;
        Some(ParsedL4 {
            udp_off,
            l4_avail,
            is_ipv4_mf: false,
        })
    } else {
        None
    }
}

/// Evaluates an Ethernet frame against the configured UDP XDP filter.
///
/// Exact wire parity with [`bpf_emit::emit_xdp_program`]:
/// - Non-target traffic always returns `XdpVerdict::pass(XdpStat::RxPassOther)`.
/// - Malformed or unauthenticated packets targeting `cfg.udp_port` return
///   `XdpAction::Drop` with the exact failure category (`RxDropTrunc`,
///   `RxDropMagic`, `RxDropBounds`, or `RxDropMac`).
/// - Valid authenticated packets targeting `cfg.udp_port` return
///   `XdpVerdict::pass(XdpStat::RxAuthPass)`.
pub fn filter_packet(frame: &[u8], cfg: &UdpFilterConfig) -> XdpVerdict {
    let pass_other = XdpVerdict::pass(XdpStat::RxPassOther);

    let l4 = match parse_l2_l3(frame) {
        Some(parsed) => parsed,
        None => return pass_other,
    };

    let udp_dport = match read_array::<2>(frame, l4.udp_off + 2) {
        Some(b) => u16::from_be_bytes(b),
        None => return pass_other,
    };
    if udp_dport != cfg.udp_port {
        return pass_other;
    }

    // 1. Minimum length & wire truncation checks.
    let drop_trunc = XdpVerdict::drop_with(XdpStat::RxDropTrunc);
    let udp_len = match read_array::<2>(frame, l4.udp_off + 4) {
        Some(b) => u16::from_be_bytes(b) as u32,
        None => return drop_trunc,
    };
    let min_udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES) as u32;
    if udp_len < min_udp_len || udp_len > l4.l4_avail {
        return drop_trunc;
    }

    let hdr_off = match l4.udp_off.checked_add(UDP_HDR_BYTES) {
        Some(off) => off,
        None => return drop_trunc,
    };
    let hdr_end = match hdr_off.checked_add(UDP_PACKET_HDR_BYTES) {
        Some(end) => end,
        None => return drop_trunc,
    };
    if hdr_end > frame.len() {
        return drop_trunc;
    }
    if udp_len > MAX_UDP_DATAGRAM_BYTES as u32 {
        return drop_trunc;
    }
    let udp_frame_end = match l4.udp_off.checked_add(udp_len as usize) {
        Some(end) => end,
        None => return drop_trunc,
    };
    if udp_frame_end > frame.len() {
        return drop_trunc;
    }

    // 2. Exact protocol magic check.
    let drop_magic = XdpVerdict::drop_with(XdpStat::RxDropMagic);
    let magic = match read_array::<4>(frame, hdr_off) {
        Some(b) => u32::from_be_bytes(b),
        None => return drop_magic,
    };
    if magic != cfg.magic_be {
        return drop_magic;
    }

    // 3. Strict shard, flag, reserved, stream_id, and payload bounds checks.
    let drop_bounds = XdpVerdict::drop_with(XdpStat::RxDropBounds);
    if l4.is_ipv4_mf {
        return drop_bounds;
    }

    let hdr = match UdpPacketHdr::from_bytes(&frame[hdr_off..hdr_end]) {
        Some(h) => h,
        None => return drop_bounds,
    };
    if hdr.slot >= cfg.total_slots() {
        return drop_bounds;
    }
    if (hdr.flags & !VALID_FLAGS_MASK) != 0 {
        return drop_bounds;
    }
    if hdr.slot < cfg.data_slots && (hdr.flags & FLAG_PARITY) != 0 {
        return drop_bounds;
    }
    if hdr.slot >= cfg.data_slots
        && ((hdr.flags & FLAG_PARITY) == 0 || (hdr.flags & FLAG_COMPRESSED) != 0)
    {
        return drop_bounds;
    }
    if hdr.reserved != 0 || hdr.stream_id == 0 {
        return drop_bounds;
    }

    let expected_udp_payload = udp_len - min_udp_len;
    if hdr.payload_len == 0 || hdr.payload_len > cfg.max_payload_bytes {
        return drop_bounds;
    }
    if (hdr.payload_len as u32) != expected_udp_payload {
        return drop_bounds;
    }
    if (hdr.frag_offset as u32) + (hdr.payload_len as u32) > cfg.max_frame_bytes {
        return drop_bounds;
    }

    // 4. Keyed SipHash-2-4 header MAC pre-check over bytes [0..24].
    let drop_mac = XdpVerdict::drop_with(XdpStat::RxDropMac);
    let prefix24 = match read_array::<24>(frame, hdr_off) {
        Some(p) => p,
        None => return drop_mac,
    };
    let [k0, k1] = effective_mac_key(cfg.mac_key);
    let expected_mac = siphash24_24b(k0, k1, &prefix24);
    if hdr.hdr_mac != expected_mac {
        return drop_mac;
    }

    XdpVerdict::pass(XdpStat::RxAuthPass)
}

/// Evaluates `frame` with [`filter_packet`] and updates `counters`.
#[inline]
pub fn filter_packet_with_counters(
    frame: &[u8],
    cfg: &UdpFilterConfig,
    counters: &mut XdpCounters,
) -> XdpVerdict {
    let verdict = filter_packet(frame, cfg);
    counters.record(verdict);
    verdict
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestFrameSpec<'a> {
        ipv6: bool,
        vlans: &'a [(u16, u16)],
        ip_options: &'a [u8],
        slot: u8,
        flags: u8,
        frag_offset: u16,
        payload_len: u16,
        cfg: UdpFilterConfig,
    }

    fn build_test_frame(spec: TestFrameSpec<'_>) -> Vec<u8> {
        let (frame_seq, stream_id) = if spec.ipv6 {
            (9, 0xCAFE_BABE)
        } else {
            (7, 0xDEAD_BEEF)
        };
        let hdr = UdpPacketHdr::new(
            frame_seq,
            spec.slot,
            spec.flags,
            stream_id,
            0x5A50_11FE,
            spec.frag_offset,
            spec.payload_len,
        )
        .with_magic(spec.cfg.magic_be)
        .sign(spec.cfg.mac_key);
        let udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + spec.payload_len as usize) as u16;

        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x02, 0x42, 0x00, 0x00, 0x00, 0x01]);
        frame.extend_from_slice(&[0x02, 0x42, 0x00, 0x00, 0x00, 0x02]);
        for &(tpid, tci) in spec.vlans {
            frame.extend_from_slice(&tpid.to_be_bytes());
            frame.extend_from_slice(&tci.to_be_bytes());
        }
        if spec.ipv6 {
            frame.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
            frame.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
            frame.extend_from_slice(&udp_len.to_be_bytes());
            frame.push(IPPROTO_UDP);
            frame.push(64);
            frame.extend_from_slice(&[0u8; 32]);
        } else {
            let ihl_bytes = IPV4_MIN_HDR_BYTES + spec.ip_options.len();
            let ip_tot_len = (ihl_bytes + udp_len as usize) as u16;
            frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
            frame.push(0x40 | ((ihl_bytes / 4) as u8));
            frame.push(0);
            frame.extend_from_slice(&ip_tot_len.to_be_bytes());
            frame.extend_from_slice(&0x1234u16.to_be_bytes());
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.push(64);
            frame.push(IPPROTO_UDP);
            frame.extend_from_slice(&0u16.to_be_bytes());
            frame.extend_from_slice(&[10, 0, 0, 2, 10, 0, 0, 1]);
            frame.extend_from_slice(spec.ip_options);
        }

        frame.extend_from_slice(&49000u16.to_be_bytes());
        frame.extend_from_slice(&spec.cfg.udp_port.to_be_bytes());
        frame.extend_from_slice(&udp_len.to_be_bytes());
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&hdr.to_bytes());
        for i in 0..spec.payload_len {
            frame.push((i & 0xFF) as u8);
        }
        frame
    }

    #[test]
    fn siphash24_aumasson_bernstein_kat() {
        // Official SipHash-2-4 test vectors (k = 00 01 .. 0f, msg = 00 01 .. len-1).
        let k0 = u64::from_le_bytes([0, 1, 2, 3, 4, 5, 6, 7]);
        let k1 = u64::from_le_bytes([8, 9, 10, 11, 12, 13, 14, 15]);
        let msg15: [u8; 15] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let expected_len0 = u64::from_le_bytes([0x31, 0x0e, 0x0e, 0xdd, 0x47, 0xdb, 0x6f, 0x72]);
        let expected_len15 = u64::from_le_bytes([0xe5, 0x45, 0xbe, 0x49, 0x61, 0xca, 0x29, 0xa1]);
        assert_eq!(siphash24(k0, k1, &[]), expected_len0);
        assert_eq!(siphash24(k0, k1, &msg15), expected_len15);

        let mut msg24 = [0u8; 24];
        for (i, b) in msg24.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(siphash24_24b(k0, k1, &msg24), siphash24(k0, k1, &msg24));
    }

    #[test]
    fn valid_ipv4_ipv6_vlan_and_options_pass() {
        let mut counters = XdpCounters::new();
        let default_cfg = UdpFilterConfig::default();
        let zero_key_cfg = UdpFilterConfig::with_key([0, 0]);
        let f_v4 = build_test_frame(TestFrameSpec {
            ipv6: false,
            vlans: &[],
            ip_options: &[],
            slot: 0,
            flags: FLAG_COMPRESSED,
            frag_offset: 0,
            payload_len: 1024,
            cfg: zero_key_cfg,
        });
        let v4 = filter_packet_with_counters(&f_v4, &default_cfg, &mut counters);
        assert_eq!(v4, XdpVerdict::pass(XdpStat::RxAuthPass));

        let custom_cfg = UdpFilterConfig::with_key([0x1122_3344_5566_7788, 0x99AA_BBCC_DDEE_FF01]);
        let f_qinq = build_test_frame(TestFrameSpec {
            ipv6: false,
            vlans: &[(ETH_P_8021AD, 100), (ETH_P_8021Q, 200)],
            ip_options: &[1u8; 16],
            slot: 8,
            flags: FLAG_PARITY | FLAG_ENCRYPTED,
            frag_offset: (DEFAULT_MAX_FRAME_BYTES - DEFAULT_MAX_PAYLOAD_BYTES as u32) as u16,
            payload_len: 1440,
            cfg: custom_cfg,
        });
        let v_qinq = filter_packet_with_counters(&f_qinq, &custom_cfg, &mut counters);
        assert_eq!(v_qinq, XdpVerdict::pass(XdpStat::RxAuthPass));

        let f_v6 = build_test_frame(TestFrameSpec {
            ipv6: true,
            vlans: &[(ETH_P_8021Q, 42)],
            ip_options: &[],
            slot: 9,
            flags: FLAG_PARITY,
            frag_offset: 0,
            payload_len: 64,
            cfg: default_cfg,
        });
        let v6 = filter_packet_with_counters(&f_v6, &zero_key_cfg, &mut counters);
        assert_eq!(v6, XdpVerdict::pass(XdpStat::RxAuthPass));
        assert_eq!(counters.rx_auth_pass(), 3);
        assert_eq!(counters.total(), 3);
    }

    #[test]
    fn counterfactual_knockout_single_bit_mac_flip_and_bad_shard() {
        let cfg = UdpFilterConfig::default();
        let valid = build_test_frame(TestFrameSpec {
            ipv6: false,
            vlans: &[],
            ip_options: &[],
            slot: 3,
            flags: FLAG_ENCRYPTED,
            frag_offset: 512,
            payload_len: 128,
            cfg,
        });
        let pass_verdict = filter_packet(&valid, &cfg);
        assert_eq!(pass_verdict, XdpVerdict::pass(XdpStat::RxAuthPass));

        let mut flipped = valid.clone();
        let mac_byte_idx = ETH_HDR_BYTES + IPV4_MIN_HDR_BYTES + UDP_HDR_BYTES + 31;
        flipped[mac_byte_idx] ^= 0x01;
        let drop_verdict = filter_packet(&flipped, &cfg);
        assert_eq!(drop_verdict, XdpVerdict::drop_with(XdpStat::RxDropMac));
        assert_ne!(pass_verdict.action, drop_verdict.action);

        let mut bad_shard = valid;
        let slot_idx = ETH_HDR_BYTES + IPV4_MIN_HDR_BYTES + UDP_HDR_BYTES + 8;
        bad_shard[slot_idx] = DEFAULT_STRIPE_SLOTS;
        let shard_verdict = filter_packet(&bad_shard, &cfg);
        assert_eq!(shard_verdict, XdpVerdict::drop_with(XdpStat::RxDropBounds));
        assert_ne!(pass_verdict.action, shard_verdict.action);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    fn write_be16(buf: &mut [u8], off: usize, val: u16) {
        let b = val.to_be_bytes();
        buf[off] = b[0];
        buf[off + 1] = b[1];
    }

    fn write_be32(buf: &mut [u8], off: usize, val: u32) {
        let b = val.to_be_bytes();
        buf[off] = b[0];
        buf[off + 1] = b[1];
        buf[off + 2] = b[2];
        buf[off + 3] = b[3];
    }

    fn write_be64(buf: &mut [u8], off: usize, val: u64) {
        let b = val.to_be_bytes();
        let mut i = 0usize;
        while i < 8 {
            buf[off + i] = b[i];
            i += 1;
        }
    }

    #[kani::proof]
    fn proof_no_panic_any_slice() {
        let buf: [u8; 128] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let mac_key: [u64; 2] = kani::any();
        let cfg = UdpFilterConfig::with_key(mac_key);

        let verdict = filter_packet(&buf[..len], &cfg);
        assert!(verdict.action == XdpAction::Pass || verdict.action == XdpAction::Drop);
    }

    #[kani::proof]
    fn proof_other_port_always_pass() {
        let mut buf: [u8; 128] = kani::any();
        let mac_key: [u64; 2] = kani::any();
        let cfg = UdpFilterConfig::with_key(mac_key);

        let vlan_count: u8 = kani::any();
        kani::assume(vlan_count <= 2);

        let mut cursor = ETH_HDR_BYTES;
        if vlan_count >= 1 {
            let tpid0: u16 = if kani::any() { ETH_P_8021Q } else { ETH_P_8021AD };
            write_be16(&mut buf, 12, tpid0);
            cursor += VLAN_HDR_BYTES;
        }
        if vlan_count == 2 {
            let tpid1: u16 = if kani::any() { ETH_P_8021Q } else { ETH_P_8021AD };
            write_be16(&mut buf, ETH_HDR_BYTES + 2, tpid1);
            cursor += VLAN_HDR_BYTES;
        }

        let eth_proto_off = cursor - 2;
        let case_kind: u8 = kani::any();
        kani::assume(case_kind < 4);

        let frame_len: usize;
        if case_kind == 0 {
            // Non-IP EtherType (ARP, LLDP, 3rd VLAN, etc.).
            let et: u16 = kani::any();
            kani::assume(
                et != ETH_P_IP && et != ETH_P_IPV6 && et != ETH_P_8021Q && et != ETH_P_8021AD,
            );
            write_be16(&mut buf, eth_proto_off, et);
            frame_len = kani::any();
            kani::assume(frame_len <= buf.len());
        } else if case_kind == 1 {
            // IPv4 with variable IHL (5..=15): either non-UDP, non-first frag, or UDP dport != target.
            write_be16(&mut buf, eth_proto_off, ETH_P_IP);
            let ihl: u8 = kani::any();
            kani::assume((5..=15).contains(&ihl));
            let ihl_bytes = (ihl as usize) * 4;
            let udp_off = cursor + ihl_bytes;
            let proto: u8 = kani::any();
            let frag_field: u16 = kani::any();
            let dport: u16 = kani::any();
            kani::assume(
                proto != IPPROTO_UDP
                    || (frag_field & IPV4_FRAG_OFF_MASK) != 0
                    || dport != cfg.udp_port,
            );
            buf[cursor] = 0x40 | ihl;
            let tot_len = (ihl_bytes + UDP_HDR_BYTES + 32) as u16;
            write_be16(&mut buf, cursor + 2, tot_len);
            write_be16(&mut buf, cursor + 6, frag_field);
            buf[cursor + 9] = proto;
            write_be16(&mut buf, udp_off + 2, dport);
            frame_len = kani::any();
            kani::assume(frame_len <= buf.len());
        } else if case_kind == 2 {
            // IPv6: either non-UDP nexthdr or UDP dport != target.
            write_be16(&mut buf, eth_proto_off, ETH_P_IPV6);
            let nexthdr: u8 = kani::any();
            let dport: u16 = kani::any();
            kani::assume(nexthdr != IPPROTO_UDP || dport != cfg.udp_port);
            buf[cursor] = 0x60;
            write_be16(&mut buf, cursor + 4, (UDP_HDR_BYTES + 32) as u16);
            buf[cursor + 6] = nexthdr;
            let udp_off = cursor + IPV6_HDR_BYTES;
            write_be16(&mut buf, udp_off + 2, dport);
            frame_len = kani::any();
            kani::assume(frame_len <= buf.len());
        } else {
            // Truncated pre-UDP frame (smaller than Eth header).
            frame_len = kani::any();
            kani::assume(frame_len < ETH_HDR_BYTES);
        }

        let verdict = filter_packet(&buf[..frame_len], &cfg);
        assert_eq!(verdict.action, XdpAction::Pass);
        assert_eq!(verdict.stat, XdpStat::RxPassOther);
    }

    #[kani::proof]
    fn proof_bad_shard_always_drop() {
        let mut buf = [0u8; 128];
        let mac_key: [u64; 2] = kani::any();
        let cfg = UdpFilterConfig::with_key(mac_key);
        let is_ipv6: bool = kani::any();
        let vlan_count: u8 = kani::any();
        kani::assume(vlan_count <= 2);

        let mut cursor = ETH_HDR_BYTES;
        if vlan_count >= 1 {
            write_be16(&mut buf, 12, ETH_P_8021Q);
            cursor += VLAN_HDR_BYTES;
        }
        if vlan_count == 2 {
            write_be16(&mut buf, ETH_HDR_BYTES + 2, ETH_P_8021AD);
            cursor += VLAN_HDR_BYTES;
        }

        let payload_len: u16 = 4;
        let udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + payload_len as usize) as u16;
        let udp_off: usize;
        if is_ipv6 {
            write_be16(&mut buf, cursor - 2, ETH_P_IPV6);
            buf[cursor] = 0x60;
            write_be16(&mut buf, cursor + 4, udp_len);
            buf[cursor + 6] = IPPROTO_UDP;
            udp_off = cursor + IPV6_HDR_BYTES;
        } else {
            write_be16(&mut buf, cursor - 2, ETH_P_IP);
            let ihl: u8 = kani::any();
            kani::assume((5..=15).contains(&ihl));
            let ihl_bytes = (ihl as usize) * 4;
            buf[cursor] = 0x40 | ihl;
            write_be16(&mut buf, cursor + 2, (ihl_bytes + udp_len as usize) as u16);
            write_be16(&mut buf, cursor + 6, 0);
            buf[cursor + 9] = IPPROTO_UDP;
            udp_off = cursor + ihl_bytes;
        }

        write_be16(&mut buf, udp_off, 49000);
        write_be16(&mut buf, udp_off + 2, cfg.udp_port);
        write_be16(&mut buf, udp_off + 4, udp_len);

        let hdr_off = udp_off + UDP_HDR_BYTES;
        let bad_slot: u8 = kani::any();
        kani::assume(bad_slot >= cfg.total_slots());

        write_be32(&mut buf, hdr_off, cfg.magic_be);
        write_be32(&mut buf, hdr_off + 4, kani::any());
        buf[hdr_off + 8] = bad_slot;
        buf[hdr_off + 9] = kani::any();
        write_be16(&mut buf, hdr_off + 10, kani::any());
        write_be32(&mut buf, hdr_off + 12, kani::any());
        write_be32(&mut buf, hdr_off + 16, kani::any());
        write_be16(&mut buf, hdr_off + 20, kani::any());
        write_be16(&mut buf, hdr_off + 22, payload_len);
        write_be64(&mut buf, hdr_off + 24, kani::any());

        let frame_len = udp_off + udp_len as usize;
        let verdict = filter_packet(&buf[..frame_len], &cfg);
        assert_eq!(verdict.action, XdpAction::Drop);
        assert_eq!(verdict.stat, XdpStat::RxDropBounds);
    }

    #[kani::proof]
    fn proof_frag_overflow_always_drop() {
        let mut buf = [0u8; 128];
        let mac_key: [u64; 2] = kani::any();
        let cfg = UdpFilterConfig::with_key(mac_key);
        let payload_len: u16 = kani::any();
        kani::assume((1..=16).contains(&payload_len));
        let frag_offset: u16 = kani::any();
        kani::assume((frag_offset as u32) + (payload_len as u32) > cfg.max_frame_bytes);

        let udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + payload_len as usize) as u16;
        write_be16(&mut buf, 12, ETH_P_IP);
        buf[14] = 0x45;
        write_be16(&mut buf, 16, (IPV4_MIN_HDR_BYTES + udp_len as usize) as u16);
        buf[23] = IPPROTO_UDP;

        let udp_off = ETH_HDR_BYTES + IPV4_MIN_HDR_BYTES;
        write_be16(&mut buf, udp_off + 2, cfg.udp_port);
        write_be16(&mut buf, udp_off + 4, udp_len);

        let hdr_off = udp_off + UDP_HDR_BYTES;
        write_be32(&mut buf, hdr_off, cfg.magic_be);
        buf[hdr_off + 8] = 0;
        buf[hdr_off + 9] = FLAG_COMPRESSED;
        write_be16(&mut buf, hdr_off + 10, 0);
        write_be32(&mut buf, hdr_off + 16, 1);
        write_be16(&mut buf, hdr_off + 20, frag_offset);
        write_be16(&mut buf, hdr_off + 22, payload_len);
        write_be64(&mut buf, hdr_off + 24, kani::any());

        let frame_len = udp_off + udp_len as usize;
        let verdict = filter_packet(&buf[..frame_len], &cfg);
        assert_eq!(verdict.action, XdpAction::Drop);
        assert_eq!(verdict.stat, XdpStat::RxDropBounds);
    }
}
