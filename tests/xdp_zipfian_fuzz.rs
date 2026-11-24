use zero_proxy::xdp::bpf_emit::{emit_xdp_program, execute_bpf_program, verify_bpf_program};
use zero_proxy::xdp::{
    filter_packet, filter_packet_with_counters, UdpFilterConfig, UdpPacketHdr, XdpAction,
    XdpCounters, XdpStat, DEFAULT_MAC_KEY, DEFAULT_MAGIC_BE, DEFAULT_MAX_FRAME_BYTES,
    DEFAULT_MAX_PAYLOAD_BYTES, DEFAULT_STRIPE_SLOTS, DEFAULT_UDP_PORT, FLAG_COMPRESSED,
    FLAG_ENCRYPTED, FLAG_PARITY, UDP_PACKET_HDR_BYTES,
    ETH_HDR_BYTES, ETH_P_8021AD, ETH_P_8021Q, ETH_P_ARP, ETH_P_IP, ETH_P_IPV6, IPPROTO_ICMP,
    IPPROTO_TCP, IPPROTO_UDP, IPV4_MF_FLAG, IPV4_MIN_HDR_BYTES, IPV6_HDR_BYTES, UDP_HDR_BYTES,
    XDP_DROP, XDP_PASS,
};

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }

    fn next_f64_unit(&mut self) -> f64 {
        let bits = self.next_u64() >> 11;
        (bits as f64) / ((1u64 << 53) as f64)
    }
}

struct ZipfSampler {
    cdf: Vec<f64>,
}

impl ZipfSampler {
    fn new(n: usize, s: f64) -> Self {
        let mut cdf = Vec::with_capacity(n);
        let mut sum = 0.0f64;
        for rank in 1..=n {
            sum += (rank as f64).powf(-s);
            cdf.push(sum);
        }
        for entry in &mut cdf {
            *entry /= sum;
        }
        Self { cdf }
    }

    fn sample(&self, rng: &mut SplitMix64) -> usize {
        let u = rng.next_f64_unit();
        for (idx, &threshold) in self.cdf.iter().enumerate() {
            if u <= threshold {
                return idx;
            }
        }
        self.cdf.len() - 1
    }
}

struct FrameSpec<'a> {
    vlans: &'a [(u16, u16)],
    ipv6: bool,
    ip_options_len: usize,
    ip_version_override: Option<u8>,
    ihl_override: Option<u8>,
    proto_override: Option<u8>,
    frag_field: u16,
    ip_tot_len_override: Option<u16>,
    udp_dport: u16,
    udp_len_override: Option<u16>,
    hdr: UdpPacketHdr,
    body_len: usize,
}

fn build_frame(spec: &FrameSpec<'_>, rng: &mut SplitMix64) -> Vec<u8> {
    let mut frame = Vec::with_capacity(256 + spec.body_len);
    frame.extend_from_slice(&[0x02, 0x42, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x42, 0x00, 0x00, 0x00, 0x02]);
    for &(tpid, tci) in spec.vlans {
        frame.extend_from_slice(&tpid.to_be_bytes());
        frame.extend_from_slice(&tci.to_be_bytes());
    }

    let natural_udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + spec.body_len) as u16;
    let udp_len = spec.udp_len_override.unwrap_or(natural_udp_len);
    let proto = spec.proto_override.unwrap_or(IPPROTO_UDP);

    if spec.ipv6 {
        frame.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
        let ver = spec.ip_version_override.unwrap_or(6);
        frame.push((ver & 0x0F) << 4);
        frame.extend_from_slice(&[0, 0, 0]);
        let ip6_plen = spec.ip_tot_len_override.unwrap_or(natural_udp_len);
        frame.extend_from_slice(&ip6_plen.to_be_bytes());
        frame.push(proto);
        frame.push(64);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        frame.extend_from_slice(&[0u8; 11]);
        frame.push(2);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        frame.extend_from_slice(&[0u8; 11]);
        frame.push(1);
    } else {
        frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
        let ver = spec.ip_version_override.unwrap_or(4);
        let opts_len = (spec.ip_options_len / 4) * 4;
        let ihl = spec.ihl_override.unwrap_or((5 + opts_len / 4) as u8);
        frame.push(((ver & 0x0F) << 4) | (ihl & 0x0F));
        frame.push(0);
        let natural_tot = (IPV4_MIN_HDR_BYTES + opts_len + natural_udp_len as usize) as u16;
        let tot_len = spec.ip_tot_len_override.unwrap_or(natural_tot);
        frame.extend_from_slice(&tot_len.to_be_bytes());
        frame.extend_from_slice(&0x1234u16.to_be_bytes());
        frame.extend_from_slice(&spec.frag_field.to_be_bytes());
        frame.push(64);
        frame.push(proto);
        frame.extend_from_slice(&0u16.to_be_bytes());
        frame.extend_from_slice(&[10, 0, 0, 2]);
        frame.extend_from_slice(&[10, 0, 0, 1]);
        frame.resize(frame.len() + opts_len, 1);
    }

    frame.extend_from_slice(&49000u16.to_be_bytes());
    frame.extend_from_slice(&spec.udp_dport.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&spec.hdr.to_bytes());
    let seed = rng.next_u64();
    for i in 0..spec.body_len {
        frame.push(((seed.wrapping_add(i as u64)) & 0xFF) as u8);
    }
    frame
}

fn random_vlans(rng: &mut SplitMix64, max_tags: usize) -> Vec<(u16, u16)> {
    let count = rng.next_usize(max_tags + 1);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let tpid = if (rng.next_u64() & 1) == 0 {
            ETH_P_8021Q
        } else {
            ETH_P_8021AD
        };
        let tci = (rng.next_u64() & 0x0FFF) as u16;
        out.push((tpid, tci));
    }
    out
}

fn valid_hdr_for_slot(rng: &mut SplitMix64, key: [u64; 2], payload_len: u16) -> UdpPacketHdr {
    let slot = rng.next_usize(DEFAULT_STRIPE_SLOTS as usize) as u8;
    let flags = if slot < 8 {
        match rng.next_usize(4) {
            0 => 0,
            1 => FLAG_COMPRESSED,
            2 => FLAG_ENCRYPTED,
            _ => FLAG_COMPRESSED | FLAG_ENCRYPTED,
        }
    } else if (rng.next_u64() & 1) == 0 {
        FLAG_PARITY
    } else {
        FLAG_PARITY | FLAG_ENCRYPTED
    };
    let max_foff = (DEFAULT_MAX_FRAME_BYTES as usize) - (payload_len as usize);
    let frag_offset = rng.next_usize(max_foff + 1) as u16;
    let stream_id = ((rng.next_u64() as u32) | 1).max(1);
    UdpPacketHdr::new(
        rng.next_u64() as u32,
        slot,
        flags,
        rng.next_u64() as u32,
        stream_id,
        frag_offset,
        payload_len,
    )
    .sign(key)
}

fn generate_zipf_case(
    class: usize,
    rng: &mut SplitMix64,
    key: [u64; 2],
) -> (Vec<u8>, Option<XdpAction>, Option<XdpStat>) {
    let vlans = random_vlans(rng, 2);
    let ipv6 = (rng.next_u64() & 1) == 1;
    let opts_len = if ipv6 { 0 } else { rng.next_usize(11) * 4 };
    let body_len = 1 + rng.next_usize(128);
    let hdr = valid_hdr_for_slot(rng, key, body_len as u16);

    let mut spec = FrameSpec {
        vlans: &vlans,
        ipv6,
        ip_options_len: opts_len,
        ip_version_override: None,
        ihl_override: None,
        proto_override: None,
        frag_field: 0,
        ip_tot_len_override: None,
        udp_dport: DEFAULT_UDP_PORT,
        udp_len_override: None,
        hdr,
        body_len,
    };

    match class {
        0 => {
            // Valid IPv4 authenticated UDP packet.
            spec.ipv6 = false;
            spec.ip_options_len = rng.next_usize(11) * 4;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Pass),
                Some(XdpStat::RxAuthPass),
            )
        }
        1 => {
            // Valid IPv6 authenticated UDP packet.
            spec.ipv6 = true;
            spec.ip_options_len = 0;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Pass),
                Some(XdpStat::RxAuthPass),
            )
        }
        2 => {
            // Single-bit MAC flip across bits 0..63.
            let bit = rng.next_usize(64);
            spec.hdr.hdr_mac ^= 1u64 << bit;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropMac),
            )
        }
        3 => {
            // Truncation inside packet header or payload after UDP header.
            let mut pkt = build_frame(&spec, rng);
            let l3_len = if spec.ipv6 {
                IPV6_HDR_BYTES
            } else {
                IPV4_MIN_HDR_BYTES + spec.ip_options_len
            };
            let min_keep = ETH_HDR_BYTES + spec.vlans.len() * 4 + l3_len + UDP_HDR_BYTES;
            let cut = min_keep + rng.next_usize(pkt.len() - min_keep);
            pkt.truncate(cut);
            (pkt, Some(XdpAction::Drop), Some(XdpStat::RxDropTrunc))
        }
        4 => {
            // Bad shard slot >= 10.
            let bad_slot = DEFAULT_STRIPE_SLOTS + (rng.next_usize(246) as u8);
            spec.hdr.slot = bad_slot;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        5 => {
            // Fragment offset + payload_len overflow (> 65536).
            // Since u16::MAX + 1 == 65536 fits, overflow requires payload_len >= 2.
            let plen = (2 + rng.next_usize(DEFAULT_MAX_PAYLOAD_BYTES as usize - 1)) as u16;
            let min_overflow_off = (DEFAULT_MAX_FRAME_BYTES as usize - plen as usize + 1) as u16;
            let span = (u16::MAX - min_overflow_off) as usize + 1;
            let foff = min_overflow_off.wrapping_add(rng.next_usize(span) as u16);
            spec.hdr = UdpPacketHdr::new(
                11,
                0,
                FLAG_COMPRESSED,
                0xABCD_1234,
                0x1111_2222,
                foff,
                plen,
            )
            .sign(key);
            spec.body_len = plen as usize;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        6 => {
            // Non-target UDP passthrough (DNS :53, QUIC :443, random ports).
            let mut port = (rng.next_u64() & 0xFFFF) as u16;
            if port == DEFAULT_UDP_PORT {
                port = 443;
            }
            spec.udp_dport = port;
            spec.hdr.magic = 0x0000_0000;
            spec.hdr.slot = 255;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Pass),
                Some(XdpStat::RxPassOther),
            )
        }
        7 => {
            // Non-UDP traffic (SSH TCP, ICMP, ARP, or triple VLAN).
            match rng.next_usize(4) {
                0 => {
                    spec.proto_override = Some(IPPROTO_TCP);
                    spec.udp_dport = 22;
                    (
                        build_frame(&spec, rng),
                        Some(XdpAction::Pass),
                        Some(XdpStat::RxPassOther),
                    )
                }
                1 => {
                    spec.proto_override = Some(IPPROTO_ICMP);
                    (
                        build_frame(&spec, rng),
                        Some(XdpAction::Pass),
                        Some(XdpStat::RxPassOther),
                    )
                }
                2 => {
                    let mut arp = vec![0u8; 42];
                    arp[12..14].copy_from_slice(&ETH_P_ARP.to_be_bytes());
                    (arp, Some(XdpAction::Pass), Some(XdpStat::RxPassOther))
                }
                _ => {
                    let triple = [
                        (ETH_P_8021AD, 10),
                        (ETH_P_8021Q, 20),
                        (ETH_P_8021Q, 30),
                    ];
                    spec.vlans = &triple;
                    (
                        build_frame(&spec, rng),
                        Some(XdpAction::Pass),
                        Some(XdpStat::RxPassOther),
                    )
                }
            }
        }
        8 => {
            // Wrong SipHash-2-4 key.
            let wrong_key = [key[0] ^ 0x1, key[1] ^ 0x8000_0000_0000_0000];
            spec.hdr = valid_hdr_for_slot(rng, wrong_key, body_len as u16);
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropMac),
            )
        }
        9 => {
            // Bad protocol magic.
            let bit = rng.next_usize(32);
            spec.hdr.magic = DEFAULT_MAGIC_BE ^ (1u32 << bit);
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropMagic),
            )
        }
        10 => {
            // Data shard 0..=7 with PARITY bit set.
            spec.hdr.slot = rng.next_usize(8) as u8;
            spec.hdr.flags = FLAG_PARITY;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        11 => {
            // Parity shard 8..=9 missing PARITY or carrying COMPRESSED.
            spec.hdr.slot = 8 + (rng.next_usize(2) as u8);
            spec.hdr.flags = if (rng.next_u64() & 1) == 0 {
                FLAG_ENCRYPTED
            } else {
                FLAG_PARITY | FLAG_COMPRESSED
            };
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        12 => {
            // Reserved high flag bits (3..=7) set.
            let bad_bit = 3 + rng.next_usize(5);
            spec.hdr.flags |= 1u8 << bad_bit;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        13 => {
            // Non-zero reserved field.
            spec.hdr.reserved = 1 + (rng.next_usize(65_535) as u16);
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        14 => {
            // Zero stream_id.
            spec.hdr.stream_id = 0;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        15 => {
            // payload_len == 0 or > 1440.
            if (rng.next_u64() & 1) == 0 {
                spec.hdr.payload_len = 0;
                spec.body_len = 0;
            } else {
                spec.hdr.payload_len = DEFAULT_MAX_PAYLOAD_BYTES + 1 + (rng.next_usize(64) as u16);
                spec.body_len = spec.hdr.payload_len as usize;
            }
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        16 => {
            // payload_len != expected_udp_payload.
            spec.hdr.payload_len = if body_len > 1 {
                (body_len - 1) as u16
            } else {
                2
            };
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        17 => {
            // IPv4 MF=1, frag_off=0 on target UDP port.
            spec.ipv6 = false;
            spec.ip_options_len = rng.next_usize(6) * 4;
            spec.frag_field = IPV4_MF_FLAG;
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropBounds),
            )
        }
        18 => {
            // Non-first IPv4 fragment (frag_off > 0) must ALWAYS pass.
            spec.ipv6 = false;
            spec.ip_options_len = rng.next_usize(6) * 4;
            spec.frag_field = 1 + (rng.next_usize(0x1FFE) as u16);
            (
                build_frame(&spec, rng),
                Some(XdpAction::Pass),
                Some(XdpStat::RxPassOther),
            )
        }
        19 => {
            // Invalid UDP length (< 40, > l4_avail, or > 16384).
            match rng.next_usize(3) {
                0 => spec.udp_len_override = Some(rng.next_usize(40) as u16),
                1 => {
                    let natural_udp = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + body_len) as u16;
                    spec.udp_len_override = Some(natural_udp + 4);
                }
                _ => {
                    spec.udp_len_override = Some(16_385);
                    spec.ip_tot_len_override = Some(16_450);
                }
            }
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropTrunc),
            )
        }
        20 => {
            // Malformed IPv4 header (bad version, ihl < 5, or tot_len < ihl*4 + 8).
            spec.ipv6 = false;
            spec.ip_options_len = 0;
            match rng.next_usize(3) {
                0 => spec.ip_version_override = Some(5),
                1 => spec.ihl_override = Some(rng.next_usize(5) as u8),
                _ => spec.ip_tot_len_override = Some(24),
            }
            (
                build_frame(&spec, rng),
                Some(XdpAction::Pass),
                Some(XdpStat::RxPassOther),
            )
        }
        21 => {
            // Bad IPv6 version or pre-UDP truncation.
            if (rng.next_u64() & 1) == 0 {
                spec.ipv6 = true;
                spec.ip_version_override = Some(5);
                (
                    build_frame(&spec, rng),
                    Some(XdpAction::Pass),
                    Some(XdpStat::RxPassOther),
                )
            } else {
                let mut pkt = build_frame(&spec, rng);
                let l3_len = if spec.ipv6 {
                    IPV6_HDR_BYTES
                } else {
                    IPV4_MIN_HDR_BYTES + spec.ip_options_len
                };
                let pre_udp_max = ETH_HDR_BYTES + spec.vlans.len() * 4 + l3_len + UDP_HDR_BYTES;
                pkt.truncate(rng.next_usize(pre_udp_max));
                (pkt, Some(XdpAction::Pass), Some(XdpStat::RxPassOther))
            }
        }
        22 => {
            // Completely arbitrary raw adversarial bytes (lengths 0..=200).
            let len = rng.next_usize(201);
            let mut raw = vec![0u8; len];
            for b in &mut raw {
                *b = (rng.next_u64() & 0xFF) as u8;
            }
            (raw, None, None)
        }
        _ => {
            // IPv6 payload_len < udp_len on target UDP port -> RxDropTrunc.
            spec.ipv6 = true;
            spec.ip_options_len = 0;
            spec.ip_tot_len_override = Some(16);
            (
                build_frame(&spec, rng),
                Some(XdpAction::Drop),
                Some(XdpStat::RxDropTrunc),
            )
        }
    }
}

#[test]
fn zipfian_s12_adversarial_12000_packets_full_parity() {
    let key = [0x1357_9BDF_2468_ACE0, 0xCAFE_F00D_DEAD_BEEF];
    let cfg = UdpFilterConfig::with_key(key);
    let prog = emit_xdp_program(&cfg);
    let summary = verify_bpf_program(&prog).expect("emitted BPF program must verify cleanly");
    assert!(summary.is_dag);

    let total_packets: usize = if cfg!(miri) { 128 } else { 12_000 };
    let mut rng = SplitMix64::new(0x5A50_9000_2026_0001);
    let zipf = ZipfSampler::new(24, 1.2);
    let mut counters = XdpCounters::new();

    for case_idx in 0..total_packets {
        let class = zipf.sample(&mut rng);
        let (pkt, expected_action, expected_stat) = generate_zipf_case(class, &mut rng, key);

        let verdict = filter_packet_with_counters(&pkt, &cfg, &mut counters);
        let vm_ret = execute_bpf_program(&prog, &pkt)
            .unwrap_or_else(|e| panic!("BPF VM error at case {case_idx} class {class}: {e}"));

        assert_eq!(
            verdict.action.as_u32(),
            vm_ret,
            "Rust vs eBPF VM parity mismatch at case {case_idx} class {class} len={}",
            pkt.len()
        );

        if let Some(exp_act) = expected_action {
            assert_eq!(
                verdict.action, exp_act,
                "action mismatch at case {case_idx} class {class}"
            );
        }
        if let Some(exp_st) = expected_stat {
            assert_eq!(
                verdict.stat, exp_st,
                "stat mismatch at case {case_idx} class {class}"
            );
        }
    }

    assert_eq!(counters.total(), total_packets as u64);
    assert!(counters.rx_pass_other() > 0);
    assert!(counters.rx_auth_pass() > 0);
    assert!(counters.rx_drop_trunc() > 0);
    assert!(counters.rx_drop_magic() > 0);
    assert!(counters.rx_drop_bounds() > 0);
    assert!(counters.rx_drop_mac() > 0);
}

#[test]
fn counterfactual_knockouts_all_64_mac_bits_and_boundaries() {
    assert_ne!(XdpAction::Pass, XdpAction::Drop);
    assert_ne!(XDP_PASS, XDP_DROP);

    let key_a = DEFAULT_MAC_KEY;
    let key_b = [0xAAAA_BBBB_CCCC_DDDD, 0x1111_2222_3333_4444];
    let cfg_zero = UdpFilterConfig::with_key([0, 0]);
    let cfg_a = UdpFilterConfig::with_key(key_a);
    let cfg_b = UdpFilterConfig::with_key(key_b);
    let prog_default = emit_xdp_program(&cfg_zero);
    let prog_a = emit_xdp_program(&cfg_a);
    let prog_b = emit_xdp_program(&cfg_b);
    assert_eq!(
        prog_default, prog_a,
        "all-zero key must emit identical bytecode to DEFAULT_MAC_KEY"
    );
    verify_bpf_program(&prog_a).expect("prog_a verifies");
    verify_bpf_program(&prog_b).expect("prog_b verifies");

    let mut rng = SplitMix64::new(0x51C0_FFEE_0000_9000);
    let vlans = [(ETH_P_8021AD, 100), (ETH_P_8021Q, 200)];
    let base_hdr = UdpPacketHdr::new(
        100,
        7,
        FLAG_COMPRESSED | FLAG_ENCRYPTED,
        0x89AB_CDEF,
        0x5A50_0001,
        (DEFAULT_MAX_FRAME_BYTES - DEFAULT_MAX_PAYLOAD_BYTES as u32) as u16,
        DEFAULT_MAX_PAYLOAD_BYTES,
    )
    .sign(key_a);
    let spec = FrameSpec {
        vlans: &vlans,
        ipv6: false,
        ip_options_len: 40,
        ip_version_override: None,
        ihl_override: None,
        proto_override: None,
        frag_field: 0,
        ip_tot_len_override: None,
        udp_dport: DEFAULT_UDP_PORT,
        udp_len_override: None,
        hdr: base_hdr,
        body_len: DEFAULT_MAX_PAYLOAD_BYTES as usize,
    };
    let valid_pkt = build_frame(&spec, &mut rng);

    let pass_v = filter_packet(&valid_pkt, &cfg_zero);
    assert_eq!(pass_v.action, XdpAction::Pass);
    assert_eq!(pass_v.stat, XdpStat::RxAuthPass);
    assert_eq!(execute_bpf_program(&prog_a, &valid_pkt).expect("vm"), XDP_PASS);

    // Key-rotation counterfactual: same valid packet rejected under key_b.
    let wrong_key_v = filter_packet(&valid_pkt, &cfg_b);
    assert_eq!(wrong_key_v.action, XdpAction::Drop);
    assert_eq!(wrong_key_v.stat, XdpStat::RxDropMac);
    assert_ne!(pass_v.action, wrong_key_v.action);
    assert_eq!(execute_bpf_program(&prog_b, &valid_pkt).expect("vm"), XDP_DROP);

    // Every single bit 0..64 of hdr_mac flipped -> MUST drop in both Rust & BPF VM.
    let hdr_start = ETH_HDR_BYTES + vlans.len() * 4 + IPV4_MIN_HDR_BYTES + 40 + UDP_HDR_BYTES;
    for bit in 0..64usize {
        let mut flipped = valid_pkt.clone();
        let byte_off = hdr_start + 24 + (bit / 8);
        flipped[byte_off] ^= 1u8 << (bit % 8);
        let v = filter_packet(&flipped, &cfg_a);
        assert_eq!(v.action, XdpAction::Drop);
        assert_eq!(v.stat, XdpStat::RxDropMac);
        assert_ne!(pass_v.action, v.action);
        assert_eq!(execute_bpf_program(&prog_a, &flipped).expect("vm"), XDP_DROP);
    }

    // Exact boundary: frag_offset + payload_len == 65536 (Pass) vs 65537 (Drop).
    let edge_ok_hdr = UdpPacketHdr::new(
        1,
        8,
        FLAG_PARITY,
        0x1111_1111,
        0x2222_2222,
        65_536u32.wrapping_sub(64) as u16,
        64,
    )
    .sign(key_a);
    let edge_bad_hdr = UdpPacketHdr::new(
        1,
        8,
        FLAG_PARITY,
        0x1111_1111,
        0x2222_2222,
        65_536u32.wrapping_sub(63) as u16,
        64,
    )
    .sign(key_a);
    let mut ok_spec = spec;
    ok_spec.ipv6 = true;
    ok_spec.ip_options_len = 0;
    ok_spec.body_len = 64;
    ok_spec.hdr = edge_ok_hdr;
    let ok_pkt = build_frame(&ok_spec, &mut rng);

    ok_spec.hdr = edge_bad_hdr;
    let bad_pkt = build_frame(&ok_spec, &mut rng);

    let ok_v = filter_packet(&ok_pkt, &cfg_a);
    let bad_v = filter_packet(&bad_pkt, &cfg_a);
    assert_eq!(ok_v.action, XdpAction::Pass);
    assert_eq!(bad_v.action, XdpAction::Drop);
    assert_eq!(bad_v.stat, XdpStat::RxDropBounds);
    assert_ne!(ok_v.action, bad_v.action);
    assert_eq!(execute_bpf_program(&prog_a, &ok_pkt).expect("vm"), XDP_PASS);
    assert_eq!(execute_bpf_program(&prog_a, &bad_pkt).expect("vm"), XDP_DROP);
}

#[test]
fn exhaustive_truncation_sweep_ipv4_ipv6_qinq() {
    let key = DEFAULT_MAC_KEY;
    let cfg = UdpFilterConfig::with_key(key);
    let prog = emit_xdp_program(&cfg);
    let mut rng = SplitMix64::new(0x7000_0001);

    type TruncConfig<'a> = (&'a [(u16, u16)], bool, usize);
    let configs: [TruncConfig<'_>; 4] = [
        (&[], false, 0),
        (&[(ETH_P_8021Q, 7)], false, 40),
        (&[(ETH_P_8021AD, 10), (ETH_P_8021Q, 20)], false, 16),
        (&[(ETH_P_8021AD, 10), (ETH_P_8021Q, 20)], true, 0),
    ];

    for (vlans, ipv6, opts_len) in configs {
        let hdr = UdpPacketHdr::new(5, 0, 0, 0xAAAA_BBBB, 0x0102_0304, 0, 32).sign(key);
        let spec = FrameSpec {
            vlans,
            ipv6,
            ip_options_len: opts_len,
            ip_version_override: None,
            ihl_override: None,
            proto_override: None,
            frag_field: 0,
            ip_tot_len_override: None,
            udp_dport: DEFAULT_UDP_PORT,
            udp_len_override: None,
            hdr,
            body_len: 32,
        };
        let full = build_frame(&spec, &mut rng);
        let l3_len = if ipv6 {
            IPV6_HDR_BYTES
        } else {
            IPV4_MIN_HDR_BYTES + opts_len
        };
        let udp_end = ETH_HDR_BYTES + vlans.len() * 4 + l3_len + UDP_HDR_BYTES;

        for cut in 0..=full.len() {
            let slice = &full[..cut];
            let rust_v = filter_packet(slice, &cfg);
            let vm_v = execute_bpf_program(&prog, slice).expect("vm truncation");
            assert_eq!(rust_v.action.as_u32(), vm_v, "cut={cut}");
            if cut < udp_end {
                assert_eq!(rust_v.action, XdpAction::Pass);
                assert_eq!(rust_v.stat, XdpStat::RxPassOther);
            } else if cut < full.len() {
                assert_eq!(rust_v.action, XdpAction::Drop);
                assert_eq!(rust_v.stat, XdpStat::RxDropTrunc);
            } else {
                assert_eq!(rust_v.action, XdpAction::Pass);
                assert_eq!(rust_v.stat, XdpStat::RxAuthPass);
            }
        }
    }
}
