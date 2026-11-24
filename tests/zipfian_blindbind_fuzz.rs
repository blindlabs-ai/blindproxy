#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr};

use zero_proxy::acme::base64url_encode;
use zero_proxy::blindbind::{
    base64url_decode_exact, build_hkdf_label, export_blindbind_secret, export_keying_material,
    parse_blindbind_headers, verify_binding, Error as BlindBindError, HybridBindingProof,
    HybridKeyPair, HybridPublicKey, Role, EXPORTER_LABEL, EXPORTER_SECRET_LEN, HYBRID_PROOF_LEN,
    HYBRID_PUBLIC_KEY_LEN,
};
use zero_proxy::config::RouteMatch;
use zero_proxy::http::{parse_request, write_forwarded_request_head_blindbind, HeaderView};

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_f64(&mut self) -> f64 {
        let bits = self.next_u64() >> 11;
        (bits as f64) * (1.0 / ((1u64 << 53) as f64))
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }
}

struct ZipfSampler {
    cdf: Vec<f64>,
}

impl ZipfSampler {
    fn new(n: usize, s: f64) -> Self {
        let mut weights = Vec::with_capacity(n);
        let mut total = 0.0f64;
        for k in 1..=n {
            let w = 1.0 / (k as f64).powf(s);
            total += w;
            weights.push(w);
        }
        let mut cdf = Vec::with_capacity(n);
        let mut acc = 0.0f64;
        for w in weights {
            acc += w / total;
            cdf.push(acc);
        }
        if let Some(last) = cdf.last_mut() {
            *last = 1.0;
        }
        Self { cdf }
    }

    fn sample(&self, rng: &mut XorShift64) -> usize {
        let u = rng.next_f64();
        for (idx, &edge) in self.cdf.iter().enumerate() {
            if u <= edge {
                return idx;
            }
        }
        self.cdf.len() - 1
    }
}

#[test]
fn zipfian_blindbind_adversarial_gauntlet_10240_cases() {
    const ITERATIONS: usize = if cfg!(miri) { 64 } else { 10_240 };
    const NUM_CLASSES: usize = 18;

    let mut rng = XorShift64::new(0x5A1F_B11D_2026_1123);
    let zipf = ZipfSampler::new(NUM_CLASSES, 1.2);

    let kp_client = HybridKeyPair::from_master_seed(&[0x33u8; 32]);
    let kp_other = HybridKeyPair::from_master_seed(&[0x77u8; 32]);
    let pk_client = kp_client.public_key();
    let pk_other = kp_other.public_key();

    let pk_raw = pk_client.to_bytes();
    let pk_b64 = base64url_encode(&pk_raw);
    let pk_other_b64 = base64url_encode(&pk_other.to_bytes());

    let ems384 = [0xA5u8; 48];
    let ems256 = [0x5Au8; 32];
    let host_ctx = b"example.com";
    let secret_valid = export_blindbind_secret(&ems384, host_ctx).expect("export valid");
    let secret_other_suite = export_blindbind_secret(&ems256, host_ctx).expect("export sha256");
    assert_ne!(secret_valid, secret_other_suite);

    let valid_proof = kp_client
        .bind(&secret_valid, Role::Client, host_ctx)
        .expect("bind valid");
    let proof_raw = valid_proof.to_bytes();
    let proof_b64 = base64url_encode(&proof_raw);

    // Baseline positive control before fuzzing.
    verify_binding(&pk_client, &secret_valid, Role::Client, host_ctx, &valid_proof)
        .expect("baseline control must verify");

    let mut total_cases = 0usize;
    let mut accepted_mutations = 0usize;
    let mut header_rejections = 0usize;
    let mut role_rejections = 0usize;
    let mut exporter_rejections = 0usize;
    let mut ed25519_rejections = 0usize;
    let mut mldsa87_rejections = 0usize;
    let mut spoof_strips = 0usize;
    let mut exporter_param_rejections = 0usize;
    let mut valid_controls_passed = 0usize;

    for iter in 0..ITERATIONS {
        // Periodic positive liveness check (every 1024 cases, and iter 0).
        if iter % 1024 == 0 {
            let hdrs = [
                HeaderView {
                    name: b"X-BlindBind-PubKey",
                    value: pk_b64.as_bytes(),
                },
                HeaderView {
                    name: b"X-BlindBind-Proof",
                    value: proof_b64.as_bytes(),
                },
            ];
            let (pk, pr) = parse_blindbind_headers(&hdrs)
                .expect("control headers")
                .expect("control present");
            verify_binding(&pk, &secret_valid, Role::Client, host_ctx, &pr)
                .expect("control verify");
            valid_controls_passed += 1;
        }

        let class = if iter < NUM_CLASSES {
            // Guarantee every single attack class is deterministically covered at least once.
            iter
        } else {
            zipf.sample(&mut rng)
        };
        total_cases += 1;

        match class {
            // 0: Cross-session exporter secret bit-flip
            0 => {
                let mut mutated_secret = secret_valid;
                let byte_idx = rng.next_usize(EXPORTER_SECRET_LEN);
                let bit = 1u8 << rng.next_usize(8);
                mutated_secret[byte_idx] ^= bit;
                assert_ne!(mutated_secret, secret_valid);
                match verify_binding(
                    &pk_client,
                    &mutated_secret,
                    Role::Client,
                    host_ctx,
                    &valid_proof,
                ) {
                    Ok(()) => accepted_mutations += 1,
                    Err(BlindBindError::ExporterMismatch) => exporter_rejections += 1,
                    Err(_) => {}
                }
            }
            // 1: ML-DSA-87 signature bit-flip (keeps role + binding_tag + Ed25519 valid!)
            1 => {
                let mut raw = proof_raw.clone();
                let mldsa_start = 1 + 32 + 64;
                let idx = mldsa_start + rng.next_usize(HYBRID_PROOF_LEN - mldsa_start);
                raw[idx] ^= 1u8 << rng.next_usize(8);
                if let Ok(pr) = HybridBindingProof::from_bytes(&raw) {
                    match verify_binding(&pk_client, &secret_valid, Role::Client, host_ctx, &pr) {
                        Ok(()) => accepted_mutations += 1,
                        Err(BlindBindError::MlDsa87VerificationFailed) => mldsa87_rejections += 1,
                        Err(_) => {}
                    }
                } else {
                    mldsa87_rejections += 1;
                }
            }
            // 2: Ed25519 signature bit-flip (keeps role + binding_tag valid!)
            2 => {
                let mut raw = proof_raw.clone();
                let idx = 33 + rng.next_usize(64);
                raw[idx] ^= 1u8 << rng.next_usize(8);
                match HybridBindingProof::from_bytes(&raw) {
                    Ok(pr) => {
                        match verify_binding(&pk_client, &secret_valid, Role::Client, host_ctx, &pr)
                        {
                            Ok(()) => accepted_mutations += 1,
                            Err(BlindBindError::Ed25519VerificationFailed) => {
                                ed25519_rejections += 1;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => ed25519_rejections += 1,
                }
            }
            // 3: Binding commitment tag bit-flip
            3 => {
                let mut raw = proof_raw.clone();
                let idx = 1 + rng.next_usize(32);
                raw[idx] ^= 1u8 << rng.next_usize(8);
                let pr = HybridBindingProof::from_bytes(&raw).expect("parse tag flip");
                match verify_binding(&pk_client, &secret_valid, Role::Client, host_ctx, &pr) {
                    Ok(()) => accepted_mutations += 1,
                    Err(BlindBindError::ExporterMismatch) => exporter_rejections += 1,
                    Err(_) => {}
                }
            }
            // 4: Role byte reflection (Server instead of Client) or invalid role byte
            4 => {
                let mut raw = proof_raw.clone();
                if rng.next_usize(2) == 0 {
                    raw[0] = Role::Server.as_byte();
                    let pr = HybridBindingProof::from_bytes(&raw).expect("server role");
                    match verify_binding(&pk_client, &secret_valid, Role::Client, host_ctx, &pr) {
                        Ok(()) => accepted_mutations += 1,
                        Err(BlindBindError::RoleMismatch) => role_rejections += 1,
                        Err(_) => {}
                    }
                } else {
                    let mut bad_role = (rng.next_u64() & 0xff) as u8;
                    if bad_role == 0x01 || bad_role == 0x02 {
                        bad_role = 0x00;
                    }
                    raw[0] = bad_role;
                    if HybridBindingProof::from_bytes(&raw).is_ok() {
                        accepted_mutations += 1;
                    } else {
                        role_rejections += 1;
                    }
                }
            }
            // 5: Wrong host context (uppercase, port suffix, subdomain, empty)
            5 => {
                let bad_contexts: [&[u8]; 5] = [
                    b"EXAMPLE.COM",
                    b"example.com:443",
                    b"evil.example.com",
                    b"example.com ",
                    b"",
                ];
                let bad_ctx = bad_contexts[rng.next_usize(bad_contexts.len())];
                match verify_binding(&pk_client, &secret_valid, Role::Client, bad_ctx, &valid_proof)
                {
                    Ok(()) => accepted_mutations += 1,
                    Err(BlindBindError::ExporterMismatch) => exporter_rejections += 1,
                    Err(_) => {}
                }
            }
            // 6: Non-canonical Base64url trailing pad bits on pubkey or proof
            6 => {
                if rng.next_usize(2) == 0 {
                    let mut mutated = pk_b64.as_bytes().to_vec();
                    let last = mutated.len() - 1;
                    // For 2624 % 3 == 2, low 2 bits of final sextet must be 0.
                    // 'A' (0) -> 'B' (1) or 'C' (2) or 'D' (3) flips a low pad bit.
                    let bad_pad = [b'B', b'C', b'D'][rng.next_usize(3)];
                    mutated[last] = bad_pad;
                    if base64url_decode_exact::<HYBRID_PUBLIC_KEY_LEN>(&mutated).is_ok() {
                        accepted_mutations += 1;
                    } else {
                        header_rejections += 1;
                    }
                } else {
                    let mut mutated = proof_b64.as_bytes().to_vec();
                    let last = mutated.len() - 1;
                    let bad_pad = [b'B', b'C', b'D'][rng.next_usize(3)];
                    mutated[last] = bad_pad;
                    if base64url_decode_exact::<HYBRID_PROOF_LEN>(&mutated).is_ok() {
                        accepted_mutations += 1;
                    } else {
                        header_rejections += 1;
                    }
                }
            }
            // 7: Illegal Base64url characters ('=', '+', '/', whitespace, NUL, non-ASCII)
            7 => {
                let bad_chars: [u8; 8] = [b'=', b'+', b'/', b' ', b'\t', 0x00, 0x7f, 0xff];
                let ch = bad_chars[rng.next_usize(bad_chars.len())];
                let mut mutated = proof_b64.as_bytes().to_vec();
                let pos = rng.next_usize(mutated.len());
                mutated[pos] = ch;
                let hdrs = [
                    HeaderView {
                        name: b"X-BlindBind-PubKey",
                        value: pk_b64.as_bytes(),
                    },
                    HeaderView {
                        name: b"X-BlindBind-Proof",
                        value: &mutated,
                    },
                ];
                if parse_blindbind_headers(&hdrs).is_ok() {
                    accepted_mutations += 1;
                } else {
                    header_rejections += 1;
                }
            }
            // 8: Truncated or extended header token lengths
            8 => {
                let mut mutated = proof_b64.as_bytes().to_vec();
                if rng.next_usize(2) == 0 {
                    let cut = 1 + rng.next_usize(32);
                    mutated.truncate(mutated.len() - cut);
                } else {
                    mutated.push(b'A');
                }
                let hdrs = [
                    HeaderView {
                        name: b"X-BlindBind-PubKey",
                        value: pk_b64.as_bytes(),
                    },
                    HeaderView {
                        name: b"X-BlindBind-Proof",
                        value: &mutated,
                    },
                ];
                if parse_blindbind_headers(&hdrs).is_ok() {
                    accepted_mutations += 1;
                } else {
                    header_rejections += 1;
                }
            }
            // 9: Malformed single-header dotted formats (0 dots, 2 dots, empty left/right)
            9 => {
                let bad_val = match rng.next_usize(4) {
                    0 => proof_b64.clone(),
                    1 => format!("{}.{}.{}", pk_b64, proof_b64, "AA"),
                    2 => format!(".{}", proof_b64),
                    _ => format!("{}.", pk_b64),
                };
                let hdrs = [HeaderView {
                    name: b"X-BlindBind-Proof",
                    value: bad_val.as_bytes(),
                }];
                if parse_blindbind_headers(&hdrs).is_ok() {
                    accepted_mutations += 1;
                } else {
                    header_rejections += 1;
                }
            }
            // 10: Ambiguous mixed two-header + dotted proof
            10 => {
                let dotted = format!("{}.{}", pk_b64, proof_b64);
                let hdrs = [
                    HeaderView {
                        name: b"X-BlindBind-PubKey",
                        value: pk_b64.as_bytes(),
                    },
                    HeaderView {
                        name: b"X-BlindBind-Proof",
                        value: dotted.as_bytes(),
                    },
                ];
                if parse_blindbind_headers(&hdrs).is_ok() {
                    accepted_mutations += 1;
                } else {
                    header_rejections += 1;
                }
            }
            // 11: Duplicate X-BlindBind-Proof or X-BlindBind-PubKey headers
            11 => {
                let dotted = format!("{}.{}", pk_b64, proof_b64);
                let hdrs = if rng.next_usize(2) == 0 {
                    [
                        HeaderView {
                            name: b"X-BlindBind-Proof",
                            value: dotted.as_bytes(),
                        },
                        HeaderView {
                            name: b"x-blindbind-proof",
                            value: dotted.as_bytes(),
                        },
                    ]
                } else {
                    [
                        HeaderView {
                            name: b"X-BlindBind-PubKey",
                            value: pk_b64.as_bytes(),
                        },
                        HeaderView {
                            name: b"x-blindbind-pubkey",
                            value: pk_b64.as_bytes(),
                        },
                    ]
                };
                if parse_blindbind_headers(&hdrs).is_ok() {
                    accepted_mutations += 1;
                } else {
                    header_rejections += 1;
                }
            }
            // 12: Missing X-BlindBind-Proof when X-BlindBind-PubKey is supplied alone
            12 => {
                let hdrs = [HeaderView {
                    name: b"X-BlindBind-PubKey",
                    value: pk_b64.as_bytes(),
                }];
                if parse_blindbind_headers(&hdrs).is_ok() {
                    accepted_mutations += 1;
                } else {
                    header_rejections += 1;
                }
            }
            // 13: Valid proof presented under a different client's public key
            13 => {
                let hdrs = [
                    HeaderView {
                        name: b"X-BlindBind-PubKey",
                        value: pk_other_b64.as_bytes(),
                    },
                    HeaderView {
                        name: b"X-BlindBind-Proof",
                        value: proof_b64.as_bytes(),
                    },
                ];
                let (pk, pr) = parse_blindbind_headers(&hdrs)
                    .expect("other pk parses")
                    .expect("some");
                match verify_binding(&pk, &secret_valid, Role::Client, host_ctx, &pr) {
                    Ok(()) => accepted_mutations += 1,
                    Err(BlindBindError::ExporterMismatch) => exporter_rejections += 1,
                    Err(_) => {}
                }
            }
            // 14: Corrupted public key bytes (Ed25519 or ML-DSA-87 component)
            14 => {
                let mut bad_pk = pk_raw.clone();
                let pos = rng.next_usize(HYBRID_PUBLIC_KEY_LEN);
                bad_pk[pos] ^= 1u8 << rng.next_usize(8);
                match HybridPublicKey::from_bytes(&bad_pk) {
                    Ok(pk) => {
                        match verify_binding(&pk, &secret_valid, Role::Client, host_ctx, &valid_proof)
                        {
                            Ok(()) => accepted_mutations += 1,
                            Err(BlindBindError::ExporterMismatch) => exporter_rejections += 1,
                            Err(_) => {}
                        }
                    }
                    Err(_) => header_rejections += 1,
                }
            }
            // 15: Spoofed X-BlindBind-Verified / Key-Sha256 stripping invariant on forwarded request
            15 => {
                let spoof_names = [
                    "X-BlindBind-Verified",
                    "x-blindbind-verified",
                    "X-BLINDBIND-VERIFIED",
                    "X-BlindBind-Key-Sha256",
                    "x-blindbind-key-sha256",
                    "X-BlindBind_Verified",
                    "X_BLINDBIND_KEY_SHA256",
                    "X_BlindBind-Verified",
                    "x_blindbind_proof",
                    "X-BlindBind",
                ];
                let name = spoof_names[rng.next_usize(spoof_names.len())];
                let raw_req = format!(
                    "GET /api/x HTTP/1.1\r\nHost: example.com\r\n{}: 1\r\nX-Custom: ok\r\n\r\n",
                    name
                );
                let parsed = parse_request(raw_req.as_bytes(), 1024, 64).expect("parse req");
                let route = RouteMatch {
                    upstream: "127.0.0.1:9000".parse().expect("upstream"),
                    tail: "/x",
                    prepend_slash: false,
                };
                let mut out = [0u8; 2048];
                let n = write_forwarded_request_head_blindbind(
                    &mut out,
                    &parsed,
                    route,
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    true,
                    None,
                )
                .expect("write forwarded");
                let forwarded = std::str::from_utf8(&out[..n]).expect("ascii").to_ascii_lowercase();
                if forwarded.contains("blindbind") || !forwarded.contains("x-custom: ok\r\n") {
                    accepted_mutations += 1;
                } else {
                    spoof_strips += 1;
                }
            }
            // 16: RFC 8446 Section 7.5 exporter invalid parameters (EMS len, label len, out len)
            16 => {
                let bad_ok = match rng.next_usize(5) {
                    0 => {
                        let bad_ems_lens = [0usize, 16, 31, 33, 47, 49, 64];
                        let len = bad_ems_lens[rng.next_usize(bad_ems_lens.len())];
                        export_keying_material(&vec![0x11u8; len], EXPORTER_LABEL, b"ctx", 32)
                            .is_ok()
                    }
                    1 => export_keying_material(&ems256, b"", b"ctx", 32).is_ok(),
                    2 => export_keying_material(&ems384, &[b'a'; 250], b"ctx", 32).is_ok(),
                    3 => export_keying_material(&ems256, EXPORTER_LABEL, b"ctx", 0).is_ok(),
                    _ => build_hkdf_label(32, b"ok", &[0u8; 256]).is_ok(),
                };
                if bad_ok {
                    accepted_mutations += 1;
                } else {
                    exporter_param_rejections += 1;
                }
            }
            // 17: Cross-suite EMS separation (SHA-256 derived secret vs SHA-384 derived secret)
            _ => {
                let mut ems_var = ems256;
                ems_var[rng.next_usize(32)] ^= 1u8 << rng.next_usize(8);
                let alt_secret = export_blindbind_secret(&ems_var, host_ctx).expect("alt export");
                match verify_binding(&pk_client, &alt_secret, Role::Client, host_ctx, &valid_proof)
                {
                    Ok(()) => accepted_mutations += 1,
                    Err(BlindBindError::ExporterMismatch) => exporter_rejections += 1,
                    Err(_) => {}
                }
            }
        }
    }

    assert_eq!(total_cases, ITERATIONS);
    assert_eq!(
        accepted_mutations, 0,
        "ZERO false accepts allowed across {} Zipfian adversarial mutations",
        ITERATIONS
    );
    assert!(valid_controls_passed >= 1);
    assert!(header_rejections > 0);
    assert!(role_rejections > 0);
    assert!(exporter_rejections > 0);
    assert!(ed25519_rejections > 0);
    assert!(mldsa87_rejections > 0);
    assert!(spoof_strips > 0);
    assert!(exporter_param_rejections > 0);
}
