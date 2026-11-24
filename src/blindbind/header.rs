//! Strict canonical Base64url decoding and HTTP header parsing for BlindBind proofs.

use crate::config::strip_host_port;
use crate::error::ProxyError;
use crate::http::HeaderView;

use super::{
    HybridBindingProof, HybridPublicKey, HYBRID_PROOF_LEN, HYBRID_PUBLIC_KEY_LEN,
};

/// Returns the exact unpadded RFC 4648 Section 5 Base64url character length for `raw_len` bytes.
///
/// Saturates at `i64::MAX as usize` when `raw_len > 0x1FFF_FFFF_FFFF_FFFF` so arithmetic
/// never overflows on any `usize` input.
#[must_use]
pub const fn base64url_encoded_len(raw_len: usize) -> usize {
    if raw_len > 0x1FFF_FFFF_FFFF_FFFF {
        return 0x7FFF_FFFF_FFFF_FFFF;
    }
    (raw_len / 3) * 4
        + match raw_len % 3 {
            0 => 0,
            1 => 2,
            _ => 3,
        }
}

/// Exact unpadded Base64url length of a serialized 2624-byte [`HybridPublicKey`] (`3499` chars).
pub const BLINDBIND_PUBKEY_B64URL_LEN: usize = base64url_encoded_len(HYBRID_PUBLIC_KEY_LEN);
/// Exact unpadded Base64url length of a serialized 4724-byte [`HybridBindingProof`] (`6299` chars).
pub const BLINDBIND_PROOF_B64URL_LEN: usize = base64url_encoded_len(HYBRID_PROOF_LEN);

/// Normalizes an HTTP `Host` header value to the canonical lowercase BlindBind host context.
#[must_use]
pub fn normalize_blindbind_context(req_host: Option<&str>) -> String {
    req_host
        .map(strip_host_port)
        .unwrap_or("")
        .to_ascii_lowercase()
}

const B64URL_LUT: [u8; 256] = {
    let mut t = [0xFFu8; 256];
    let mut i = 0usize;
    while i < 26 {
        t[b'A' as usize + i] = i as u8;
        t[b'a' as usize + i] = (i + 26) as u8;
        i += 1;
    }
    let mut d = 0usize;
    while d < 10 {
        t[b'0' as usize + d] = (d + 52) as u8;
        d += 1;
    }
    t[b'-' as usize] = 62;
    t[b'_' as usize] = 63;
    t
};

fn decode_b64url_sextet(b: u8) -> Option<u8> {
    B64URL_LUT.get(usize::from(b)).copied().filter(|&v| v < 64)
}

/// Strictly decodes an unpadded canonical RFC 4648 Section 5 Base64url byte slice into
/// an exact `N`-byte array.
///
/// Rejects wrong length, `=` padding, whitespace, non-base64url characters, and non-zero
/// trailing pad bits.
pub fn base64url_decode_exact<const N: usize>(input: &[u8]) -> Result<[u8; N], ProxyError> {
    if input.len() != base64url_encoded_len(N) {
        return Err(ProxyError::Unauthorized("invalid blindbind base64url length\n"));
    }
    let mut out = [0u8; N];
    let mut i = 0usize;
    let mut o = 0usize;

    while i + 4 <= input.len() {
        let Some(v0) = decode_b64url_sextet(input[i]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        let Some(v1) = decode_b64url_sextet(input[i + 1]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        let Some(v2) = decode_b64url_sextet(input[i + 2]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        let Some(v3) = decode_b64url_sextet(input[i + 3]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        out[o] = (v0 << 2) | (v1 >> 4);
        out[o + 1] = (v1 << 4) | (v2 >> 2);
        out[o + 2] = (v2 << 6) | v3;
        i += 4;
        o += 3;
    }

    let rem = input.len() - i;
    if rem == 2 {
        let Some(v0) = decode_b64url_sextet(input[i]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        let Some(v1) = decode_b64url_sextet(input[i + 1]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        if (v1 & 0x0f) != 0 {
            return Err(ProxyError::Unauthorized("non-canonical blindbind pad bits\n"));
        }
        out[o] = (v0 << 2) | (v1 >> 4);
    } else if rem == 3 {
        let Some(v0) = decode_b64url_sextet(input[i]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        let Some(v1) = decode_b64url_sextet(input[i + 1]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        let Some(v2) = decode_b64url_sextet(input[i + 2]) else {
            return Err(ProxyError::Unauthorized("invalid blindbind base64url char\n"));
        };
        if (v2 & 0x03) != 0 {
            return Err(ProxyError::Unauthorized("non-canonical blindbind pad bits\n"));
        }
        out[o] = (v0 << 2) | (v1 >> 4);
        out[o + 1] = (v1 << 4) | (v2 >> 2);
    }

    Ok(out)
}

/// Borrowed `(pubkey_b64url, proof_b64url)` header slices extracted from HTTP request headers.
pub type BlindBindHeaderTokens<'a> = (&'a [u8], &'a [u8]);

fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !a[i].eq_ignore_ascii_case(&b[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Extracts raw `(pubkey_b64url, proof_b64url)` tokens from parsed HTTP request headers.
///
/// Accepts either:
/// - Two-header form: `X-BlindBind-PubKey: <pk>` + `X-BlindBind-Proof: <proof>`
/// - Single-header dotted form: `X-BlindBind-Proof: <pk>.<proof>`
///
/// Returns `Ok(None)` when neither header is present (normal browser traffic).
/// Fails closed with `ProxyError::Unauthorized` on duplicates, missing half, or ambiguity.
pub fn parse_blindbind_header_tokens<'a>(
    headers: &[HeaderView<'a>],
) -> Result<Option<BlindBindHeaderTokens<'a>>, ProxyError> {
    let mut pubkey_val: Option<&'a [u8]> = None;
    let mut proof_val: Option<&'a [u8]> = None;

    for hv in headers {
        if eq_ascii_ci(hv.name, b"x-blindbind-pubkey") {
            if pubkey_val.is_some() {
                return Err(ProxyError::Unauthorized("duplicate X-BlindBind-PubKey\n"));
            }
            pubkey_val = Some(hv.value);
        } else if eq_ascii_ci(hv.name, b"x-blindbind-proof") {
            if proof_val.is_some() {
                return Err(ProxyError::Unauthorized("duplicate X-BlindBind-Proof\n"));
            }
            proof_val = Some(hv.value);
        }
    }

    match (pubkey_val, proof_val) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(ProxyError::Unauthorized("missing X-BlindBind-Proof\n")),
        (Some(pk), Some(proof)) => {
            if pk.is_empty() || proof.is_empty() || proof.contains(&b'.') {
                return Err(ProxyError::Unauthorized("malformed blindbind headers\n"));
            }
            Ok(Some((pk, proof)))
        }
        (None, Some(combined)) => {
            let Some(dot) = combined.iter().position(|&b| b == b'.') else {
                return Err(ProxyError::Unauthorized("missing X-BlindBind-PubKey\n"));
            };
            let pk = &combined[..dot];
            let proof = &combined[dot + 1..];
            if pk.is_empty() || proof.is_empty() || proof.contains(&b'.') {
                return Err(ProxyError::Unauthorized("malformed X-BlindBind-Proof\n"));
            }
            Ok(Some((pk, proof)))
        }
    }
}

/// Parses and decodes optional BlindBind headers into a canonical `(HybridPublicKey, HybridBindingProof)`.
///
/// Returns `Ok(None)` when no BlindBind headers are present.
pub fn parse_blindbind_headers(
    headers: &[HeaderView<'_>],
) -> Result<Option<(HybridPublicKey, HybridBindingProof)>, ProxyError> {
    let Some((pk_tok, proof_tok)) = parse_blindbind_header_tokens(headers)? else {
        return Ok(None);
    };
    let pk_bytes = base64url_decode_exact::<HYBRID_PUBLIC_KEY_LEN>(pk_tok)?;
    let proof_bytes = base64url_decode_exact::<HYBRID_PROOF_LEN>(proof_tok)?;

    let pk = HybridPublicKey::from_bytes(&pk_bytes)
        .map_err(|_| ProxyError::Unauthorized("invalid blindbind public key\n"))?;
    let proof = HybridBindingProof::from_bytes(&proof_bytes)
        .map_err(|_| ProxyError::Unauthorized("invalid blindbind proof\n"))?;
    Ok(Some((pk, proof)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::base64url_encode;
    use crate::blindbind::{HybridKeyPair, Role, EXPORTER_SECRET_LEN};

    #[test]
    fn base64url_encoded_len_no_overflow_at_usize_max() {
        assert_eq!(base64url_encoded_len(0), 0);
        assert_eq!(base64url_encoded_len(1), 2);
        assert_eq!(base64url_encoded_len(2), 3);
        assert_eq!(base64url_encoded_len(3), 4);
        let sat = base64url_encoded_len(usize::MAX);
        assert_eq!(sat, 0x7FFF_FFFF_FFFF_FFFF);
        assert_ne!(sat, 0);
    }

    #[test]
    fn base64url_decode_exact_roundtrip_and_canonical_pad_bits() {
        assert_eq!(BLINDBIND_PUBKEY_B64URL_LEN, 3499);
        assert_eq!(BLINDBIND_PROOF_B64URL_LEN, 6299);

        let b3 = [0x01u8, 0x23, 0x45];
        assert_eq!(
            base64url_decode_exact::<3>(base64url_encode(&b3).as_bytes()).expect("len 3"),
            b3
        );
        let b4 = [0xFFu8, 0x00, 0xFE, 0x80];
        let enc4 = base64url_encode(&b4);
        assert_eq!(
            base64url_decode_exact::<4>(enc4.as_bytes()).expect("len 4"),
            b4
        );
        // Set a non-zero low pad bit on the final base64url char (rem == 2 => low 4 bits must be 0).
        let mut bad4 = enc4.into_bytes();
        let last = bad4.len() - 1;
        bad4[last] = b'B';
        assert!(base64url_decode_exact::<4>(&bad4).is_err());

        let b5 = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x55];
        let enc5 = base64url_encode(&b5);
        assert_eq!(
            base64url_decode_exact::<5>(enc5.as_bytes()).expect("len 5"),
            b5
        );
        // Set a non-zero low pad bit on rem == 3 (low 2 bits must be 0).
        let mut bad5 = enc5.into_bytes();
        let last5 = bad5.len() - 1;
        bad5[last5] = b'B';
        assert!(base64url_decode_exact::<5>(&bad5).is_err());
        // Reject '=' padding and standard base64 '+' '/'.
        assert!(base64url_decode_exact::<3>(b"AQID=").is_err());
        assert!(base64url_decode_exact::<3>(b"AQ+D").is_err());
        assert!(base64url_decode_exact::<3>(b"AQ/D").is_err());
    }

    #[test]
    fn parse_blindbind_headers_both_formats_and_fail_closed_cases() {
        let kp = HybridKeyPair::from_master_seed(&[0x5Au8; 32]);
        let pk_b64 = base64url_encode(&kp.public_key().to_bytes());
        let proof = kp
            .bind(&[0x33u8; EXPORTER_SECRET_LEN], Role::Client, b"example.com")
            .expect("bind");
        let proof_b64 = base64url_encode(&proof.to_bytes());

        // Normal browser request without BlindBind headers -> Ok(None).
        let plain = [HeaderView {
            name: b"Host",
            value: b"example.com",
        }];
        assert!(parse_blindbind_headers(&plain).expect("browser").is_none());

        // Two-header format -> Ok(Some).
        let two = [
            HeaderView {
                name: b"X-BlindBind-PubKey",
                value: pk_b64.as_bytes(),
            },
            HeaderView {
                name: b"X-BlindBind-Proof",
                value: proof_b64.as_bytes(),
            },
        ];
        let (parsed_pk, parsed_proof) = parse_blindbind_headers(&two)
            .expect("two-header")
            .expect("some");
        assert_eq!(parsed_pk, kp.public_key());
        assert_eq!(parsed_proof, proof);

        // Single-header dotted format -> Ok(Some).
        let dotted = format!("{}.{}", pk_b64, proof_b64);
        let one = [HeaderView {
            name: b"x-blindbind-proof",
            value: dotted.as_bytes(),
        }];
        let (parsed_pk2, parsed_proof2) = parse_blindbind_headers(&one)
            .expect("dotted")
            .expect("some");
        assert_eq!(parsed_pk2, kp.public_key());
        assert_eq!(parsed_proof2, proof);

        // Fail-closed: duplicates, missing half, extra dot, mixed two-header + dot.
        let dup_proof = [
            HeaderView {
                name: b"X-BlindBind-Proof",
                value: dotted.as_bytes(),
            },
            HeaderView {
                name: b"x-blindbind-proof",
                value: dotted.as_bytes(),
            },
        ];
        assert!(parse_blindbind_header_tokens(&dup_proof).is_err());

        let only_pk = [HeaderView {
            name: b"X-BlindBind-PubKey",
            value: pk_b64.as_bytes(),
        }];
        assert!(parse_blindbind_header_tokens(&only_pk).is_err());

        let mixed = [
            HeaderView {
                name: b"X-BlindBind-PubKey",
                value: pk_b64.as_bytes(),
            },
            HeaderView {
                name: b"X-BlindBind-Proof",
                value: dotted.as_bytes(),
            },
        ];
        assert!(parse_blindbind_header_tokens(&mixed).is_err());

        let extra_dot = format!("{}.{}.extra", pk_b64, proof_b64);
        let bad_dots = [HeaderView {
            name: b"X-BlindBind-Proof",
            value: extra_dot.as_bytes(),
        }];
        assert!(parse_blindbind_header_tokens(&bad_dots).is_err());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(20)]
    fn proof_header_parser_no_panic() {
        let count: usize = kani::any();
        kani::assume(count <= 3);

        let name_choices: [&[u8]; 3] = [b"X-BlindBind-PubKey", b"X-BlindBind-Proof", b"Host"];
        let mut bufs = [[0u8; 8]; 3];
        let mut lens = [0usize; 3];
        let mut kinds = [0usize; 3];
        for i in 0..3 {
            kinds[i] = kani::any();
            kani::assume(kinds[i] < 3);
            lens[i] = kani::any();
            kani::assume(lens[i] <= 8);
            bufs[i] = kani::any();
        }
        let h0 = HeaderView {
            name: name_choices[kinds[0]],
            value: &bufs[0][..lens[0]],
        };
        let h1 = HeaderView {
            name: name_choices[kinds[1]],
            value: &bufs[1][..lens[1]],
        };
        let h2 = HeaderView {
            name: name_choices[kinds[2]],
            value: &bufs[2][..lens[2]],
        };
        let all = [h0, h1, h2];
        let slice = &all[..count];
        let res = parse_blindbind_header_tokens(slice);
        if let Ok(Some((pk, proof))) = res {
            assert!(!pk.is_empty());
            assert!(!proof.is_empty());
            assert!(!proof.contains(&b'.'));
        }
    }

    #[kani::proof]
    fn proof_base64url_decode_exact_no_panic() {
        // Prove canonical base64url decoder never panics across N % 3 in {0, 1, 2}.
        let raw_in: [u8; 7] = kani::any();
        let in_len: usize = kani::any();
        kani::assume(in_len <= 7);
        let _ = base64url_decode_exact::<3>(&raw_in[..in_len]);
        let _ = base64url_decode_exact::<4>(&raw_in[..in_len]);
        let _ = base64url_decode_exact::<5>(&raw_in[..in_len]);
    }
}
