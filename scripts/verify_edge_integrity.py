#!/usr/bin/env python3
"""Zero-dependency external TLS 1.3, CT, SPKI, Content-Digest, header & CAA edge verifier.

Uses Python 3 standard library only (0 external packages).
"""

import argparse
import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import ssl
import struct
import sys
from typing import Dict, List, Optional, Tuple


# OID 1.3.6.1.4.1.11129.2.4.2 (RFC 6962 Embedded Precertificate SCT List)
CT_SCT_EXT_OID_DER = bytes.fromhex("060a2b06010401d679020402")


def read_der_tlv(data: bytes, offset: int) -> Tuple[int, int, int, int]:
    """Reads a single ASN.1 DER TLV at `offset`.

    Returns `(tag, value_start, value_end, next_offset)`.
    """
    if offset >= len(data):
        raise ValueError("truncated DER TLV")
    tag = data[offset]
    pos = offset + 1
    if pos >= len(data):
        raise ValueError("truncated DER length")
    first_len = data[pos]
    pos += 1
    if first_len < 0x80:
        length = first_len
    else:
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or num_bytes > 4 or pos + num_bytes > len(data):
            raise ValueError("invalid DER length encoding")
        length = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes
    value_start = pos
    value_end = value_start + length
    if value_end > len(data):
        raise ValueError("DER value extends past buffer")
    return tag, value_start, value_end, value_end


def extract_spki_and_extensions(cert_der: bytes) -> Tuple[bytes, Optional[bytes]]:
    """Extracts exact DER bytes of SubjectPublicKeyInfo and optional v3 extensions SEQUENCE."""
    tag, cert_val_start, cert_val_end, _ = read_der_tlv(cert_der, 0)
    if tag != 0x30:
        raise ValueError("certificate outer tag is not SEQUENCE")

    # First child of Certificate is TBSCertificate
    tbs_tag, tbs_start, tbs_end, _ = read_der_tlv(cert_der, cert_val_start)
    if tbs_tag != 0x30 or tbs_end > cert_val_end:
        raise ValueError("TBSCertificate is not a valid SEQUENCE")

    pos = tbs_start
    # Optional version [0] EXPLICIT
    first_tag, _, _, next_pos = read_der_tlv(cert_der, pos)
    if first_tag == 0xA0:
        pos = next_pos

    # Skip: serialNumber, signature, issuer, validity, subject (5 elements)
    for _ in range(5):
        _, _, _, pos = read_der_tlv(cert_der, pos)

    # Next element MUST be SubjectPublicKeyInfo (SEQUENCE)
    spki_start = pos
    spki_tag, _, _, spki_end = read_der_tlv(cert_der, spki_start)
    if spki_tag != 0x30 or spki_end > tbs_end:
        raise ValueError("SubjectPublicKeyInfo is not a valid SEQUENCE")
    spki_der = cert_der[spki_start:spki_end]

    # Scan remaining optional fields in TBSCertificate for extensions [3] EXPLICIT
    ext_seq_der: Optional[bytes] = None
    pos = spki_end
    while pos < tbs_end:
        f_tag, f_val_start, f_val_end, next_pos = read_der_tlv(cert_der, pos)
        if f_tag == 0xA3:
            ext_seq_der = cert_der[f_val_start:f_val_end]
            break
        pos = next_pos

    return spki_der, ext_seq_der


def extract_embedded_ct_scts(ext_seq_der: Optional[bytes]) -> List[Dict[str, object]]:
    """Parses RFC 6962 embedded SignedCertificateTimestampList from X.509 v3 extensions."""
    if not ext_seq_der:
        return []
    tag, seq_start, seq_end, _ = read_der_tlv(ext_seq_der, 0)
    if tag != 0x30:
        return []

    sct_list_bytes: Optional[bytes] = None
    pos = seq_start
    while pos < seq_end:
        e_tag, e_start, e_end, next_pos = read_der_tlv(ext_seq_der, pos)
        pos = next_pos
        if e_tag != 0x30:
            continue
        oid_tag, _, _, oid_end = read_der_tlv(ext_seq_der, e_start)
        if oid_tag != 0x06:
            continue
        if ext_seq_der[e_start:oid_end] != CT_SCT_EXT_OID_DER:
            continue
        # Optional BOOLEAN critical, then OCTET STRING extnValue
        cur = oid_end
        while cur < e_end:
            c_tag, c_val_start, c_val_end, cur = read_der_tlv(ext_seq_der, cur)
            if c_tag == 0x04:
                # extnValue wraps an OCTET STRING containing SignedCertificateTimestampList
                inner_tag, inner_start, inner_end, _ = read_der_tlv(
                    ext_seq_der[c_val_start:c_val_end], 0
                )
                if inner_tag == 0x04:
                    sct_list_bytes = ext_seq_der[c_val_start + inner_start : c_val_start + inner_end]
                break
        break

    if not sct_list_bytes or len(sct_list_bytes) < 2:
        return []

    total_len = struct.unpack("!H", sct_list_bytes[:2])[0]
    if total_len + 2 > len(sct_list_bytes):
        raise ValueError("truncated RFC 6962 SCT list")

    scts: List[Dict[str, object]] = []
    idx = 2
    end = 2 + total_len
    while idx < end:
        if idx + 2 > end:
            raise ValueError("truncated SCT item length")
        item_len = struct.unpack("!H", sct_list_bytes[idx : idx + 2])[0]
        idx += 2
        if idx + item_len > end or item_len < 43:
            raise ValueError("truncated SCT item body")
        item = sct_list_bytes[idx : idx + item_len]
        idx += item_len
        version = item[0]
        log_id_hex = item[1:33].hex()
        timestamp_ms = struct.unpack("!Q", item[33:41])[0]
        scts.append(
            {
                "version": version,
                "log_id_hex": log_id_hex,
                "timestamp_ms": timestamp_ms,
            }
        )
    return scts


def check_tls13_and_reject_tls12(
    host: str, port: int, timeout: float
) -> Tuple[bytes, str, Tuple[str, str, int]]:
    """Verifies TLS 1.3 handshake succeeds with CA validation and TLS 1.2 fails."""
    ctx13 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx13.load_default_certs()
    ctx13.verify_mode = ssl.CERT_REQUIRED
    ctx13.check_hostname = True
    ctx13.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx13.maximum_version = ssl.TLSVersion.TLSv1_3

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with ctx13.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            version = tls_sock.version() or ""
            cipher = tls_sock.cipher()
            cert_der = tls_sock.getpeercert(binary_form=True)
            if version != "TLSv1.3":
                raise RuntimeError(f"expected TLSv1.3, negotiated {version!r}")
            if not cert_der:
                raise RuntimeError("peer did not present a leaf certificate")
            if cipher is None:
                raise RuntimeError("missing negotiated cipher tuple")

    # Counterfactual check: TLS 1.2-only client MUST be rejected.
    ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx12.check_hostname = False
    ctx12.verify_mode = ssl.CERT_NONE
    ctx12.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx12.maximum_version = ssl.TLSVersion.TLSv1_2

    tls12_succeeded = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx12.wrap_socket(raw_sock, server_hostname=host) as tls12_sock:
                if tls12_sock.version():
                    tls12_succeeded = True
    except (ssl.SSLError, OSError, EOFError):
        tls12_succeeded = False

    if tls12_succeeded:
        raise RuntimeError("SECURITY FAILURE: server accepted TLS 1.2 handshake")

    return cert_der, version, cipher


def fetch_https_tls13(
    host: str, port: int, path: str, timeout: float
) -> Tuple[int, List[Tuple[str, str]], bytes]:
    """Performs a strict TLS 1.3 HTTP/1.1 GET request and returns (status, headers, body)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_default_certs()
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=ctx)
    try:
        conn.request("GET", path, headers={"Host": host, "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read()
        headers = resp.getheaders()
        return resp.status, headers, body
    finally:
        conn.close()


def header_values_ci(headers: List[Tuple[str, str]], name: str) -> List[str]:
    target = name.lower()
    return [v for k, v in headers if k.lower() == target]


def verify_security_headers(path: str, headers: List[Tuple[str, str]]) -> None:
    """Enforces HSTS preload, Permissions-Policy, zero Server header, and baseline hardening."""
    server_hdrs = header_values_ci(headers, "server")
    if server_hdrs:
        raise RuntimeError(f"{path}: unexpected Server header present: {server_hdrs!r}")

    hsts_vals = header_values_ci(headers, "strict-transport-security")
    if len(hsts_vals) != 1:
        raise RuntimeError(f"{path}: missing or duplicate Strict-Transport-Security: {hsts_vals!r}")
    hsts = hsts_vals[0]
    tokens = [part.strip() for part in hsts.split(";") if part.strip()]
    tokens_lower = [t.lower() for t in tokens]
    max_age = -1
    for t in tokens_lower:
        if t.startswith("max-age="):
            try:
                max_age = int(t.split("=", 1)[1].strip())
            except ValueError as exc:
                raise RuntimeError(f"{path}: invalid HSTS max-age in {hsts!r}") from exc
    if max_age < 31_536_000:
        raise RuntimeError(f"{path}: HSTS max-age too small ({max_age} < 31536000)")
    if "includesubdomains" not in tokens_lower or "preload" not in tokens_lower:
        raise RuntimeError(f"{path}: HSTS missing includeSubDomains/preload: {hsts!r}")

    pp_vals = header_values_ci(headers, "permissions-policy")
    if not pp_vals or not pp_vals[0].strip():
        raise RuntimeError(f"{path}: missing Permissions-Policy header")

    xcto = header_values_ci(headers, "x-content-type-options")
    if [v.lower() for v in xcto] != ["nosniff"]:
        raise RuntimeError(f"{path}: invalid X-Content-Type-Options: {xcto!r}")

    xfo = header_values_ci(headers, "x-frame-options")
    if [v.upper() for v in xfo] != ["DENY"]:
        raise RuntimeError(f"{path}: invalid X-Frame-Options: {xfo!r}")

    rp = header_values_ci(headers, "referrer-policy")
    if [v.lower() for v in rp] != ["no-referrer"]:
        raise RuntimeError(f"{path}: invalid Referrer-Policy: {rp!r}")


def encode_dns_name(host: str) -> bytes:
    labels = host.strip(".").split(".")
    out = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if not raw or len(raw) > 63:
            raise ValueError(f"invalid DNS label: {label!r}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def skip_dns_name(pkt: bytes, offset: int) -> int:
    pos = offset
    jumps = 0
    while True:
        if pos >= len(pkt):
            raise ValueError("truncated DNS name")
        length = pkt[pos]
        if length == 0:
            return pos + 1
        if (length & 0xC0) == 0xC0:
            if pos + 2 > len(pkt):
                raise ValueError("truncated DNS name pointer")
            return pos + 2
        if (length & 0xC0) != 0:
            raise ValueError("invalid DNS label bits")
        pos += 1 + length
        jumps += 1
        if jumps > 128:
            raise ValueError("DNS name loop")


def build_dns_query(host: str, qtype: int) -> Tuple[int, bytes]:
    txid = secrets.randbelow(65536)
    # Standard query with RD=1, ARCOUNT=1 (EDNS0 OPT with DO=1 for AD bit)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 1)
    question = encode_dns_name(host) + struct.pack("!HH", qtype, 1)
    # EDNS0 OPT RR: root(0), type=41, udp_size=1232, ext_rcode=0, ver=0, DO=0x8000, rdlen=0
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0x00008000, 0)
    return txid, header + question + opt


def dns_exchange(server_ip: str, query: bytes, timeout: float) -> bytes:
    family = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server_ip, 53))
        resp, _ = sock.recvfrom(4096)
    if len(resp) >= 12 and (struct.unpack("!H", resp[2:4])[0] & 0x0200):
        # TC bit set -> retry over TCP
        with socket.create_connection((server_ip, 53), timeout=timeout) as tsock:
            tsock.sendall(struct.pack("!H", len(query)) + query)
            hdr = b""
            while len(hdr) < 2:
                chunk = tsock.recv(2 - len(hdr))
                if not chunk:
                    raise RuntimeError("truncated DNS TCP length")
                hdr += chunk
            want = struct.unpack("!H", hdr)[0]
            buf = bytearray()
            while len(buf) < want:
                chunk = tsock.recv(want - len(buf))
                if not chunk:
                    raise RuntimeError("truncated DNS TCP response")
                buf.extend(chunk)
            return bytes(buf)
    return resp


def load_dns_servers(explicit: Optional[str]) -> List[str]:
    if explicit:
        return [explicit]
    servers: List[str] = []
    if os.path.exists("/etc/resolv.conf"):
        try:
            with open("/etc/resolv.conf", "r", encoding="ascii", errors="ignore") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        ip = parts[1]
                        if ip not in servers:
                            servers.append(ip)
        except OSError:
            pass
    for fallback in ("1.1.1.1", "8.8.8.8"):
        if fallback not in servers:
            servers.append(fallback)
    return servers


def query_dns_caa(
    host: str, dns_server: Optional[str], timeout: float
) -> Tuple[List[Tuple[int, str, str]], bool, str]:
    """Queries DNS CAA (RRTYPE 257) using pure stdlib sockets.

    Returns `(records, ad_flag, resolver_ip)`.
    """
    txid, query = build_dns_query(host, 257)
    last_err: Optional[Exception] = None
    for server in load_dns_servers(dns_server):
        try:
            resp = dns_exchange(server, query, timeout)
            if len(resp) < 12:
                raise RuntimeError("DNS response shorter than 12 bytes")
            r_txid, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", resp[:12])
            if r_txid != txid:
                raise RuntimeError("DNS transaction ID mismatch")
            rcode = flags & 0x000F
            if rcode != 0:
                raise RuntimeError(f"DNS RCODE={rcode} from {server}")
            ad_flag = bool(flags & 0x0020)
            pos = 12
            for _ in range(qdcount):
                pos = skip_dns_name(resp, pos)
                pos += 4
            records: List[Tuple[int, str, str]] = []
            for _ in range(ancount):
                pos = skip_dns_name(resp, pos)
                if pos + 10 > len(resp):
                    raise RuntimeError("truncated DNS RR header")
                rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", resp[pos : pos + 10])
                pos += 10
                rdata = resp[pos : pos + rdlen]
                pos += rdlen
                if rtype == 257 and rclass == 1 and len(rdata) >= 2:
                    caa_flags = rdata[0]
                    tag_len = rdata[1]
                    if 2 + tag_len <= len(rdata):
                        tag = rdata[2 : 2 + tag_len].decode("ascii", errors="replace")
                        val = rdata[2 + tag_len :].decode("ascii", errors="replace")
                        records.append((caa_flags, tag, val))
            if records or dns_server is not None:
                return records, ad_flag, server
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            continue
    if last_err is not None:
        raise RuntimeError(f"DNS CAA lookup failed: {last_err}") from last_err
    return [], False, "none"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Zero-dep external TLS 1.3, CT, SPKI, Content-Digest, header & CAA verifier"
    )
    parser.add_argument("--host", required=True, help="Target hostname (e.g. example.com)")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument(
        "--expected-caa",
        default=None,
        help="Optional expected CAA issuer domain to enforce via DNS (e.g. ca.example.com)",
    )
    parser.add_argument(
        "--asset",
        action="append",
        default=None,
        help="Static asset path to verify against Content-Digest and manifest (repeatable; default: /)",
    )
    parser.add_argument(
        "--dns-server",
        default=None,
        help="Optional explicit DNS resolver IP (default: /etc/resolv.conf + 1.1.1.1/8.8.8.8)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Network timeout in seconds (default: 8.0)",
    )
    args = parser.parse_args()

    host = args.host.strip().lower()
    failures: List[str] = []

    print(f"=== Zero-Proxy External Edge Integrity Verifier: {host}:{args.port} ===")

    # 1. TLS 1.3 handshake + TLS 1.2 rejection counterfactual
    cert_der: Optional[bytes] = None
    spki_b64 = ""
    spki_hex = ""
    cert_hex = ""
    try:
        cert_der, tls_ver, cipher = check_tls13_and_reject_tls12(host, args.port, args.timeout)
        spki_der, ext_seq_der = extract_spki_and_extensions(cert_der)
        spki_digest = hashlib.sha256(spki_der).digest()
        spki_b64 = base64.b64encode(spki_digest).decode("ascii")
        spki_hex = spki_digest.hex()
        cert_hex = hashlib.sha256(cert_der).hexdigest()
        print(
            f"[PASS] TLS 1.3 strict: negotiated {tls_ver} ({cipher[0]}), TLS 1.2 rejected"
        )
        scts = extract_embedded_ct_scts(ext_seq_der)
        if len(scts) < 2:
            raise RuntimeError(f"expected >= 2 embedded RFC 6962 CT SCTs, found {len(scts)}")
        print(
            f"[PASS] CT embedded SCTs: {len(scts)} RFC 6962 SCTs present in leaf certificate"
        )
    except Exception as exc:  # noqa: BLE001
        failures.append(f"TLS/CT check failed: {exc}")
        print(f"[FAIL] TLS/CT: {exc}")

    # 2. Fetch /.well-known/edge-integrity.json and cross-check SPKI + headers
    manifest: Optional[Dict[str, object]] = None
    manifest_path = "/.well-known/edge-integrity.json"
    try:
        status, m_headers, m_body = fetch_https_tls13(host, args.port, manifest_path, args.timeout)
        if status != 200:
            raise RuntimeError(f"{manifest_path} returned HTTP {status}")
        verify_security_headers(manifest_path, m_headers)

        m_digest_b64 = base64.b64encode(hashlib.sha256(m_body).digest()).decode("ascii")
        expected_m_cd = f"sha-256=:{m_digest_b64}:"
        actual_m_cd = header_values_ci(m_headers, "content-digest")
        if actual_m_cd != [expected_m_cd]:
            raise RuntimeError(
                f"{manifest_path} Content-Digest mismatch: got {actual_m_cd!r}, expected {expected_m_cd!r}"
            )

        manifest = json.loads(m_body.decode("utf-8"))
        if manifest.get("schema") != "zero-proxy.integrity.v1":
            raise RuntimeError(f"unexpected manifest schema: {manifest.get('schema')!r}")
        if str(manifest.get("host", "")).lower() != host:
            raise RuntimeError(f"manifest host mismatch: {manifest.get('host')!r} != {host!r}")
        if manifest.get("tls_min_version") != "1.3":
            raise RuntimeError(f"manifest tls_min_version != 1.3: {manifest.get('tls_min_version')!r}")

        if cert_der is not None:
            if manifest.get("cert_spki_sha256") != spki_b64:
                raise RuntimeError("SPKI SHA-256 (base64) mismatch between live cert and manifest")
            if str(manifest.get("cert_spki_sha256_hex", "")).lower() != spki_hex:
                raise RuntimeError("SPKI SHA-256 (hex) mismatch between live cert and manifest")
            if str(manifest.get("cert_sha256_hex", "")).lower() != cert_hex:
                raise RuntimeError("Leaf cert SHA-256 mismatch between live cert and manifest")

        print(
            f"[PASS] SPKI integrity manifest: exact bit-for-bit match (spki_sha256={spki_b64}, days_remaining={manifest.get('cert_days_remaining')})"
        )
    except Exception as exc:  # noqa: BLE001
        failures.append(f"Integrity manifest check failed: {exc}")
        print(f"[FAIL] Integrity manifest: {exc}")

    # 3 & 4. Verify configured asset bodies vs Content-Digest AND manifest + headers
    required_assets = args.asset if args.asset else ["/"]
    manifest_assets: Dict[str, Dict[str, object]] = {}
    if isinstance(manifest, dict) and isinstance(manifest.get("static_assets"), list):
        for entry in manifest["static_assets"]:
            if isinstance(entry, dict) and isinstance(entry.get("path"), str):
                manifest_assets[entry["path"]] = entry

    for asset_path in required_assets:
        try:
            if asset_path not in manifest_assets:
                raise RuntimeError(f"{asset_path} missing from integrity manifest static_assets")
            entry = manifest_assets[asset_path]
            status, headers, body = fetch_https_tls13(host, args.port, asset_path, args.timeout)
            if status != 200:
                raise RuntimeError(f"{asset_path} returned HTTP {status}")
            verify_security_headers(asset_path, headers)

            digest = hashlib.sha256(body).digest()
            digest_hex = digest.hex()
            digest_b64 = base64.b64encode(digest).decode("ascii")
            expected_cd = f"sha-256=:{digest_b64}:"

            actual_cd = header_values_ci(headers, "content-digest")
            if actual_cd != [expected_cd]:
                raise RuntimeError(
                    f"{asset_path} Content-Digest header mismatch: got {actual_cd!r}, expected {expected_cd!r}"
                )
            if entry.get("size_bytes") != len(body):
                raise RuntimeError(
                    f"{asset_path} size mismatch: live={len(body)}, manifest={entry.get('size_bytes')}"
                )
            if str(entry.get("sha256_hex", "")).lower() != digest_hex:
                raise RuntimeError(f"{asset_path} sha256_hex mismatch against manifest")
            if entry.get("content_digest") != expected_cd:
                raise RuntimeError(f"{asset_path} content_digest mismatch against manifest")

            print(
                f"[PASS] Asset {asset_path}: {len(body)}B verified (Content-Digest + manifest + HSTS/Permissions-Policy/0-Server)"
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"Asset {asset_path} failed: {exc}")
            print(f"[FAIL] Asset {asset_path}: {exc}")

    # 5. Optional DNS CAA check (pure stdlib UDP/TCP DNS query)
    if args.expected_caa is None:
        print("[SKIP] DNS CAA (pass --expected-caa <ca-domain> to enforce)")
    else:
        try:
            caa_records, ad_flag, resolver = query_dns_caa(host, args.dns_server, args.timeout)
            expected_ca = args.expected_caa.strip().lower()
            matched = [
                rec
                for rec in caa_records
                if rec[1].lower() in ("issue", "issuewild")
                and rec[2].split(";", 1)[0].strip().lower() == expected_ca
            ]
            if not matched:
                raise RuntimeError(
                    f"no CAA issue/issuewild record authorizing {expected_ca!r} (got {caa_records!r} via {resolver})"
                )
            rec_summary = ", ".join(f"{f} {t} \"{v}\"" for f, t, v in caa_records)
            print(
                f"[PASS] DNS CAA ({resolver}): [{rec_summary}] (DNSSEC AD={'1' if ad_flag else '0'})"
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"DNS CAA check failed: {exc}")
            print(f"[FAIL] DNS CAA: {exc}")

    if failures:
        print(f"RESULT: FAILED ({len(failures)} error(s))")
        return 1

    print("RESULT: ALL EDGE INTEGRITY CHECKS PASSED (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
