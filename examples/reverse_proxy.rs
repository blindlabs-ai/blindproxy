#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use zero_proxy::xdp::bpf_emit::{emit_xdp_program, execute_bpf_program, verify_bpf_program};
use zero_proxy::xdp::{
    filter_packet, UdpFilterConfig, UdpPacketHdr, XdpAction, ETH_P_IP, IPPROTO_UDP,
    IPV4_MIN_HDR_BYTES, UDP_HDR_BYTES, UDP_PACKET_HDR_BYTES, XDP_DROP, XDP_PASS,
};
use zero_proxy::{ProxyConfig, ProxyServer};

fn build_demo_udp_frame(cfg: &UdpFilterConfig, payload: &[u8]) -> Vec<u8> {
    let hdr = UdpPacketHdr::new(1, 0, 0, 0x1234_5678, 1, 0, payload.len() as u16)
        .with_magic(cfg.magic_be)
        .sign(cfg.mac_key);

    let udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + payload.len()) as u16;
    let ip_tot_len = (IPV4_MIN_HDR_BYTES + usize::from(udp_len)) as u16;

    let mut frame = Vec::with_capacity(14 + usize::from(ip_tot_len));
    // Ethernet II header (dst MAC, src MAC, EtherType = IPv4).
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    frame.extend_from_slice(&ETH_P_IP.to_be_bytes());

    // Minimal 20-byte IPv4 header.
    frame.push(0x45);
    frame.push(0x00);
    frame.extend_from_slice(&ip_tot_len.to_be_bytes());
    frame.extend_from_slice(&0x0001u16.to_be_bytes());
    frame.extend_from_slice(&0x0000u16.to_be_bytes());
    frame.push(64);
    frame.push(IPPROTO_UDP);
    frame.extend_from_slice(&0x0000u16.to_be_bytes());
    frame.extend_from_slice(&[10, 0, 0, 2]);
    frame.extend_from_slice(&[10, 0, 0, 1]);

    // UDP header + 32-byte authenticated packet header + payload.
    frame.extend_from_slice(&49_000u16.to_be_bytes());
    frame.extend_from_slice(&cfg.udp_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&0x0000u16.to_be_bytes());
    frame.extend_from_slice(&hdr.to_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn main() {
    // 1. Start a minimal local ephemeral HTTP/1.1 upstream on 127.0.0.1:0.
    let upstream_listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream");
    let upstream_addr = upstream_listener.local_addr().expect("upstream addr");
    let upstream_thread = thread::spawn(move || {
        let (mut stream, _) = upstream_listener.accept().expect("accept upstream");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut req_buf = [0u8; 1024];
        let _ = stream.read(&mut req_buf);
        let body = b"{\"ok\":true}";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(resp.as_bytes())
            .expect("write upstream head");
        stream.write_all(body).expect("write upstream body");
    });

    // 2. Start Zero-Proxy on 127.0.0.1:0 routing /api/ to the local upstream.
    let mut cfg = ProxyConfig {
        listen: SocketAddr::from(([127, 0, 0, 1], 0)),
        ..ProxyConfig::default()
    };
    cfg.add_route_spec(&format!("/api/={}", upstream_addr))
        .expect("configure /api/ route");

    let server = ProxyServer::bind(cfg).expect("bind zero-proxy");
    let proxy_addr = server.local_addr();
    let handle = server.handle();
    let proxy_thread = thread::spawn(move || {
        let _ = server.run();
    });

    // 3. Send HTTP/1.1 GET /api/ping and verify 200 OK + JSON body.
    let mut client = TcpStream::connect(proxy_addr).expect("connect to proxy");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    client
        .write_all(b"GET /api/ping HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
        .expect("send request");
    let mut resp = String::new();
    client.read_to_string(&mut resp).expect("read response");
    assert!(
        resp.starts_with("HTTP/1.1 200 OK\r\n"),
        "unexpected response: {}",
        resp
    );
    assert!(
        resp.ends_with("{\"ok\":true}"),
        "unexpected body: {}",
        resp
    );

    handle.stop();
    proxy_thread.join().expect("join proxy thread");
    upstream_thread.join().expect("join upstream thread");

    // 4. Emit, statically verify, and execute the RFC 9669 eBPF UDP filter.
    let xdp_cfg = UdpFilterConfig::default();
    let prog = emit_xdp_program(&xdp_cfg);
    let summary = verify_bpf_program(&prog).expect("verify emitted eBPF program");
    assert!(summary.is_dag, "emitted eBPF program must be a DAG");

    let valid_frame = build_demo_udp_frame(&xdp_cfg, b"hello zero-proxy");
    let pass_verdict = filter_packet(&valid_frame, &xdp_cfg);
    assert_eq!(pass_verdict.action, XdpAction::Pass);
    assert_eq!(
        execute_bpf_program(&prog, &valid_frame).expect("execute eBPF VM on valid frame"),
        XDP_PASS
    );

    // Flip 1 bit in the SipHash-2-4 header MAC and verify deterministic XDP_DROP.
    let mut tampered_frame = valid_frame;
    let mac_offset = 14 + IPV4_MIN_HDR_BYTES + UDP_HDR_BYTES + 24;
    tampered_frame[mac_offset] ^= 0x01;
    let drop_verdict = filter_packet(&tampered_frame, &xdp_cfg);
    assert_eq!(drop_verdict.action, XdpAction::Drop);
    assert_eq!(
        execute_bpf_program(&prog, &tampered_frame).expect("execute eBPF VM on tampered frame"),
        XDP_DROP
    );

    println!(
        "zero-proxy reverse_proxy example OK: HTTP 200 verified; eBPF DAG verified ({} insns), valid=XDP_PASS, tampered=XDP_DROP",
        prog.len()
    );
}
