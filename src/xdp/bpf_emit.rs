//! Zero-dependency pure-Rust Linux 64-bit eBPF ISA compiler, static packet-bounds
//! verifier, and instruction-level VM for the configurable UDP XDP filter.
//!
//! No C compiler (`clang`/`llvm`) or external crate is required. Calling
//! [`emit_xdp_program`] directly produces verifier-clean RFC 9669 / Linux eBPF
//! bytecode (`Vec<[u8; 8]>`) with exact wire parity to [`super::filter_packet`].

use core::fmt;

use super::{
    effective_mac_key, UdpFilterConfig, ETH_HDR_BYTES, ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP,
    ETH_P_IPV6, FLAG_COMPRESSED, FLAG_PARITY, IPPROTO_UDP, IPV4_FRAG_OFF_MASK, IPV4_MIN_HDR_BYTES,
    IPV6_HDR_BYTES, MAX_UDP_DATAGRAM_BYTES, UDP_HDR_BYTES, UDP_PACKET_HDR_BYTES, VLAN_HDR_BYTES,
    XDP_DROP, XDP_PASS,
};

// --- RFC 9669 / Linux UAPI eBPF opcode constants ---

const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_JMP32: u8 = 0x06;
const BPF_ALU64: u8 = 0x07;

const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;

const BPF_IMM: u8 = 0x00;
const BPF_MEM: u8 = 0x60;

const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;
const BPF_TO_BE: u8 = 0x08;

const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_MUL: u8 = 0x20;
const BPF_DIV: u8 = 0x30;
const BPF_OR: u8 = 0x40;
const BPF_AND: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_NEG: u8 = 0x80;
const BPF_MOD: u8 = 0x90;
const BPF_XOR: u8 = 0xA0;
const BPF_MOV: u8 = 0xB0;
const BPF_ARSH: u8 = 0xC0;
const BPF_END: u8 = 0xD0;

const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JSET: u8 = 0x40;
const BPF_JNE: u8 = 0x50;
const BPF_JSGT: u8 = 0x60;
const BPF_JSGE: u8 = 0x70;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_JLT: u8 = 0xA0;
const BPF_JLE: u8 = 0xB0;
const BPF_JSLT: u8 = 0xC0;
const BPF_JSLE: u8 = 0xD0;

const OP_LD_IMM64: u8 = BPF_LD | BPF_DW | BPF_IMM;
const OP_JA: u8 = BPF_JMP | BPF_JA;
const OP_CALL: u8 = BPF_JMP | BPF_CALL;
const OP_EXIT: u8 = BPF_JMP | BPF_EXIT;
const OP_END_BE: u8 = BPF_ALU | BPF_END | BPF_TO_BE;

const R0: u8 = 0;
const R1: u8 = 1;
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R5: u8 = 5;
const R6: u8 = 6;
const R7: u8 = 7;
const R8: u8 = 8;
const R9: u8 = 9;
const R10: u8 = 10;

const MAX_BPF_INSNS: usize = 1_000_000;
const MAX_PACKET_OFF: u64 = 65_535;
const MAX_VM_STEPS: usize = 100_000;

const CTX_BASE: u64 = 0x1000_0000;
const PKT_BASE: u64 = 0x2000_0000;
const STACK_BASE: u64 = 0x3000_0000;
const STACK_SIZE: usize = 512;

/// Summary metrics produced by [`verify_bpf_program`] on an accepted program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfVerifySummary {
    /// Total 8-byte eBPF instruction slots (counting each `LD_IMM64` as 2).
    pub insn_count: usize,
    /// Number of memory load instructions verified against packet/ctx/stack bounds.
    pub load_count: usize,
    /// Number of conditional or unconditional branch instructions.
    pub branch_count: usize,
    /// True when every jump strictly moves forward (acyclic guaranteed termination).
    pub is_dag: bool,
}

/// Errors reported by [`verify_bpf_program`] or [`execute_bpf_program`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfError {
    /// Program contains zero instructions.
    EmptyProgram,
    /// Program exceeds the Linux 1,000,000-instruction verifier limit.
    TooManyInstructions,
    /// `LD_IMM64` appears in the final slot with no 2nd immediate slot.
    TruncatedLdImm64,
    /// Unrecognized or invalid eBPF opcode at `pc`.
    InvalidOpcode {
        /// Instruction index.
        pc: usize,
        /// Raw opcode byte.
        opcode: u8,
    },
    /// Register index outside `R0..=R10`.
    InvalidRegister {
        /// Instruction index.
        pc: usize,
        /// Invalid register number.
        reg: u8,
    },
    /// Attempted write to read-only frame pointer `R10`.
    ReadOnlyFramePointerWrite {
        /// Instruction index.
        pc: usize,
    },
    /// Jump target falls outside `0..insns.len()`.
    JumpTargetOutOfRange {
        /// Instruction index.
        pc: usize,
        /// Computed out-of-bounds target PC.
        target: i64,
    },
    /// Negative jump offset violates strict forward-DAG termination invariant.
    BackwardJump {
        /// Instruction index.
        pc: usize,
        /// Raw signed offset.
        off: i16,
    },
    /// Jump lands on the second 8-byte slot of a `LD_IMM64` instruction.
    JumpIntoLdImm64SecondSlot {
        /// Instruction index.
        pc: usize,
        /// Illegal landing PC.
        target: usize,
    },
    /// Execution path reaches the end of the program without `BPF_EXIT`.
    MissingExit {
        /// Instruction index.
        pc: usize,
    },
    /// Instruction reads an uninitialized register (including `R0` at `BPF_EXIT`).
    UninitializedRegisterRead {
        /// Instruction index.
        pc: usize,
        /// Uninitialized register number.
        reg: u8,
    },
    /// Packet load or variable pointer add is not dominated by a `data_end` check.
    PacketBoundsNotProven {
        /// Instruction index.
        pc: usize,
        /// Requested memory offset.
        offset: i16,
        /// Access width in bytes.
        size: usize,
    },
    /// Runtime VM load/store attempted out-of-bounds memory access.
    InvalidMemoryAccess {
        /// Instruction index.
        pc: usize,
        /// Virtual address.
        addr: u64,
        /// Access width in bytes.
        size: usize,
    },
    /// Helper call is unsupported by standalone XDP VM.
    UnsupportedHelper {
        /// Instruction index.
        pc: usize,
        /// Helper identifier immediate.
        id: i32,
    },
    /// Runtime VM exceeded its bounded step limit.
    StepLimitExceeded,
}

impl fmt::Display for BpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProgram => write!(f, "empty eBPF program"),
            Self::TooManyInstructions => write!(f, "eBPF program exceeds 1M instruction limit"),
            Self::TruncatedLdImm64 => write!(f, "truncated LD_IMM64 instruction"),
            Self::InvalidOpcode { pc, opcode } => {
                write!(f, "invalid opcode 0x{opcode:02x} at pc={pc}")
            }
            Self::InvalidRegister { pc, reg } => write!(f, "invalid register r{reg} at pc={pc}"),
            Self::ReadOnlyFramePointerWrite { pc } => write!(f, "write to read-only r10 at pc={pc}"),
            Self::JumpTargetOutOfRange { pc, target } => {
                write!(f, "jump target {target} out of range at pc={pc}")
            }
            Self::BackwardJump { pc, off } => write!(f, "backward jump off={off} at pc={pc}"),
            Self::JumpIntoLdImm64SecondSlot { pc, target } => {
                write!(f, "jump into LD_IMM64 second slot {target} at pc={pc}")
            }
            Self::MissingExit { pc } => write!(f, "missing BPF_EXIT at pc={pc}"),
            Self::UninitializedRegisterRead { pc, reg } => {
                write!(f, "uninitialized register r{reg} read at pc={pc}")
            }
            Self::PacketBoundsNotProven { pc, offset, size } => {
                write!(
                    f,
                    "packet bounds not proven for off={offset} size={size} at pc={pc}"
                )
            }
            Self::InvalidMemoryAccess { pc, addr, size } => {
                write!(
                    f,
                    "invalid memory access addr=0x{addr:x} size={size} at pc={pc}"
                )
            }
            Self::UnsupportedHelper { pc, id } => {
                write!(f, "unsupported BPF helper #{id} at pc={pc}")
            }
            Self::StepLimitExceeded => write!(f, "eBPF VM exceeded step limit"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodedInsn {
    op: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
}

#[inline]
const fn encode_insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let regs = ((src & 0x0F) << 4) | (dst & 0x0F);
    let off_b = off.to_le_bytes();
    let imm_b = imm.to_le_bytes();
    [
        op, regs, off_b[0], off_b[1], imm_b[0], imm_b[1], imm_b[2], imm_b[3],
    ]
}

#[inline]
const fn decode_insn(raw: [u8; 8]) -> DecodedInsn {
    DecodedInsn {
        op: raw[0],
        dst: raw[1] & 0x0F,
        src: (raw[1] >> 4) & 0x0F,
        off: i16::from_le_bytes([raw[2], raw[3]]),
        imm: i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
    }
}

#[inline]
const fn mem_size_bytes(size_bits: u8) -> Option<usize> {
    match size_bits {
        BPF_W => Some(4),
        BPF_H => Some(2),
        BPF_B => Some(1),
        BPF_DW => Some(8),
        _ => None,
    }
}

struct BpfAsm {
    insns: Vec<[u8; 8]>,
}

impl BpfAsm {
    fn new() -> Self {
        Self {
            insns: Vec::with_capacity(560),
        }
    }

    fn emit(&mut self, op: u8, dst: u8, src: u8, off: i16, imm: i32) {
        self.insns.push(encode_insn(op, dst, src, off, imm));
    }

    fn mov64_reg(&mut self, dst: u8, src: u8) {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0);
    }

    fn mov64_imm(&mut self, dst: u8, imm: i32) {
        self.emit(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm);
    }

    fn alu64_reg(&mut self, alu: u8, dst: u8, src: u8) {
        self.emit(BPF_ALU64 | alu | BPF_X, dst, src, 0, 0);
    }

    fn alu64_imm(&mut self, alu: u8, dst: u8, imm: i32) {
        self.emit(BPF_ALU64 | alu | BPF_K, dst, 0, 0, imm);
    }

    fn bswap(&mut self, dst: u8, bits: i32) {
        self.emit(OP_END_BE, dst, 0, 0, bits);
    }

    fn ldx(&mut self, size: u8, dst: u8, src: u8, off: i16) {
        self.emit(BPF_LDX | BPF_MEM | size, dst, src, off, 0);
    }

    fn ld_imm64(&mut self, dst: u8, val: u64) {
        let lo = (val & 0xFFFF_FFFF) as u32 as i32;
        let hi = (val >> 32) as u32 as i32;
        self.emit(OP_LD_IMM64, dst, 0, 0, lo);
        self.emit(0, 0, 0, 0, hi);
    }

    fn jmp_reg(&mut self, cond: u8, dst: u8, src: u8) -> usize {
        let idx = self.insns.len();
        self.emit(BPF_JMP | cond | BPF_X, dst, src, 0, 0);
        idx
    }

    fn jmp_imm(&mut self, cond: u8, dst: u8, imm: i32) -> usize {
        let idx = self.insns.len();
        self.emit(BPF_JMP | cond | BPF_K, dst, 0, 0, imm);
        idx
    }

    fn ja(&mut self) -> usize {
        let idx = self.insns.len();
        self.emit(OP_JA, 0, 0, 0, 0);
        idx
    }

    fn exit(&mut self) {
        self.emit(OP_EXIT, 0, 0, 0, 0);
    }

    fn patch_to_here(&mut self, idx: usize) {
        let target = self.insns.len();
        let rel = target.saturating_sub(idx + 1);
        let off = i16::try_from(rel).unwrap_or(i16::MAX);
        let bytes = off.to_le_bytes();
        self.insns[idx][2] = bytes[0];
        self.insns[idx][3] = bytes[1];
    }

    fn patch_all(&mut self, indices: &[usize]) {
        for &idx in indices {
            self.patch_to_here(idx);
        }
    }
}

fn emit_pkt_bounds_check(asm: &mut BpfAsm, ptr_reg: u8, bytes: i32, fail_jumps: &mut Vec<usize>) {
    asm.mov64_reg(R2, ptr_reg);
    asm.alu64_imm(BPF_ADD, R2, bytes);
    fail_jumps.push(asm.jmp_reg(BPF_JGT, R2, R7));
}

fn emit_vlan_unwrap(asm: &mut BpfAsm, pass_jumps: &mut Vec<usize>) {
    let j_8021q = asm.jmp_imm(BPF_JEQ, R3, ETH_P_8021Q as i32);
    let j_skip = asm.jmp_imm(BPF_JNE, R3, ETH_P_8021AD as i32);
    asm.patch_to_here(j_8021q);

    emit_pkt_bounds_check(asm, R6, VLAN_HDR_BYTES as i32, pass_jumps);
    asm.ldx(BPF_H, R3, R6, 2);
    asm.bswap(R3, 16);
    asm.mov64_reg(R6, R2);

    asm.patch_to_here(j_skip);
}

fn emit_rotl64(asm: &mut BpfAsm, reg: u8, bits: i32) {
    asm.mov64_reg(R5, reg);
    asm.alu64_imm(BPF_LSH, reg, bits);
    asm.alu64_imm(BPF_RSH, R5, 64 - bits);
    asm.alu64_reg(BPF_OR, reg, R5);
}

fn emit_sipround(asm: &mut BpfAsm) {
    for &(dst, src, rot, rot_dst) in &[
        (R0, R1, 13, true),
        (R2, R3, 16, false),
        (R0, R3, 21, false),
        (R2, R1, 17, true),
    ] {
        asm.alu64_reg(BPF_ADD, dst, src);
        emit_rotl64(asm, src, rot);
        asm.alu64_reg(BPF_XOR, src, dst);
        if rot_dst {
            emit_rotl64(asm, dst, 32);
        }
    }
}

fn emit_sip_absorb_r4(asm: &mut BpfAsm) {
    asm.alu64_reg(BPF_XOR, R3, R4);
    emit_sipround(asm);
    emit_sipround(asm);
    asm.alu64_reg(BPF_XOR, R0, R4);
}

fn emit_l3_ipv4(asm: &mut BpfAsm, pass_jumps: &mut Vec<usize>) -> usize {
    emit_pkt_bounds_check(asm, R6, IPV4_MIN_HDR_BYTES as i32, pass_jumps);

    asm.ldx(BPF_B, R1, R6, 0);
    asm.mov64_reg(R2, R1);
    asm.alu64_imm(BPF_RSH, R2, 4);
    pass_jumps.push(asm.jmp_imm(BPF_JNE, R2, 4));

    asm.alu64_imm(BPF_AND, R1, 0x0F);
    pass_jumps.push(asm.jmp_imm(BPF_JLT, R1, 5));

    asm.ldx(BPF_B, R2, R6, 9);
    pass_jumps.push(asm.jmp_imm(BPF_JNE, R2, IPPROTO_UDP as i32));

    asm.ldx(BPF_H, R2, R6, 6);
    asm.bswap(R2, 16);
    asm.mov64_reg(R4, R2);
    asm.alu64_imm(BPF_AND, R4, IPV4_FRAG_OFF_MASK as i32);
    pass_jumps.push(asm.jmp_imm(BPF_JNE, R4, 0));

    // Extract MF bit (0x2000 >> 13) into R9 as 0 or 1.
    asm.mov64_reg(R9, R2);
    asm.alu64_imm(BPF_RSH, R9, 13);
    asm.alu64_imm(BPF_AND, R9, 1);

    // ihl_bytes = ihl * 4 (provably in [20, 60]).
    asm.alu64_imm(BPF_LSH, R1, 2);
    asm.ldx(BPF_H, R8, R6, 2);
    asm.bswap(R8, 16);

    asm.mov64_reg(R2, R1);
    asm.alu64_imm(BPF_ADD, R2, UDP_HDR_BYTES as i32);
    pass_jumps.push(asm.jmp_reg(BPF_JLT, R8, R2));

    // l4_avail = ip_tot_len - ihl_bytes.
    asm.alu64_reg(BPF_SUB, R8, R1);
    // udph = iph + ihl_bytes; verify udph + 8 <= data_end.
    asm.alu64_reg(BPF_ADD, R6, R1);
    emit_pkt_bounds_check(asm, R6, UDP_HDR_BYTES as i32, pass_jumps);

    asm.ja()
}

fn emit_l3_ipv6(asm: &mut BpfAsm, pass_jumps: &mut Vec<usize>) {
    emit_pkt_bounds_check(asm, R6, IPV6_HDR_BYTES as i32, pass_jumps);

    asm.ldx(BPF_B, R1, R6, 0);
    asm.alu64_imm(BPF_RSH, R1, 4);
    pass_jumps.push(asm.jmp_imm(BPF_JNE, R1, 6));

    asm.ldx(BPF_B, R1, R6, 6);
    pass_jumps.push(asm.jmp_imm(BPF_JNE, R1, IPPROTO_UDP as i32));

    asm.ldx(BPF_H, R8, R6, 4);
    asm.bswap(R8, 16);
    asm.mov64_imm(R9, 0);

    asm.alu64_imm(BPF_ADD, R6, IPV6_HDR_BYTES as i32);
    emit_pkt_bounds_check(asm, R6, UDP_HDR_BYTES as i32, pass_jumps);
}

fn emit_udp_header_checks(asm: &mut BpfAsm, cfg: &UdpFilterConfig, drop_jumps: &mut Vec<usize>) {
    let min_udp = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES) as i32;

    // 1. Truncation & length bounds.
    asm.ldx(BPF_H, R5, R6, 4);
    asm.bswap(R5, 16);
    drop_jumps.push(asm.jmp_imm(BPF_JLT, R5, min_udp));
    drop_jumps.push(asm.jmp_reg(BPF_JGT, R5, R8));
    drop_jumps.push(asm.jmp_imm(BPF_JGT, R5, MAX_UDP_DATAGRAM_BYTES as i32));

    // Check full UDP datagram fits in packet (R5 provably in [40, 16384]).
    asm.mov64_reg(R2, R6);
    asm.alu64_reg(BPF_ADD, R2, R5);
    drop_jumps.push(asm.jmp_reg(BPF_JGT, R2, R7));

    // Advance R6 to hdr = udph + 8 and prove constant 32-byte range for verifier.
    asm.alu64_imm(BPF_ADD, R6, UDP_HDR_BYTES as i32);
    emit_pkt_bounds_check(asm, R6, UDP_PACKET_HDR_BYTES as i32, drop_jumps);

    // 2. Magic check (handles full 32-bit unsigned magic without sign-extension).
    asm.ldx(BPF_W, R1, R6, 0);
    asm.bswap(R1, 32);
    asm.ld_imm64(R2, cfg.magic_be as u64);
    drop_jumps.push(asm.jmp_reg(BPF_JNE, R1, R2));

    // 3. IPv4 MF guard, slot/flag parity rules, reserved, stream_id, payload bounds.
    drop_jumps.push(asm.jmp_imm(BPF_JNE, R9, 0));

    asm.ldx(BPF_B, R1, R6, 8);
    drop_jumps.push(asm.jmp_imm(BPF_JGE, R1, cfg.total_slots() as i32));

    asm.ldx(BPF_B, R2, R6, 9);
    asm.mov64_reg(R3, R2);
    asm.alu64_imm(BPF_AND, R3, 0xF8);
    drop_jumps.push(asm.jmp_imm(BPF_JNE, R3, 0));

    let j_parity = asm.jmp_imm(BPF_JGE, R1, cfg.data_slots as i32);
    // Data shard (0..data_slots): PARITY flag must be 0.
    asm.mov64_reg(R3, R2);
    asm.alu64_imm(BPF_AND, R3, FLAG_PARITY as i32);
    drop_jumps.push(asm.jmp_imm(BPF_JNE, R3, 0));
    let j_after_flags = asm.ja();

    // Parity shard (data_slots..total_slots): PARITY flag must be 1 and COMPRESSED must be 0.
    asm.patch_to_here(j_parity);
    asm.mov64_reg(R3, R2);
    asm.alu64_imm(BPF_AND, R3, FLAG_PARITY as i32);
    drop_jumps.push(asm.jmp_imm(BPF_JEQ, R3, 0));
    asm.mov64_reg(R3, R2);
    asm.alu64_imm(BPF_AND, R3, FLAG_COMPRESSED as i32);
    drop_jumps.push(asm.jmp_imm(BPF_JNE, R3, 0));
    asm.patch_to_here(j_after_flags);

    asm.ldx(BPF_H, R1, R6, 10);
    drop_jumps.push(asm.jmp_imm(BPF_JNE, R1, 0));

    asm.ldx(BPF_W, R1, R6, 16);
    drop_jumps.push(asm.jmp_imm(BPF_JEQ, R1, 0));

    asm.ldx(BPF_H, R1, R6, 22);
    asm.bswap(R1, 16);
    drop_jumps.push(asm.jmp_imm(BPF_JEQ, R1, 0));
    drop_jumps.push(asm.jmp_imm(BPF_JGT, R1, cfg.max_payload_bytes as i32));

    asm.mov64_reg(R2, R5);
    asm.alu64_imm(BPF_SUB, R2, min_udp);
    drop_jumps.push(asm.jmp_reg(BPF_JNE, R1, R2));

    asm.ldx(BPF_H, R3, R6, 20);
    asm.bswap(R3, 16);
    asm.alu64_reg(BPF_ADD, R3, R1);
    let max_frame_i32 = cfg.max_frame_bytes.min(0x0002_0000) as i32;
    drop_jumps.push(asm.jmp_imm(BPF_JGT, R3, max_frame_i32));
}

fn emit_siphash24_mac_check(asm: &mut BpfAsm, mac_key: [u64; 2], drop_jumps: &mut Vec<usize>) {
    let [k0, k1] = effective_mac_key(mac_key);

    asm.ld_imm64(R0, 0x736f_6d65_7073_6575u64 ^ k0);
    asm.ld_imm64(R1, 0x646f_7261_6e64_6f6du64 ^ k1);
    asm.ld_imm64(R2, 0x6c79_6765_6e65_7261u64 ^ k0);
    asm.ld_imm64(R3, 0x7465_6462_7974_6573u64 ^ k1);

    for word_off in [0i16, 8i16, 16i16] {
        asm.ldx(BPF_DW, R4, R6, word_off);
        emit_sip_absorb_r4(asm);
    }

    asm.ld_imm64(R4, 24u64 << 56);
    emit_sip_absorb_r4(asm);

    asm.alu64_imm(BPF_XOR, R2, 0xFF);
    for _ in 0..4 {
        emit_sipround(asm);
    }

    asm.alu64_reg(BPF_XOR, R0, R1);
    asm.alu64_reg(BPF_XOR, R0, R2);
    asm.alu64_reg(BPF_XOR, R0, R3);

    asm.ldx(BPF_DW, R4, R6, 24);
    asm.bswap(R4, 64);
    drop_jumps.push(asm.jmp_reg(BPF_JNE, R0, R4));
}

/// Emits standalone, verifier-clean Linux 64-bit eBPF XDP bytecode directly
/// from safe Rust with zero C compiler dependency.
///
/// The emitted program takes `struct xdp_md *ctx` in `R1`, performs zero stack
/// spills and zero backward branches, proves every packet load against
/// `ctx->data_end`, and returns `XDP_PASS` (`2`) or `XDP_DROP` (`1`) in `R0`.
pub fn emit_xdp_program(cfg: &UdpFilterConfig) -> Vec<[u8; 8]> {
    let mut asm = BpfAsm::new();
    let mut pass_jumps = Vec::new();
    let mut drop_jumps = Vec::new();

    // Load data (R6) and data_end (R7) from struct xdp_md *ctx (R1).
    asm.ldx(BPF_W, R6, R1, 0);
    asm.ldx(BPF_W, R7, R1, 4);

    // Ethernet II header (14 bytes).
    emit_pkt_bounds_check(&mut asm, R6, ETH_HDR_BYTES as i32, &mut pass_jumps);
    asm.ldx(BPF_H, R3, R6, 12);
    asm.bswap(R3, 16);
    asm.mov64_reg(R6, R2);

    // Up to 2 stacked 802.1Q / 802.1ad VLAN tags.
    for _ in 0..2 {
        emit_vlan_unwrap(&mut asm, &mut pass_jumps);
    }

    // L3 dispatch: IPv4 vs IPv6 vs non-IP pass.
    let j_ipv4 = asm.jmp_imm(BPF_JEQ, R3, ETH_P_IP as i32);
    let j_ipv6 = asm.jmp_imm(BPF_JEQ, R3, ETH_P_IPV6 as i32);
    pass_jumps.push(asm.ja());

    asm.patch_to_here(j_ipv4);
    let j_v4_to_udp = emit_l3_ipv4(&mut asm, &mut pass_jumps);

    asm.patch_to_here(j_ipv6);
    emit_l3_ipv6(&mut asm, &mut pass_jumps);

    // UDP destination port fast-path bypass.
    asm.patch_to_here(j_v4_to_udp);
    asm.ldx(BPF_H, R1, R6, 2);
    asm.bswap(R1, 16);
    pass_jumps.push(asm.jmp_imm(BPF_JNE, R1, cfg.udp_port as i32));

    // Strict target UDP header checks + keyed SipHash-2-4 header MAC.
    emit_udp_header_checks(&mut asm, cfg, &mut drop_jumps);
    emit_siphash24_mac_check(&mut asm, cfg.mac_key, &mut drop_jumps);

    // Pass return block.
    asm.patch_all(&pass_jumps);
    asm.mov64_imm(R0, XDP_PASS as i32);
    asm.exit();

    // Drop return block.
    asm.patch_all(&drop_jumps);
    asm.mov64_imm(R0, XDP_DROP as i32);
    asm.exit();

    asm.insns
}

// --- Static eBPF Verifier (DAG + Packet-Bounds Abstract Interpreter) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegAbs {
    Uninit,
    CtxPtr,
    FramePtr,
    PktPtr {
        id: u32,
        const_off: u32,
        proven_range: u32,
    },
    PktEnd,
    Scalar {
        umin: u64,
        umax: u64,
    },
}

#[derive(Debug, Clone, Copy)]
struct AbsState {
    regs: [RegAbs; 11],
}

impl AbsState {
    fn entry() -> Self {
        let mut regs = [RegAbs::Uninit; 11];
        regs[1] = RegAbs::CtxPtr; // R1
        regs[10] = RegAbs::FramePtr; // R10
        Self { regs }
    }
}

fn join_reg(a: RegAbs, b: RegAbs, join_id: u32) -> RegAbs {
    match (a, b) {
        (RegAbs::CtxPtr, RegAbs::CtxPtr) => RegAbs::CtxPtr,
        (RegAbs::FramePtr, RegAbs::FramePtr) => RegAbs::FramePtr,
        (RegAbs::PktEnd, RegAbs::PktEnd) => RegAbs::PktEnd,
        (
            RegAbs::PktPtr {
                id: id_a,
                const_off: off_a,
                proven_range: pr_a,
            },
            RegAbs::PktPtr {
                id: id_b,
                const_off: off_b,
                proven_range: pr_b,
            },
        ) => {
            if id_a == id_b && off_a == off_b {
                RegAbs::PktPtr {
                    id: id_a,
                    const_off: off_a,
                    proven_range: pr_a.min(pr_b),
                }
            } else {
                RegAbs::PktPtr {
                    id: join_id,
                    const_off: 0,
                    proven_range: pr_a.min(pr_b),
                }
            }
        }
        (
            RegAbs::Scalar {
                umin: mn_a,
                umax: mx_a,
            },
            RegAbs::Scalar {
                umin: mn_b,
                umax: mx_b,
            },
        ) => RegAbs::Scalar {
            umin: mn_a.min(mn_b),
            umax: mx_a.max(mx_b),
        },
        _ => RegAbs::Uninit,
    }
}

fn merge_state(slot: &mut Option<AbsState>, incoming: AbsState, pc: usize) {
    match slot {
        None => *slot = Some(incoming),
        Some(existing) => {
            let base_id = 0x8000_0000u32.wrapping_add((pc as u32).wrapping_mul(16));
            for i in 0..11 {
                existing.regs[i] = join_reg(existing.regs[i], incoming.regs[i], base_id + i as u32);
            }
        }
    }
}

fn require_init(state: &AbsState, reg: u8, pc: usize) -> Result<RegAbs, BpfError> {
    let r = state.regs[reg as usize];
    if r == RegAbs::Uninit {
        return Err(BpfError::UninitializedRegisterRead { pc, reg });
    }
    Ok(r)
}

fn is_valid_alu_op(alu: u8, is64: bool) -> bool {
    matches!(
        alu,
        BPF_ADD
            | BPF_SUB
            | BPF_MUL
            | BPF_DIV
            | BPF_OR
            | BPF_AND
            | BPF_LSH
            | BPF_RSH
            | BPF_NEG
            | BPF_MOD
            | BPF_XOR
            | BPF_MOV
            | BPF_ARSH
    ) || (!is64 && alu == BPF_END)
}

fn is_valid_cond_jmp(jmp_op: u8) -> bool {
    matches!(
        jmp_op,
        BPF_JEQ
            | BPF_JGT
            | BPF_JGE
            | BPF_JSET
            | BPF_JNE
            | BPF_JSGT
            | BPF_JSGE
            | BPF_JLT
            | BPF_JLE
            | BPF_JSLT
            | BPF_JSLE
    )
}

fn check_structure(insns: &[[u8; 8]]) -> Result<(Vec<bool>, usize, usize), BpfError> {
    if insns.is_empty() {
        return Err(BpfError::EmptyProgram);
    }
    if insns.len() > MAX_BPF_INSNS {
        return Err(BpfError::TooManyInstructions);
    }

    let n = insns.len();
    let mut is_start = vec![false; n];
    let mut load_count = 0usize;
    let mut branch_count = 0usize;

    let mut pc = 0usize;
    while pc < n {
        is_start[pc] = true;
        let d = decode_insn(insns[pc]);
        if d.dst > R10 {
            return Err(BpfError::InvalidRegister { pc, reg: d.dst });
        }
        if d.src > R10 {
            return Err(BpfError::InvalidRegister { pc, reg: d.src });
        }

        if d.op == OP_LD_IMM64 {
            if pc + 1 >= n {
                return Err(BpfError::TruncatedLdImm64);
            }
            if d.dst == R10 {
                return Err(BpfError::ReadOnlyFramePointerWrite { pc });
            }
            pc += 2;
            continue;
        }

        let cls = d.op & 0x07;
        match cls {
            BPF_LDX => {
                if (d.op & 0xE0) != BPF_MEM || mem_size_bytes(d.op & 0x18).is_none() {
                    return Err(BpfError::InvalidOpcode { pc, opcode: d.op });
                }
                if d.dst == R10 {
                    return Err(BpfError::ReadOnlyFramePointerWrite { pc });
                }
                load_count += 1;
            }
            BPF_ST | BPF_STX => {
                if (d.op & 0xE0) != BPF_MEM || mem_size_bytes(d.op & 0x18).is_none() {
                    return Err(BpfError::InvalidOpcode { pc, opcode: d.op });
                }
            }
            BPF_ALU | BPF_ALU64 => {
                let is64 = cls == BPF_ALU64;
                if !is_valid_alu_op(d.op & 0xF0, is64) {
                    return Err(BpfError::InvalidOpcode { pc, opcode: d.op });
                }
                if d.dst == R10 {
                    return Err(BpfError::ReadOnlyFramePointerWrite { pc });
                }
            }
            BPF_JMP | BPF_JMP32 => {
                if d.op == OP_EXIT {
                    // Valid terminal instruction.
                } else if d.op == OP_JA {
                    branch_count += 1;
                } else if d.op == OP_CALL {
                    return Err(BpfError::UnsupportedHelper { pc, id: d.imm });
                } else if is_valid_cond_jmp(d.op & 0xF0) {
                    branch_count += 1;
                } else {
                    return Err(BpfError::InvalidOpcode { pc, opcode: d.op });
                }
            }
            _ => return Err(BpfError::InvalidOpcode { pc, opcode: d.op }),
        }
        pc += 1;
    }

    // Validate all jump targets are strictly forward and land on instruction boundaries.
    pc = 0;
    while pc < n {
        let d = decode_insn(insns[pc]);
        if d.op == OP_LD_IMM64 {
            pc += 2;
            continue;
        }
        let cls = d.op & 0x07;
        let is_jump = (cls == BPF_JMP || cls == BPF_JMP32) && d.op != OP_EXIT && d.op != OP_CALL;
        if is_jump {
            if d.off < 0 {
                return Err(BpfError::BackwardJump { pc, off: d.off });
            }
            let target = (pc as i64) + 1 + (d.off as i64);
            if target < 0 || (target as usize) >= n {
                return Err(BpfError::JumpTargetOutOfRange { pc, target });
            }
            let t = target as usize;
            if !is_start[t] {
                return Err(BpfError::JumpIntoLdImm64SecondSlot { pc, target: t });
            }
        }
        pc += 1;
    }

    Ok((is_start, load_count, branch_count))
}

fn scalar_max_for_width(size: usize) -> u64 {
    match size {
        1 => u8::MAX as u64,
        2 => u16::MAX as u64,
        4 => u32::MAX as u64,
        _ => u64::MAX,
    }
}

fn apply_abs_alu(
    state: &mut AbsState,
    d: DecodedInsn,
    pc: usize,
    next_pkt_id: &mut u32,
) -> Result<(), BpfError> {
    let is64 = (d.op & 0x07) == BPF_ALU64;
    let alu = d.op & 0xF0;
    let is_reg = (d.op & BPF_X) != 0;

    if !is64 && alu == BPF_END {
        let _ = require_init(state, d.dst, pc)?;
        let umax = match d.imm {
            16 => u16::MAX as u64,
            32 => u32::MAX as u64,
            64 => u64::MAX,
            _ => return Err(BpfError::InvalidOpcode { pc, opcode: d.op }),
        };
        state.regs[d.dst as usize] = RegAbs::Scalar { umin: 0, umax };
        return Ok(());
    }

    if alu == BPF_MOV {
        let val = if is_reg {
            let src_val = require_init(state, d.src, pc)?;
            if is64 {
                src_val
            } else {
                RegAbs::Scalar {
                    umin: 0,
                    umax: u32::MAX as u64,
                }
            }
        } else {
            let v = if is64 {
                (d.imm as i64) as u64
            } else {
                (d.imm as u32) as u64
            };
            RegAbs::Scalar { umin: v, umax: v }
        };
        state.regs[d.dst as usize] = val;
        return Ok(());
    }

    let lhs = require_init(state, d.dst, pc)?;
    let rhs = if is_reg {
        require_init(state, d.src, pc)?
    } else {
        let v = if is64 {
            (d.imm as i64) as u64
        } else {
            (d.imm as u32) as u64
        };
        RegAbs::Scalar { umin: v, umax: v }
    };

    // Pointer arithmetic on PTR_TO_PACKET.
    if let RegAbs::PktPtr {
        id,
        const_off,
        proven_range,
    } = lhs
    {
        if is64 && alu == BPF_ADD {
            if let RegAbs::Scalar { umin, umax } = rhs {
                if umin == umax && umax <= MAX_PACKET_OFF {
                    let delta = umax as u32;
                    let new_off = const_off.checked_add(delta).ok_or(
                        BpfError::PacketBoundsNotProven {
                            pc,
                            offset: 0,
                            size: delta as usize,
                        },
                    )?;
                    state.regs[d.dst as usize] = RegAbs::PktPtr {
                        id,
                        const_off: new_off,
                        proven_range: proven_range.saturating_sub(delta),
                    };
                    return Ok(());
                }
                if umax <= MAX_PACKET_OFF {
                    *next_pkt_id = next_pkt_id.wrapping_add(1);
                    state.regs[d.dst as usize] = RegAbs::PktPtr {
                        id: *next_pkt_id,
                        const_off: 0,
                        proven_range: 0,
                    };
                    return Ok(());
                }
            }
        }
        return Err(BpfError::PacketBoundsNotProven {
            pc,
            offset: 0,
            size: 0,
        });
    }

    let (lmin, lmax) = match lhs {
        RegAbs::Scalar { umin, umax } => (umin, umax),
        _ => (0, u64::MAX),
    };
    let (rmin, rmax) = match rhs {
        RegAbs::Scalar { umin, umax } => (umin, umax),
        _ => (0, u64::MAX),
    };

    let (umin, umax) = match alu {
        BPF_AND => (0, lmax.min(rmax)),
        BPF_RSH if rmin == rmax && rmin < 64 => (lmin >> rmin, lmax >> rmin),
        BPF_LSH if rmin == rmax && rmin < 64 => {
            if lmax.leading_zeros() >= (rmin as u32) {
                (lmin << rmin, lmax << rmin)
            } else {
                (0, u64::MAX)
            }
        }
        BPF_ADD => match lmax.checked_add(rmax) {
            Some(mx) => (lmin.saturating_add(rmin), mx),
            None => (0, u64::MAX),
        },
        _ => (0, if is64 { u64::MAX } else { u32::MAX as u64 }),
    };
    state.regs[d.dst as usize] = RegAbs::Scalar { umin, umax };
    Ok(())
}

fn find_good_pkt_pointers(state: &mut AbsState, pkt_reg: u8) {
    let (target_id, target_off) = match state.regs[pkt_reg as usize] {
        RegAbs::PktPtr { id, const_off, .. } => (id, const_off),
        _ => return,
    };
    for reg in &mut state.regs {
        if let RegAbs::PktPtr {
            id,
            const_off,
            proven_range,
        } = reg
        {
            if *id == target_id && *const_off <= target_off {
                let gained = target_off - *const_off;
                if gained > *proven_range {
                    *proven_range = gained;
                }
            }
        }
    }
}

fn refine_cond_branch(
    base: &AbsState,
    d: DecodedInsn,
    pc: usize,
) -> Result<(AbsState, AbsState), BpfError> {
    let lhs = require_init(base, d.dst, pc)?;
    let is_reg = (d.op & BPF_X) != 0;
    let is64 = (d.op & 0x07) == BPF_JMP;
    let jmp_op = d.op & 0xF0;

    let rhs = if is_reg {
        require_init(base, d.src, pc)?
    } else {
        let v = if is64 {
            (d.imm as i64) as u64
        } else {
            (d.imm as u32) as u64
        };
        RegAbs::Scalar { umin: v, umax: v }
    };

    let mut taken = *base;
    let mut fallthrough = *base;

    // Packet pointer bounds proof: `if ptr > data_end goto out` proves `ptr <= data_end` on fallthrough.
    if matches!(lhs, RegAbs::PktPtr { .. }) && rhs == RegAbs::PktEnd {
        if jmp_op == BPF_JGT {
            find_good_pkt_pointers(&mut fallthrough, d.dst);
        } else if jmp_op == BPF_JLE {
            find_good_pkt_pointers(&mut taken, d.dst);
        }
        return Ok((taken, fallthrough));
    }

    // Scalar range refinement on immediate comparisons.
    if let (RegAbs::Scalar { umin, umax }, RegAbs::Scalar { umin: k, umax: k2 }) = (lhs, rhs) {
        if k == k2 {
            match jmp_op {
                BPF_JLT => {
                    taken.regs[d.dst as usize] = RegAbs::Scalar {
                        umin,
                        umax: umax.min(k.saturating_sub(1)),
                    };
                    fallthrough.regs[d.dst as usize] = RegAbs::Scalar {
                        umin: umin.max(k),
                        umax,
                    };
                }
                BPF_JGT => {
                    taken.regs[d.dst as usize] = RegAbs::Scalar {
                        umin: umin.max(k.saturating_add(1)),
                        umax,
                    };
                    fallthrough.regs[d.dst as usize] = RegAbs::Scalar {
                        umin,
                        umax: umax.min(k),
                    };
                }
                BPF_JGE => {
                    taken.regs[d.dst as usize] = RegAbs::Scalar {
                        umin: umin.max(k),
                        umax,
                    };
                    fallthrough.regs[d.dst as usize] = RegAbs::Scalar {
                        umin,
                        umax: umax.min(k.saturating_sub(1)),
                    };
                }
                BPF_JLE => {
                    taken.regs[d.dst as usize] = RegAbs::Scalar {
                        umin,
                        umax: umax.min(k),
                    };
                    fallthrough.regs[d.dst as usize] = RegAbs::Scalar {
                        umin: umin.max(k.saturating_add(1)),
                        umax,
                    };
                }
                _ => {}
            }
        }
    }

    Ok((taken, fallthrough))
}

/// Statically verifies an eBPF XDP program for structural safety, strict DAG
/// termination, register initialization, and dominated `data_end` packet bounds.
pub fn verify_bpf_program(insns: &[[u8; 8]]) -> Result<BpfVerifySummary, BpfError> {
    let (_is_start, load_count, branch_count) = check_structure(insns)?;
    let n = insns.len();
    let mut states: Vec<Option<AbsState>> = vec![None; n];
    states[0] = Some(AbsState::entry());
    let mut next_pkt_id = 1u32;

    let mut pc = 0usize;
    while pc < n {
        let Some(mut state) = states[pc] else {
            let d = decode_insn(insns[pc]);
            pc += if d.op == OP_LD_IMM64 { 2 } else { 1 };
            continue;
        };

        let d = decode_insn(insns[pc]);
        if d.op == OP_LD_IMM64 {
            let d2 = decode_insn(insns[pc + 1]);
            let val = ((d2.imm as u32 as u64) << 32) | (d.imm as u32 as u64);
            state.regs[d.dst as usize] = RegAbs::Scalar {
                umin: val,
                umax: val,
            };
            let next_pc = pc + 2;
            if next_pc >= n {
                return Err(BpfError::MissingExit { pc });
            }
            merge_state(&mut states[next_pc], state, next_pc);
            pc = next_pc;
            continue;
        }

        let cls = d.op & 0x07;
        match cls {
            BPF_LDX => {
                let sz = mem_size_bytes(d.op & 0x18).unwrap_or(0);
                let base = require_init(&state, d.src, pc)?;
                match base {
                    RegAbs::CtxPtr => {
                        if sz == 4 && d.off == 0 {
                            state.regs[d.dst as usize] = RegAbs::PktPtr {
                                id: 0,
                                const_off: 0,
                                proven_range: 0,
                            };
                        } else if sz == 4 && d.off == 4 {
                            state.regs[d.dst as usize] = RegAbs::PktEnd;
                        } else if sz == 4 && (d.off == 8 || d.off == 12 || d.off == 16 || d.off == 20)
                        {
                            state.regs[d.dst as usize] = RegAbs::Scalar {
                                umin: 0,
                                umax: u32::MAX as u64,
                            };
                        } else {
                            return Err(BpfError::PacketBoundsNotProven {
                                pc,
                                offset: d.off,
                                size: sz,
                            });
                        }
                    }
                    RegAbs::PktPtr { proven_range, .. } => {
                        if d.off < 0 || (d.off as u32).saturating_add(sz as u32) > proven_range {
                            return Err(BpfError::PacketBoundsNotProven {
                                pc,
                                offset: d.off,
                                size: sz,
                            });
                        }
                        state.regs[d.dst as usize] = RegAbs::Scalar {
                            umin: 0,
                            umax: scalar_max_for_width(sz),
                        };
                    }
                    RegAbs::FramePtr => {
                        if d.off >= 0 || (d.off as i32) < -(STACK_SIZE as i32) {
                            return Err(BpfError::PacketBoundsNotProven {
                                pc,
                                offset: d.off,
                                size: sz,
                            });
                        }
                        state.regs[d.dst as usize] = RegAbs::Scalar {
                            umin: 0,
                            umax: scalar_max_for_width(sz),
                        };
                    }
                    _ => {
                        return Err(BpfError::PacketBoundsNotProven {
                            pc,
                            offset: d.off,
                            size: sz,
                        });
                    }
                }
                if pc + 1 >= n {
                    return Err(BpfError::MissingExit { pc });
                }
                merge_state(&mut states[pc + 1], state, pc + 1);
            }
            BPF_ST | BPF_STX => {
                let sz = mem_size_bytes(d.op & 0x18).unwrap_or(0);
                let base = require_init(&state, d.dst, pc)?;
                if cls == BPF_STX {
                    let _ = require_init(&state, d.src, pc)?;
                }
                if base != RegAbs::FramePtr || d.off >= 0 || (d.off as i32) < -(STACK_SIZE as i32) {
                    return Err(BpfError::PacketBoundsNotProven {
                        pc,
                        offset: d.off,
                        size: sz,
                    });
                }
                if pc + 1 >= n {
                    return Err(BpfError::MissingExit { pc });
                }
                merge_state(&mut states[pc + 1], state, pc + 1);
            }
            BPF_ALU | BPF_ALU64 => {
                apply_abs_alu(&mut state, d, pc, &mut next_pkt_id)?;
                if pc + 1 >= n {
                    return Err(BpfError::MissingExit { pc });
                }
                merge_state(&mut states[pc + 1], state, pc + 1);
            }
            BPF_JMP | BPF_JMP32 => {
                if d.op == OP_EXIT {
                    let _ = require_init(&state, R0, pc)?;
                } else if d.op == OP_JA {
                    let target = pc + 1 + (d.off as usize);
                    merge_state(&mut states[target], state, target);
                } else {
                    let (taken, fallthrough) = refine_cond_branch(&state, d, pc)?;
                    let target = pc + 1 + (d.off as usize);
                    merge_state(&mut states[target], taken, target);
                    if pc + 1 >= n {
                        return Err(BpfError::MissingExit { pc });
                    }
                    merge_state(&mut states[pc + 1], fallthrough, pc + 1);
                }
            }
            _ => return Err(BpfError::InvalidOpcode { pc, opcode: d.op }),
        }

        pc += 1;
    }

    Ok(BpfVerifySummary {
        insn_count: n,
        load_count,
        branch_count,
        is_dag: true,
    })
}

// --- Pure-Rust 64-bit eBPF ISA Virtual Machine ---

struct VmMem<'a> {
    ctx: [u8; 24],
    pkt: &'a [u8],
    stack: [u8; STACK_SIZE],
}

impl<'a> VmMem<'a> {
    fn new(pkt: &'a [u8]) -> Self {
        let mut ctx = [0u8; 24];
        let pkt_start = PKT_BASE as u32;
        let pkt_end = pkt_start.saturating_add(pkt.len() as u32);
        ctx[0..4].copy_from_slice(&pkt_start.to_le_bytes());
        ctx[4..8].copy_from_slice(&pkt_end.to_le_bytes());
        ctx[8..12].copy_from_slice(&pkt_start.to_le_bytes());
        ctx[12..16].copy_from_slice(&1u32.to_le_bytes());
        Self {
            ctx,
            pkt,
            stack: [0u8; STACK_SIZE],
        }
    }

    fn load(&self, addr: u64, size: usize, pc: usize) -> Result<u64, BpfError> {
        let slice = self.resolve_read(addr, size, pc)?;
        match size {
            1 => Ok(slice[0] as u64),
            2 => Ok(u16::from_le_bytes([slice[0], slice[1]]) as u64),
            4 => Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64),
            8 => Ok(u64::from_le_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ])),
            _ => Err(BpfError::InvalidMemoryAccess { pc, addr, size }),
        }
    }

    fn store(&mut self, addr: u64, size: usize, val: u64, pc: usize) -> Result<(), BpfError> {
        let end = addr
            .checked_add(size as u64)
            .ok_or(BpfError::InvalidMemoryAccess { pc, addr, size })?;
        let stack_end = STACK_BASE + STACK_SIZE as u64;
        if addr < STACK_BASE || end > stack_end {
            return Err(BpfError::InvalidMemoryAccess { pc, addr, size });
        }
        let off = (addr - STACK_BASE) as usize;
        let dst = self
            .stack
            .get_mut(off..off + size)
            .ok_or(BpfError::InvalidMemoryAccess { pc, addr, size })?;
        match size {
            1 => dst[0] = (val & 0xFF) as u8,
            2 => dst.copy_from_slice(&(val as u16).to_le_bytes()),
            4 => dst.copy_from_slice(&(val as u32).to_le_bytes()),
            8 => dst.copy_from_slice(&val.to_le_bytes()),
            _ => return Err(BpfError::InvalidMemoryAccess { pc, addr, size }),
        }
        Ok(())
    }

    fn resolve_read(&self, addr: u64, size: usize, pc: usize) -> Result<&[u8], BpfError> {
        let end = addr
            .checked_add(size as u64)
            .ok_or(BpfError::InvalidMemoryAccess { pc, addr, size })?;
        let regions: [(u64, &[u8]); 3] = [
            (CTX_BASE, &self.ctx),
            (PKT_BASE, self.pkt),
            (STACK_BASE, &self.stack),
        ];
        for (base, mem) in regions {
            let limit = base + mem.len() as u64;
            if addr >= base && end <= limit {
                let off = (addr - base) as usize;
                return mem
                    .get(off..off + size)
                    .ok_or(BpfError::InvalidMemoryAccess { pc, addr, size });
            }
        }
        Err(BpfError::InvalidMemoryAccess { pc, addr, size })
    }
}

fn eval_alu_vm(op: u8, lhs_raw: u64, rhs_raw: u64, imm: i32, pc: usize) -> Result<u64, BpfError> {
    let is64 = (op & 0x07) == BPF_ALU64;
    let alu = op & 0xF0;

    if !is64 && alu == BPF_END {
        let is_be = (op & BPF_TO_BE) != 0;
        let res = match imm {
            16 => {
                let v = lhs_raw as u16;
                (if is_be { v.swap_bytes() } else { v }) as u64
            }
            32 => {
                let v = lhs_raw as u32;
                (if is_be { v.swap_bytes() } else { v }) as u64
            }
            64 => {
                if is_be {
                    lhs_raw.swap_bytes()
                } else {
                    lhs_raw
                }
            }
            _ => return Err(BpfError::InvalidOpcode { pc, opcode: op }),
        };
        return Ok(res);
    }

    let is_reg = (op & BPF_X) != 0;
    let (lhs, rhs) = if is64 {
        let r = if is_reg { rhs_raw } else { (imm as i64) as u64 };
        (lhs_raw, r)
    } else {
        let r = if is_reg {
            rhs_raw as u32 as u64
        } else {
            imm as u32 as u64
        };
        (lhs_raw as u32 as u64, r)
    };

    let res64 = match alu {
        BPF_ADD => lhs.wrapping_add(rhs),
        BPF_SUB => lhs.wrapping_sub(rhs),
        BPF_MUL => lhs.wrapping_mul(rhs),
        BPF_DIV => {
            if rhs == 0 {
                0
            } else {
                lhs / rhs
            }
        }
        BPF_OR => lhs | rhs,
        BPF_AND => lhs & rhs,
        BPF_LSH => lhs.wrapping_shl((rhs & if is64 { 63 } else { 31 }) as u32),
        BPF_RSH => lhs.wrapping_shr((rhs & if is64 { 63 } else { 31 }) as u32),
        BPF_NEG => (-(lhs as i64)) as u64,
        BPF_MOD => {
            if rhs == 0 {
                lhs
            } else {
                lhs % rhs
            }
        }
        BPF_XOR => lhs ^ rhs,
        BPF_MOV => rhs,
        BPF_ARSH => {
            let sh = (rhs & if is64 { 63 } else { 31 }) as u32;
            if is64 {
                ((lhs as i64) >> sh) as u64
            } else {
                ((lhs as i32) >> sh) as u32 as u64
            }
        }
        _ => return Err(BpfError::InvalidOpcode { pc, opcode: op }),
    };

    Ok(if is64 { res64 } else { res64 as u32 as u64 })
}

fn eval_jmp_vm(op: u8, lhs_raw: u64, rhs_raw: u64, imm: i32, pc: usize) -> Result<bool, BpfError> {
    // 4-bit outcome mask per opcode nibble (bits 0..3: <, ==, >, JSET; 0 = invalid).
    let code = ((op >> 4) & 15) as u32;
    let spec = ((0x0031_3100_6458_6420i64 >> (code << 2)) & 15) as u8;
    if spec == 0 {
        return Err(BpfError::InvalidOpcode { pc, opcode: op });
    }
    let sh = if (op & 0x07) == BPF_JMP { 0u32 } else { 32u32 };
    let a = (lhs_raw as i64) << sh;
    let b = (if (op & BPF_X) != 0 {
        rhs_raw as i64
    } else {
        imm as i64
    }) << sh;
    if spec == 8 {
        return Ok((a & b) != 0);
    }
    // Signed opcodes are nibbles 6, 7, 12, 13 (bitmask 0x30C0); unsigned flips sign bit.
    let flip = if ((0x30C0u32 >> code) & 1) != 0 {
        0i64
    } else {
        i64::MIN
    };
    let ka = a ^ flip;
    let kb = b ^ flip;
    let cmp_bit = if ka < kb {
        1u8
    } else if ka == kb {
        2u8
    } else {
        4u8
    };
    Ok((spec & cmp_bit) != 0)
}

/// Executes eBPF XDP bytecode instruction-by-instruction on `frame` inside a
/// bounds-checked pure-Rust 64-bit eBPF virtual machine, returning `R0 as u32`.
pub fn execute_bpf_program(insns: &[[u8; 8]], frame: &[u8]) -> Result<u32, BpfError> {
    if insns.is_empty() {
        return Err(BpfError::EmptyProgram);
    }

    let mut mem = VmMem::new(frame);
    let mut regs = [0u64; 11];
    regs[R1 as usize] = CTX_BASE;
    regs[R10 as usize] = STACK_BASE + STACK_SIZE as u64;

    let mut pc = 0usize;
    let mut steps = 0usize;
    let n = insns.len();

    while steps < MAX_VM_STEPS {
        if pc >= n {
            return Err(BpfError::MissingExit { pc });
        }
        steps += 1;
        let d = decode_insn(insns[pc]);
        if d.dst > R10 {
            return Err(BpfError::InvalidRegister { pc, reg: d.dst });
        }
        if d.src > R10 {
            return Err(BpfError::InvalidRegister { pc, reg: d.src });
        }

        if d.op == OP_LD_IMM64 {
            if pc + 1 >= n {
                return Err(BpfError::TruncatedLdImm64);
            }
            let d2 = decode_insn(insns[pc + 1]);
            regs[d.dst as usize] = ((d2.imm as u32 as u64) << 32) | (d.imm as u32 as u64);
            pc += 2;
            continue;
        }

        let cls = d.op & 0x07;
        match cls {
            BPF_LDX if (d.op & 0xE0) == BPF_MEM => {
                let sz = mem_size_bytes(d.op & 0x18)
                    .ok_or(BpfError::InvalidOpcode { pc, opcode: d.op })?;
                let addr = regs[d.src as usize].wrapping_add(d.off as i64 as u64);
                regs[d.dst as usize] = mem.load(addr, sz, pc)?;
                pc += 1;
            }
            BPF_ST | BPF_STX if (d.op & 0xE0) == BPF_MEM => {
                let sz = mem_size_bytes(d.op & 0x18)
                    .ok_or(BpfError::InvalidOpcode { pc, opcode: d.op })?;
                let addr = regs[d.dst as usize].wrapping_add(d.off as i64 as u64);
                let val = if cls == BPF_STX {
                    regs[d.src as usize]
                } else {
                    (d.imm as i64) as u64
                };
                mem.store(addr, sz, val, pc)?;
                pc += 1;
            }
            BPF_ALU | BPF_ALU64 => {
                let lhs = regs[d.dst as usize];
                let rhs = regs[d.src as usize];
                regs[d.dst as usize] = eval_alu_vm(d.op, lhs, rhs, d.imm, pc)?;
                pc += 1;
            }
            BPF_JMP | BPF_JMP32 => {
                if d.op == OP_EXIT {
                    return Ok(regs[R0 as usize] as u32);
                }
                if d.op == OP_JA {
                    let target = (pc as i64) + 1 + (d.off as i64);
                    if target < 0 || (target as usize) >= n {
                        return Err(BpfError::JumpTargetOutOfRange { pc, target });
                    }
                    pc = target as usize;
                    continue;
                }
                if d.op == OP_CALL {
                    return Err(BpfError::UnsupportedHelper { pc, id: d.imm });
                }
                let taken = eval_jmp_vm(
                    d.op,
                    regs[d.dst as usize],
                    regs[d.src as usize],
                    d.imm,
                    pc,
                )?;
                if taken {
                    let target = (pc as i64) + 1 + (d.off as i64);
                    if target < 0 || (target as usize) >= n {
                        return Err(BpfError::JumpTargetOutOfRange { pc, target });
                    }
                    pc = target as usize;
                } else {
                    pc += 1;
                }
            }
            _ => return Err(BpfError::InvalidOpcode { pc, opcode: d.op }),
        }
    }

    Err(BpfError::StepLimitExceeded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdp::{
        filter_packet, UdpFilterConfig, UdpPacketHdr, XdpAction, FLAG_COMPRESSED, FLAG_PARITY,
    };

    #[test]
    fn emitted_program_passes_static_verifier() {
        let cfg = UdpFilterConfig::default();
        let prog = emit_xdp_program(&cfg);
        let summary = verify_bpf_program(&prog).expect("emitted XDP program must verify cleanly");
        assert!(summary.is_dag);
        assert!(summary.insn_count > 400 && summary.insn_count < 700);
        assert!(summary.load_count >= 20);
        assert!(summary.branch_count >= 25);
    }

    #[test]
    fn verifier_rejects_removed_packet_bounds_check_counterfactual() {
        let cfg = UdpFilterConfig::default();
        let mut mutated = emit_xdp_program(&cfg);
        // Replace the very first `if R2 > R7 goto pass` (Ethernet bounds check) with a no-op `mov r2, r2`.
        let first_jgt = mutated
            .iter()
            .position(|raw| {
                let d = decode_insn(*raw);
                d.op == (BPF_JMP | BPF_JGT | BPF_X) && d.dst == R2 && d.src == R7
            })
            .expect("must find Ethernet bounds JGT");
        mutated[first_jgt] = encode_insn(BPF_ALU64 | BPF_MOV | BPF_X, R2, R2, 0, 0);

        let err = verify_bpf_program(&mutated).expect_err("missing bounds check must fail verifier");
        assert!(matches!(err, BpfError::PacketBoundsNotProven { .. }));
    }

    #[test]
    fn verifier_rejects_backward_jump_and_r10_write() {
        let loop_prog = vec![
            encode_insn(BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 2),
            encode_insn(OP_JA, 0, 0, -1, 0),
        ];
        assert!(matches!(
            verify_bpf_program(&loop_prog),
            Err(BpfError::BackwardJump { .. })
        ));

        let r10_write = vec![
            encode_insn(BPF_ALU64 | BPF_MOV | BPF_K, R10, 0, 0, 0),
            encode_insn(OP_EXIT, 0, 0, 0, 0),
        ];
        assert!(matches!(
            verify_bpf_program(&r10_write),
            Err(BpfError::ReadOnlyFramePointerWrite { .. })
        ));
    }

    fn build_test_udp_frame(dport: u16, hdr: &UdpPacketHdr, payload: &[u8]) -> Vec<u8> {
        let udp_len = (UDP_HDR_BYTES + UDP_PACKET_HDR_BYTES + payload.len()) as u16;
        let ip_tot_len = (IPV4_MIN_HDR_BYTES + udp_len as usize) as u16;
        let mut pkt = Vec::with_capacity(ETH_HDR_BYTES + ip_tot_len as usize);
        pkt.extend_from_slice(&[0u8; 12]);
        pkt.extend_from_slice(&ETH_P_IP.to_be_bytes());
        pkt.push(0x45);
        pkt.push(0);
        pkt.extend_from_slice(&ip_tot_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0, 64, IPPROTO_UDP, 0, 0]);
        pkt.extend_from_slice(&[10, 0, 0, 2, 10, 0, 0, 1]);
        pkt.extend_from_slice(&49000u16.to_be_bytes());
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(&udp_len.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
        pkt.extend_from_slice(&hdr.to_bytes());
        pkt.extend_from_slice(payload);
        pkt
    }

    #[test]
    fn rust_and_bpf_vm_parity_across_core_cases() {
        let key = [0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210];
        let cfg = UdpFilterConfig::with_key(key);
        let prog = emit_xdp_program(&cfg);
        verify_bpf_program(&prog).expect("custom-key program must verify");

        let hdr = UdpPacketHdr::new(
            42,
            0,
            FLAG_COMPRESSED,
            0x1234_5678,
            0xAABB_CCDD,
            0,
            16,
        )
        .sign(key);
        let pkt = build_test_udp_frame(cfg.udp_port, &hdr, &[0x5Au8; 16]);

        let rust_pass = filter_packet(&pkt, &cfg);
        let vm_pass = execute_bpf_program(&prog, &pkt).expect("vm pass");
        assert_eq!(rust_pass.action, XdpAction::Pass);
        assert_eq!(vm_pass, XDP_PASS);

        // Counterfactual knockout: flip 1 bit in MAC -> both drop!
        let mut bad_mac = pkt.clone();
        bad_mac[ETH_HDR_BYTES + IPV4_MIN_HDR_BYTES + UDP_HDR_BYTES + 24] ^= 0x80;
        let rust_drop = filter_packet(&bad_mac, &cfg);
        let vm_drop = execute_bpf_program(&prog, &bad_mac).expect("vm drop");
        assert_eq!(rust_drop.action, XdpAction::Drop);
        assert_eq!(vm_drop, XDP_DROP);
        assert_ne!(rust_pass.action, rust_drop.action);
        assert_ne!(vm_pass, vm_drop);

        // Parity shard with COMPRESSED flag -> both drop!
        let bad_parity_hdr = UdpPacketHdr::new(
            42,
            8,
            FLAG_PARITY | FLAG_COMPRESSED,
            0x1234_5678,
            0xAABB_CCDD,
            0,
            16,
        )
        .sign(key);
        let bad_parity = build_test_udp_frame(cfg.udp_port, &bad_parity_hdr, &[0x5Au8; 16]);
        assert_eq!(filter_packet(&bad_parity, &cfg).action, XdpAction::Drop);
        assert_eq!(execute_bpf_program(&prog, &bad_parity).expect("vm"), XDP_DROP);
    }

    #[test]
    fn custom_udp_filter_config_verifies_and_matches_vm_parity() {
        let custom_cfg = UdpFilterConfig {
            udp_port: 9443,
            magic_be: 0x4142_4344,
            max_frame_bytes: 32_768,
            max_payload_bytes: 512,
            data_slots: 4,
            parity_slots: 2,
            mac_key: [0xA1B2_C3D4_E5F6_0718, 0x1827_3645_5463_7281],
        };
        let prog = emit_xdp_program(&custom_cfg);
        let summary = verify_bpf_program(&prog).expect("custom config must verify");
        assert!(summary.is_dag);

        let hdr = UdpPacketHdr::new(11, 4, FLAG_PARITY, 0x1111_2222, 0x3333_4444, 0, 32)
            .with_magic(custom_cfg.magic_be)
            .sign(custom_cfg.mac_key);
        let pkt = build_test_udp_frame(custom_cfg.udp_port, &hdr, &[0xABu8; 32]);

        assert_eq!(filter_packet(&pkt, &custom_cfg).action, XdpAction::Pass);
        assert_eq!(execute_bpf_program(&prog, &pkt).expect("vm pass"), XDP_PASS);

        // Slot 6 is out of bounds for 4+2 slots -> both drop!
        let bad_slot_hdr = UdpPacketHdr::new(11, 6, FLAG_PARITY, 0x1111_2222, 0x3333_4444, 0, 32)
            .with_magic(custom_cfg.magic_be)
            .sign(custom_cfg.mac_key);
        let bad_slot_pkt = build_test_udp_frame(custom_cfg.udp_port, &bad_slot_hdr, &[0xABu8; 32]);
        assert_eq!(filter_packet(&bad_slot_pkt, &custom_cfg).action, XdpAction::Drop);
        assert_eq!(execute_bpf_program(&prog, &bad_slot_pkt).expect("vm drop"), XDP_DROP);
    }

    #[test]
    fn eval_jmp_vm_exhaustive_rfc9669_parity() {
        let vals64: [u64; 12] = [
            0,
            1,
            2,
            0x7FFF_FFFF,
            0x8000_0000,
            0xFFFF_FFFF,
            0x0000_0001_0000_0000,
            0x0000_0001_8000_0000,
            0xFFFF_FFFF_0000_0000,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            u64::MAX,
        ];
        let imms: [i32; 8] = [i32::MIN, -2, -1, 0, 1, 2, 0x7FFF_FFFE, i32::MAX];

        for cls in [BPF_JMP, BPF_JMP32] {
            for src_flag in [BPF_K, BPF_X] {
                for nibble in 0u8..16 {
                    let cond = nibble << 4;
                    let op = cls | src_flag | cond;
                    for &lhs_raw in &vals64 {
                        for &rhs_raw in &vals64 {
                            for &imm in &imms {
                                let (lhs, rhs, slhs, srhs) = if cls == BPF_JMP {
                                    let r = if src_flag == BPF_X {
                                        rhs_raw
                                    } else {
                                        (imm as i64) as u64
                                    };
                                    (lhs_raw, r, lhs_raw as i64, r as i64)
                                } else {
                                    let l32 = lhs_raw as u32;
                                    let r32 = if src_flag == BPF_X {
                                        rhs_raw as u32
                                    } else {
                                        imm as u32
                                    };
                                    (
                                        l32 as u64,
                                        r32 as u64,
                                        l32 as i32 as i64,
                                        r32 as i32 as i64,
                                    )
                                };
                                let expected = match cond {
                                    BPF_JEQ => Ok(lhs == rhs),
                                    BPF_JGT => Ok(lhs > rhs),
                                    BPF_JGE => Ok(lhs >= rhs),
                                    BPF_JSET => Ok((lhs & rhs) != 0),
                                    BPF_JNE => Ok(lhs != rhs),
                                    BPF_JSGT => Ok(slhs > srhs),
                                    BPF_JSGE => Ok(slhs >= srhs),
                                    BPF_JLT => Ok(lhs < rhs),
                                    BPF_JLE => Ok(lhs <= rhs),
                                    BPF_JSLT => Ok(slhs < srhs),
                                    BPF_JSLE => Ok(slhs <= srhs),
                                    _ => Err(BpfError::InvalidOpcode { pc: 7, opcode: op }),
                                };
                                let got = eval_jmp_vm(op, lhs_raw, rhs_raw, imm, 7);
                                assert_eq!(
                                    got, expected,
                                    "mismatch op=0x{op:02x} lhs=0x{lhs_raw:016x} rhs=0x{rhs_raw:016x} imm={imm}"
                                );
                            }
                        }
                    }
                }
            }
        }

        // Counterfactual knockouts: signed vs unsigned, and JMP vs JMP32 width separation.
        assert_ne!(
            eval_jmp_vm(BPF_JMP | BPF_JLT | BPF_X, 0, u64::MAX, 0, 0).expect("jlt"),
            eval_jmp_vm(BPF_JMP | BPF_JSLT | BPF_X, 0, u64::MAX, 0, 0).expect("jslt"),
        );
        assert_ne!(
            eval_jmp_vm(BPF_JMP | BPF_JEQ | BPF_X, 0x0000_0001_0000_0000, 0, 0, 0).expect("jeq64"),
            eval_jmp_vm(BPF_JMP32 | BPF_JEQ | BPF_X, 0x0000_0001_0000_0000, 0, 0, 0)
                .expect("jeq32"),
        );
    }
}
