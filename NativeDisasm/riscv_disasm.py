"""
Disassembler RISC-V (RV32IMC / RV64IMC) para código nativo MicroPython.

Cobre o subconjunto de instruções emitido pelo mpy-cross para arch_codes 11-12
(rv32imc / rv64imc). Instruções de 32 bits (base RV32I/RV64I + M) e 16 bits
(extensão C — compressed).

Referência: RISC-V ISA Manual Volume I (Unprivileged), Chapters 2 + 12–16.
Encoding: little-endian.
"""

from NativeDisasm.base import sign_extend, read_u16_le, read_u32_le


# ---------------------------------------------------------------------------
# Registradores — nomes ABI
# ---------------------------------------------------------------------------

_REG = [
    "zero", "ra",  "sp",  "gp",  "tp",  "t0",  "t1",  "t2",
    "s0",   "s1",  "a0",  "a1",  "a2",  "a3",  "a4",  "a5",
    "a6",   "a7",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
    "s8",   "s9",  "s10", "s11", "t3",  "t4",  "t5",  "t6",
]

# Registradores compactos (C extension): x8–x15 → s0, s1, a0–a5
_CREG = ["s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5"]


# ---------------------------------------------------------------------------
# Tabelas de opcodes
# ---------------------------------------------------------------------------

# Mnemonics para BRANCH (opcode 1100011, funct3)
_BRANCH = ["beq", "bne", "???", "???", "blt", "bge", "bltu", "bgeu"]

# Mnemonics para LOAD (opcode 0000011, funct3)
_LOAD = ["lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "???"]

# Mnemonics para STORE (opcode 0100011, funct3)
_STORE = ["sb", "sh", "sw", "sd", "???", "???", "???", "???"]

# ALU imediato (OP-IMM, opcode 0010011, funct3)
_ALU_IMM = ["addi", "slli", "slti", "sltiu", "xori", "srli", "ori", "andi"]

# ALU registrador (OP, opcode 0110011, funct3)
_ALU_REG = ["add", "sll", "slt", "sltu", "xor", "srl", "or", "and"]

# ALU registrador com funct7=0x20 (sub/sra)
_ALU_REG_ALT = ["sub", "???", "???", "???", "???", "sra", "???", "???"]

# M extension (funct7=0x01) — opcode OP (0110011)
_MULDIV = ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]


# ---------------------------------------------------------------------------
# Decodificação — instruções de 32 bits
# ---------------------------------------------------------------------------

def _decode_32(inst: int, addr: int) -> tuple[str, str]:
    """Retorna (mnemonic, operands) para instrução RV de 32 bits."""

    opcode = inst & 0x7F
    rd     = (inst >> 7) & 0x1F
    funct3 = (inst >> 12) & 0x7
    rs1    = (inst >> 15) & 0x1F
    rs2    = (inst >> 20) & 0x1F
    funct7 = (inst >> 25) & 0x7F

    # ---- LUI (opcode 0110111) ----
    if opcode == 0b0110111:
        imm = inst & 0xFFFFF000
        # Sign-extend do valor de 32 bits (para display)
        if imm & 0x80000000:
            imm -= 0x100000000
        return "lui", f"{_REG[rd]}, 0x{(inst >> 12) & 0xFFFFF:x}"

    # ---- AUIPC (opcode 0010111) ----
    if opcode == 0b0010111:
        return "auipc", f"{_REG[rd]}, 0x{(inst >> 12) & 0xFFFFF:x}"

    # ---- JAL (opcode 1101111) ----
    if opcode == 0b1101111:
        # imm[20|10:1|11|19:12]
        imm20 = (inst >> 31) & 1
        imm10_1 = (inst >> 21) & 0x3FF
        imm11 = (inst >> 20) & 1
        imm19_12 = (inst >> 12) & 0xFF
        imm = (imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1)
        offset = sign_extend(imm, 21)
        target = (addr + offset) & 0xFFFFFFFF
        if rd == 0:
            return "j", f"0x{target:x}"
        if rd == 1:
            return "jal", f"0x{target:x}"
        return "jal", f"{_REG[rd]}, 0x{target:x}"

    # ---- JALR (opcode 1100111) ----
    if opcode == 0b1100111:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)
        if rd == 0 and rs1 == 1 and imm == 0:
            return "ret", ""
        if rd == 0 and imm == 0:
            return "jr", _REG[rs1]
        if rd == 1 and imm == 0:
            return "jalr", _REG[rs1]
        if imm == 0:
            return "jalr", f"{_REG[rd]}, {_REG[rs1]}"
        return "jalr", f"{_REG[rd]}, {imm}({_REG[rs1]})"

    # ---- BRANCH (opcode 1100011) ----
    if opcode == 0b1100011:
        # imm[12|10:5] rs2 rs1 funct3 imm[4:1|11]
        imm12 = (inst >> 31) & 1
        imm10_5 = (inst >> 25) & 0x3F
        imm4_1 = (inst >> 8) & 0xF
        imm11 = (inst >> 7) & 1
        imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1)
        offset = sign_extend(imm, 13)
        target = (addr + offset) & 0xFFFFFFFF
        mnem = _BRANCH[funct3]
        # Pseudo-ops para comparação com zero
        if rs2 == 0 and mnem == "beq":
            return "beqz", f"{_REG[rs1]}, 0x{target:x}"
        if rs2 == 0 and mnem == "bne":
            return "bnez", f"{_REG[rs1]}, 0x{target:x}"
        if rs1 == 0 and mnem == "blt":
            return "bgtz", f"{_REG[rs2]}, 0x{target:x}"
        if rs2 == 0 and mnem == "bge":
            return "bgez", f"{_REG[rs1]}, 0x{target:x}"
        if rs2 == 0 and mnem == "blt":
            return "bltz", f"{_REG[rs1]}, 0x{target:x}"
        if rs1 == 0 and mnem == "bge":
            return "blez", f"{_REG[rs2]}, 0x{target:x}"
        return mnem, f"{_REG[rs1]}, {_REG[rs2]}, 0x{target:x}"

    # ---- LOAD (opcode 0000011) ----
    if opcode == 0b0000011:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)
        mnem = _LOAD[funct3]
        return mnem, f"{_REG[rd]}, {imm}({_REG[rs1]})"

    # ---- STORE (opcode 0100011) ----
    if opcode == 0b0100011:
        imm11_5 = (inst >> 25) & 0x7F
        imm4_0 = (inst >> 7) & 0x1F
        imm = sign_extend((imm11_5 << 5) | imm4_0, 12)
        mnem = _STORE[funct3]
        return mnem, f"{_REG[rs2]}, {imm}({_REG[rs1]})"

    # ---- OP-IMM (opcode 0010011) ----
    if opcode == 0b0010011:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)

        if funct3 == 0:  # ADDI
            if rs1 == 0:
                return "li", f"{_REG[rd]}, {imm}"
            if imm == 0:
                return "mv", f"{_REG[rd]}, {_REG[rs1]}"
            return "addi", f"{_REG[rd]}, {_REG[rs1]}, {imm}"

        if funct3 == 1:  # SLLI
            shamt = (inst >> 20) & 0x3F
            return "slli", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"

        if funct3 == 5:  # SRLI / SRAI
            shamt = (inst >> 20) & 0x3F
            if funct7 & 0x20:
                return "srai", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"
            return "srli", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"

        if funct3 == 4 and imm == -1:  # XORI rd, rs1, -1 → NOT pseudo
            return "not", f"{_REG[rd]}, {_REG[rs1]}"

        if funct3 == 3:  # SLTIU
            if imm == 1:
                return "seqz", f"{_REG[rd]}, {_REG[rs1]}"
            return "sltiu", f"{_REG[rd]}, {_REG[rs1]}, {imm}"

        if funct3 == 2:  # SLTI
            return "slti", f"{_REG[rd]}, {_REG[rs1]}, {imm}"

        mnem = _ALU_IMM[funct3]
        return mnem, f"{_REG[rd]}, {_REG[rs1]}, {imm}"

    # ---- OP (opcode 0110011) ----
    if opcode == 0b0110011:
        if funct7 == 0x01:
            # M extension: mul/div/rem
            mnem = _MULDIV[funct3]
            return mnem, f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"

        if funct7 == 0x20:
            # SUB / SRA
            mnem = _ALU_REG_ALT[funct3]
            if funct3 == 0 and rs1 == 0:
                return "neg", f"{_REG[rd]}, {_REG[rs2]}"
            return mnem, f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"

        # Normal (funct7=0x00)
        mnem = _ALU_REG[funct3]
        if funct3 == 2 and rs1 == 0:  # SLT rd, x0, rs2 → SGTZ pseudo
            return "sgtz", f"{_REG[rd]}, {_REG[rs2]}"
        if funct3 == 3 and rs1 == 0:  # SLTU rd, x0, rs2 → SNEZ pseudo
            return "snez", f"{_REG[rd]}, {_REG[rs2]}"
        return mnem, f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"

    # ---- OP-IMM-32 (opcode 0011011) — RV64 only: ADDIW, SLLIW, SRLIW, SRAIW ----
    if opcode == 0b0011011:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)
        if funct3 == 0:
            if rs1 == 0:
                return "li", f"{_REG[rd]}, {imm}"  # sext.w
            return "addiw", f"{_REG[rd]}, {_REG[rs1]}, {imm}"
        if funct3 == 1:
            shamt = (inst >> 20) & 0x1F
            return "slliw", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"
        if funct3 == 5:
            shamt = (inst >> 20) & 0x1F
            if funct7 & 0x20:
                return "sraiw", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"
            return "srliw", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"
        return "dw", f"0x{inst:08x}"

    # ---- OP-32 (opcode 0111011) — RV64 only: ADDW, SUBW, SLLW, SRLW, SRAW, MULW, DIVW, etc. ----
    if opcode == 0b0111011:
        if funct7 == 0x01:
            m_ops = ["mulw", "???", "???", "???", "divw", "divuw", "remw", "remuw"]
            return m_ops[funct3], f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"
        if funct7 == 0x20:
            if funct3 == 0:
                return "subw", f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"
            if funct3 == 5:
                return "sraw", f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"
        if funct7 == 0x00:
            w_ops = ["addw", "sllw", "???", "???", "???", "srlw", "???", "???"]
            return w_ops[funct3], f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"
        return "dw", f"0x{inst:08x}"

    # ---- FENCE (opcode 0001111) ----
    if opcode == 0b0001111:
        return "fence", ""

    # ---- SYSTEM (opcode 1110011) ----
    if opcode == 0b1110011:
        if inst == 0x00000073:
            return "ecall", ""
        if inst == 0x00100073:
            return "ebreak", ""
        # CSR instructions
        csr = (inst >> 20) & 0xFFF
        if funct3 == 1:
            return "csrrw", f"{_REG[rd]}, 0x{csr:x}, {_REG[rs1]}"
        if funct3 == 2:
            return "csrrs", f"{_REG[rd]}, 0x{csr:x}, {_REG[rs1]}"
        if funct3 == 3:
            return "csrrc", f"{_REG[rd]}, 0x{csr:x}, {_REG[rs1]}"
        if funct3 == 5:
            return "csrrwi", f"{_REG[rd]}, 0x{csr:x}, {rs1}"
        if funct3 == 6:
            return "csrrsi", f"{_REG[rd]}, 0x{csr:x}, {rs1}"
        if funct3 == 7:
            return "csrrci", f"{_REG[rd]}, 0x{csr:x}, {rs1}"
        return "dw", f"0x{inst:08x}"

    return "dw", f"0x{inst:08x}"


# ---------------------------------------------------------------------------
# Decodificação — instruções comprimidas de 16 bits (extensão C)
# ---------------------------------------------------------------------------

def _decode_16(inst: int, addr: int) -> tuple[str, str]:
    """Retorna (mnemonic, operands) para instrução RVC (compressed) de 16 bits."""

    op   = inst & 0x3          # bits [1:0]
    funct3 = (inst >> 13) & 0x7  # bits [15:13]

    # ====== Quadrant 0 (op=00) ======
    if op == 0:
        rd_p = (inst >> 2) & 0x7   # bits [4:2] → registrador compacto
        rs1_p = (inst >> 7) & 0x7  # bits [9:7]

        # C.ADDI4SPN (funct3=000)
        if funct3 == 0:
            # nzuimm[5:4|9:6|2|3]
            nzuimm = (
                ((inst >> 6) & 1) << 2 |
                ((inst >> 5) & 1) << 3 |
                ((inst >> 11) & 3) << 4 |
                ((inst >> 7) & 0xF) << 6
            )
            if nzuimm == 0:
                return "dw", f"0x{inst:04x}"  # ilegal
            return "c.addi4spn", f"{_CREG[rd_p]}, sp, {nzuimm}"

        # C.LW (funct3=010)
        if funct3 == 2:
            offset = (
                ((inst >> 6) & 1) << 2 |
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 1) << 6
            )
            return "c.lw", f"{_CREG[rd_p]}, {offset}({_CREG[rs1_p]})"

        # C.LD (funct3=011) — RV64 only
        if funct3 == 3:
            offset = (
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 0x3) << 6
            )
            return "c.ld", f"{_CREG[rd_p]}, {offset}({_CREG[rs1_p]})"

        # C.SW (funct3=110)
        if funct3 == 6:
            rs2_p = (inst >> 2) & 0x7
            offset = (
                ((inst >> 6) & 1) << 2 |
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 1) << 6
            )
            return "c.sw", f"{_CREG[rs2_p]}, {offset}({_CREG[rs1_p]})"

        # C.SD (funct3=111) — RV64 only
        if funct3 == 7:
            rs2_p = (inst >> 2) & 0x7
            offset = (
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 0x3) << 6
            )
            return "c.sd", f"{_CREG[rs2_p]}, {offset}({_CREG[rs1_p]})"

        return "dw", f"0x{inst:04x}"

    # ====== Quadrant 1 (op=01) ======
    if op == 1:
        rd = (inst >> 7) & 0x1F   # bits [11:7]

        # C.NOP / C.ADDI (funct3=000)
        if funct3 == 0:
            nzimm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
            nzimm = sign_extend(nzimm, 6)
            if rd == 0:
                return "c.nop", ""
            return "c.addi", f"{_REG[rd]}, {nzimm}"

        # C.JAL (funct3=001) — RV32 only
        # C.ADDIW (funct3=001) — RV64 only
        if funct3 == 1:
            # Para RV32: C.JAL; para RV64: C.ADDIW
            # Tratamos ambos — contexto decide
            imm = _decode_cj_imm(inst)
            target = (addr + imm) & 0xFFFFFFFF
            # Se rd != 0, pode ser c.addiw (RV64)
            if rd != 0:
                nzimm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
                nzimm = sign_extend(nzimm, 6)
                return "c.addiw", f"{_REG[rd]}, {nzimm}"
            return "c.jal", f"0x{target:x}"

        # C.LI (funct3=010)
        if funct3 == 2:
            imm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
            imm = sign_extend(imm, 6)
            return "c.li", f"{_REG[rd]}, {imm}"

        # C.ADDI16SP / C.LUI (funct3=011)
        if funct3 == 3:
            if rd == 2:
                # C.ADDI16SP
                nzimm = (
                    ((inst >> 6) & 1) << 4 |
                    ((inst >> 2) & 1) << 5 |
                    ((inst >> 5) & 1) << 6 |
                    ((inst >> 3) & 0x3) << 7 |
                    ((inst >> 12) & 1) << 9
                )
                nzimm = sign_extend(nzimm, 10)
                return "c.addi16sp", f"sp, {nzimm}"
            else:
                # C.LUI
                nzimm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
                nzimm = sign_extend(nzimm, 6)
                return "c.lui", f"{_REG[rd]}, 0x{nzimm & 0xFFFFF:x}"

        # C.SRLI / C.SRAI / C.ANDI / sub-ops (funct3=100)
        if funct3 == 4:
            return _decode_c_alu(inst)

        # C.J (funct3=101)
        if funct3 == 5:
            imm = _decode_cj_imm(inst)
            target = (addr + imm) & 0xFFFFFFFF
            return "c.j", f"0x{target:x}"

        # C.BEQZ (funct3=110)
        if funct3 == 6:
            rs1_p = (inst >> 7) & 0x7
            offset = _decode_cb_offset(inst)
            target = (addr + offset) & 0xFFFFFFFF
            return "c.beqz", f"{_CREG[rs1_p]}, 0x{target:x}"

        # C.BNEZ (funct3=111)
        if funct3 == 7:
            rs1_p = (inst >> 7) & 0x7
            offset = _decode_cb_offset(inst)
            target = (addr + offset) & 0xFFFFFFFF
            return "c.bnez", f"{_CREG[rs1_p]}, 0x{target:x}"

        return "dw", f"0x{inst:04x}"

    # ====== Quadrant 2 (op=10) ======
    if op == 2:
        rd = (inst >> 7) & 0x1F

        # C.SLLI (funct3=000)
        if funct3 == 0:
            shamt = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
            return "c.slli", f"{_REG[rd]}, {shamt}"

        # C.LWSP (funct3=010)
        if funct3 == 2:
            offset = (
                ((inst >> 4) & 0x7) << 2 |
                ((inst >> 12) & 1) << 5 |
                ((inst >> 2) & 0x3) << 6
            )
            return "c.lwsp", f"{_REG[rd]}, {offset}(sp)"

        # C.LDSP (funct3=011) — RV64 only
        if funct3 == 3:
            offset = (
                ((inst >> 5) & 0x3) << 3 |
                ((inst >> 12) & 1) << 5 |
                ((inst >> 2) & 0x7) << 6
            )
            return "c.ldsp", f"{_REG[rd]}, {offset}(sp)"

        # C.JR / C.MV / C.EBREAK / C.JALR / C.ADD (funct3=100)
        if funct3 == 4:
            bit12 = (inst >> 12) & 1
            rs2 = (inst >> 2) & 0x1F
            if bit12 == 0:
                if rs2 == 0:
                    # C.JR
                    return "c.jr", _REG[rd]
                # C.MV
                return "c.mv", f"{_REG[rd]}, {_REG[rs2]}"
            else:
                if rs2 == 0 and rd == 0:
                    return "c.ebreak", ""
                if rs2 == 0:
                    # C.JALR
                    return "c.jalr", _REG[rd]
                # C.ADD
                return "c.add", f"{_REG[rd]}, {_REG[rs2]}"

        # C.SWSP (funct3=110)
        if funct3 == 6:
            rs2 = (inst >> 2) & 0x1F
            offset = (
                ((inst >> 9) & 0xF) << 2 |
                ((inst >> 7) & 0x3) << 6
            )
            return "c.swsp", f"{_REG[rs2]}, {offset}(sp)"

        # C.SDSP (funct3=111) — RV64 only
        if funct3 == 7:
            rs2 = (inst >> 2) & 0x1F
            offset = (
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 7) & 0x7) << 6
            )
            return "c.sdsp", f"{_REG[rs2]}, {offset}(sp)"

        return "dw", f"0x{inst:04x}"

    return "dw", f"0x{inst:04x}"


# ---------------------------------------------------------------------------
# Helpers para extensão C
# ---------------------------------------------------------------------------

def _decode_cj_imm(inst: int) -> int:
    """Decodifica imediato de C.J / C.JAL — 12 bits com sign-extend."""
    # imm[11|4|9:8|10|6|7|3:1|5]
    bits = (
        ((inst >> 3) & 0x7) << 1 |   # bits[5:3] → imm[3:1]
        ((inst >> 11) & 1) << 4 |     # bit[11] → imm[4]
        ((inst >> 2) & 1) << 5 |      # bit[2] → imm[5]
        ((inst >> 7) & 1) << 6 |      # bit[7] → imm[6]
        ((inst >> 6) & 1) << 7 |      # bit[6] → imm[7]
        ((inst >> 9) & 0x3) << 8 |    # bits[10:9] → imm[9:8]
        ((inst >> 8) & 1) << 10 |     # bit[8] → imm[10]
        ((inst >> 12) & 1) << 11      # bit[12] → imm[11]
    )
    return sign_extend(bits, 12)


def _decode_cb_offset(inst: int) -> int:
    """Decodifica offset de C.BEQZ / C.BNEZ — 9 bits com sign-extend."""
    # offset[8|4:3] rs1' offset[7:6|2:1|5]
    bits = (
        ((inst >> 3) & 0x3) << 1 |   # bits[4:3] → imm[2:1]
        ((inst >> 10) & 0x3) << 3 |   # bits[11:10] → imm[4:3]
        ((inst >> 2) & 1) << 5 |      # bit[2] → imm[5]
        ((inst >> 5) & 0x3) << 6 |    # bits[6:5] → imm[7:6]
        ((inst >> 12) & 1) << 8       # bit[12] → imm[8]
    )
    return sign_extend(bits, 9)


def _decode_c_alu(inst: int) -> tuple[str, str]:
    """Decodifica sub-grupo ALU compacto (funct3=100, quadrant 1)."""
    funct2 = (inst >> 10) & 0x3
    rd_p = (inst >> 7) & 0x7

    if funct2 == 0:
        # C.SRLI
        shamt = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
        return "c.srli", f"{_CREG[rd_p]}, {shamt}"

    if funct2 == 1:
        # C.SRAI
        shamt = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
        return "c.srai", f"{_CREG[rd_p]}, {shamt}"

    if funct2 == 2:
        # C.ANDI
        imm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
        imm = sign_extend(imm, 6)
        return "c.andi", f"{_CREG[rd_p]}, {imm}"

    # funct2 == 3: sub-grupo de operações registrador-registrador
    bit12 = (inst >> 12) & 1
    funct2b = (inst >> 5) & 0x3
    rs2_p = (inst >> 2) & 0x7

    if bit12 == 0:
        ops = ["c.sub", "c.xor", "c.or", "c.and"]
        return ops[funct2b], f"{_CREG[rd_p]}, {_CREG[rs2_p]}"
    else:
        # RV64: c.subw, c.addw
        ops64 = ["c.subw", "c.addw", "???", "???"]
        return ops64[funct2b], f"{_CREG[rd_p]}, {_CREG[rs2_p]}"


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def disassemble(code: bytes, arch_code: int) -> str:
    """
    Disassembla código RISC-V (RV32IMC / RV64IMC).

    Parâmetros:
        code       — bytes do código de máquina
        arch_code  — código de arquitetura (11=rv32imc, 12=rv64imc)

    Retorna string formatada (offset + assembly), uma instrução por linha.
    """
    instructions: list[tuple[int, str]] = []
    pos = 0

    while pos < len(code):
        start = pos
        try:
            if pos + 1 >= len(code):
                instructions.append((pos, f"db      0x{code[pos]:02x}"))
                pos += 1
                continue

            # Lê os dois primeiros bytes para determinar o tamanho da instrução
            hw = read_u16_le(code, pos)

            if (hw & 0x3) != 0x3:
                # Instrução comprimida de 16 bits (extensão C)
                pos += 2
                mnem, operands = _decode_16(hw, start)
            else:
                # Instrução de 32 bits
                if pos + 3 >= len(code):
                    # Bytes insuficientes
                    for i in range(pos, len(code)):
                        instructions.append((i, f"db      0x{code[i]:02x}"))
                    break
                inst = read_u32_le(code, pos)
                pos += 4
                mnem, operands = _decode_32(inst, start)

        except (IndexError, KeyError):
            for i in range(start, len(code)):
                instructions.append((i, f"db      0x{code[i]:02x}"))
            break

        asm = f"{mnem:<8s} {operands}" if operands else mnem
        instructions.append((start, asm))

    lines = []
    for offset, asm_str in instructions:
        lines.append(f"0x{offset:04x}:  {asm_str}")
    return "\n".join(lines)
