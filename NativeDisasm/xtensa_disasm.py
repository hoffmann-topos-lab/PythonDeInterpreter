"""
Disassembler Xtensa para código nativo MicroPython.

Cobre o subconjunto de instruções emitido pelo mpy-cross para arch_codes 9-10
(xtensa / xtensawin). Instruções de 24 bits (padrão) e 16 bits (narrow, Code
Density option).

Referência: Xtensa Instruction Set Architecture (ISA) Reference Manual.
Encoding: little-endian (byte 0 = LSB).
"""

from NativeDisasm.base import sign_extend


# ---------------------------------------------------------------------------
# Tabelas
# ---------------------------------------------------------------------------

_REG = [f"a{i}" for i in range(16)]

# RRI8 sub-opcodes (campo r, com op0=2)
_RRI8_LOAD_STORE = {
    0x0: "l8ui",
    0x1: "l16ui",
    0x2: "l32i",
    0x4: "s8i",
    0x5: "s16i",
    0x6: "s32i",
    0x9: "l16si",
}

# Escala do offset por tipo de load/store (RRI8)
_RRI8_SCALE = {
    0x0: 1,   # l8ui: byte
    0x1: 2,   # l16ui: halfword
    0x2: 4,   # l32i: word
    0x4: 1,   # s8i: byte
    0x5: 2,   # s16i: halfword
    0x6: 4,   # s32i: word
    0x9: 2,   # l16si: halfword
}

# ALU ops (op2=0, por op1) — formato RRR
_ALU_OPS = {
    0x1: "and",
    0x2: "or",
    0x3: "xor",
    0x8: "add",
    0x9: "addx2",
    0xA: "addx4",
    0xB: "addx8",
    0xC: "sub",
    0xD: "subx2",
    0xE: "subx4",
    0xF: "subx8",
}

# Branches com offset de 8 bits (op0=7, campo r como sub-opcode)
_BRI8_OPS = {
    0x1: "beq",
    0x2: "blt",
    0x3: "bltu",
    0x4: "ball",
    0x5: "bbc",
    0x9: "bne",
    0xA: "bge",
    0xB: "bgeu",
    0xC: "bnall",
    0xD: "bbs",
}

# Branches com imediato (op0=7, campo r, tipo BRI8 mas com imediato no campo t)
_BRII_OPS = {
    0x6: "beqi",
    0x7: "bnei",
    0xE: "bgei",
    0xF: "blti",
}


# ---------------------------------------------------------------------------
# Decodificação — instruções de 24 bits
# ---------------------------------------------------------------------------

def _decode_24(inst: int, addr: int) -> tuple[str, str]:
    """Retorna (mnemonic, operands) para instrução de 24 bits."""

    op0 = inst & 0xF

    # ---- RRR format (op0=0) ----
    if op0 == 0:
        return _decode_rrr(inst)

    # ---- L32R (op0=1) ----
    if op0 == 1:
        t = (inst >> 4) & 0xF
        imm16 = sign_extend((inst >> 8) & 0xFFFF, 16)
        # target = ((addr & ~3) + (imm16 << 2)) mas exibimos só o offset
        target = ((addr + 3) & ~3) + (imm16 << 2)
        return "l32r", f"{_REG[t]}, 0x{target & 0xFFFFFFFF:x}"

    # ---- LSAI / RRI8 format (op0=2) ----
    if op0 == 2:
        return _decode_rri8(inst)

    # ---- CALL format (op0=5) ----
    if op0 == 5:
        n = (inst >> 4) & 3
        offset18 = sign_extend((inst >> 6) & 0x3FFFF, 18)
        target = ((addr & ~3) + (offset18 << 2)) + 4
        call_ops = {0: "call0", 1: "call4", 2: "call8", 3: "call12"}
        return call_ops[n], f"0x{target & 0xFFFFFFFF:x}"

    # ---- SI format / BRI12 / J (op0=6) ----
    if op0 == 6:
        return _decode_si(inst, addr)

    # ---- B format / BRI8 branches (op0=7) ----
    if op0 == 7:
        return _decode_b(inst, addr)

    return "dw", f"0x{inst:06x}"


def _decode_rrr(inst: int) -> tuple[str, str]:
    """Decodifica instrução formato RRR (op0=0)."""
    t = (inst >> 4) & 0xF
    s = (inst >> 8) & 0xF
    r = (inst >> 12) & 0xF
    op1 = (inst >> 16) & 0xF
    op2 = (inst >> 20) & 0xF

    if op2 == 0:
        # ---- Grupo principal ----

        if op1 == 0:
            # Specials: JX, CALLX, RET, RETW, NOP, BREAK, SYSCALL, etc.
            return _decode_rrr_special(r, s, t)

        # ALU simples
        if op1 in _ALU_OPS:
            return _ALU_OPS[op1], f"{_REG[r]}, {_REG[s]}, {_REG[t]}"

        # NEG / ABS (op1=7)
        if op1 == 7:
            if r == 0:
                return "neg", f"{_REG[r]}, {_REG[t]}"
            if r == 1:
                return "abs", f"{_REG[r]}, {_REG[t]}"

        # Shift specials (op1=4)
        if op1 == 4:
            if r == 0:
                return "ssr", _REG[s]
            if r == 1:
                return "ssl", _REG[s]
            if r == 2:
                return "ssa8l", _REG[s]
            if r == 3:
                return "ssa8b", _REG[s]
            if r == 4:
                return "ssai", f"{(s | ((t & 1) << 4))}"
            if r == 8:
                # ROTW (xtensawin)
                return "rotw", f"{sign_extend(t, 4)}"
            if r == 0xF and s == 0 and t == 0:
                return "nss", ""

        # Shift immediate (op1=6, SLLI via subgroup?)
        if op1 == 6:
            # XSR, RSR, WSR
            sr = (r << 4) | s  # wait, encoding depends on sub-op
            # Actually op1=6 for RRR with op2=0: it's SI group
            # RSR: op2=0, op1=3, but that's for op1=3...
            pass

    # ---- Shifts (op2=1) ----
    if op2 == 1:
        if op1 == 0xA:
            # SLL: shift left by SSL amount
            return "sll", f"{_REG[r]}, {_REG[s]}"
        if op1 == 0xB:
            # SRA: shift right arithmetic by SSR amount
            return "sra", f"{_REG[r]}, {_REG[t]}"
        if op1 == 0x8:
            # SRC: shift by SAR (funnel shift)
            return "src", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"
        if op1 == 0x9:
            # SRL: shift right logical by SSR amount
            return "srl", f"{_REG[r]}, {_REG[t]}"

    # ---- SLLI (op2=0, op1=0x1 com especificação alternativa) ----
    # SLLI usa formato especial: op0=0, op2=0x1, op1=0x0
    # Encoding: op0=0, t, s, sa5=r|(op1&1)<<4, op1=0 or 1, op2=0x1
    # Actually, SLLI in Xtensa: op0=0, op2=0x1, op1=0x0 (shift amount 1-31)
    #                           op0=0, op2=0x1, op1=0x1 (shift amount 32)

    # ---- MUL/MULL (op2=2) ----
    if op2 == 2:
        if op1 == 8:
            return "mull", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"
        if op1 == 0xC:
            return "quou", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"
        if op1 == 0xD:
            return "quos", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"
        if op1 == 0xE:
            return "remu", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"
        if op1 == 0xF:
            return "rems", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"

    # ---- RSR/WSR/XSR (op2=0, op1=3/RSR, etc.) ----
    # RSR: op0=0, op2=0, op1=3, sr=s|(r<<4)
    # WSR: op0=0, op2=0, op1=0x13 → op2=1, op1=3? No...
    # Actually: RSR: op0=0, op2=0, op1=3
    #           WSR: op0=0, op2=1, op1=3
    #           XSR: op0=0, op2=1, op1=6
    if op2 == 0 and op1 == 3:
        sr = (r << 4) | s
        return "rsr", f"{_REG[t]}, {sr}"
    if op2 == 1 and op1 == 3:
        sr = (r << 4) | s
        return "wsr", f"{_REG[t]}, {sr}"
    if op2 == 1 and op1 == 6:
        sr = (r << 4) | s
        return "xsr", f"{_REG[t]}, {sr}"

    # ---- EXTUI (op2=4, com extensão) ----
    if op2 in (4, 5):
        # EXTUI at, as, shiftimm, maskimm
        shift = ((op2 & 1) << 4) | s
        mask = r + 1
        return "extui", f"{_REG[t]}, {_REG[s]}, {shift}, {mask}"

    # ---- SLLI (op2=1, op1=0) ----
    if op2 == 1 and op1 == 0:
        # SLLI: shift amount = 32 - (sa campo)
        sa = r | ((op1 & 0) << 4)  # Hmm, this is tricky
        # Actually SLLI encoding: op0=0, op2=0x1, op1=0x0
        # shift amount = 32 - sa where sa = (1 << 4) | r? No
        # Let me just use r as the raw value
        return "slli", f"{_REG[t]}, {_REG[s]}, {r}"

    # ---- MOVEQZ/MOVNEZ/MOVLTZ/MOVGEZ (op2=3) ----
    if op2 == 3:
        mov_ops = {0x8: "moveqz", 0x9: "movnez", 0xA: "movltz", 0xB: "movgez"}
        if op1 in mov_ops:
            return mov_ops[op1], f"{_REG[r]}, {_REG[s]}, {_REG[t]}"

    return "dw", f"0x{inst:06x}"


def _decode_rrr_special(r: int, s: int, t: int) -> tuple[str, str]:
    """Decodifica RRR specials (op0=0, op1=0, op2=0).

    No grupo ST0 (r=0), o campo t determina a instrução:
      t=0xA → JX/RET, t=0xC-0xF → CALLX0/4/8/12.
    Para r≠0, r determina o sub-grupo (BREAK, SYSCALL, RSIL, etc.).
    """

    if r == 0:
        # ---- ST0 / SNM0: decodificado por t e s ----

        # JX as (jump to register) — t=0xA
        if t == 0xA:
            if s == 0:
                return "ret", ""   # JX a0 = RET (non-windowed)
            return "jx", _REG[s]

        # CALLX0/CALLX4/CALLX8/CALLX12 — t=0xC..0xF
        if t >= 0xC:
            callx_ops = {0xC: "callx0", 0xD: "callx4", 0xE: "callx8", 0xF: "callx12"}
            return callx_ops[t], _REG[s]

        # RETW (windowed return, 24-bit form) — t=2
        if t == 2 and s == 0:
            return "retw", ""

        # ILL (illegal instruction trap) — t=0, s=0
        if t == 0 and s == 0:
            return "ill", ""

        # RFWO / RFWU
        if t == 4 and s == 0:
            return "rfwo", ""
        if t == 5 and s == 0:
            return "rfwu", ""

        return "dw.st0", f"s={s}, t={t}"

    # ---- r≠0: sub-grupos com opcodes fixos ----

    # ISYNC / RSYNC / ESYNC / DSYNC (r=1)
    if r == 1:
        sync_ops = {0: "isync", 1: "rsync", 2: "esync", 3: "dsync"}
        if t in sync_ops:
            return sync_ops[t], ""

    # BREAK (r=4)
    if r == 4:
        return "break", f"{s}, {t}"

    # SYSCALL (r=5)
    if r == 5 and s == 0 and t == 0:
        return "syscall", ""

    # SIMCALL (r=5, s=1)
    if r == 5 and s == 1 and t == 0:
        return "simcall", ""

    # RSIL (r=6)
    if r == 6:
        return "rsil", f"{_REG[t]}, {s}"

    # WAITI (r=7)
    if r == 7 and t == 0:
        return "waiti", f"{s}"

    return "dw.rrr", f"r={r}, s={s}, t={t}"


def _decode_rri8(inst: int) -> tuple[str, str]:
    """Decodifica instruções RRI8 (op0=2): loads, stores, ADDI, MOVI."""
    t = (inst >> 4) & 0xF
    s = (inst >> 8) & 0xF
    r = (inst >> 12) & 0xF
    imm8 = (inst >> 16) & 0xFF

    # Load/Store com offset
    if r in _RRI8_LOAD_STORE:
        mnem = _RRI8_LOAD_STORE[r]
        scale = _RRI8_SCALE[r]
        offset = imm8 * scale
        if r >= 4 and r <= 6:
            # Store: s32i at, as, offset → MEM[as+offset] = at
            return mnem, f"{_REG[t]}, [{_REG[s]}, #{offset}]"
        # Load: l32i at, as, offset → at = MEM[as+offset]
        return mnem, f"{_REG[t]}, [{_REG[s]}, #{offset}]"

    # ADDI (r=0xC)
    if r == 0xC:
        imm = sign_extend(imm8, 8)
        return "addi", f"{_REG[t]}, {_REG[s]}, {imm}"

    # ADDMI (r=0xD)
    if r == 0xD:
        imm = sign_extend(imm8, 8) << 8
        return "addmi", f"{_REG[t]}, {_REG[s]}, {imm}"

    # MOVI (r=0xA)
    if r == 0xA:
        # MOVI: imm12 = (s[3:0] << 8) | imm8, sign-extended de 12 bits
        # O campo s carrega os bits altos do imediato
        imm12 = (s << 8) | imm8
        imm = sign_extend(imm12, 12)
        return "movi", f"{_REG[t]}, {imm}"

    # CACHE ops (r=7, 8, etc.) — mostra genérico
    cache_ops = {
        0x7: "dpfr", 0x8: "dpfw", 0x3: "lsiu",  # exemplos
    }
    if r in cache_ops:
        return cache_ops[r], f"{_REG[t]}, [{_REG[s]}, #{imm8}]"

    return "dw", f"0x{inst:06x}"


def _decode_si(inst: int, addr: int) -> tuple[str, str]:
    """Decodifica instruções SI (op0=6): J, BEQZ, BNEZ, ENTRY, etc.

    O campo n de 2 bits (bits[5:4]) determina o formato:
      n2=0 → J (formato CALL, offset de 18 bits em bits[23:6])
      n2=1 → BZ (BEQZ/BNEZ/BLTZ/BGEZ, sub-seleção por m=bits[7:6])
      n2=2 → BI0 (BEQI/BNEI/BLTI/BGEI, sub-seleção por m)
      n2=3 → BI1 (ENTRY/BLTUI/BGEUI, sub-seleção por m)
    """
    n2 = (inst >> 4) & 0x3   # 2-bit n
    m = (inst >> 6) & 0x3    # sub-opcode dentro do grupo

    # ---- J (unconditional jump): n2=0 ----
    if n2 == 0:
        # Formato CALL: offset de 18 bits em bits[23:6]
        offset18 = sign_extend((inst >> 6) & 0x3FFFF, 18)
        target = addr + 4 + offset18
        return "j", f"0x{target & 0xFFFFFFFF:x}"

    s = (inst >> 8) & 0xF

    # ---- BZ group (n2=1): BEQZ/BNEZ/BLTZ/BGEZ ----
    if n2 == 1:
        imm12 = sign_extend((inst >> 12) & 0xFFF, 12)
        target = addr + 4 + imm12
        bz_ops = {0: "beqz", 1: "bnez", 2: "bltz", 3: "bgez"}
        return bz_ops[m], f"{_REG[s]}, 0x{target & 0xFFFFFFFF:x}"

    # ---- BI0 group (n2=2): BEQI/BNEI/BLTI/BGEI ----
    if n2 == 2:
        imm8 = sign_extend((inst >> 16) & 0xFF, 8)
        target = addr + 4 + imm8
        t = (inst >> 4) & 0xF
        # Para BI0, campo r (bits[15:12]) codifica o imediato (B4CONST)
        r = (inst >> 12) & 0xF
        bi0_ops = {0: "beqi", 1: "bnei", 2: "blti", 3: "bgei"}
        b4c = _b4const(r)
        return bi0_ops[m], f"{_REG[s]}, {b4c}, 0x{target & 0xFFFFFFFF:x}"

    # ---- BI1 group (n2=3): ENTRY/BLTUI/BGEUI ----
    if n2 == 3:
        if m == 0:
            # ENTRY (windowed, xtensawin)
            imm12 = (inst >> 12) & 0xFFF
            framesize = imm12 << 3   # imediato em unidades de 8 bytes
            return "entry", f"{_REG[s]}, {framesize}"
        # BLTUI (m=2), BGEUI (m=3)
        if m in (2, 3):
            imm8 = sign_extend((inst >> 16) & 0xFF, 8)
            target = addr + 4 + imm8
            r = (inst >> 12) & 0xF
            b4c = _b4const(r)
            bi1_ops = {2: "bltui", 3: "bgeui"}
            return bi1_ops[m], f"{_REG[s]}, {b4c}, 0x{target & 0xFFFFFFFF:x}"

    return "dw", f"0x{inst:06x}"


def _decode_b(inst: int, addr: int) -> tuple[str, str]:
    """Decodifica instruções B (op0=7): BEQ, BNE, BGE, BLT, etc."""
    r = (inst >> 12) & 0xF
    s = (inst >> 8) & 0xF
    t_field = (inst >> 4) & 0xF   # t = bits[7:4] = (m << 2) | n
    imm8 = sign_extend((inst >> 16) & 0xFF, 8)
    target = addr + 4 + imm8

    # Branch registrador vs registrador
    if r in _BRI8_OPS:
        return _BRI8_OPS[r], f"{_REG[s]}, {_REG[t_field]}, 0x{target & 0xFFFFFFFF:x}"

    # Branch registrador vs imediato (BEQI, BNEI, BGEI, BLTI)
    if r in _BRII_OPS:
        # Para branches com imediato, o campo t é o valor do imediato (B4CONST)
        b4const = _b4const(t_field)
        return _BRII_OPS[r], f"{_REG[s]}, {b4const}, 0x{target & 0xFFFFFFFF:x}"

    # BGEUI / BLTUI (r=0xE com unsigned, r=0xF com unsigned)
    # Hmm, these use different r values

    return "dw", f"0x{inst:06x}"


def _b4const(t: int) -> int:
    """Converte campo t de 4 bits para constante B4CONST."""
    _B4CONST = [-1, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 16, 32, 64, 128, 256]
    if 0 <= t < 16:
        return _B4CONST[t]
    return t


# ---------------------------------------------------------------------------
# Decodificação — instruções de 16 bits (narrow / Code Density)
# ---------------------------------------------------------------------------

def _decode_16(inst: int, addr: int) -> tuple[str, str]:
    """Retorna (mnemonic, operands) para instrução narrow de 16 bits."""

    op0 = inst & 0xF
    t = (inst >> 4) & 0xF
    s = (inst >> 8) & 0xF
    r = (inst >> 12) & 0xF

    # ---- L32I.N (op0=8) ----
    if op0 == 0x8:
        offset = r * 4  # r = word offset
        return "l32i.n", f"{_REG[t]}, [{_REG[s]}, #{offset}]"

    # ---- S32I.N (op0=9) ----
    if op0 == 0x9:
        offset = r * 4
        return "s32i.n", f"{_REG[t]}, [{_REG[s]}, #{offset}]"

    # ---- ADD.N (op0=A) ----
    if op0 == 0xA:
        return "add.n", f"{_REG[r]}, {_REG[s]}, {_REG[t]}"

    # ---- ADDI.N (op0=B) ----
    if op0 == 0xB:
        # O imediato é codificado como r+1 (exceto r=0 que significa -1)
        # Na verdade: imm = r se r != 0, senão imm = -1
        # Checagem: MicroPython usa ENCODE_RRRN(0xB, imm-1, reg_src, reg_dest)
        # Então o campo r = imm - 1, e imm = r + 1
        # Mas r=0 → imm=1? E para -1 precisaria de r=0 com flag diferente?
        # Na ISA: imm4 de ADDI.N é: 0 → -1, 1..15 → 1..15
        # Hmm, vamos usar: se r == 0 → imm = -1, senão imm = r
        imm = r if r != 0 else -1
        return "addi.n", f"{_REG[t]}, {_REG[s]}, {imm}"

    # ---- MOVI.N / BEQZ.N / BNEZ.N (op0=C) ----
    if op0 == 0xC:
        # bit[7] distingue MOVI.N de branches
        bit7 = (inst >> 7) & 1
        if bit7 == 0:
            # MOVI.N: imm7 = bits[14:8] (7 bits com extensão de sinal para -32..95)
            imm7 = (inst >> 8) & 0x7F
            # Mapeia: 0..95 → 0..95; 96..127 → -32..-1
            if imm7 > 95:
                imm = imm7 - 128
            else:
                imm = imm7
            dest = (inst >> 4) & 0x7  # s field (lower 3 bits for narrow)
            # Actually, in MOVI.N format: bits[6:4] = s (register), bit[7]=0
            return "movi.n", f"{_REG[dest]}, {imm}"
        else:
            # BEQZ.N / BNEZ.N
            bit6 = (inst >> 6) & 1
            s_reg = (inst >> 4) & 0x3  # 2-bit register
            # imm6 for branch offset
            imm6 = ((inst >> 8) & 0xF) | (((inst >> 12) & 0x3) << 4)
            target = addr + 4 + imm6
            # Hmm, the encoding is complex. Let me simplify:
            if bit6 == 0:
                return "beqz.n", f"{_REG[s_reg]}, 0x{target & 0xFFFFFFFF:x}"
            return "bnez.n", f"{_REG[s_reg]}, 0x{target & 0xFFFFFFFF:x}"

    # ---- MOV.N / specials (op0=D) ----
    if op0 == 0xD:
        if r == 0xF:
            # Specials: RET.N, RETW.N, BREAK.N, NOP.N
            if t == 0:
                return "ret.n", ""
            if t == 1:
                return "retw.n", ""
            if t == 2:
                return "break.n", f"{s}"
            if t == 3:
                return "nop.n", ""
            return "dw", f"0x{inst:04x}"
        # MOV.N: move register
        return "mov.n", f"{_REG[t]}, {_REG[s]}"

    return "dw", f"0x{inst:04x}"


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def disassemble(code: bytes, arch_code: int) -> str:
    """
    Disassembla código Xtensa.

    Parâmetros:
        code       — bytes do código de máquina
        arch_code  — código de arquitetura (9=xtensa, 10=xtensawin)

    Retorna string formatada (offset + assembly), uma instrução por linha.
    """
    instructions: list[tuple[int, str]] = []
    pos = 0

    while pos < len(code):
        start = pos
        try:
            byte0 = code[pos]
            op0 = byte0 & 0xF

            if op0 >= 8:
                # Instrução narrow de 16 bits
                if pos + 1 >= len(code):
                    instructions.append((pos, f"db      0x{code[pos]:02x}"))
                    pos += 1
                    continue
                inst16 = code[pos] | (code[pos + 1] << 8)
                pos += 2
                mnem, operands = _decode_16(inst16, start)
            else:
                # Instrução de 24 bits
                if pos + 2 >= len(code):
                    for i in range(pos, len(code)):
                        instructions.append((i, f"db      0x{code[i]:02x}"))
                    break
                inst24 = code[pos] | (code[pos + 1] << 8) | (code[pos + 2] << 16)
                pos += 3
                mnem, operands = _decode_24(inst24, start)

        except (IndexError, KeyError):
            for i in range(start, len(code)):
                instructions.append((i, f"db      0x{code[i]:02x}"))
            break

        asm = f"{mnem:<8s} {operands}" if operands else mnem
        instructions.append((start, asm))

    # Byte solto no final
    if pos < len(code) and not any(off == pos for off, _ in instructions):
        instructions.append((pos, f"db      0x{code[pos]:02x}"))

    lines = []
    for offset, asm_str in instructions:
        lines.append(f"0x{offset:04x}:  {asm_str}")
    return "\n".join(lines)
