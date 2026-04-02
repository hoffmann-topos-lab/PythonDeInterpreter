"""
Disassembler ARM Thumb / Thumb-2 para código nativo MicroPython.

Cobre o subconjunto de instruções emitido pelo mpy-cross para arch_codes 3-8
(armv6 até armv7emdp). Instruções 16-bit (Thumb-1) e 32-bit (Thumb-2).
"""

from NativeDisasm.base import sign_extend

# ---------------------------------------------------------------------------
# Tabelas
# ---------------------------------------------------------------------------

_REG = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
]

_CC = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "",
]

# Data-processing opcodes (formato 4 — 010000 xxxx Rm Rd)
_DP_OPS = [
    "and", "eor", "lsl", "lsr", "asr", "adc", "sbc", "ror",
    "tst", "neg", "cmp", "cmn", "orr", "mul", "bic", "mvn",
]

# Load/store register offset (formato 7/8 — 0101 xxx Rm Rn Rd)
_LDST_REG = [
    "str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reglist(bits: int, extra: str = "") -> str:
    """Formata uma lista de registradores a partir de bitmask."""
    regs = []
    for i in range(8):
        if bits & (1 << i):
            regs.append(_REG[i])
    if extra:
        regs.append(extra)
    return "{" + ", ".join(regs) + "}"


def _read_hw(code: bytes, pos: int) -> int:
    """Lê um halfword (16 bits) little-endian."""
    return code[pos] | (code[pos + 1] << 8)


# ---------------------------------------------------------------------------
# Decodificação de instrução Thumb 16-bit
# ---------------------------------------------------------------------------

def _decode_thumb16(hw: int, addr: int) -> tuple[str, str]:
    """Retorna (mnemonic, operands) para instrução Thumb 16-bit."""

    top5 = (hw >> 11) & 0x1F
    top4 = (hw >> 12) & 0xF
    top3 = (hw >> 13) & 0x7

    # ---- Shift por imediato (00000-00010) ----
    if top5 <= 2:
        imm5 = (hw >> 6) & 0x1F
        rm = (hw >> 3) & 7
        rd = hw & 7
        ops = ["lsl", "lsr", "asr"]
        return ops[top5], f"{_REG[rd]}, {_REG[rm]}, #{imm5}"

    # ---- Add/Sub registrador/imm3 (00011xx) ----
    if top5 == 3:
        op = (hw >> 9) & 3  # 0=add_reg, 1=sub_reg, 2=add_imm3, 3=sub_imm3
        rn = (hw >> 3) & 7
        rd = hw & 7
        if op < 2:
            rm = (hw >> 6) & 7
            mnem = "add" if op == 0 else "sub"
            return mnem, f"{_REG[rd]}, {_REG[rn]}, {_REG[rm]}"
        imm3 = (hw >> 6) & 7
        mnem = "add" if op == 2 else "sub"
        return mnem, f"{_REG[rd]}, {_REG[rn]}, #{imm3}"

    # ---- Move/Compare/Add/Sub imm8 (001xx) ----
    if top3 == 1:
        op = (hw >> 11) & 3  # 0=movs, 1=cmp, 2=adds, 3=subs
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        ops = ["movs", "cmp", "adds", "subs"]
        return ops[op], f"{_REG[rd]}, #{imm8}"

    # ---- Data-processing registrador (010000) ----
    if (hw >> 10) == 0b010000:
        op = (hw >> 6) & 0xF
        rm = (hw >> 3) & 7
        rd = hw & 7
        mnem = _DP_OPS[op]
        if mnem in ("tst", "cmp", "cmn"):
            return mnem, f"{_REG[rd]}, {_REG[rm]}"
        if mnem == "neg":
            return "neg", f"{_REG[rd]}, {_REG[rm]}"
        return mnem, f"{_REG[rd]}, {_REG[rm]}"

    # ---- Special data / BX / BLX (010001) ----
    if (hw >> 10) == 0b010001:
        op = (hw >> 8) & 3
        rm = (hw >> 3) & 0xF  # 4 bits (acessa r0-r15)
        rd = (hw & 7) | ((hw >> 4) & 8)  # D:Rd (4 bits)
        if op == 0:
            return "add", f"{_REG[rd]}, {_REG[rm]}"
        if op == 1:
            return "cmp", f"{_REG[rd]}, {_REG[rm]}"
        if op == 2:
            return "mov", f"{_REG[rd]}, {_REG[rm]}"
        # op == 3: BX / BLX
        if hw & 0x80:
            return "blx", _REG[rm]
        return "bx", _REG[rm]

    # ---- LDR Rd, [PC, #imm8*4] (01001) ----
    if top5 == 0b01001:
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        return "ldr", f"{_REG[rd]}, [pc, #{imm8 * 4}]"

    # ---- Load/Store registrador offset (0101) ----
    if top4 == 0b0101:
        op = (hw >> 9) & 7
        rm = (hw >> 6) & 7
        rn = (hw >> 3) & 7
        rd = hw & 7
        return _LDST_REG[op], f"{_REG[rd]}, [{_REG[rn]}, {_REG[rm]}]"

    # ---- STR/LDR word imm5 (0110x) ----
    if top4 == 0b0110:
        is_load = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rd = hw & 7
        mnem = "ldr" if is_load else "str"
        off = imm5 * 4
        return mnem, f"{_REG[rd]}, [{_REG[rn]}, #{off}]"

    # ---- STRB/LDRB imm5 (0111x) ----
    if top4 == 0b0111:
        is_load = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rd = hw & 7
        mnem = "ldrb" if is_load else "strb"
        return mnem, f"{_REG[rd]}, [{_REG[rn]}, #{imm5}]"

    # ---- STRH/LDRH imm5 (1000x) ----
    if top5 in (0b10000, 0b10001):
        is_load = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rd = hw & 7
        mnem = "ldrh" if is_load else "strh"
        off = imm5 * 2
        return mnem, f"{_REG[rd]}, [{_REG[rn]}, #{off}]"

    # ---- STR/LDR SP-relative (1001x) ----
    if top4 == 0b1001:
        is_load = (hw >> 11) & 1
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        mnem = "ldr" if is_load else "str"
        off = imm8 * 4
        return mnem, f"{_REG[rd]}, [sp, #{off}]"

    # ---- ADD Rd, PC/SP, #imm8*4 (1010x) ----
    if top4 == 0b1010:
        is_sp = (hw >> 11) & 1
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        src = "sp" if is_sp else "pc"
        off = imm8 * 4
        return "add", f"{_REG[rd]}, {src}, #{off}"

    # ---- Miscelânea (1011xxxx) ----
    if top4 == 0b1011:
        # ADD/SUB SP (10110000)
        if (hw >> 8) == 0b10110000:
            if hw & 0x80:
                imm7 = hw & 0x7F
                return "sub", f"sp, sp, #{imm7 * 4}"
            imm7 = hw & 0x7F
            return "add", f"sp, sp, #{imm7 * 4}"

        # PUSH (1011010x)
        if (hw >> 9) == 0b1011010:
            rlist = hw & 0xFF
            extra = "lr" if (hw >> 8) & 1 else ""
            return "push", _reglist(rlist, extra)

        # POP (1011110x)
        if (hw >> 9) == 0b1011110:
            rlist = hw & 0xFF
            extra = "pc" if (hw >> 8) & 1 else ""
            return "pop", _reglist(rlist, extra)

        # BKPT (10111110)
        if (hw >> 8) == 0xBE:
            return "bkpt", f"#{hw & 0xFF}"

        # NOP / IT / hints (10111111)
        if (hw >> 8) == 0xBF:
            if (hw & 0xFF) == 0:
                return "nop", ""
            # IT block (armv7m+)
            mask = hw & 0xF
            cond = (hw >> 4) & 0xF
            if mask:
                # Simplificado — mostra apenas a primeira condição
                return f"it{_it_suffix(cond, mask)}", _CC[cond]
            return "nop", ""

        # SXTH/SXTB/UXTH/UXTB (10110010 xx Rm Rd)
        if (hw >> 10) == 0b10110010:
            op = (hw >> 6) & 3
            rm = (hw >> 3) & 7
            rd = hw & 7
            ops = ["sxth", "sxtb", "uxth", "uxtb"]
            return ops[op], f"{_REG[rd]}, {_REG[rm]}"

        # REV/REV16/REVSH (10111010 xx Rm Rd)
        if (hw >> 10) == 0b10111010:
            op = (hw >> 6) & 3
            rm = (hw >> 3) & 7
            rd = hw & 7
            ops = ["rev", "rev16", "???", "revsh"]
            return ops[op], f"{_REG[rd]}, {_REG[rm]}"

        return "dw", f"0x{hw:04x}"

    # ---- STMIA/LDMIA (1100x) ----
    if top4 == 0b1100:
        is_load = (hw >> 11) & 1
        rn = (hw >> 8) & 7
        rlist = hw & 0xFF
        mnem = "ldmia" if is_load else "stmia"
        return mnem, f"{_REG[rn]}!, {_reglist(rlist)}"

    # ---- Branch condicional (1101 cond) | SVC (11011111) ----
    if top4 == 0b1101:
        cond = (hw >> 8) & 0xF
        if cond == 0xF:
            # SVC
            return "svc", f"#{hw & 0xFF}"
        if cond == 0xE:
            # UDF ou reservado
            return "udf", f"#{hw & 0xFF}"
        imm8 = sign_extend(hw & 0xFF, 8)
        target = addr + 4 + (imm8 << 1)
        return f"b{_CC[cond]}", f"0x{target:x}"

    # ---- Branch incondicional (11100) ----
    if top5 == 0b11100:
        imm11 = sign_extend(hw & 0x7FF, 11)
        target = addr + 4 + (imm11 << 1)
        return "b", f"0x{target:x}"

    return "dw", f"0x{hw:04x}"


def _it_suffix(cond: int, mask: int) -> str:
    """Gera sufixo T/E para bloco IT."""
    base = cond & 1
    s = ""
    for bit in [3, 2, 1]:
        if mask & (1 << bit):
            break
        if mask & (1 << (bit - 1)):
            s += "t" if ((mask >> (bit - 1)) & 1) == base else "e"
    return s


# ---------------------------------------------------------------------------
# Decodificação de instrução Thumb-2 32-bit
# ---------------------------------------------------------------------------

def _decode_thumb32(hw0: int, hw1: int, addr: int) -> tuple[str, str]:
    """Retorna (mnemonic, operands) para instrução Thumb-2 32-bit."""

    op1 = (hw0 >> 11) & 0x3  # bits [12:11] do primeiro halfword

    # ---- Branches (B.W, BL, BLX) ----
    # Primeiro halfword: 11110 S ...  (bits [15:11] = 11110 = 30)
    # Segundo halfword: bit[15]=1 sempre para branches
    if (hw0 >> 11) == 0b11110 and (hw1 & 0x8000):
        s_bit = (hw0 >> 10) & 1
        j1 = (hw1 >> 13) & 1
        j2 = (hw1 >> 11) & 1
        imm11 = hw1 & 0x7FF
        hw1_top2 = (hw1 >> 14) & 3
        is_unconditional = (hw1 >> 12) & 1

        if hw1_top2 == 3:
            # BL (bit12=1) ou BLX (bit12=0)
            imm10 = hw0 & 0x3FF
            i1 = 1 - (j1 ^ s_bit)
            i2 = 1 - (j2 ^ s_bit)
            imm25 = (s_bit << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
            offset = sign_extend(imm25, 25)
            target = addr + 4 + offset
            if is_unconditional:
                return "bl", f"0x{target:x}"
            return "blx", f"0x{target & ~1:x}"
        else:
            # B.W: hw1_top2 == 2 (bits [15:14] = 10)
            if is_unconditional:
                # Unconditional B.W
                imm10 = hw0 & 0x3FF
                i1 = 1 - (j1 ^ s_bit)
                i2 = 1 - (j2 ^ s_bit)
                imm25 = (s_bit << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                offset = sign_extend(imm25, 25)
                target = addr + 4 + offset
                return "b.w", f"0x{target:x}"
            # Conditional B.W
            cond = (hw0 >> 6) & 0xF
            imm6 = hw0 & 0x3F
            i1 = 1 - (j1 ^ s_bit)
            i2 = 1 - (j2 ^ s_bit)
            imm21 = (s_bit << 20) | (i1 << 19) | (i2 << 18) | (imm6 << 12) | (imm11 << 1)
            offset = sign_extend(imm21, 21)
            target = addr + 4 + offset
            return f"b{_CC[cond]}.w", f"0x{target:x}"

    # ---- LDR.W / STR.W com imm12 ----
    # 11111000 1 1 0 L Rn | Rt imm12
    # L=1 → LDR.W, L=0 → STR.W
    if (hw0 >> 4) == 0xF8D:
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        imm12 = hw1 & 0xFFF
        return "ldr.w", f"{_REG[rt]}, [{_REG[rn]}, #{imm12}]"

    if (hw0 >> 4) == 0xF8C:
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        imm12 = hw1 & 0xFFF
        return "str.w", f"{_REG[rt]}, [{_REG[rn]}, #{imm12}]"

    # ---- LDRB.W / STRB.W com imm12 ----
    if (hw0 >> 4) == 0xF89:
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        imm12 = hw1 & 0xFFF
        return "ldrb.w", f"{_REG[rt]}, [{_REG[rn]}, #{imm12}]"

    if (hw0 >> 4) == 0xF88:
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        imm12 = hw1 & 0xFFF
        return "strb.w", f"{_REG[rt]}, [{_REG[rn]}, #{imm12}]"

    # ---- LDRH.W / STRH.W com imm12 ----
    if (hw0 >> 4) == 0xF8B:
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        imm12 = hw1 & 0xFFF
        return "ldrh.w", f"{_REG[rt]}, [{_REG[rn]}, #{imm12}]"

    if (hw0 >> 4) == 0xF8A:
        rn = hw0 & 0xF
        rt = (hw1 >> 12) & 0xF
        imm12 = hw1 & 0xFFF
        return "strh.w", f"{_REG[rt]}, [{_REG[rn]}, #{imm12}]"

    # ---- MOVW Rd, #imm16 (11110 i 10 0100 imm4 | 0 imm3 Rd imm8) ----
    if (hw0 & 0xFBF0) == 0xF240:
        i = (hw0 >> 10) & 1
        imm4 = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        return "movw", f"{_REG[rd]}, #0x{imm16:x}"

    # ---- MOVT Rd, #imm16 (11110 i 10 1100 imm4 | 0 imm3 Rd imm8) ----
    if (hw0 & 0xFBF0) == 0xF2C0:
        i = (hw0 >> 10) & 1
        imm4 = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        return "movt", f"{_REG[rd]}, #0x{imm16:x}"

    # ---- ADD.W / SUB.W com imm12 (modificado Thumb) ----
    # 11110 i 01 000 S Rn | 0 imm3 Rd imm8  (ADD.W)
    # 11110 i 01 101 S Rn | 0 imm3 Rd imm8  (SUB.W)
    if (hw0 & 0xFBE0) == 0xF100:
        # ADD.W
        s_flag = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        i = (hw0 >> 10) & 1
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        mnem = "adds.w" if s_flag else "add.w"
        return mnem, f"{_REG[rd]}, {_REG[rn]}, #{_thumb_expand_imm(imm12)}"

    if (hw0 & 0xFBE0) == 0xF1A0:
        # SUB.W
        s_flag = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        i = (hw0 >> 10) & 1
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        mnem = "subs.w" if s_flag else "sub.w"
        return mnem, f"{_REG[rd]}, {_REG[rn]}, #{_thumb_expand_imm(imm12)}"

    # ---- CMP.W (11110 i 01 1011 Rn | 0 imm3 1111 imm8) ----
    if (hw0 & 0xFBF0) == 0xF1B0 and (hw1 & 0x0F00) == 0x0F00:
        rn = hw0 & 0xF
        i = (hw0 >> 10) & 1
        imm3 = (hw1 >> 12) & 7
        imm8 = hw1 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        return "cmp.w", f"{_REG[rn]}, #{_thumb_expand_imm(imm12)}"

    # ---- Desconhecido ----
    return "dw", f"0x{hw0:04x}, 0x{hw1:04x}"


def _thumb_expand_imm(imm12: int) -> int:
    """Expande ThumbExpandImm (imediato modificado de 12 bits)."""
    if (imm12 >> 8) == 0:
        return imm12 & 0xFF
    if (imm12 >> 8) == 1:
        val = imm12 & 0xFF
        return (val << 16) | val
    if (imm12 >> 8) == 2:
        val = imm12 & 0xFF
        return (val << 24) | (val << 8)
    if (imm12 >> 8) == 3:
        val = imm12 & 0xFF
        return (val << 24) | (val << 16) | (val << 8) | val
    # Rotação
    rot = (imm12 >> 7) & 0x1F
    val = 0x80 | (imm12 & 0x7F)
    return ((val >> rot) | (val << (32 - rot))) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# API pública
# ---------------------------------------------------------------------------

def disassemble(code: bytes, arch_code: int) -> str:
    """
    Disassembla código ARM Thumb / Thumb-2.

    Parâmetros:
        code       — bytes do código de máquina
        arch_code  — código de arquitetura (3-8)

    Retorna string formatada (offset + assembly), uma instrução por linha.
    """
    instructions: list[tuple[int, str]] = []
    pos = 0

    while pos + 1 < len(code):
        start = pos
        try:
            hw0 = _read_hw(code, pos)
            pos += 2

            if hw0 >= 0xE800 and pos + 1 < len(code):
                # Instrução 32-bit Thumb-2
                hw1 = _read_hw(code, pos)
                pos += 2
                mnem, operands = _decode_thumb32(hw0, hw1, start)
            else:
                # Instrução 16-bit
                mnem, operands = _decode_thumb16(hw0, start)

        except (IndexError, KeyError):
            for i in range(start, len(code), 2):
                if i + 1 < len(code):
                    w = _read_hw(code, i)
                    instructions.append((i, f"dw      0x{w:04x}"))
                else:
                    instructions.append((i, f"db      0x{code[i]:02x}"))
            break

        asm = f"{mnem:<7s} {operands}" if operands else mnem
        instructions.append((start, asm))

    # Byte solto no final
    if pos < len(code):
        instructions.append((pos, f"db      0x{code[pos]:02x}"))

    lines = []
    for offset, asm_str in instructions:
        lines.append(f"0x{offset:04x}:  {asm_str}")
    return "\n".join(lines)
