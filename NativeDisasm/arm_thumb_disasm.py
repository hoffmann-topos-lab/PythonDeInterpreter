from NativeDisasm.base import sign_extend


_REG = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
]

_CC = [
    "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
    "hi", "ls", "ge", "lt", "gt", "le", "al", "",
]


_DP_OPS = [
    "and", "eor", "lsl", "lsr", "asr", "adc", "sbc", "ror",
    "tst", "neg", "cmp", "cmn", "orr", "mul", "bic", "mvn",
]

_LDST_REG = [
    "str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh",
]


def _reglist(bits: int, extra: str = "") -> str:
    regs = []
    for i in range(8):
        if bits & (1 << i):
            regs.append(_REG[i])
    if extra:
        regs.append(extra)
    return "{" + ", ".join(regs) + "}"


def _read_hw(code: bytes, pos: int) -> int:

    return code[pos] | (code[pos + 1] << 8)



def _decode_thumb16(hw: int, addr: int) -> tuple[str, str]:

    top5 = (hw >> 11) & 0x1F
    top4 = (hw >> 12) & 0xF
    top3 = (hw >> 13) & 0x7

    if top5 <= 2:
        imm5 = (hw >> 6) & 0x1F
        rm = (hw >> 3) & 7
        rd = hw & 7
        ops = ["lsl", "lsr", "asr"]
        return ops[top5], f"{_REG[rd]}, {_REG[rm]}, #{imm5}"

    if top5 == 3:
        op = (hw >> 9) & 3 
        rn = (hw >> 3) & 7
        rd = hw & 7
        if op < 2:
            rm = (hw >> 6) & 7
            mnem = "add" if op == 0 else "sub"
            return mnem, f"{_REG[rd]}, {_REG[rn]}, {_REG[rm]}"
        imm3 = (hw >> 6) & 7
        mnem = "add" if op == 2 else "sub"
        return mnem, f"{_REG[rd]}, {_REG[rn]}, #{imm3}"

    if top3 == 1:
        op = (hw >> 11) & 3  
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        ops = ["movs", "cmp", "adds", "subs"]
        return ops[op], f"{_REG[rd]}, #{imm8}"

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

    if (hw >> 10) == 0b010001:
        op = (hw >> 8) & 3
        rm = (hw >> 3) & 0xF 
        rd = (hw & 7) | ((hw >> 4) & 8)  
        if op == 0:
            return "add", f"{_REG[rd]}, {_REG[rm]}"
        if op == 1:
            return "cmp", f"{_REG[rd]}, {_REG[rm]}"
        if op == 2:
            return "mov", f"{_REG[rd]}, {_REG[rm]}"
        if hw & 0x80:
            return "blx", _REG[rm]
        return "bx", _REG[rm]

    if top5 == 0b01001:
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        return "ldr", f"{_REG[rd]}, [pc, #{imm8 * 4}]"

    if top4 == 0b0101:
        op = (hw >> 9) & 7
        rm = (hw >> 6) & 7
        rn = (hw >> 3) & 7
        rd = hw & 7
        return _LDST_REG[op], f"{_REG[rd]}, [{_REG[rn]}, {_REG[rm]}]"

    if top4 == 0b0110:
        is_load = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rd = hw & 7
        mnem = "ldr" if is_load else "str"
        off = imm5 * 4
        return mnem, f"{_REG[rd]}, [{_REG[rn]}, #{off}]"

    if top4 == 0b0111:
        is_load = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rd = hw & 7
        mnem = "ldrb" if is_load else "strb"
        return mnem, f"{_REG[rd]}, [{_REG[rn]}, #{imm5}]"

    if top5 in (0b10000, 0b10001):
        is_load = (hw >> 11) & 1
        imm5 = (hw >> 6) & 0x1F
        rn = (hw >> 3) & 7
        rd = hw & 7
        mnem = "ldrh" if is_load else "strh"
        off = imm5 * 2
        return mnem, f"{_REG[rd]}, [{_REG[rn]}, #{off}]"

    if top4 == 0b1001:
        is_load = (hw >> 11) & 1
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        mnem = "ldr" if is_load else "str"
        off = imm8 * 4
        return mnem, f"{_REG[rd]}, [sp, #{off}]"

    if top4 == 0b1010:
        is_sp = (hw >> 11) & 1
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        src = "sp" if is_sp else "pc"
        off = imm8 * 4
        return "add", f"{_REG[rd]}, {src}, #{off}"

    if top4 == 0b1011:
        if (hw >> 8) == 0b10110000:
            if hw & 0x80:
                imm7 = hw & 0x7F
                return "sub", f"sp, sp, #{imm7 * 4}"
            imm7 = hw & 0x7F
            return "add", f"sp, sp, #{imm7 * 4}"

        if (hw >> 9) == 0b1011010:
            rlist = hw & 0xFF
            extra = "lr" if (hw >> 8) & 1 else ""
            return "push", _reglist(rlist, extra)

        if (hw >> 9) == 0b1011110:
            rlist = hw & 0xFF
            extra = "pc" if (hw >> 8) & 1 else ""
            return "pop", _reglist(rlist, extra)

        if (hw >> 8) == 0xBE:
            return "bkpt", f"#{hw & 0xFF}"

        if (hw >> 8) == 0xBF:
            if (hw & 0xFF) == 0:
                return "nop", ""
            mask = hw & 0xF
            cond = (hw >> 4) & 0xF
            if mask:

                return f"it{_it_suffix(cond, mask)}", _CC[cond]
            return "nop", ""

        if (hw >> 10) == 0b10110010:
            op = (hw >> 6) & 3
            rm = (hw >> 3) & 7
            rd = hw & 7
            ops = ["sxth", "sxtb", "uxth", "uxtb"]
            return ops[op], f"{_REG[rd]}, {_REG[rm]}"

        if (hw >> 10) == 0b10111010:
            op = (hw >> 6) & 3
            rm = (hw >> 3) & 7
            rd = hw & 7
            ops = ["rev", "rev16", "???", "revsh"]
            return ops[op], f"{_REG[rd]}, {_REG[rm]}"

        return "dw", f"0x{hw:04x}"

    if top4 == 0b1100:
        is_load = (hw >> 11) & 1
        rn = (hw >> 8) & 7
        rlist = hw & 0xFF
        mnem = "ldmia" if is_load else "stmia"
        return mnem, f"{_REG[rn]}!, {_reglist(rlist)}"

    if top4 == 0b1101:
        cond = (hw >> 8) & 0xF
        if cond == 0xF:
            return "svc", f"#{hw & 0xFF}"
        if cond == 0xE:
            return "udf", f"#{hw & 0xFF}"
        imm8 = sign_extend(hw & 0xFF, 8)
        target = addr + 4 + (imm8 << 1)
        return f"b{_CC[cond]}", f"0x{target:x}"

    if top5 == 0b11100:
        imm11 = sign_extend(hw & 0x7FF, 11)
        target = addr + 4 + (imm11 << 1)
        return "b", f"0x{target:x}"

    return "dw", f"0x{hw:04x}"


def _it_suffix(cond: int, mask: int) -> str:
    base = cond & 1
    s = ""
    for bit in [3, 2, 1]:
        if mask & (1 << bit):
            break
        if mask & (1 << (bit - 1)):
            s += "t" if ((mask >> (bit - 1)) & 1) == base else "e"
    return s


def _decode_thumb32(hw0: int, hw1: int, addr: int) -> tuple[str, str]:

    op1 = (hw0 >> 11) & 0x3 

    if (hw0 >> 11) == 0b11110 and (hw1 & 0x8000):
        s_bit = (hw0 >> 10) & 1
        j1 = (hw1 >> 13) & 1
        j2 = (hw1 >> 11) & 1
        imm11 = hw1 & 0x7FF
        hw1_top2 = (hw1 >> 14) & 3
        is_unconditional = (hw1 >> 12) & 1

        if hw1_top2 == 3:
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
            if is_unconditional:
                imm10 = hw0 & 0x3FF
                i1 = 1 - (j1 ^ s_bit)
                i2 = 1 - (j2 ^ s_bit)
                imm25 = (s_bit << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                offset = sign_extend(imm25, 25)
                target = addr + 4 + offset
                return "b.w", f"0x{target:x}"
            cond = (hw0 >> 6) & 0xF
            imm6 = hw0 & 0x3F
            i1 = 1 - (j1 ^ s_bit)
            i2 = 1 - (j2 ^ s_bit)
            imm21 = (s_bit << 20) | (i1 << 19) | (i2 << 18) | (imm6 << 12) | (imm11 << 1)
            offset = sign_extend(imm21, 21)
            target = addr + 4 + offset
            return f"b{_CC[cond]}.w", f"0x{target:x}"


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

    if (hw0 & 0xFBF0) == 0xF240:
        i = (hw0 >> 10) & 1
        imm4 = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        return "movw", f"{_REG[rd]}, #0x{imm16:x}"

    if (hw0 & 0xFBF0) == 0xF2C0:
        i = (hw0 >> 10) & 1
        imm4 = hw0 & 0xF
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        return "movt", f"{_REG[rd]}, #0x{imm16:x}"

    if (hw0 & 0xFBE0) == 0xF100:
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
        s_flag = (hw0 >> 4) & 1
        rn = hw0 & 0xF
        i = (hw0 >> 10) & 1
        imm3 = (hw1 >> 12) & 7
        rd = (hw1 >> 8) & 0xF
        imm8 = hw1 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        mnem = "subs.w" if s_flag else "sub.w"
        return mnem, f"{_REG[rd]}, {_REG[rn]}, #{_thumb_expand_imm(imm12)}"

    if (hw0 & 0xFBF0) == 0xF1B0 and (hw1 & 0x0F00) == 0x0F00:
        rn = hw0 & 0xF
        i = (hw0 >> 10) & 1
        imm3 = (hw1 >> 12) & 7
        imm8 = hw1 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8
        return "cmp.w", f"{_REG[rn]}, #{_thumb_expand_imm(imm12)}"

    return "dw", f"0x{hw0:04x}, 0x{hw1:04x}"


def _thumb_expand_imm(imm12: int) -> int:
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
    rot = (imm12 >> 7) & 0x1F
    val = 0x80 | (imm12 & 0x7F)
    return ((val >> rot) | (val << (32 - rot))) & 0xFFFFFFFF



def disassemble(code: bytes, arch_code: int) -> str:

    instructions: list[tuple[int, str]] = []
    pos = 0

    while pos + 1 < len(code):
        start = pos
        try:
            hw0 = _read_hw(code, pos)
            pos += 2

            if hw0 >= 0xE800 and pos + 1 < len(code):
                hw1 = _read_hw(code, pos)
                pos += 2
                mnem, operands = _decode_thumb32(hw0, hw1, start)
            else:
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

    if pos < len(code):
        instructions.append((pos, f"db      0x{code[pos]:02x}"))

    lines = []
    for offset, asm_str in instructions:
        lines.append(f"0x{offset:04x}:  {asm_str}")
    return "\n".join(lines)
