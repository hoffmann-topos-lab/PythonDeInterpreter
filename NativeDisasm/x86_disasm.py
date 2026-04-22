from NativeDisasm.base import read_i8, read_i32_le

_REG64 = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
]
_REG32 = [
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d",
]
_REG16 = [
    "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",
    "r8w", "r9w", "r10w","r11w","r12w","r13w","r14w","r15w",
]
_REG8 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
_REG8_REX = [
    "al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b","r11b","r12b","r13b","r14b","r15b",
]

_GRP1 = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]


_GRP2 = ["rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"]


_GRP3 = ["test", "test", "not", "neg", "mul", "imul", "div", "idiv"]


_CC = ["o","no","b","nb","z","nz","be","a","s","ns","p","np","l","nl","le","g"]




def _reg(index: int, size: int, has_rex: bool) -> str:
    if size == 64:
        return _REG64[index]
    if size == 32:
        return _REG32[index]
    if size == 16:
        return _REG16[index]
    if has_rex:
        return _REG8_REX[index]
    return _REG8[index]


def _fmt_disp(disp: int) -> str:
    if disp == 0:
        return ""
    if disp > 0:
        return f"+0x{disp:x}"
    return f"-0x{-disp:x}"


def _fmt_imm(value: int, signed: bool = True) -> str:
    if signed and value < 0:
        return f"-0x{-value:x}"
    return f"0x{value & 0xFFFFFFFF:x}"


def _decode_rm(data: bytes, off: int, rex_b: int, rex_x: int,
               size: int) -> tuple[str, int]:

    modrm = data[off]
    mod = (modrm >> 6) & 3
    raw_rm = modrm & 7
    rm = raw_rm | (rex_b << 3)
    eaten = 1 

    if mod == 3:
        return _reg(rm, size, True), eaten


    if raw_rm == 4:
        sib = data[off + eaten]
        eaten += 1
        scale = (sib >> 6) & 3
        raw_idx = (sib >> 3) & 7
        idx = raw_idx | (rex_x << 3)
        raw_base = sib & 7
        base = raw_base | (rex_b << 3)

        parts: list[str] = []

        if raw_base == 5 and mod == 0:
            disp = read_i32_le(data, off + eaten)
            eaten += 4
            if raw_idx != 4:
                parts.append(f"{_REG64[idx]}*{1 << scale}")
            if disp != 0 or not parts:
                parts.insert(0, f"0x{disp:x}")
        else:
            parts.append(_REG64[base])
            if raw_idx != 4:
                if scale == 0:
                    parts.append(_REG64[idx])
                else:
                    parts.append(f"{_REG64[idx]}*{1 << scale}")

            if mod == 1:
                disp = read_i8(data, off + eaten)
                eaten += 1
                if disp != 0:
                    parts[0] += _fmt_disp(disp)
            elif mod == 2:
                disp = read_i32_le(data, off + eaten)
                eaten += 4
                if disp != 0:
                    parts[0] += _fmt_disp(disp)

        return "[" + "+".join(parts) + "]", eaten

    if raw_rm == 5 and mod == 0:
        disp = read_i32_le(data, off + eaten)
        eaten += 4
        return f"[rip{_fmt_disp(disp)}]", eaten

    base_reg = _REG64[rm]
    if mod == 0:
        return f"[{base_reg}]", eaten
    if mod == 1:
        disp = read_i8(data, off + eaten)
        eaten += 1
        return f"[{base_reg}{_fmt_disp(disp)}]", eaten
    disp = read_i32_le(data, off + eaten)
    eaten += 4
    return f"[{base_reg}{_fmt_disp(disp)}]", eaten


def _decode_alu_rm_r(data, pos, rex_r, rex_b, rex_x, op_size, mnem, direction):
    reg_idx = ((data[pos] >> 3) & 7) | (rex_r << 3)
    rm_str, eaten = _decode_rm(data, pos, rex_b, rex_x, op_size)
    pos += eaten
    reg_str = _reg(reg_idx, op_size, True)
    if direction == 0:

        return mnem, f"{rm_str}, {reg_str}", pos
    return mnem, f"{reg_str}, {rm_str}", pos


def _decode_one(code: bytes, pos: int, mode: int):

    rex = 0
    has_rex = False

    if mode == 64 and 0x40 <= code[pos] <= 0x4F:
        rex = code[pos]
        has_rex = True
        pos += 1

    rex_w = (rex >> 3) & 1
    rex_r = (rex >> 2) & 1
    rex_b = rex & 1
    rex_x = (rex >> 1) & 1

    op_size = 64 if rex_w else 32

    op = code[pos]
    pos += 1

    if op == 0x90 and not has_rex:
        return "nop", "", pos


    if op == 0xC3:
        return "ret", "", pos

    if op == 0xCC:
        return "int3", "", pos

    if 0x50 <= op <= 0x57:
        rd = (op - 0x50) | (rex_b << 3)
        return "push", _REG64[rd], pos

    if 0x58 <= op <= 0x5F:
        rd = (op - 0x58) | (rex_b << 3)
        return "pop", _REG64[rd], pos

    if 0xB8 <= op <= 0xBF:
        rd = (op - 0xB8) | (rex_b << 3)
        if rex_w:
            imm = int.from_bytes(code[pos:pos + 8], "little", signed=False)
            pos += 8
            return "mov", f"{_REG64[rd]}, 0x{imm:x}", pos
        imm = int.from_bytes(code[pos:pos + 4], "little", signed=False)
        pos += 4
        return "mov", f"{_REG32[rd]}, 0x{imm:x}", pos

    if op in (0x89, 0x8B, 0x8D):
        reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        reg_str = _reg(reg_idx, op_size, has_rex)
        if op == 0x89:
            return "mov", f"{rm_str}, {reg_str}", pos
        if op == 0x8B:
            return "mov", f"{reg_str}, {rm_str}", pos
        return "lea", f"{reg_str}, {rm_str}", pos

    if op in (0x88, 0x8A):
        reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, 8)
        pos += eaten
        reg_str = _reg(reg_idx, 8, has_rex)
        if op == 0x88:
            return "mov", f"{rm_str}, {reg_str}", pos
        return "mov", f"{reg_str}, {rm_str}", pos

    if op == 0x83:
        digit = (code[pos] >> 3) & 7
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        imm = read_i8(code, pos)
        pos += 1
        return _GRP1[digit], f"{rm_str}, {_fmt_imm(imm)}", pos

    if op == 0x81:
        digit = (code[pos] >> 3) & 7
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        imm = read_i32_le(code, pos)
        pos += 4
        return _GRP1[digit], f"{rm_str}, {_fmt_imm(imm, signed=False)}", pos

    if op == 0x80:
        digit = (code[pos] >> 3) & 7
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, 8)
        pos += eaten
        imm = read_i8(code, pos)
        pos += 1
        return _GRP1[digit], f"{rm_str}, {_fmt_imm(imm)}", pos

    _ALU_PAIRS = {
        0x01: ("add", 0), 0x03: ("add", 1),
        0x09: ("or",  0), 0x0B: ("or",  1),
        0x21: ("and", 0), 0x23: ("and", 1),
        0x29: ("sub", 0), 0x2B: ("sub", 1),
        0x31: ("xor", 0), 0x33: ("xor", 1),
        0x39: ("cmp", 0), 0x3B: ("cmp", 1),
    }
    if op in _ALU_PAIRS:
        mnem, direction = _ALU_PAIRS[op]
        return _decode_alu_rm_r(code, pos, rex_r, rex_b, rex_x,
                                op_size, mnem, direction)

    if op == 0x84:
        reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, 8)
        pos += eaten
        reg_str = _reg(reg_idx, 8, has_rex)
        return "test", f"{rm_str}, {reg_str}", pos
    if op == 0x85:
        reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        reg_str = _reg(reg_idx, op_size, has_rex)
        return "test", f"{rm_str}, {reg_str}", pos

    if op == 0xFF:
        digit = (code[pos] >> 3) & 7
        eff_size = 64 if mode == 64 and digit in (2, 4, 6) else op_size
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, eff_size)
        pos += eaten
        _g5 = {0: "inc", 1: "dec", 2: "call", 4: "jmp", 6: "push"}
        mnem = _g5.get(digit, f"grp5/{digit}")
        return mnem, rm_str, pos

    if op == 0xF7:
        digit = (code[pos] >> 3) & 7
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        mnem = _GRP3[digit]
        if digit <= 1:
            imm = read_i32_le(code, pos)
            pos += 4
            return mnem, f"{rm_str}, {_fmt_imm(imm, signed=False)}", pos
        return mnem, rm_str, pos

    if op == 0xC1:
        digit = (code[pos] >> 3) & 7
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        imm = code[pos]
        pos += 1
        return _GRP2[digit], f"{rm_str}, {imm}", pos
    if op == 0xD1:
        digit = (code[pos] >> 3) & 7
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        return _GRP2[digit], f"{rm_str}, 1", pos

    if op == 0xC7:
        digit = (code[pos] >> 3) & 7
        if digit == 0:
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
            pos += eaten
            imm = read_i32_le(code, pos)
            pos += 4
            return "mov", f"{rm_str}, {_fmt_imm(imm, signed=False)}", pos
        return "db", f"0xc7", pos

    if op == 0x63 and mode == 64:
        reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, 32)
        pos += eaten
        reg_str = _reg(reg_idx, op_size, has_rex)
        return "movsxd", f"{reg_str}, {rm_str}", pos

    if op == 0x87:
        reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
        rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
        pos += eaten
        reg_str = _reg(reg_idx, op_size, has_rex)
        return "xchg", f"{reg_str}, {rm_str}", pos

    if op == 0xE9:
        rel = read_i32_le(code, pos)
        pos += 4
        return "jmp", f"0x{pos + rel:x}", pos
    if op == 0xEB:
        rel = read_i8(code, pos)
        pos += 1
        return "jmp", f"0x{pos + rel:x}", pos

    if 0x70 <= op <= 0x7F:
        cc = op - 0x70
        rel = read_i8(code, pos)
        pos += 1
        return f"j{_CC[cc]}", f"0x{pos + rel:x}", pos

    if op == 0xE8:
        rel = read_i32_le(code, pos)
        pos += 4
        return "call", f"0x{pos + rel:x}", pos

    if op == 0x6A:
        imm = read_i8(code, pos)
        pos += 1
        return "push", _fmt_imm(imm), pos
    if op == 0x68:
        imm = read_i32_le(code, pos)
        pos += 4
        return "push", _fmt_imm(imm, signed=False), pos

    if op == 0xC9:
        return "leave", "", pos

    if op == 0x99:
        return ("cqo" if rex_w else "cdq"), "", pos

    if op == 0x0F:
        op2 = code[pos]
        pos += 1

        if 0x80 <= op2 <= 0x8F:
            cc = op2 - 0x80
            rel = read_i32_le(code, pos)
            pos += 4
            return f"j{_CC[cc]}", f"0x{pos + rel:x}", pos

        if 0x90 <= op2 <= 0x9F:
            cc = op2 - 0x90
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, 8)
            pos += eaten
            return f"set{_CC[cc]}", rm_str, pos


        if op2 in (0xB6, 0xB7):
            src_size = 8 if op2 == 0xB6 else 16
            reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, src_size)
            pos += eaten
            reg_str = _reg(reg_idx, op_size, has_rex)
            return "movzx", f"{reg_str}, {rm_str}", pos

        if op2 in (0xBE, 0xBF):
            src_size = 8 if op2 == 0xBE else 16
            reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, src_size)
            pos += eaten
            reg_str = _reg(reg_idx, op_size, has_rex)
            return "movsx", f"{reg_str}, {rm_str}", pos

        if op2 == 0xAF:
            reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
            pos += eaten
            reg_str = _reg(reg_idx, op_size, has_rex)
            return "imul", f"{reg_str}, {rm_str}", pos

        if 0x40 <= op2 <= 0x4F:
            cc = op2 - 0x40
            reg_idx = ((code[pos] >> 3) & 7) | (rex_r << 3)
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
            pos += eaten
            reg_str = _reg(reg_idx, op_size, has_rex)
            return f"cmov{_CC[cc]}", f"{reg_str}, {rm_str}", pos

        if op2 == 0x1F:
            rm_str, eaten = _decode_rm(code, pos, rex_b, rex_x, op_size)
            pos += eaten
            return "nop", rm_str, pos

        return "db", f"0x0f, 0x{op2:02x}", pos


    return "db", f"0x{op:02x}", pos - 1 + 1 


def disassemble(code: bytes, mode: int = 64) -> str:
    instructions: list[tuple[int, str, str]] = []
    pos = 0

    while pos < len(code):
        start = pos
        try:
            mnem, operands, pos = _decode_one(code, pos, mode)
        except (IndexError, KeyError):
            for i in range(start, len(code)):
                instructions.append((i, f"{code[i]:02x}", f"db 0x{code[i]:02x}"))
            break

        raw = code[start:pos]
        hex_str = " ".join(f"{b:02x}" for b in raw)
        asm = f"{mnem:<7s} {operands}" if operands else mnem
        instructions.append((start, hex_str, asm))

    lines = []
    for offset, _hex_str, asm_str in instructions:
        lines.append(f"0x{offset:04x}:  {asm_str}")
    return "\n".join(lines)
