from NativeDisasm.base import sign_extend, read_u16_le, read_u32_le


_REG = [
    "zero", "ra",  "sp",  "gp",  "tp",  "t0",  "t1",  "t2",
    "s0",   "s1",  "a0",  "a1",  "a2",  "a3",  "a4",  "a5",
    "a6",   "a7",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
    "s8",   "s9",  "s10", "s11", "t3",  "t4",  "t5",  "t6",
]

_CREG = ["s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5"]


_BRANCH = ["beq", "bne", "???", "???", "blt", "bge", "bltu", "bgeu"]

_LOAD = ["lb", "lh", "lw", "ld", "lbu", "lhu", "lwu", "???"]

_STORE = ["sb", "sh", "sw", "sd", "???", "???", "???", "???"]

_ALU_IMM = ["addi", "slli", "slti", "sltiu", "xori", "srli", "ori", "andi"]

_ALU_REG = ["add", "sll", "slt", "sltu", "xor", "srl", "or", "and"]

_ALU_REG_ALT = ["sub", "???", "???", "???", "???", "sra", "???", "???"]

_MULDIV = ["mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"]



def _decode_32(inst: int, addr: int) -> tuple[str, str]:

    opcode = inst & 0x7F
    rd     = (inst >> 7) & 0x1F
    funct3 = (inst >> 12) & 0x7
    rs1    = (inst >> 15) & 0x1F
    rs2    = (inst >> 20) & 0x1F
    funct7 = (inst >> 25) & 0x7F

    if opcode == 0b0110111:
        imm = inst & 0xFFFFF000
        if imm & 0x80000000:
            imm -= 0x100000000
        return "lui", f"{_REG[rd]}, 0x{(inst >> 12) & 0xFFFFF:x}"

    if opcode == 0b0010111:
        return "auipc", f"{_REG[rd]}, 0x{(inst >> 12) & 0xFFFFF:x}"

    if opcode == 0b1101111:

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

    if opcode == 0b1100011:
        imm12 = (inst >> 31) & 1
        imm10_5 = (inst >> 25) & 0x3F
        imm4_1 = (inst >> 8) & 0xF
        imm11 = (inst >> 7) & 1
        imm = (imm12 << 12) | (imm11 << 11) | (imm10_5 << 5) | (imm4_1 << 1)
        offset = sign_extend(imm, 13)
        target = (addr + offset) & 0xFFFFFFFF
        mnem = _BRANCH[funct3]
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

    if opcode == 0b0000011:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)
        mnem = _LOAD[funct3]
        return mnem, f"{_REG[rd]}, {imm}({_REG[rs1]})"

    if opcode == 0b0100011:
        imm11_5 = (inst >> 25) & 0x7F
        imm4_0 = (inst >> 7) & 0x1F
        imm = sign_extend((imm11_5 << 5) | imm4_0, 12)
        mnem = _STORE[funct3]
        return mnem, f"{_REG[rs2]}, {imm}({_REG[rs1]})"

    if opcode == 0b0010011:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)

        if funct3 == 0:  
            if rs1 == 0:
                return "li", f"{_REG[rd]}, {imm}"
            if imm == 0:
                return "mv", f"{_REG[rd]}, {_REG[rs1]}"
            return "addi", f"{_REG[rd]}, {_REG[rs1]}, {imm}"

        if funct3 == 1:  
            shamt = (inst >> 20) & 0x3F
            return "slli", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"

        if funct3 == 5: 
            shamt = (inst >> 20) & 0x3F
            if funct7 & 0x20:
                return "srai", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"
            return "srli", f"{_REG[rd]}, {_REG[rs1]}, {shamt}"

        if funct3 == 4 and imm == -1: 
            return "not", f"{_REG[rd]}, {_REG[rs1]}"

        if funct3 == 3:  
            if imm == 1:
                return "seqz", f"{_REG[rd]}, {_REG[rs1]}"
            return "sltiu", f"{_REG[rd]}, {_REG[rs1]}, {imm}"

        if funct3 == 2:  
            return "slti", f"{_REG[rd]}, {_REG[rs1]}, {imm}"

        mnem = _ALU_IMM[funct3]
        return mnem, f"{_REG[rd]}, {_REG[rs1]}, {imm}"

    if opcode == 0b0110011:
        if funct7 == 0x01:
            mnem = _MULDIV[funct3]
            return mnem, f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"

        if funct7 == 0x20:
            mnem = _ALU_REG_ALT[funct3]
            if funct3 == 0 and rs1 == 0:
                return "neg", f"{_REG[rd]}, {_REG[rs2]}"
            return mnem, f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"

        mnem = _ALU_REG[funct3]
        if funct3 == 2 and rs1 == 0: 
            return "sgtz", f"{_REG[rd]}, {_REG[rs2]}"
        if funct3 == 3 and rs1 == 0: 
            return "snez", f"{_REG[rd]}, {_REG[rs2]}"
        return mnem, f"{_REG[rd]}, {_REG[rs1]}, {_REG[rs2]}"

    if opcode == 0b0011011:
        imm = sign_extend((inst >> 20) & 0xFFF, 12)
        if funct3 == 0:
            if rs1 == 0:
                return "li", f"{_REG[rd]}, {imm}" 
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

    if opcode == 0b0001111:
        return "fence", ""

    if opcode == 0b1110011:
        if inst == 0x00000073:
            return "ecall", ""
        if inst == 0x00100073:
            return "ebreak", ""
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



def _decode_16(inst: int, addr: int) -> tuple[str, str]:

    op   = inst & 0x3        
    funct3 = (inst >> 13) & 0x7 

    if op == 0:
        rd_p = (inst >> 2) & 0x7  
        rs1_p = (inst >> 7) & 0x7 


        if funct3 == 0:

            nzuimm = (
                ((inst >> 6) & 1) << 2 |
                ((inst >> 5) & 1) << 3 |
                ((inst >> 11) & 3) << 4 |
                ((inst >> 7) & 0xF) << 6
            )
            if nzuimm == 0:
                return "dw", f"0x{inst:04x}" 
            return "c.addi4spn", f"{_CREG[rd_p]}, sp, {nzuimm}"

        if funct3 == 2:
            offset = (
                ((inst >> 6) & 1) << 2 |
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 1) << 6
            )
            return "c.lw", f"{_CREG[rd_p]}, {offset}({_CREG[rs1_p]})"

        if funct3 == 3:
            offset = (
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 0x3) << 6
            )
            return "c.ld", f"{_CREG[rd_p]}, {offset}({_CREG[rs1_p]})"

        if funct3 == 6:
            rs2_p = (inst >> 2) & 0x7
            offset = (
                ((inst >> 6) & 1) << 2 |
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 1) << 6
            )
            return "c.sw", f"{_CREG[rs2_p]}, {offset}({_CREG[rs1_p]})"

        if funct3 == 7:
            rs2_p = (inst >> 2) & 0x7
            offset = (
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 5) & 0x3) << 6
            )
            return "c.sd", f"{_CREG[rs2_p]}, {offset}({_CREG[rs1_p]})"

        return "dw", f"0x{inst:04x}"

    if op == 1:
        rd = (inst >> 7) & 0x1F   
        if funct3 == 0:
            nzimm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
            nzimm = sign_extend(nzimm, 6)
            if rd == 0:
                return "c.nop", ""
            return "c.addi", f"{_REG[rd]}, {nzimm}"


        if funct3 == 1:

            imm = _decode_cj_imm(inst)
            target = (addr + imm) & 0xFFFFFFFF
            if rd != 0:
                nzimm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
                nzimm = sign_extend(nzimm, 6)
                return "c.addiw", f"{_REG[rd]}, {nzimm}"
            return "c.jal", f"0x{target:x}"

        if funct3 == 2:
            imm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
            imm = sign_extend(imm, 6)
            return "c.li", f"{_REG[rd]}, {imm}"

        if funct3 == 3:
            if rd == 2:
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
                nzimm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
                nzimm = sign_extend(nzimm, 6)
                return "c.lui", f"{_REG[rd]}, 0x{nzimm & 0xFFFFF:x}"

        if funct3 == 4:
            return _decode_c_alu(inst)

        if funct3 == 5:
            imm = _decode_cj_imm(inst)
            target = (addr + imm) & 0xFFFFFFFF
            return "c.j", f"0x{target:x}"

        if funct3 == 6:
            rs1_p = (inst >> 7) & 0x7
            offset = _decode_cb_offset(inst)
            target = (addr + offset) & 0xFFFFFFFF
            return "c.beqz", f"{_CREG[rs1_p]}, 0x{target:x}"

        if funct3 == 7:
            rs1_p = (inst >> 7) & 0x7
            offset = _decode_cb_offset(inst)
            target = (addr + offset) & 0xFFFFFFFF
            return "c.bnez", f"{_CREG[rs1_p]}, 0x{target:x}"

        return "dw", f"0x{inst:04x}"

    if op == 2:
        rd = (inst >> 7) & 0x1F

        if funct3 == 0:
            shamt = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
            return "c.slli", f"{_REG[rd]}, {shamt}"

        if funct3 == 2:
            offset = (
                ((inst >> 4) & 0x7) << 2 |
                ((inst >> 12) & 1) << 5 |
                ((inst >> 2) & 0x3) << 6
            )
            return "c.lwsp", f"{_REG[rd]}, {offset}(sp)"

        if funct3 == 3:
            offset = (
                ((inst >> 5) & 0x3) << 3 |
                ((inst >> 12) & 1) << 5 |
                ((inst >> 2) & 0x7) << 6
            )
            return "c.ldsp", f"{_REG[rd]}, {offset}(sp)"

        if funct3 == 4:
            bit12 = (inst >> 12) & 1
            rs2 = (inst >> 2) & 0x1F
            if bit12 == 0:
                if rs2 == 0:
                    return "c.jr", _REG[rd]
                return "c.mv", f"{_REG[rd]}, {_REG[rs2]}"
            else:
                if rs2 == 0 and rd == 0:
                    return "c.ebreak", ""
                if rs2 == 0:
                    return "c.jalr", _REG[rd]
                return "c.add", f"{_REG[rd]}, {_REG[rs2]}"

        if funct3 == 6:
            rs2 = (inst >> 2) & 0x1F
            offset = (
                ((inst >> 9) & 0xF) << 2 |
                ((inst >> 7) & 0x3) << 6
            )
            return "c.swsp", f"{_REG[rs2]}, {offset}(sp)"

        if funct3 == 7:
            rs2 = (inst >> 2) & 0x1F
            offset = (
                ((inst >> 10) & 0x7) << 3 |
                ((inst >> 7) & 0x7) << 6
            )
            return "c.sdsp", f"{_REG[rs2]}, {offset}(sp)"

        return "dw", f"0x{inst:04x}"

    return "dw", f"0x{inst:04x}"




def _decode_cj_imm(inst: int) -> int:

    bits = (
        ((inst >> 3) & 0x7) << 1 |   
        ((inst >> 11) & 1) << 4 |     
        ((inst >> 2) & 1) << 5 |      
        ((inst >> 7) & 1) << 6 |     
        ((inst >> 6) & 1) << 7 |      
        ((inst >> 9) & 0x3) << 8 |    
        ((inst >> 8) & 1) << 10 |   
        ((inst >> 12) & 1) << 11      
    )
    return sign_extend(bits, 12)


def _decode_cb_offset(inst: int) -> int:
    bits = (
        ((inst >> 3) & 0x3) << 1 |  
        ((inst >> 10) & 0x3) << 3 |   
        ((inst >> 2) & 1) << 5 |     
        ((inst >> 5) & 0x3) << 6 |    
        ((inst >> 12) & 1) << 8      
    )
    return sign_extend(bits, 9)


def _decode_c_alu(inst: int) -> tuple[str, str]:

    funct2 = (inst >> 10) & 0x3
    rd_p = (inst >> 7) & 0x7

    if funct2 == 0:
        shamt = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
        return "c.srli", f"{_CREG[rd_p]}, {shamt}"

    if funct2 == 1:
        shamt = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
        return "c.srai", f"{_CREG[rd_p]}, {shamt}"

    if funct2 == 2:
        imm = ((inst >> 2) & 0x1F) | (((inst >> 12) & 1) << 5)
        imm = sign_extend(imm, 6)
        return "c.andi", f"{_CREG[rd_p]}, {imm}"

    bit12 = (inst >> 12) & 1
    funct2b = (inst >> 5) & 0x3
    rs2_p = (inst >> 2) & 0x7

    if bit12 == 0:
        ops = ["c.sub", "c.xor", "c.or", "c.and"]
        return ops[funct2b], f"{_CREG[rd_p]}, {_CREG[rs2_p]}"
    else:
        ops64 = ["c.subw", "c.addw", "???", "???"]
        return ops64[funct2b], f"{_CREG[rd_p]}, {_CREG[rs2_p]}"



def disassemble(code: bytes, arch_code: int) -> str:

    instructions: list[tuple[int, str]] = []
    pos = 0

    while pos < len(code):
        start = pos
        try:
            if pos + 1 >= len(code):
                instructions.append((pos, f"db      0x{code[pos]:02x}"))
                pos += 1
                continue


            hw = read_u16_le(code, pos)

            if (hw & 0x3) != 0x3:
                pos += 2
                mnem, operands = _decode_16(hw, start)
            else:

                if pos + 3 >= len(code):

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
