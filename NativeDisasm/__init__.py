"""
Disassembly de código de máquina nativo de arquivos .mpy.

Funções @micropython.native e @micropython.viper são compiladas em código
de máquina — o bytecode original não é preservado. Este módulo decodifica
o código de máquina e retorna assembly legível.

API pública:
    disassemble_native(code, arch_code, prelude_offset) → str
"""

from NativeDisasm.base import format_hex_dump


# Mapeamento arch_code → nome legível
_ARCH_NAMES = {
    0: "bytecode",
    1: "x86",
    2: "x64",
    3: "armv6",
    4: "armv6m",
    5: "armv7m",
    6: "armv7em",
    7: "armv7emsp",
    8: "armv7emdp",
    9: "xtensa",
    10: "xtensawin",
    11: "rv32imc",
    12: "rv64imc",
}

# Tamanho do padding/relocation no início do código nativo.
# Determinado empiricamente: contém ponteiro de relocation (sizeof void*)
# mais eventuais bytes de trampoline/alinhamento.
#   x86/x64:    8 bytes (relocation pointer alinhado a 8)
#   ARM 32-bit: 4 bytes (1 × uint32)
#   xtensa:     4 bytes (1 × uint32, non-windowed CALL0 ABI)
#   xtensawin:  8 bytes (4 reloc + J trampoline + pad até ENTRY)
#   RV32/RV64:  4/8 bytes (sizeof void*)
_ARCH_PADDING = {
    1: 8,   # x86
    2: 8,   # x64
    10: 8,  # xtensawin (4 reloc + 4 J-trampoline)
    12: 8,  # rv64imc
}
_DEFAULT_PADDING = 4  # ARM (3-8), xtensa (9), rv32imc (11)


def _get_padding(arch_code: int) -> int:
    """Retorna o tamanho do padding/relocation para a arquitetura."""
    return _ARCH_PADDING.get(arch_code, _DEFAULT_PADDING)


def disassemble_native(code: bytes, arch_code: int, prelude_offset: int) -> str:
    """
    Disassembla código de máquina nativo de uma função .mpy.

    Parâmetros:
        code            — bytes crus do code object (máquina + prelude)
        arch_code       — código de arquitetura do header .mpy
        prelude_offset  — offset onde começa o prelude (fim do código de máquina)

    Retorna:
        String formatada com uma instrução/linha por linha.
    """
    # Extrai apenas o código de máquina (sem padding e sem prelude)
    machine_start = _get_padding(arch_code)
    machine_end = prelude_offset if prelude_offset > 0 else len(code)

    if machine_start >= machine_end:
        return "# (sem código de máquina)"

    machine_code = code[machine_start:machine_end]
    arch_name = _ARCH_NAMES.get(arch_code, f"arch_{arch_code}")
    n_bytes = len(machine_code)

    # Tenta despachar para disassembler específico da arquitetura
    disasm_fn = _get_disassembler(arch_code)

    lines = [f"# {arch_name} assembly ({n_bytes} bytes)"]

    if disasm_fn is not None:
        lines.append(disasm_fn(machine_code, arch_code))
    else:
        # Fallback: hex dump
        lines.append(format_hex_dump(machine_code, start_offset=machine_start))

    return "\n".join(lines)


def _get_disassembler(arch_code: int):
    """
    Retorna a função de disassembly para a arquitetura, ou None para fallback.

    Disassemblers são importados sob demanda para evitar carregar módulos
    desnecessários.
    """
    if arch_code in (1, 2):
        from NativeDisasm.x86_disasm import disassemble
        return lambda code, ac: disassemble(code, mode=64 if ac == 2 else 32)
    if 3 <= arch_code <= 8:
        from NativeDisasm.arm_thumb_disasm import disassemble
        return lambda code, ac: disassemble(code, ac)
    if arch_code in (9, 10):
        from NativeDisasm.xtensa_disasm import disassemble
        return lambda code, ac: disassemble(code, ac)
    if arch_code in (11, 12):
        from NativeDisasm.riscv_disasm import disassemble
        return lambda code, ac: disassemble(code, ac)
    return None
