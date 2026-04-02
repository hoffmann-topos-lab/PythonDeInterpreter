"""
Parser do formato .mpy (MicroPython bytecode), versão 6.x.

Suporta MicroPython 1.19–1.27 (sub-versões 6.0–6.3).

Fontes:
  https://docs.micropython.org/en/latest/reference/mpyfiles.html
  https://github.com/micropython/micropython/blob/master/py/persistentcode.c
  https://github.com/micropython/micropython/blob/master/py/bc0.h
"""

import io
from dataclasses import dataclass, field
from typing import Any, List

# ---------------------------------------------------------------------------
# Tabela de arquiteturas (bits 5–2 do byte 2 do header)
# ---------------------------------------------------------------------------
ARCH_NAMES = {
    0:  "bytecode",
    1:  "x86",
    2:  "x64",
    3:  "armv6",
    4:  "armv6m",      # RP2040 (Pico / Pico W)
    5:  "armv7m",      # RP2350 modo ARM (Pico 2), STM32F1/F2/F3
    6:  "armv7em",     # STM32F4/F7, nRF52
    7:  "armv7emsp",   # STM32 FPU single-precision
    8:  "armv7emdp",   # STM32 FPU double-precision
    9:  "xtensa",      # ESP8266
    10: "xtensawin",   # ESP32, ESP32-S2, ESP32-S3
    11: "rv32imc",     # RP2350 modo RISC-V (Pico 2), ESP32-C3/C6/P4
    12: "rv64imc",
}

# Tipos de raw-code (bits 1-0 do header vuint)
KIND_BYTECODE = 0
KIND_NATIVE   = 1   # @micropython.native  → código de máquina
KIND_VIPER    = 2   # @micropython.viper   → código de máquina tipado
KIND_ASM      = 3   # @micropython.asm_thumb etc.


# ---------------------------------------------------------------------------
# Estrutura de dados
# ---------------------------------------------------------------------------

@dataclass
class RawCodeObject:
    """Um elemento raw-code do arquivo .mpy."""
    kind: int                                   # KIND_BYTECODE / KIND_NATIVE / KIND_VIPER
    code: bytes                                 # bytes crus (inclui preâmbulo para bytecode)
    children: List["RawCodeObject"] = field(default_factory=list)
    prelude_offset: int = -1                    # offset do prelude dentro de code (native only)

    @property
    def kind_name(self) -> str:
        return {KIND_BYTECODE: "bytecode", KIND_NATIVE: "native", KIND_VIPER: "viper"}.get(
            self.kind, f"kind_{self.kind}"
        )


# ---------------------------------------------------------------------------
# Decodificador de vuint
# ---------------------------------------------------------------------------

def _read_vuint(stream) -> int:
    """
    Decodifica um variably-encoded unsigned integer (MSB-first).

    Formato MicroPython: 7 bits úteis por byte, MSB-first (big-endian groups).
    MSB=1 indica que mais bytes seguem; MSB=0 é o último byte.
    result = (result << 7) | (byte & 0x7F)
    """
    result = 0
    while True:
        b = stream.read(1)
        if not b:
            raise EOFError("Fim de arquivo inesperado ao ler vuint")
        byte = b[0]
        result = (result << 7) | (byte & 0x7F)
        if (byte & 0x80) == 0:
            break
    return result


# ---------------------------------------------------------------------------
# Parser do header
# ---------------------------------------------------------------------------

def _parse_header(stream) -> dict:
    """
    Lê e valida o header de 4 bytes do .mpy.

    Layout:
      Byte 0: 0x4D ('M')
      Byte 1: versão major (6)
      Byte 2: flags/arquitetura
                bit 7   : reservado (0)
                bit 6   : se 1, um vuint extra de flags de arq. segue
                bits 5-2: código de arquitetura
                bits 1-0: sub-versão
      Byte 3: bits de small int (31 ou 63)
    """
    magic = stream.read(1)
    if magic != b"M":
        raise ValueError(f"Magic inválido: {magic!r} (esperado b'M')")

    raw_version = stream.read(1)
    if not raw_version:
        raise EOFError("Header truncado ao ler versão")
    version = raw_version[0]
    if version != 6:
        raise ValueError(
            f"Versão .mpy não suportada: {version} (este decompiler suporta apenas versão 6)"
        )

    raw_flags = stream.read(1)
    if not raw_flags:
        raise EOFError("Header truncado ao ler flags")
    flags_byte = raw_flags[0]

    raw_si = stream.read(1)
    if not raw_si:
        raise EOFError("Header truncado ao ler smallint_bits")
    smallint_bits = raw_si[0]

    arch_code       = (flags_byte >> 2) & 0x0F
    sub_version     = flags_byte & 0x03
    has_arch_flags  = bool((flags_byte >> 6) & 0x01)

    arch_extra = _read_vuint(stream) if has_arch_flags else None

    return {
        "version":       version,
        "sub_version":   sub_version,
        "arch_code":     arch_code,
        "arch_name":     ARCH_NAMES.get(arch_code, f"arch_{arch_code}"),
        "smallint_bits": smallint_bits,
        "has_arch_flags": has_arch_flags,
        "arch_extra":    arch_extra,
    }


# ---------------------------------------------------------------------------
# Tabela de qstrs built-in (mpy-cross v1.27, arch=0)
#
# Qstrs estáticos são referenciados apenas pelo ID numérico no .mpy.
# Esta tabela mapeia IDs conhecidos → string real.
#
# IDs confirmados via análise de tests/mpy/ com mpy-cross v1.27.
# Para descobrir mais IDs: executar tests/mpy/discover_builtin_qstrs.py.
# ---------------------------------------------------------------------------

_BUILTIN_QSTRS: dict = {
    # Todos os IDs abaixo foram confirmados empiricamente via arquivos probe
    # compilados com mpy-cross v1.27 (mpy-cross versionado em venv/).
    # IDs não mapeados retornam "<static:N>" no fallback de _parse_qstr_table.

    # --- Dunders de protocolo (confirmados via probe5 / probe8) ---
    9:   "__call__",
    10:  "__class__",
    11:  "__delitem__",
    12:  "__enter__",
    13:  "__exit__",
    14:  "__getattr__",
    15:  "__getitem__",
    16:  "__hash__",
    17:  "__init__",
    19:  "__next__",
    20:  "__iter__",
    22:  "__module__",
    23:  "__name__",
    24:  "__new__",
    26:  "__qualname__",
    27:  "__len__",
    28:  "__setitem__",
    29:  "__str__",

    # --- Exceções built-in (confirmados via probe3) ---
    31:  "AssertionError",
    32:  "AttributeError",
    36:  "Exception",
    38:  "ImportError",
    40:  "IndexError",
    41:  "KeyError",
    44:  "MemoryError",
    45:  "NameError",
    47:  "NotImplementedError",
    48:  "OSError",
    49:  "OverflowError",
    50:  "RuntimeError",
    51:  "StopIteration",
    54:  "TypeError",
    55:  "ValueError",
    56:  "ZeroDivisionError",

    # --- Funções / tipos built-in (confirmados via probe2/4/6/7/8/9) ---
    57:  "abs",
    58:  "all",
    59:  "any",
    60:  "append",
    62:  "bool",
    67:  "callable",
    68:  "chr",
    69:  "classmethod",
    70:  "clear",
    73:  "copy",
    74:  "count",
    75:  "dict",
    76:  "dir",
    77:  "divmod",
    80:  "eval",
    82:  "extend",
    84:  "format",
    86:  "get",
    87:  "getattr",
    88:  "globals",
    89:  "hasattr",
    90:  "hash",
    91:  "id",
    92:  "index",
    93:  "insert",
    94:  "int",
    97:  "isinstance",
    100: "issubclass",
    102: "items",
    103: "iter",
    106: "keys",
    107: "len",
    108: "list",
    110: "locals",
    114: "map",
    115: "micropython",
    116: "next",
    117: "object",
    118: "open",
    119: "ord",
    120: "pop",
    122: "pow",
    123: "print",
    124: "range",
    128: "remove",
    130: "repr",
    131: "reverse",
    134: "round",
    140: "set",
    141: "setattr",
    142: "setdefault",
    143: "sort",
    144: "sorted",
    148: "staticmethod",
    151: "str",
    153: "sum",
    154: "super",
    157: "tuple",
    158: "type",
    159: "update",
    163: "values",
    165: "zip",
}


# ---------------------------------------------------------------------------
# Parser da tabela de qstrs
# ---------------------------------------------------------------------------

def _parse_qstr_table(stream, n: int) -> list:
    """
    Lê n qstrs da tabela global.

    Formato de cada entrada (py/persistentcode.c — load_qstr):
      len_enc = vuint
        se len_enc & 1 == 1 → qstr estática (built-in): id = len_enc >> 1, sem dados
        senão               → qstr dinâmica: length = len_enc >> 1,
                              seguido de `length` bytes UTF-8 + 1 byte terminador nulo

    IDs estáticos são resolvidos via _BUILTIN_QSTRS. IDs não mapeados ficam
    como "<static:N>" — executar tests/mpy/discover_builtin_qstrs.py para ampliar.
    """
    qstrs = []
    for _ in range(n):
        len_enc = _read_vuint(stream)
        if len_enc & 1:
            static_id = len_enc >> 1
            name = _BUILTIN_QSTRS.get(static_id, f"<static:{static_id}>")
            qstrs.append(name)
        else:
            length = len_enc >> 1
            data = stream.read(length)
            if len(data) < length:
                raise EOFError("qstr truncado")
            stream.read(1)  # descarta terminador nulo
            qstrs.append(data.decode("utf-8", errors="replace"))
    return qstrs


# ---------------------------------------------------------------------------
# Parser da tabela de constantes
# ---------------------------------------------------------------------------

def _parse_const_obj(stream) -> Any:
    """
    Lê um objeto constante.

    Byte de tipo (MP_PERSISTENT_OBJ_* de py/persistentcode.h):
      0  → fun_table (referência interna); retorna None
      1  → None
      2  → False
      3  → True
      4  → Ellipsis
      5  → str:     vuint(len) + len bytes UTF-8 + 1 nulo
      6  → bytes:   vuint(len) + len bytes + 1 nulo
      7  → int:     vuint(len) + len bytes decimal ASCII (sem nulo)
      8  → float:   vuint(len) + len bytes ASCII (sem nulo)
      9  → complex: vuint(len) + len bytes ASCII (sem nulo)
      10 → tuple:   vuint(n) + n objetos recursivos
    """
    type_byte = stream.read(1)
    if not type_byte:
        raise EOFError("Fim de arquivo inesperado ao ler tipo de constante")
    t = type_byte[0]

    if t == 0:   return None        # FUN_TABLE
    if t == 1:   return None        # None
    if t == 2:   return False       # False
    if t == 3:   return True        # True
    if t == 4:   return ...         # Ellipsis

    if t in (5, 6):  # str ou bytes
        length = _read_vuint(stream)
        data = stream.read(length)
        if len(data) < length:
            raise EOFError("Dado de constante truncado")
        stream.read(1)  # descarta terminador nulo
        return data.decode("utf-8", errors="replace") if t == 5 else data

    if t in (7, 8, 9):  # int, float, complex (sem terminador nulo)
        length = _read_vuint(stream)
        data = stream.read(length)
        if len(data) < length:
            raise EOFError("Dado de constante truncado")
        text = data.decode("ascii")
        if t == 7:
            return int(text)
        if t == 8:
            return float(text)
        try:
            return complex(text)
        except ValueError:
            return text

    if t == 10:  # tuple
        n = _read_vuint(stream)
        return tuple(_parse_const_obj(stream) for _ in range(n))

    raise ValueError(
        f"Tipo de constante desconhecido: 0x{t:02x} "
        f"('{chr(t) if 32 <= t < 127 else '?'}')"
    )


def _parse_const_table(stream, n: int) -> list:
    """Lê n objetos constantes da tabela global."""
    return [_parse_const_obj(stream) for _ in range(n)]


# ---------------------------------------------------------------------------
# Parser de elemento raw-code (recursivo)
# ---------------------------------------------------------------------------

def _read_native_extra(stream, kind: int) -> int:
    """
    Consome os metadados extras que seguem o fun_data de code objects
    nativos/viper/asm no formato .mpy v6.

    Retorna o prelude_offset para KIND_NATIVE, -1 para os demais.

    Ref: micropython/py/persistentcode.c — load_raw_code()
    """
    if kind == KIND_NATIVE:
        # @micropython.native: 1 vuint (prelude_offset)
        return _read_vuint(stream)

    elif kind == KIND_VIPER:
        # @micropython.viper: scope_flags + optional rodata/bss/relocations
        scope_flags = _read_vuint(stream)
        rodata_size = 0
        if scope_flags & 0x20:                  # MP_SCOPE_FLAG_VIPERRODATA
            rodata_size = _read_vuint(stream)
        if scope_flags & 0x40:                  # MP_SCOPE_FLAG_VIPERBSS
            _read_vuint(stream)                 # bss_size (descartado)
        if scope_flags & 0x20:
            stream.read(rodata_size)            # rodata bytes
        if scope_flags & 0x10:                  # MP_SCOPE_FLAG_VIPERRELOC
            while True:
                b = stream.read(1)
                if not b:
                    break
                op = b[0]
                if op == 0xFF:
                    break
                if op & 1:
                    _read_vuint(stream)         # addr
                op >>= 1
                if op <= 5 and (op & 1):
                    _read_vuint(stream)         # n

    elif kind == KIND_ASM:
        # @micropython.asm_*: 3 vuints (scope_flags, n_pos_args, type_sig)
        _read_vuint(stream)
        _read_vuint(stream)
        _read_vuint(stream)

    return -1


def _parse_raw_code(stream) -> RawCodeObject:
    """
    Lê um elemento raw-code do stream.

    Header vuint: (code_len << 3) | (has_children << 2) | kind
      kind         : bits 1-0 (0=bytecode, 1=native, 2=viper, 3=asm)
      has_children : bit 2
      code_len     : bits restantes (>> 3)

    Para code objects nativos (kind != 0), há metadados extras após os
    bytes de código que precisam ser consumidos antes dos filhos.
    """
    hdr = _read_vuint(stream)
    kind         = hdr & 0x03
    has_children = bool((hdr >> 2) & 0x01)
    code_len     = hdr >> 3

    code = stream.read(code_len)
    if len(code) < code_len:
        raise EOFError(
            f"raw-code truncado: esperado {code_len} bytes, lido {len(code)}"
        )

    # Consome metadados extras de code objects nativos
    prelude_offset = -1
    if kind != KIND_BYTECODE:
        prelude_offset = _read_native_extra(stream, kind)

    children = []
    if has_children:
        n_children = _read_vuint(stream)
        for _ in range(n_children):
            children.append(_parse_raw_code(stream))

    return RawCodeObject(kind=kind, code=code, children=children,
                         prelude_offset=prelude_offset)


# ---------------------------------------------------------------------------
# Ponto de entrada público
# ---------------------------------------------------------------------------

def load_mpy(path: str) -> tuple:
    """
    Carrega um arquivo .mpy e retorna seus componentes.

    Retorna:
        (header, qstr_table, const_table, raw_root)

        header      : dict com version, sub_version, arch_code, arch_name, smallint_bits
        qstr_table  : list[str] — strings internadas do módulo
        const_table : list[Any] — objetos constantes globais
        raw_root    : RawCodeObject — código-raiz (módulo externo)

    Levanta:
        ValueError  — magic inválido ou versão não suportada
        EOFError    — arquivo truncado
    """
    with open(path, "rb") as f:
        header      = _parse_header(f)
        n_qstrs     = _read_vuint(f)
        n_consts    = _read_vuint(f)
        qstr_table  = _parse_qstr_table(f, n_qstrs)
        const_table = _parse_const_table(f, n_consts)
        raw_root    = _parse_raw_code(f)

    return header, qstr_table, const_table, raw_root


def mpy_info(path: str) -> str:
    """
    Retorna uma string legível com os metadados de um .mpy.
    Útil para debug e para o painel de metadados da UI.
    """
    header, qstrs, consts, root = load_mpy(path)
    arch = header["arch_name"]
    sub  = header["sub_version"]
    lines = [
        f"MicroPython .mpy v6.{sub} · {arch}",
        f"  qstrs:     {len(qstrs)}",
        f"  constantes:{len(consts)}",
        f"  código-raiz: {root.kind_name} ({len(root.code)} bytes, {len(root.children)} filhos)",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI de teste
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python mpy_loader.py <arquivo.mpy>")
        sys.exit(1)
    try:
        print(mpy_info(sys.argv[1]))
    except Exception as e:
        print(f"Erro: {e}", file=sys.stderr)
        sys.exit(1)
