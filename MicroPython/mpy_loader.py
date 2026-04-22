import io
from dataclasses import dataclass, field
from typing import Any, List


ARCH_NAMES = {
    0:  "bytecode",
    1:  "x86",
    2:  "x64",
    3:  "armv6",
    4:  "armv6m",     
    5:  "armv7m",      
    6:  "armv7em",    
    7:  "armv7emsp",  
    8:  "armv7emdp",   
    9:  "xtensa",    
    10: "xtensawin",  
    11: "rv32imc",     
    12: "rv64imc",
}


KIND_BYTECODE = 0
KIND_NATIVE   = 1   
KIND_VIPER    = 2   
KIND_ASM      = 3   




@dataclass
class RawCodeObject:
    """Um elemento raw-code do arquivo .mpy."""
    kind: int                                  
    code: bytes                                
    children: List["RawCodeObject"] = field(default_factory=list)
    prelude_offset: int = -1                   

    @property
    def kind_name(self) -> str:
        return {KIND_BYTECODE: "bytecode", KIND_NATIVE: "native", KIND_VIPER: "viper"}.get(
            self.kind, f"kind_{self.kind}"
        )


def _read_vuint(stream) -> int:

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

def _parse_header(stream) -> dict:

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




_BUILTIN_QSTRS: dict = {
    5:   ".0",             
    7:   "<module>",      
    8:   "_",
    9:   "__call__",
    10:  "__class__",
    11:  "__delitem__",
    12:  "__enter__",
    13:  "__exit__",
    14:  "__getattr__",
    15:  "__getitem__",
    16:  "__hash__",
    17:  "__init__",
    19:  "__iter__",
    20:  "__len__",
    22:  "__module__",
    23:  "__name__",
    24:  "__new__",
    25:  "__next__",         
    26:  "__qualname__",
    27:  "__repr__",
    28:  "__setitem__",
    29:  "__str__",
    30:  "ArithmeticError",
    31:  "AssertionError",
    32:  "AttributeError",
    33:  "BaseException",
    34:  "EOFError",
    36:  "Exception",
    37:  "GeneratorExit",
    38:  "ImportError",
    39:  "IndentationError",
    40:  "IndexError",
    41:  "KeyError",
    42:  "KeyboardInterrupt",
    43:  "LookupError",
    44:  "MemoryError",
    45:  "NameError",
    47:  "NotImplementedError",
    48:  "OSError",
    49:  "OverflowError",
    50:  "RuntimeError",
    51:  "StopIteration",
    52:  "SyntaxError",
    53:  "SystemExit",
    54:  "TypeError",
    55:  "ValueError",
    56:  "ZeroDivisionError",
    57:  "abs",
    58:  "all",
    59:  "any",
    60:  "append",
    61:  "args",
    62:  "bool",
    64:  "bytearray",
    66:  "bytes",
    67:  "callable",
    68:  "chr",
    69:  "classmethod",
    70:  "clear",
    71:  "close",
    72:  "const",
    73:  "copy",
    74:  "count",
    75:  "dict",
    76:  "dir",
    77:  "divmod",
    79:  "endswith",
    80:  "eval",
    81:  "exec",
    82:  "extend",
    83:  "find",
    84:  "format",
    85:  "from_bytes",
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
    104: "join",
    105: "key",
    106: "keys",
    107: "len",
    108: "list",
    110: "locals",
    111: "lower",
    112: "lstrip",
    113: "main",
    114: "map",
    115: "micropython",
    116: "next",
    117: "object",
    118: "open",
    119: "ord",
    120: "pop",
    121: "popitem",
    122: "pow",
    123: "print",
    124: "range",
    125: "read",
    126: "readinto",
    127: "readline",
    128: "remove",
    129: "replace",
    130: "repr",
    131: "reverse",
    132: "rfind",
    134: "round",
    136: "rstrip",
    137: "self",
    138: "send",
    140: "set",
    141: "setattr",
    142: "setdefault",
    143: "sort",
    144: "sorted",
    145: "split",
    146: "start",
    147: "startswith",
    148: "staticmethod",
    149: "step",
    150: "stop",
    151: "str",
    152: "strip",
    153: "sum",
    154: "super",
    156: "to_bytes",
    157: "tuple",
    158: "type",
    159: "update",
    160: "upper",
    162: "value",
    163: "values",
    164: "write",
    165: "zip",
}


def _parse_qstr_table(stream, n: int) -> list:

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
            stream.read(1)   
            qstrs.append(data.decode("utf-8", errors="replace"))
    return qstrs



def _parse_const_obj(stream) -> Any:

    type_byte = stream.read(1)
    if not type_byte:
        raise EOFError("Fim de arquivo inesperado ao ler tipo de constante")
    t = type_byte[0]

    if t == 0:   return None       
    if t == 1:   return None       
    if t == 2:   return False       
    if t == 3:   return True        
    if t == 4:   return ...         

    if t in (5, 6): 
        length = _read_vuint(stream)
        data = stream.read(length)
        if len(data) < length:
            raise EOFError("Dado de constante truncado")
        stream.read(1)  
        return data.decode("utf-8", errors="replace") if t == 5 else data

    if t in (7, 8, 9): 
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

    if t == 10: 
        n = _read_vuint(stream)
        return tuple(_parse_const_obj(stream) for _ in range(n))

    raise ValueError(
        f"Tipo de constante desconhecido: 0x{t:02x} "
        f"('{chr(t) if 32 <= t < 127 else '?'}')"
    )


def _parse_const_table(stream, n: int) -> list:
    return [_parse_const_obj(stream) for _ in range(n)]



def _read_native_extra(stream, kind: int) -> int:

    if kind == KIND_NATIVE:
        return _read_vuint(stream)

    elif kind == KIND_VIPER:
     
        scope_flags = _read_vuint(stream)
        rodata_size = 0
        if scope_flags & 0x20:                  
            rodata_size = _read_vuint(stream)
        if scope_flags & 0x40:                 
            _read_vuint(stream)               
        if scope_flags & 0x20:
            stream.read(rodata_size)         
        if scope_flags & 0x10:                  
            while True:
                b = stream.read(1)
                if not b:
                    break
                op = b[0]
                if op == 0xFF:
                    break
                if op & 1:
                    _read_vuint(stream)    
                op >>= 1
                if op <= 5 and (op & 1):
                    _read_vuint(stream)        
    elif kind == KIND_ASM:
        _read_vuint(stream)
        _read_vuint(stream)
        _read_vuint(stream)

    return -1


def _parse_raw_code(stream) -> RawCodeObject:

    hdr = _read_vuint(stream)
    kind         = hdr & 0x03
    has_children = bool((hdr >> 2) & 0x01)
    code_len     = hdr >> 3

    code = stream.read(code_len)
    if len(code) < code_len:
        raise EOFError(
            f"raw-code truncado: esperado {code_len} bytes, lido {len(code)}"
        )

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



def load_mpy(path: str) -> tuple:

    with open(path, "rb") as f:
        header      = _parse_header(f)
        n_qstrs     = _read_vuint(f)
        n_consts    = _read_vuint(f)
        qstr_table  = _parse_qstr_table(f, n_qstrs)
        const_table = _parse_const_table(f, n_consts)
        raw_root    = _parse_raw_code(f)

    return header, qstr_table, const_table, raw_root


def mpy_info(path: str) -> str:

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
