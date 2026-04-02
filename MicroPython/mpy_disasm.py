"""
Decodificador de opcodes MicroPython — bytecode versão 6.x.

Produz listas de dicts de instrução com o mesmo formato de
Decompiler/disasm.py, permitindo que cfg.py e stack_sim sejam reutilizados.

Fontes:
  https://github.com/micropython/micropython/blob/master/py/bc0.h
  https://github.com/micropython/micropython/blob/master/py/bc.h
"""

from typing import Any

# ---------------------------------------------------------------------------
# Tabelas de opcodes
# ---------------------------------------------------------------------------

# Operadores unários (índice = byte - 0xd0)
# Confirmado via mpy-cross v1.27: pos=0, neg=1, inv=2, not=3
UNARY_OPS = ["+", "-", "~", "not", "abs", "bool", "id"]

# Operadores binários (índice = byte - 0xd7)
# Confirmado via mpy-cross v1.27 (bc0.h MicroPython 1.27):
#   0-5  : comparações  <  >  ==  <=  >=  !=
#   6-8  : in  is  exc_match (interno)
#   9-21 : in-place |= ^= &= <<= >>= += -= *= @= //= /= %= **=
#   22-34: binários   |  ^  &  <<  >>  +  -  *  @  //  /  %  **
BINARY_OPS = [
    # 0-8: comparações + membership + exc_match
    "<", ">", "==", "<=", ">=", "!=", "in", "is", "exc_match",
    # 9-21: in-place (augmented assignment)
    "|=", "^=", "&=", "<<=", ">>=", "+=", "-=", "*=", "@=", "//=", "/=", "%=", "**=",
    # 22-34: operadores binários regulares
    "|", "^", "&", "<<", ">>", "+", "-", "*", "@", "//", "/", "%", "**",
]

# Opcodes sem argumento
_NO_ARG = {
    0x50: "LOAD_CONST_FALSE",
    0x51: "LOAD_CONST_NONE",
    0x52: "LOAD_CONST_TRUE",
    0x53: "LOAD_NULL",
    0x54: "LOAD_BUILD_CLASS",
    0x55: "LOAD_SUBSCR",
    0x56: "STORE_SUBSCR",
    0x57: "DUP_TOP",
    0x58: "DUP_TOP_TWO",
    0x59: "POP_TOP",
    0x5a: "ROT_TWO",
    0x5b: "ROT_THREE",
    0x5c: "WITH_CLEANUP",
    0x5d: "END_FINALLY",
    0x5e: "GET_ITER",
    0x5f: "GET_ITER_STACK",
    0x62: "STORE_MAP",
    0x63: "RETURN_VALUE",
    0x64: "RAISE_LAST",
    0x65: "RAISE_OBJ",
    0x66: "RAISE_FROM",
    0x67: "YIELD_VALUE",
    0x68: "YIELD_FROM",
    0x69: "IMPORT_STAR",
}

# Opcodes com argumento = índice na qstr_table
_QSTR_ARG = {
    0x10: "LOAD_CONST_STRING",
    0x11: "LOAD_NAME",
    0x12: "LOAD_GLOBAL",
    0x13: "LOAD_ATTR",
    0x14: "LOAD_METHOD",
    0x15: "LOAD_SUPER_METHOD",
    0x16: "STORE_NAME",
    0x17: "STORE_GLOBAL",
    0x18: "STORE_ATTR",
    0x19: "DELETE_NAME",
    0x1a: "DELETE_GLOBAL",
    0x1b: "IMPORT_NAME",
    0x1c: "IMPORT_FROM",
}

# Opcodes com argumento = vuint simples (índice numérico ou contador)
_UINT_ARG = {
    0x23: "LOAD_CONST_OBJ",        # índice na const_table
    0x24: "LOAD_FAST_N",           # índice de variável local
    0x25: "LOAD_DEREF",            # índice de closure
    0x26: "STORE_FAST_N",
    0x27: "STORE_DEREF",
    0x28: "DELETE_FAST",
    0x29: "DELETE_DEREF",
    0x2a: "BUILD_TUPLE",           # n itens
    0x2b: "BUILD_LIST",
    0x2c: "BUILD_MAP",
    0x2d: "BUILD_SET",
    0x2e: "BUILD_SLICE",
    0x2f: "STORE_COMP",
    0x30: "UNPACK_SEQUENCE",
    0x32: "MAKE_FUNCTION",         # referência ao filho raw-code
    0x33: "MAKE_FUNCTION_DEFARGS",
}

# Opcodes com dois vuints consecutivos
_TWO_UINT_ARGS = {
    0x20: "MAKE_CLOSURE",           # (filho idx, n_closed)
    0x21: "MAKE_CLOSURE_DEFARGS",
}

# Opcodes com um vuint "empacotado" (packed): (low_8_bits, high_8_bits)
# CALL_*:   low = n_pos, high = n_kw   — vm.c: unum & 0xFF, (unum >> 8) & 0xFF
# UNPACK_EX: low = n_before, high = n_after
_PACKED_UINT_ARG = {
    0x31: "UNPACK_EX",              # (n_before, n_after)
    0x34: "CALL_FUNCTION",          # (n_pos, n_kw)
    0x35: "CALL_FUNCTION_VAR_KW",
    0x36: "CALL_METHOD",
    0x37: "CALL_METHOD_VAR_KW",
}

# Opcodes de salto signed (argumento = offset signed relativo ao opcode, 1 ou 2 bytes)
# target = opcode_offset + (arg - 64)   para 1 byte
# target = opcode_offset + (arg - 16384) para 2 bytes
_JUMP_ARG = {
    0x42: "JUMP",
    0x43: "POP_JUMP_IF_TRUE",
    0x44: "POP_JUMP_IF_FALSE",
    0x45: "JUMP_IF_TRUE_OR_POP",
    0x46: "JUMP_IF_FALSE_OR_POP",
}

# Opcodes de salto FORWARD unsigned (MP_BC_ARG_ULABEL em bc0.h)
# target = next_ip + raw_arg  (sem subtração de 64)
# FOR_ITER e POP_EXCEPT_JUMP também são ULABEL: saltam sempre PARA FRENTE
_SETUP_JUMP_ARG = {
    0x47: "SETUP_WITH",
    0x48: "SETUP_EXCEPT",
    0x49: "SETUP_FINALLY",
    0x4a: "POP_EXCEPT_JUMP",
    0x4b: "FOR_ITER",
}


# ---------------------------------------------------------------------------
# Helpers de leitura de bytes
# ---------------------------------------------------------------------------

def _read_vuint_b(code: bytes, ip: int) -> tuple:
    """
    Lê um vuint (MSB-first) de `code` a partir de `ip`.
    Retorna (value, next_ip).
    """
    result = 0
    while True:
        if ip >= len(code):
            raise EOFError(f"vuint truncado em offset {ip}")
        b = code[ip]; ip += 1
        result = (result << 7) | (b & 0x7F)
        if (b & 0x80) == 0:
            break
    return result, ip


def _read_signed_vuint_b(code: bytes, ip: int) -> tuple:
    """
    Lê um inteiro com sinal (zigzag encoding) de `code` a partir de `ip`.
    Convenção MicroPython: valor = n>>1 se n par, -(n>>1)-1 se n ímpar.
    """
    n, ip = _read_vuint_b(code, ip)
    value = (n >> 1) if (n & 1) == 0 else -(n >> 1) - 1
    return value, ip


def _read_jump_arg(code: bytes, ip: int) -> tuple:
    """
    Lê o argumento de um opcode de salto (1 ou 2 bytes, signed).

    Encoding MicroPython:
      1 byte: b1 & 0x80 == 0  →  rel = b1 - 64      (range -64..+63)
      2 bytes: b1 & 0x80 == 1  →  rel = ((b1 & 0x7F) << 8 | b2) - 16384
    Retorna (rel_offset, next_ip).
    """
    if ip >= len(code):
        raise EOFError(f"argumento de salto truncado em offset {ip}")
    b1 = code[ip]; ip += 1
    if b1 & 0x80 == 0:
        return b1 - 64, ip
    if ip >= len(code):
        raise EOFError(f"segundo byte de salto truncado em offset {ip}")
    b2 = code[ip]; ip += 1
    return ((b1 & 0x7F) << 8 | b2) - 16384, ip


# ---------------------------------------------------------------------------
# Decodificador do preâmbulo de função
# ---------------------------------------------------------------------------

def decode_prelude(code: bytes) -> tuple:
    """
    Decodifica o preâmbulo de função MicroPython (.mpy v6).

    Retorna (meta, instr_start) onde:
      meta        : dict com n_state, n_exc_stack, scope_flags,
                    n_pos_args, n_kwonly_args, n_def_pos_args, sig_end,
                    n_info, n_cell, line_table_start
      instr_start : int — offset em `code` onde as instruções começam

    Layout do preâmbulo (py/bc.h MP_BC_PRELUDE_*):
      [signature bytes — xSSSSEAA + continuação se bit 7 set]
      [prelude size byte(s) — xIIIIIIC por byte, acumula n_info e n_cell]
      [n_info bytes de line info table]
      [n_cell bytes de cell info]
      [instruções]
    """
    ip = 0

    # ------------------------------------------------------------------
    # 1. Signature — primeiro byte: xSSSSEAA
    # ------------------------------------------------------------------
    if ip >= len(code):
        raise ValueError("bytecode vazio — sem preâmbulo")

    b0 = code[ip]; ip += 1
    n_state      = (b0 >> 3) & 0x0F   # 4 bits, vale n_state - 1
    n_exc_stack  = (b0 >> 2) & 0x01   # 1 bit
    n_pos_args   = b0 & 0x03           # 2 bits

    n_kwonly_args   = 0
    n_def_pos_args  = 0
    scope_flags     = 0

    # acumuladores de shift para os campos dos bytes de continuação
    ns_shift  = 4   # próximos bits de n_state
    ne_shift  = 1   # próximos bits de n_exc_stack
    na_shift  = 2   # próximos bits de n_pos_args
    nk_shift  = 0   # próximos bits de n_kwonly_args
    sf_shift  = 0   # próximos bits de scope_flags
    nd_shift  = 0   # próximos bits de n_def_pos_args

    # ------------------------------------------------------------------
    # 2. Bytes de continuação: xFSSKAED
    # ------------------------------------------------------------------
    if b0 & 0x80:
        while True:
            if ip >= len(code):
                raise ValueError("preâmbulo truncado nos bytes de continuação")
            b = code[ip]; ip += 1

            n_state     |= ((b >> 4) & 0x03) << ns_shift;  ns_shift += 2
            n_exc_stack |= ((b >> 1) & 0x01) << ne_shift;  ne_shift += 1
            n_pos_args  |= ((b >> 2) & 0x01) << na_shift;  na_shift += 1
            n_kwonly_args  |= ((b >> 3) & 0x01) << nk_shift; nk_shift += 1
            scope_flags    |= ((b >> 6) & 0x01) << sf_shift; sf_shift += 1
            n_def_pos_args |= (b & 0x01) << nd_shift;        nd_shift += 1

            if not (b & 0x80):
                break

    n_state += 1   # o encoding armazena n_state - 1
    sig_end = ip

    # ------------------------------------------------------------------
    # 3. Prelude size — bytes xIIIIIIC (MP_BC_PRELUDE_SIZE_DECODE_INTO)
    #    Cada byte: bit 0 = 1 bit de n_cell, bits 6:1 = 6 bits de n_info
    #    bit 7 = continuação
    # ------------------------------------------------------------------
    n_info = 0
    n_cell = 0
    n = 0
    while True:
        if ip >= len(code):
            raise ValueError("preâmbulo truncado nos bytes de size")
        z = code[ip]; ip += 1
        n_cell |= (z & 0x01) << n
        n_info |= ((z & 0x7E) >> 1) << (6 * n)
        n += 1
        if not (z & 0x80):
            break

    # ------------------------------------------------------------------
    # 4. Pula n_info bytes de line table + n_cell bytes de cell info
    # ------------------------------------------------------------------
    line_table_start = ip
    instr_start = ip + n_info + n_cell

    meta = {
        "n_state":          n_state,
        "n_exc_stack":      n_exc_stack,
        "scope_flags":      scope_flags,
        "n_pos_args":       n_pos_args,
        "n_kwonly_args":    n_kwonly_args,
        "n_def_pos_args":   n_def_pos_args,
        "sig_end":          sig_end,
        "n_info":           n_info,
        "n_cell":           n_cell,
        "line_table_start": line_table_start,
    }
    return meta, instr_start


def decode_prelude_qstrs(code: bytes, meta: dict, qstrs: list,
                         is_module: bool = False) -> tuple:
    """
    Extrai simple_name e arg_names da seção n_info do preâmbulo.

    Layout de n_info para funções (não-módulo):
      simple_name : 1 vuint (índice na qstr_table)
      arg_names   : n_pos_args + n_kwonly_args vuints
      line_info   : bytes restantes

    Para o módulo raiz:
      simple_name : 1 vuint
      source_file : 1 vuint
      line_info   : bytes restantes

    Retorna (simple_name: str, arg_names: list[str]).
    """
    lt_start = meta["line_table_start"]
    n_info   = meta["n_info"]
    info     = code[lt_start : lt_start + n_info]

    if not info:
        return None, []

    # Lê vuints do início de info
    pos = 0

    def _next_vuint():
        nonlocal pos
        result = 0
        while pos < len(info):
            b = info[pos]; pos += 1
            result = (result << 7) | (b & 0x7F)
            if (b & 0x80) == 0:
                break
        return result

    def _resolve(idx):
        return qstrs[idx] if 0 <= idx < len(qstrs) else f"<qstr_{idx}>"

    simple_name_idx = _next_vuint()
    simple_name = _resolve(simple_name_idx)

    if is_module:
        # Módulo: segundo vuint é source_file, sem arg_names
        _next_vuint()  # source_file (descartado — já temos o filename)
        return simple_name, []

    # Função: lê n_pos_args + n_kwonly_args nomes de argumento
    n_args = meta.get("n_pos_args", 0) + meta.get("n_kwonly_args", 0)
    arg_names = []
    for _ in range(n_args):
        if pos >= len(info):
            break
        idx = _next_vuint()
        arg_names.append(_resolve(idx))

    return simple_name, arg_names


# ---------------------------------------------------------------------------
# Decodificador da tabela de números de linha
# ---------------------------------------------------------------------------

def decode_line_table(code: bytes, line_table_start: int, n_info: int) -> dict:
    """
    Decodifica a tabela de números de linha.

    Parâmetros:
      code             — bytecode completo da função
      line_table_start — offset onde a line table começa (= sig_end + size_bytes)
      n_info           — número exato de bytes na line table

    Retorna dict {bytecode_offset: numero_de_linha}.

    Formatos de entrada (py/bc.h):
      0b0LLBBBBB — compacto (1 byte)
        bc_delta   = byte & 0x1F
        line_delta = (byte >> 5) & 0x03
      0b1LLLBBBB + next_byte — extendido (2 bytes)
        bc_delta   = byte & 0x0F
        line_delta = ((byte & 0x70) << 4) | next_byte
    """
    line_map = {}
    bc_offset = 0
    line_no = 1   # MicroPython começa em linha 1
    ip = line_table_start
    end = line_table_start + n_info

    while ip < end:
        b = code[ip]

        if b & 0x80:
            # extendido: 2 bytes
            if ip + 1 >= end:
                break
            next_b = code[ip + 1]
            bc_delta   = b & 0x0F
            line_delta = ((b & 0x70) << 4) | next_b
            ip += 2
        else:
            # compacto: 1 byte
            bc_delta   = b & 0x1F
            line_delta = (b >> 5) & 0x03
            ip += 1

        bc_offset += bc_delta
        line_no   += line_delta
        line_map[bc_offset] = line_no

    return line_map


# ---------------------------------------------------------------------------
# Decodificador de instrução individual
# ---------------------------------------------------------------------------

def _make_instr(offset: int, opcode: int, opname: str,
                arg: Any, argval: Any, argrepr: str,
                jump_target=None) -> dict:
    return {
        "offset":        offset,
        "opcode":        opcode,
        "opname":        opname,
        "arg":           arg,
        "argval":        argval,
        "argrepr":       argrepr,
        "is_jump_target": False,    # calculado em pós-processamento
        "jump_target":   jump_target,
    }


def decode_one(code: bytes, ip: int, qstrs: list, consts: list) -> tuple:
    """
    Decodifica uma instrução a partir de `ip` em `code`.
    Retorna (instr_dict, next_ip).
    """
    if ip >= len(code):
        raise EOFError(f"fim inesperado do bytecode em offset {ip}")

    offset = ip
    byte   = code[ip]; ip += 1

    # ------------------------------------------------------------------
    # Ranges de multi-opcodes (0x70–0xff)
    # ------------------------------------------------------------------
    if 0x70 <= byte <= 0xaf:
        val = byte - 0x70 - 16
        return _make_instr(offset, byte, "LOAD_CONST_SMALL_INT_MULTI",
                           arg=byte, argval=val, argrepr=repr(val)), ip

    if 0xb0 <= byte <= 0xbf:
        idx = byte - 0xb0
        return _make_instr(offset, byte, "LOAD_FAST_MULTI",
                           arg=byte, argval=idx, argrepr=f"_local_{idx}"), ip

    if 0xc0 <= byte <= 0xcf:
        idx = byte - 0xc0
        return _make_instr(offset, byte, "STORE_FAST_MULTI",
                           arg=byte, argval=idx, argrepr=f"_local_{idx}"), ip

    if 0xd0 <= byte <= 0xd6:
        op = UNARY_OPS[byte - 0xd0]
        return _make_instr(offset, byte, "UNARY_OP_MULTI",
                           arg=byte, argval=op, argrepr=op), ip

    if 0xd7 <= byte <= 0xff:
        idx = byte - 0xd7
        op  = BINARY_OPS[idx] if idx < len(BINARY_OPS) else f"binop_{idx}"
        return _make_instr(offset, byte, "BINARY_OP_MULTI",
                           arg=byte, argval=op, argrepr=op), ip

    # ------------------------------------------------------------------
    # Opcodes sem argumento
    # ------------------------------------------------------------------
    if byte in _NO_ARG:
        opname = _NO_ARG[byte]
        return _make_instr(offset, byte, opname,
                           arg=None, argval=None, argrepr=""), ip

    # ------------------------------------------------------------------
    # LOAD_CONST_SMALL_INT — signed vuint (zigzag)
    # ------------------------------------------------------------------
    if byte == 0x22:
        val, ip = _read_signed_vuint_b(code, ip)
        return _make_instr(offset, byte, "LOAD_CONST_SMALL_INT",
                           arg=val, argval=val, argrepr=repr(val)), ip

    # ------------------------------------------------------------------
    # Opcodes com argumento de qstr
    # ------------------------------------------------------------------
    if byte in _QSTR_ARG:
        opname = _QSTR_ARG[byte]
        idx, ip = _read_vuint_b(code, ip)
        name = qstrs[idx] if idx < len(qstrs) else f"<qstr_{idx}>"
        return _make_instr(offset, byte, opname,
                           arg=idx, argval=name, argrepr=name), ip

    # ------------------------------------------------------------------
    # Opcodes com um vuint
    # ------------------------------------------------------------------
    if byte in _UINT_ARG:
        opname = _UINT_ARG[byte]
        idx, ip = _read_vuint_b(code, ip)

        if byte == 0x23:   # LOAD_CONST_OBJ
            val = consts[idx] if idx < len(consts) else f"<const_{idx}>"
            argval = val; argrepr = repr(val)
        elif byte in (0x24, 0x26, 0x28):  # LOAD/STORE/DELETE_FAST_N
            argval = idx; argrepr = f"_local_{idx}"
        elif byte in (0x25, 0x27, 0x29):  # LOAD/STORE/DELETE_DEREF
            argval = idx; argrepr = f"_cell_{idx}"
        else:
            argval = idx; argrepr = str(idx)

        return _make_instr(offset, byte, opname,
                           arg=idx, argval=argval, argrepr=argrepr), ip

    # ------------------------------------------------------------------
    # Opcodes com dois vuints
    # ------------------------------------------------------------------
    if byte in _TWO_UINT_ARGS:
        opname = _TWO_UINT_ARGS[byte]
        a, ip = _read_vuint_b(code, ip)
        b, ip = _read_vuint_b(code, ip)
        argval = (a, b)
        if byte in (0x20, 0x21):               # MAKE_CLOSURE*
            argrepr = f"child={a}, n_closed={b}"
        else:
            argrepr = f"{a}, {b}"
        return _make_instr(offset, byte, opname,
                           arg=(a, b), argval=argval, argrepr=argrepr), ip

    # ------------------------------------------------------------------
    # Opcodes com vuint empacotado: (low_8, high_8) num único vuint
    # CALL_*: low = n_pos, high = n_kw (vm.c: unum & 0xFF, unum >> 8)
    # UNPACK_EX: low = n_before, high = n_after
    # ------------------------------------------------------------------
    if byte in _PACKED_UINT_ARG:
        opname = _PACKED_UINT_ARG[byte]
        packed, ip = _read_vuint_b(code, ip)
        a = packed & 0xFF
        b = (packed >> 8) & 0xFF
        argval = (a, b)
        if byte == 0x31:                       # UNPACK_EX
            argrepr = f"n_before={a}, n_after={b}"
        else:                                  # CALL_*
            argrepr = f"n_pos={a}, n_kw={b}"
        return _make_instr(offset, byte, opname,
                           arg=packed, argval=argval, argrepr=argrepr), ip

    # ------------------------------------------------------------------
    # UNWIND_JUMP — jump offset + vuint n_unwind
    # ------------------------------------------------------------------
    if byte == 0x40:
        rel, ip = _read_jump_arg(code, ip)
        n_unwind, ip = _read_vuint_b(code, ip)
        target = ip + rel
        return _make_instr(offset, byte, "UNWIND_JUMP",
                           arg=(rel, n_unwind), argval=(target, n_unwind),
                           argrepr=f"target={target}, n_unwind={n_unwind}",
                           jump_target=target), ip

    # ------------------------------------------------------------------
    # Opcodes de salto signed: target = next_ip + (arg - 64)
    # onde next_ip é ip após leitura do argumento (igual ao do VM MicroPython)
    # ------------------------------------------------------------------
    if byte in _JUMP_ARG:
        opname = _JUMP_ARG[byte]
        rel, ip = _read_jump_arg(code, ip)
        target = ip + rel           # ip aqui = next_ip após consumir o arg
        return _make_instr(offset, byte, opname,
                           arg=rel, argval=target,
                           argrepr=f"to {target}",
                           jump_target=target), ip

    # ------------------------------------------------------------------
    # SETUP_WITH/EXCEPT/FINALLY — ULABEL forward-only
    # target = next_ip + raw_arg  (sem subtração de 64)
    # ------------------------------------------------------------------
    if byte in _SETUP_JUMP_ARG:
        opname = _SETUP_JUMP_ARG[byte]
        if ip >= len(code):
            raise EOFError(f"argumento SETUP truncado em offset {ip}")
        raw_arg = code[ip]; ip += 1
        # 2-byte extendido?
        if raw_arg & 0x80:
            if ip >= len(code):
                raise EOFError(f"segundo byte SETUP truncado em offset {ip}")
            b2 = code[ip]; ip += 1
            raw_arg = ((raw_arg & 0x7F) << 8) | b2
        target = ip + raw_arg
        return _make_instr(offset, byte, opname,
                           arg=raw_arg, argval=target,
                           argrepr=f"to {target}",
                           jump_target=target), ip

    # ------------------------------------------------------------------
    # Opcode desconhecido — emite placeholder para não abortar o disasm
    # ------------------------------------------------------------------
    return _make_instr(offset, byte, f"UNKNOWN_0x{byte:02x}",
                       arg=None, argval=None, argrepr=""), ip


# ---------------------------------------------------------------------------
# Função principal
# ---------------------------------------------------------------------------

def parse_mpy_instructions(raw_code, qstrs: list, consts: list) -> tuple:
    """
    Decodifica todas as instruções de um RawCodeObject de tipo bytecode.

    Retorna (prelude_meta, instr_start, instructions, line_map) onde:
      prelude_meta  : dict com n_state, n_pos_args, etc.
      instr_start   : int — offset onde as instruções começam
      instructions  : list[dict] — formato idêntico a parse_instructions() de disasm.py
      line_map      : dict {offset: line_no}
    """
    code = raw_code.code

    meta, instr_start = decode_prelude(code)
    line_map = decode_line_table(code, meta["line_table_start"], meta["n_info"])

    instructions = []
    ip = instr_start
    while ip < len(code):
        try:
            instr, ip = decode_one(code, ip, qstrs, consts)
        except (EOFError, IndexError) as exc:
            # bytecode truncado ou mal-formado: encerra graciosamente
            instructions.append(_make_instr(
                ip, 0x00, "TRUNCATED", arg=None, argval=None,
                argrepr=str(exc)
            ))
            break
        instructions.append(instr)

    # Pós-processamento: marca is_jump_target nos alvos de salto
    targets = {
        instr["jump_target"]
        for instr in instructions
        if instr["jump_target"] is not None
    }
    for instr in instructions:
        instr["is_jump_target"] = instr["offset"] in targets

    return meta, instr_start, instructions, line_map


def format_instructions(instructions: list, line_map: dict = None) -> str:
    """Renderiza as instruções como texto legível (para o painel de bytecode da UI)."""
    lines = []
    for instr in instructions:
        off  = instr["offset"]
        lno  = line_map.get(off, "") if line_map else ""
        mark = ">>" if instr["is_jump_target"] else "  "
        jt   = f"  (-> {instr['jump_target']})" if instr["jump_target"] is not None else ""
        line = f"{mark} {off:>4}  {lno:>4}  {instr['opname']:<30} {instr['argrepr']}{jt}"
        lines.append(line)
    return "\n".join(lines)
