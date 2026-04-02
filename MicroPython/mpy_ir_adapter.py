"""
MicroPython → pipeline adapter.

Converte RawCodeObject (saída de mpy_loader) em MpyCodeObject,
um duck-type de types.CodeType compatível com utils/cfg.py e
utils/ast_recover.py.

Os atributos CPython-compatíveis expostos são:
    co_name, co_filename, co_firstlineno,
    co_argcount, co_posonlyargcount, co_kwonlyargcount,
    co_flags, co_varnames, co_cellvars, co_freevars,
    co_consts, co_names

Nomes de variáveis locais são sintetizados (_arg_N, _local_N) pois
o bytecode MicroPython não armazena esses nomes. mpy_extract.py
pode sobrescrever co_name nos filhos depois de processar MAKE_FUNCTION.
"""

from dataclasses import dataclass, field
from typing import List, Tuple

from MicroPython.mpy_disasm import parse_mpy_instructions, decode_prelude, decode_prelude_qstrs
from MicroPython.mpy_loader import KIND_BYTECODE, KIND_NATIVE

# ---------------------------------------------------------------------------
# Mapeamento de scope_flags MicroPython → co_flags CPython (aproximado)
# Fonte: py/bc.h  MP_SCOPE_FLAG_*
# ---------------------------------------------------------------------------
_MP_SCOPE_GENERATOR   = 0x01
_MP_SCOPE_VARKEYWORDS = 0x02
_MP_SCOPE_VARARGS     = 0x04
_MP_SCOPE_DEFKWARGS   = 0x08

_CO_VARARGS     = 0x04
_CO_VARKEYWORDS = 0x08
_CO_GENERATOR   = 0x20


def _mp_flags_to_co_flags(scope_flags: int) -> int:
    co = 0
    if scope_flags & _MP_SCOPE_GENERATOR:
        co |= _CO_GENERATOR
    if scope_flags & _MP_SCOPE_VARARGS:
        co |= _CO_VARARGS
    if scope_flags & _MP_SCOPE_VARKEYWORDS:
        co |= _CO_VARKEYWORDS
    return co


# ---------------------------------------------------------------------------
# Duck-type de types.CodeType
# ---------------------------------------------------------------------------

@dataclass
class MpyCodeObject:
    """
    Duck-type de types.CodeType para o pipeline MicroPython.

    Só os atributos consumidos por utils/cfg.py, utils/ast_recover.py e
    utils/codegen.py são definidos. Atributos ausentes no CPython original
    (n_def_pos_args, scope_flags, kind, arch_code) são extras MicroPython.
    """
    # -- compatíveis com types.CodeType --
    co_name:           str
    co_filename:       str
    co_firstlineno:    int
    co_argcount:       int       # n_pos_args do preâmbulo
    co_posonlyargcount: int      # 0 — MicroPython não distingue
    co_kwonlyargcount: int       # n_kwonly_args do preâmbulo
    co_flags:          int       # derivado de scope_flags
    co_varnames:       tuple     # sintetizado: (_arg_0 … _local_N)
    co_cellvars:       tuple     # () — MicroPython não distingue cell/free
    co_freevars:       tuple     # sintetizado: (_cell_0 … _cell_N)
    co_consts:         tuple     # objetos LOAD_CONST_OBJ referenciados
    co_names:          tuple     # qstrs de LOAD/STORE NAME/GLOBAL/ATTR

    # -- extras MicroPython --
    kind:              int       # KIND_BYTECODE / KIND_NATIVE / KIND_VIPER
    arch_code:         int       # código de arquitetura do header .mpy
    n_def_pos_args:    int       # n_def_pos_args do preâmbulo
    scope_flags:       int       # scope_flags brutos do preâmbulo

    # -- dados internos do pipeline --
    _instructions: list = field(default_factory=list)   # list[dict] de mpy_disasm
    _children:     list = field(default_factory=list)   # list[MpyCodeObject]
    _line_map:     dict = field(default_factory=dict)   # {offset: line_no}
    _prelude:      dict = field(default_factory=dict)   # metadados brutos do preâmbulo
    _native_code:  bytes = b""                          # bytes crus de código nativo (máquina + prelude)
    _prelude_offset: int = -1                           # offset do prelude dentro de _native_code


# ---------------------------------------------------------------------------
# Inferência de nomes a partir das instruções
# ---------------------------------------------------------------------------

def _infer_varnames(instructions: list, n_pos_args: int,
                    arg_names: list = None) -> tuple:
    """
    Constrói co_varnames a partir dos slots locais usados nas instruções.

    Se `arg_names` foi extraído do prelude (nomes reais), usa-os para os
    primeiros slots. Demais slots recebem nomes sintéticos (_local_N).
    """
    max_idx = -1
    for instr in instructions:
        op = instr["opname"]
        if op in ("LOAD_FAST_N", "STORE_FAST_N", "DELETE_FAST"):
            idx = instr.get("arg")
            if isinstance(idx, int) and idx > max_idx:
                max_idx = idx
        elif op in ("LOAD_FAST_MULTI", "STORE_FAST_MULTI"):
            idx = instr.get("argval")
            if isinstance(idx, int) and idx > max_idx:
                max_idx = idx
    if max_idx < 0 and not arg_names:
        return ()
    n_slots = max(max_idx + 1, len(arg_names) if arg_names else 0)
    names = []
    for i in range(n_slots):
        if arg_names and i < len(arg_names):
            names.append(arg_names[i])
        elif i < n_pos_args:
            names.append(f"_arg_{i}")
        else:
            names.append(f"_local_{i}")
    return tuple(names)


def _patch_local_names(instructions: list, varnames: tuple) -> None:
    """
    Substitui '_local_N' pelo nome correto de co_varnames nas instruções
    LOAD/STORE_FAST_MULTI e LOAD/STORE/DELETE_FAST_N.

    Isso corrige a desconexão entre os nomes sintéticos do disassembler
    (_local_0, _local_1, …) e os nomes inferidos (_arg_0, _arg_1, …).
    """
    _FAST_OPS = frozenset({
        "LOAD_FAST_N", "LOAD_FAST_MULTI",
        "STORE_FAST_N", "STORE_FAST_MULTI",
        "DELETE_FAST",
    })
    for instr in instructions:
        if instr["opname"] in _FAST_OPS:
            idx = instr.get("argval")
            if isinstance(idx, int) and 0 <= idx < len(varnames):
                instr["argrepr"] = varnames[idx]


def _infer_freevars(instructions: list) -> tuple:
    """Infere co_freevars a partir de LOAD/STORE/DELETE_DEREF."""
    max_idx = -1
    for instr in instructions:
        if instr["opname"] in ("LOAD_DEREF", "STORE_DEREF", "DELETE_DEREF"):
            idx = instr.get("arg")
            if isinstance(idx, int) and idx > max_idx:
                max_idx = idx
    if max_idx < 0:
        return ()
    return tuple(f"_cell_{i}" for i in range(max_idx + 1))


def _infer_names(instructions: list) -> tuple:
    """
    Infere co_names a partir de opcodes que referenciam qstrs globais/de atributo.
    Preserva a ordem de primeira aparição.
    """
    NAME_OPS = {
        "LOAD_NAME", "STORE_NAME", "DELETE_NAME",
        "LOAD_GLOBAL", "STORE_GLOBAL", "DELETE_GLOBAL",
        "LOAD_ATTR", "STORE_ATTR",
        "LOAD_METHOD", "LOAD_SUPER_METHOD",
        "IMPORT_NAME", "IMPORT_FROM",
        "LOAD_CONST_STRING",
    }
    seen: dict = {}   # idx → name, em ordem de aparição
    for instr in instructions:
        if instr["opname"] in NAME_OPS:
            idx = instr.get("arg")
            val = instr.get("argval")
            if isinstance(idx, int) and isinstance(val, str) and idx not in seen:
                seen[idx] = val
    return tuple(seen.values())


def _infer_consts(instructions: list, consts: list) -> tuple:
    """Coleta objetos constantes referenciados por LOAD_CONST_OBJ."""
    result = []
    seen: set = set()
    for instr in instructions:
        if instr["opname"] == "LOAD_CONST_OBJ":
            idx = instr.get("arg")
            if isinstance(idx, int) and idx not in seen:
                seen.add(idx)
                if idx < len(consts):
                    result.append(consts[idx])
    return tuple(result)


# ---------------------------------------------------------------------------
# Ponto de entrada público
# ---------------------------------------------------------------------------

def adapt_raw_code(
    raw,
    qstrs: list,
    consts: list,
    filename: str,
    name: str = "<module>",
    arch_code: int = 0,
) -> "MpyCodeObject":
    """
    Converte um RawCodeObject em MpyCodeObject, processando filhos recursivamente.

    Parâmetros:
        raw       — RawCodeObject de mpy_loader
        qstrs     — tabela global de qstrs do .mpy
        consts    — tabela global de constantes do .mpy
        filename  — nome do arquivo .mpy (para co_filename)
        name      — nome do código (para co_name; padrão "<module>" para raiz)
        arch_code — código de arquitetura do header .mpy

    Filhos recebem nomes temporários "<child_0>", "<child_1>", etc.
    mpy_extract.py sobrescreve esses nomes ao processar MAKE_FUNCTION.
    """
    # Adapta filhos primeiro (pós-ordem)
    children = [
        adapt_raw_code(
            child, qstrs, consts, filename,
            name=f"<child_{i}>", arch_code=arch_code,
        )
        for i, child in enumerate(raw.children)
    ]

    if raw.kind != KIND_BYTECODE:
        # Código native/viper — sem bytecode decodificável, mas o prelude
        # embutido no final do código de máquina contém a assinatura da
        # função (n_pos_args, arg_names, simple_name).
        native_meta = {}
        native_name = name
        native_arg_names = []
        n_pos = 0
        n_kw = 0
        sflags = 0
        co_flags = 0

        if raw.kind == KIND_NATIVE and raw.prelude_offset >= 0:
            prelude_bytes = raw.code[raw.prelude_offset:]
            native_meta, _ = decode_prelude(prelude_bytes)
            n_pos   = native_meta.get("n_pos_args", 0)
            n_kw    = native_meta.get("n_kwonly_args", 0)
            sflags  = native_meta.get("scope_flags", 0)
            co_flags = _mp_flags_to_co_flags(sflags)

            sn, arg_names = decode_prelude_qstrs(
                prelude_bytes, native_meta, qstrs, is_module=False
            )
            if sn:
                native_name = sn
            native_arg_names = arg_names

        varnames = tuple(native_arg_names) if native_arg_names else ()

        return MpyCodeObject(
            co_name=native_name,
            co_filename=filename,
            co_firstlineno=1,
            co_argcount=n_pos,
            co_posonlyargcount=0,
            co_kwonlyargcount=n_kw,
            co_flags=co_flags,
            co_varnames=varnames,
            co_cellvars=(),
            co_freevars=(),
            co_consts=(),
            co_names=(),
            kind=raw.kind,
            arch_code=arch_code,
            n_def_pos_args=native_meta.get("n_def_pos_args", 0),
            scope_flags=sflags,
            _instructions=[],
            _children=children,
            _line_map={},
            _prelude=native_meta,
            _native_code=raw.code,
            _prelude_offset=raw.prelude_offset,
        )

    # Decodifica bytecode
    meta, _instr_start, instructions, line_map = parse_mpy_instructions(
        raw, qstrs, consts
    )

    n_pos      = meta.get("n_pos_args", 0)
    n_kw       = meta.get("n_kwonly_args", 0)
    n_def      = meta.get("n_def_pos_args", 0)
    sflags     = meta.get("scope_flags", 0)
    co_flags   = _mp_flags_to_co_flags(sflags)

    # Extrai nomes reais do prelude (simple_name, arg_names)
    is_mod = (name == "<module>")
    prelude_name, arg_names = decode_prelude_qstrs(
        raw.code, meta, qstrs, is_module=is_mod
    )

    varnames   = _infer_varnames(instructions, n_pos, arg_names=arg_names)
    _patch_local_names(instructions, varnames)
    freevars   = _infer_freevars(instructions)
    names_tup  = _infer_names(instructions)
    co_consts  = _infer_consts(instructions, consts)

    firstlineno = min(line_map.values()) if line_map else 1

    # Usa nome real do prelude quando disponível (exceto para <module>)
    real_name = prelude_name if (prelude_name and not is_mod) else name

    return MpyCodeObject(
        co_name=real_name,
        co_filename=filename,
        co_firstlineno=firstlineno,
        co_argcount=n_pos,
        co_posonlyargcount=0,
        co_kwonlyargcount=n_kw,
        co_flags=co_flags,
        co_varnames=varnames,
        co_cellvars=(),
        co_freevars=freevars,
        co_consts=co_consts,
        co_names=names_tup,
        kind=raw.kind,
        arch_code=arch_code,
        n_def_pos_args=n_def,
        scope_flags=sflags,
        _instructions=instructions,
        _children=children,
        _line_map=line_map,
        _prelude=meta,
    )
