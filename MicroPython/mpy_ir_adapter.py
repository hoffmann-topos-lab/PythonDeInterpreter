from dataclasses import dataclass, field
from typing import List, Tuple

from MicroPython.mpy_disasm import parse_mpy_instructions, decode_prelude, decode_prelude_qstrs
from MicroPython.mpy_loader import KIND_BYTECODE, KIND_NATIVE


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


@dataclass
class MpyCodeObject:
 
    co_name:           str
    co_filename:       str
    co_firstlineno:    int
    co_argcount:       int      
    co_posonlyargcount: int      
    co_kwonlyargcount: int       
    co_flags:          int      
    co_varnames:       tuple    
    co_cellvars:       tuple     
    co_freevars:       tuple     
    co_consts:         tuple     
    co_names:          tuple    


    kind:              int       
    arch_code:         int       
    n_def_pos_args:    int      
    scope_flags:       int       


    _instructions: list = field(default_factory=list)  
    _children:     list = field(default_factory=list)   
    _line_map:     dict = field(default_factory=dict)   
    _prelude:      dict = field(default_factory=dict)   
    _native_code:  bytes = b""                          
    _prelude_offset: int = -1                           




def _infer_varnames(instructions: list, n_pos_args: int,
                    arg_names: list = None) -> tuple:
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

    NAME_OPS = {
        "LOAD_NAME", "STORE_NAME", "DELETE_NAME",
        "LOAD_GLOBAL", "STORE_GLOBAL", "DELETE_GLOBAL",
        "LOAD_ATTR", "STORE_ATTR",
        "LOAD_METHOD", "LOAD_SUPER_METHOD",
        "IMPORT_NAME", "IMPORT_FROM",
        "LOAD_CONST_STRING",
    }
    seen: dict = {}  
    for instr in instructions:
        if instr["opname"] in NAME_OPS:
            idx = instr.get("arg")
            val = instr.get("argval")
            if isinstance(idx, int) and isinstance(val, str) and idx not in seen:
                seen[idx] = val
    return tuple(seen.values())


def _infer_consts(instructions: list, consts: list) -> tuple:
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



def adapt_raw_code(
    raw,
    qstrs: list,
    consts: list,
    filename: str,
    name: str = "<module>",
    arch_code: int = 0,
) -> "MpyCodeObject":
    children = [
        adapt_raw_code(
            child, qstrs, consts, filename,
            name=f"<child_{i}>", arch_code=arch_code,
        )
        for i, child in enumerate(raw.children)
    ]

    if raw.kind != KIND_BYTECODE:
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

    meta, _instr_start, instructions, line_map = parse_mpy_instructions(
        raw, qstrs, consts
    )

    n_pos      = meta.get("n_pos_args", 0)
    n_kw       = meta.get("n_kwonly_args", 0)
    n_def      = meta.get("n_def_pos_args", 0)
    sflags     = meta.get("scope_flags", 0)
    co_flags   = _mp_flags_to_co_flags(sflags)

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
