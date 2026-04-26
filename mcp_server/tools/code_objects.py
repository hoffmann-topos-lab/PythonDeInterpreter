"""List and introspect code objects inside a .pyc/.mpy."""

import types

from ..runner import (
    collect_code_objects,
    find_code_object,
    run_full,
)
from ..formats import detect_format
from ..pagination import truncate_text


def _co_kind(co) -> str:
    if isinstance(co, types.CodeType):
        flags = co.co_flags
        if flags & 0x20:  # CO_GENERATOR
            return "generator"
        if co.co_name == "<lambda>":
            return "lambda"
        if co.co_name.startswith("<") and co.co_name.endswith(">"):
            if "genexpr" in co.co_name:
                return "genexpr"
            if "listcomp" in co.co_name:
                return "listcomp"
            if "setcomp" in co.co_name:
                return "setcomp"
            if "dictcomp" in co.co_name:
                return "dictcomp"
            if co.co_name == "<module>":
                return "module"
        return "function"
    # MpyCodeObject
    from MicroPython.mpy_loader import KIND_BYTECODE, KIND_NATIVE, KIND_VIPER
    if getattr(co, "kind", KIND_BYTECODE) != KIND_BYTECODE:
        return {1: "native", 2: "viper", 3: "asm"}.get(co.kind, "native")
    if co.co_name == "<module>":
        return "module"
    return "function"


def _pyc_hierarchy_node(co) -> dict:
    return {
        "name": co.co_name,
        "kind": _co_kind(co),
        "first_lineno": getattr(co, "co_firstlineno", None),
        "argcount": getattr(co, "co_argcount", 0),
        "children": [
            _pyc_hierarchy_node(c)
            for c in (co.co_consts or ())
            if isinstance(c, types.CodeType)
        ],
    }


def _mpy_hierarchy_node(co) -> dict:
    return {
        "name": co.co_name,
        "kind": _co_kind(co),
        "first_lineno": getattr(co, "co_firstlineno", None),
        "argcount": getattr(co, "co_argcount", 0),
        "arch_code": getattr(co, "arch_code", 0),
        "children": [_mpy_hierarchy_node(c) for c in (co._children or [])],
    }


def _serialize_const(c) -> dict:
    if isinstance(c, types.CodeType):
        return {"kind": "code", "name": c.co_name}
    if isinstance(c, (str, int, float, bool)) or c is None:
        return {"kind": type(c).__name__, "value": c}
    if isinstance(c, (bytes, bytearray)):
        return {"kind": "bytes", "hex": bytes(c).hex(), "len": len(c)}
    if isinstance(c, tuple):
        return {"kind": "tuple", "items": [_serialize_const(x) for x in c]}
    if isinstance(c, frozenset):
        return {"kind": "frozenset", "items": [_serialize_const(x) for x in c]}
    return {"kind": type(c).__name__, "repr": repr(c)}


def register(mcp):
    @mcp.tool()
    def list_code_objects(path: str) -> dict:
        """Hierarchical tree of all code objects in the binary."""
        fmt = detect_format(path)
        if fmt == "pyc":
            from ..runner import load_pyc_root
            root = load_pyc_root(path)
            return {"format": fmt, "tree": _pyc_hierarchy_node(root)}
        if fmt == "mpy":
            from ..runner import load_mpy_root
            data = load_mpy_root(path)
            return {"format": fmt, "tree": _mpy_hierarchy_node(data["mpy_root"])}
        raise ValueError(f"formato não suportado: {fmt}")

    @mcp.tool()
    def list_code_object_names(path: str) -> dict:
        """Flat list of all code object names (for quick enumeration)."""
        fmt, cos = collect_code_objects(path)
        return {
            "format": fmt,
            "count": len(cos),
            "names": [c.co_name for c in cos],
        }

    @mcp.tool()
    def get_code_object_metadata(path: str, name: str) -> dict:
        """Return co_* attributes of a code object (names, varnames, consts summary, flags, argcount...)."""
        fmt, co = find_code_object(path, name)
        base = {
            "format": fmt,
            "name": co.co_name,
            "kind": _co_kind(co),
            "first_lineno": getattr(co, "co_firstlineno", None),
            "argcount": getattr(co, "co_argcount", 0),
            "posonlyargcount": getattr(co, "co_posonlyargcount", 0),
            "kwonlyargcount": getattr(co, "co_kwonlyargcount", 0),
            "flags": getattr(co, "co_flags", 0),
            "varnames": list(getattr(co, "co_varnames", ()) or ()),
            "cellvars": list(getattr(co, "co_cellvars", ()) or ()),
            "freevars": list(getattr(co, "co_freevars", ()) or ()),
            "names": list(getattr(co, "co_names", ()) or ()),
            "filename": getattr(co, "co_filename", None),
        }
        if fmt == "pyc":
            base["stacksize"] = getattr(co, "co_stacksize", None)
            base["nlocals"] = getattr(co, "co_nlocals", None)
        else:
            base["arch_code"] = getattr(co, "arch_code", None)
            base["scope_flags"] = getattr(co, "scope_flags", None)
            base["n_def_pos_args"] = getattr(co, "n_def_pos_args", None)
        return base

    @mcp.tool()
    def get_co_consts(path: str, name: str) -> dict:
        """Return the constants table for a code object (nested CodeType shown as {kind:'code', name})."""
        fmt, co = find_code_object(path, name)
        consts = getattr(co, "co_consts", ()) or ()
        return {
            "format": fmt,
            "name": co.co_name,
            "count": len(consts),
            "consts": [_serialize_const(c) for c in consts],
        }

    @mcp.tool()
    def get_code_object_source(path: str, name: str) -> dict:
        """Return only the recovered Python source belonging to the given code object.

        Uses `split_recovered_functions` from UI/ui_parsers.
        """
        from UI.ui_parsers import split_recovered_functions
        out = run_full(path)
        funcs = split_recovered_functions(out["recovered"])
        text = funcs.get(name)
        if text is None:
            raise KeyError(f"função '{name}' não encontrada no recuperado")
        return {"format": out["format"], "name": name, **truncate_text(text)}

    @mcp.tool()
    def get_code_object_bytecode(path: str, name: str) -> dict:
        """Return only the bytecode block for a code object, delimited by the disassembly header."""
        out = run_full(path)
        bc = out["bytecode"]
        meta = out["meta"] or {}
        info = meta.get(name)
        if not info:
            # tentativa de fallback: procurar pelo header no texto
            pass
        # Localiza o início pelo header "Disassembly of <code object NAME at ..."
        needle = f"<code object {name} at "
        idx = bc.find(needle)
        if idx == -1:
            raise KeyError(f"bloco de disassembly para '{name}' não encontrado")
        # Começa na linha do header
        line_start = bc.rfind("\n", 0, idx) + 1
        # Termina quando outro header de code object aparece
        next_hdr = bc.find("Disassembly of <code object ", idx + len(needle))
        end = next_hdr if next_hdr != -1 else len(bc)
        # Volta à quebra de linha antes do próximo cabeçalho
        if next_hdr != -1:
            line_before = bc.rfind("\n", 0, next_hdr)
            if line_before != -1:
                end = line_before
        snippet = bc[line_start:end]
        return {"format": out["format"], "name": name, **truncate_text(snippet)}
