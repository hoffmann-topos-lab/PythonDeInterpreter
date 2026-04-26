"""Ponte entre as tools MCP e os pipelines do decompilador.

Evita reimplementar lógica: reusa `run_engine` / `run_mpy_engine` para a
execução ponta-a-ponta e importa diretamente os módulos de cada estágio para
chamadas granulares.
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any

from .cache import get_or_compute
from .formats import detect_format, require_path


def run_full(path: str) -> dict:
    """Executa o pipeline completo (via subprocess das engines existentes).

    Retorna: {bytecode, recovered, meta, format}.
    """
    p = require_path(path)
    fmt = detect_format(str(p))

    def _compute():
        if fmt == "pyc":
            from Decompiler.engine_runner import run_engine
            bc, rc, meta = run_engine(str(p))
        elif fmt == "mpy":
            from MicroPython.mpy_engine_runner import run_mpy_engine
            bc, rc, meta = run_mpy_engine(str(p))
        else:
            raise ValueError(f"formato não suportado: {fmt} ({p})")
        return {"bytecode": bc, "recovered": rc, "meta": meta, "format": fmt}

    return get_or_compute(str(p), "full_pipeline", _compute)


# ---------------------------------------------------------------------------
# CPython
# ---------------------------------------------------------------------------

def load_pyc_root(path: str) -> types.CodeType:
    def _compute():
        from Decompiler.loader import load_code_object
        return load_code_object(path)
    return get_or_compute(path, "pyc_root_co", _compute)


def collect_pyc_code_objects(path: str) -> list[types.CodeType]:
    def _compute():
        root = load_pyc_root(path)
        seen = set()
        out: list[types.CodeType] = []

        def walk(co):
            if not isinstance(co, types.CodeType):
                return
            if id(co) in seen:
                return
            seen.add(id(co))
            out.append(co)
            for c in (co.co_consts or ()):
                if isinstance(c, types.CodeType):
                    walk(c)

        walk(root)
        out.sort(key=lambda c: (0 if c.co_name == "<module>" else 1,
                                 getattr(c, "co_firstlineno", 0),
                                 c.co_name))
        return out
    return get_or_compute(path, "pyc_all_cos", _compute)


def find_pyc_code_object(path: str, name: str) -> types.CodeType:
    for co in collect_pyc_code_objects(path):
        if co.co_name == name:
            return co
    raise KeyError(f"code object '{name}' não encontrado em {path}")


def pyc_stage_artifacts(path: str, co: types.CodeType) -> dict:
    def _compute():
        import sys as _sys
        _root = Path(__file__).resolve().parent.parent
        _dec = str(_root / "Decompiler")
        if _dec not in _sys.path:
            _sys.path.insert(0, _dec)
        from disasm import parse_instructions  # type: ignore
        from stack_sim import simulate_stack  # type: ignore
        from patterns import detect_high_level_patterns  # type: ignore
        from utils.cfg import build_basic_blocks, build_cfg
        from utils.ast_recover import build_recovered_ast

        ins = parse_instructions(co)
        blocks = build_basic_blocks(ins, code_obj=co)
        cfg = build_cfg(blocks, ins, co)
        stack_info = simulate_stack(blocks, cfg, ins, co)
        patterns = detect_high_level_patterns(
            blocks=blocks, cfg=cfg, stack_info=stack_info, code_obj=co,
        )
        recovered_ast = build_recovered_ast(
            blocks=blocks, cfg=cfg, stack_info=stack_info,
            patterns=patterns, code_obj=co,
        )
        return {
            "instructions": ins,
            "blocks": blocks,
            "cfg": cfg,
            "stack_info": stack_info,
            "patterns": patterns,
            "recovered_ast": recovered_ast,
        }
    return get_or_compute(path, f"pyc_stage_{id(co)}", _compute)


# ---------------------------------------------------------------------------
# MicroPython
# ---------------------------------------------------------------------------

def load_mpy_root(path: str):
    """Retorna (header, qstrs, consts, raw_root, mpy_root_adapted)."""
    def _compute():
        from MicroPython.mpy_loader import load_mpy
        from MicroPython.mpy_ir_adapter import adapt_raw_code
        header, qstrs, consts, raw_root = load_mpy(path)
        mpy_root = adapt_raw_code(
            raw_root, qstrs, consts,
            filename=Path(path).name,
            name="<module>",
            arch_code=header["arch_code"],
        )
        return {
            "header": header,
            "qstrs": qstrs,
            "consts": consts,
            "raw_root": raw_root,
            "mpy_root": mpy_root,
        }
    return get_or_compute(path, "mpy_root", _compute)


def collect_mpy_code_objects(path: str) -> list:
    def _compute():
        data = load_mpy_root(path)
        root = data["mpy_root"]
        out = []

        def walk(obj):
            out.append(obj)
            for c in obj._children:
                walk(c)

        walk(root)
        return out
    return get_or_compute(path, "mpy_all_cos", _compute)


def find_mpy_code_object(path: str, name: str):
    for obj in collect_mpy_code_objects(path):
        if obj.co_name == name:
            return obj
    raise KeyError(f"code object '{name}' não encontrado em {path}")


def mpy_stage_artifacts(path: str, mpy_obj) -> dict:
    def _compute():
        from MicroPython.mpy_stack_sim import (
            build_mpy_basic_blocks, build_mpy_cfg, simulate_mpy_stack,
        )
        from MicroPython.mpy_patterns import detect_mpy_patterns
        from utils.ast_recover import build_recovered_ast

        ins = mpy_obj._instructions
        blocks = build_mpy_basic_blocks(ins, mpy_obj)
        cfg = build_mpy_cfg(blocks, ins, mpy_obj)
        stack_info = simulate_mpy_stack(blocks, cfg, ins, mpy_obj)
        patterns = detect_mpy_patterns(
            blocks=blocks, cfg=cfg, stack_info=stack_info, code_obj=mpy_obj,
        )
        recovered_ast = build_recovered_ast(
            blocks=blocks, cfg=cfg, stack_info=stack_info,
            patterns=patterns, code_obj=mpy_obj,
        )
        return {
            "instructions": ins,
            "blocks": blocks,
            "cfg": cfg,
            "stack_info": stack_info,
            "patterns": patterns,
            "recovered_ast": recovered_ast,
        }
    return get_or_compute(path, f"mpy_stage_{id(mpy_obj)}", _compute)


# ---------------------------------------------------------------------------
# Dispatch por formato
# ---------------------------------------------------------------------------

def collect_code_objects(path: str) -> tuple[str, list]:
    fmt = detect_format(path)
    if fmt == "pyc":
        return fmt, collect_pyc_code_objects(path)
    if fmt == "mpy":
        return fmt, collect_mpy_code_objects(path)
    raise ValueError(f"formato não suportado: {fmt}")


def find_code_object(path: str, name: str) -> tuple[str, Any]:
    fmt = detect_format(path)
    if fmt == "pyc":
        return fmt, find_pyc_code_object(path, name)
    if fmt == "mpy":
        return fmt, find_mpy_code_object(path, name)
    raise ValueError(f"formato não suportado: {fmt}")


def stage_artifacts(path: str, co) -> dict:
    fmt = detect_format(path)
    if fmt == "pyc":
        return pyc_stage_artifacts(path, co)
    if fmt == "mpy":
        return mpy_stage_artifacts(path, co)
    raise ValueError(f"formato não suportado: {fmt}")
