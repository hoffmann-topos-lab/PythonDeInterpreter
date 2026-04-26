"""Tools that expose each pipeline stage individually."""

from ..runner import (
    collect_code_objects,
    find_code_object,
    run_full,
    stage_artifacts,
)
from ..pagination import truncate_text


def _iter_target_cos(path: str, name: str | None):
    fmt, cos = collect_code_objects(path)
    if name is None:
        return fmt, cos
    for co in cos:
        if co.co_name == name:
            return fmt, [co]
    raise KeyError(f"code object '{name}' não encontrado em {path}")


def _instr_to_dict(instr: dict) -> dict:
    keys = ("offset", "opname", "arg", "argval", "argrepr", "jump_target",
            "is_target", "starts_line")
    return {k: instr.get(k) for k in keys if k in instr}


def _block_to_dict(block: dict) -> dict:
    return {
        "id": block["id"],
        "start_offset": block.get("start_offset"),
        "end_offset": block.get("end_offset"),
        "n_instructions": len(block.get("instructions") or []),
        "first_opname": (block.get("instructions") or [{}])[0].get("opname") if block.get("instructions") else None,
        "last_opname": (block.get("instructions") or [{}])[-1].get("opname") if block.get("instructions") else None,
    }


def _cfg_to_dict(cfg: dict) -> dict:
    return {str(src): sorted(list(dests)) for src, dests in cfg.items()}


def _cfg_to_dot(cfg: dict) -> str:
    lines = ["digraph CFG {", "  rankdir=TB;", "  node [shape=box];"]
    for src, dests in cfg.items():
        for d in sorted(dests):
            lines.append(f"  {src} -> {d};")
    lines.append("}")
    return "\n".join(lines)


def _cfg_to_mermaid(cfg: dict) -> str:
    lines = ["flowchart TD"]
    for src, dests in cfg.items():
        if not dests:
            lines.append(f"  BB{src}")
        for d in sorted(dests):
            lines.append(f"  BB{src} --> BB{d}")
    return "\n".join(lines)


def _stack_summary(blocks, stack_info) -> list[dict]:
    from utils.ir import stmt_repr, expr_repr
    bs = stack_info.get("block_statements") or {}
    bc = stack_info.get("block_conditions") or {}
    ins_ = stack_info.get("in_stack") or {}
    outs_ = stack_info.get("out_stack") or {}
    result = []
    for b in sorted(blocks, key=lambda bb: bb.get("start_offset") or 0):
        bid = b["id"]
        result.append({
            "block_id": bid,
            "in_stack": [expr_repr(x) for x in (ins_.get(bid) or [])],
            "out_stack": [expr_repr(x) for x in (outs_.get(bid) or [])],
            "statements": [stmt_repr(s) for s in (bs.get(bid) or [])],
            "conditions": [expr_repr(c) for c in (bc.get(bid) or [])],
        })
    return result


def _patterns_summary(patterns: dict) -> dict:
    return {
        "n_ifs": len(patterns.get("ifs") or []),
        "n_loops": len(patterns.get("loops") or []),
        "n_try_regions": len(patterns.get("try_regions") or []),
        "n_short_circuit_candidates": len(patterns.get("short_circuit_candidates") or []),
        "ifs": patterns.get("ifs") or [],
        "loops": patterns.get("loops") or [],
        "try_regions": patterns.get("try_regions") or [],
    }


def _recovered_ast_summary(recovered_ast: dict) -> list[dict]:
    out = []
    for s in (recovered_ast.get("structures") or []):
        t = s.get("type")
        entry = {"type": t}
        if t == "TryExceptFinally":
            entry.update({
                "try": s.get("try_blocks"),
                "except": s.get("except_blocks"),
                "finally": s.get("finally_blocks"),
            })
        elif t == "Loop":
            entry.update({"header": s.get("header"), "body": s.get("body_blocks")})
        elif t == "If":
            entry.update({
                "cond": s.get("cond_block"),
                "then": s.get("then_blocks"),
                "else": s.get("else_blocks"),
                "join": s.get("join_block"),
            })
        elif t == "TryRegion":
            entry.update({
                "range": s.get("range"),
                "depth": s.get("depth"),
                "protected": s.get("protected_blocks"),
                "handler": s.get("handler_blocks"),
            })
        out.append(entry)
    return out


def register(mcp):
    @mcp.tool()
    def stage_dis(path: str, name: str | None = None) -> dict:
        """Raw disassembly output. If 'name' is None, returns text for all code objects."""
        fmt, cos = _iter_target_cos(path, name)
        if fmt == "pyc":
            import dis as _dis
            import io
            buf = io.StringIO()
            for co in cos:
                buf.write(f"\n{'=' * 60}\n[CO] {co.co_name}  (firstlineno={getattr(co, 'co_firstlineno', None)})\n{'=' * 60}\n")
                _dis.dis(co, file=buf)
            return truncate_text(buf.getvalue())
        # mpy
        from MicroPython.mpy_disasm import format_instructions
        parts = []
        for co in cos:
            parts.append(f"\n{'=' * 60}\n[CO] {co.co_name}\n{'=' * 60}")
            parts.append(format_instructions(co._instructions, co._line_map))
        return truncate_text("\n".join(parts))

    @mcp.tool()
    def stage_parse(path: str, name: str | None = None) -> dict:
        """Parsed instruction list per code object."""
        fmt, cos = _iter_target_cos(path, name)
        out = []
        for co in cos:
            if fmt == "pyc":
                art = stage_artifacts(path, co)
                instrs = art["instructions"]
            else:
                instrs = co._instructions
            out.append({
                "code_object": co.co_name,
                "n_instructions": len(instrs),
                "instructions": [_instr_to_dict(i) for i in instrs],
            })
        return {"format": fmt, "code_objects": out}

    @mcp.tool()
    def stage_blocks(path: str, name: str | None = None) -> dict:
        """Basic block boundaries per code object (summary, not full instruction bodies)."""
        fmt, cos = _iter_target_cos(path, name)
        out = []
        for co in cos:
            art = stage_artifacts(path, co)
            blocks = art["blocks"]
            out.append({
                "code_object": co.co_name,
                "n_blocks": len(blocks),
                "blocks": [_block_to_dict(b) for b in blocks],
            })
        return {"format": fmt, "code_objects": out}

    @mcp.tool()
    def stage_cfg(path: str, name: str | None = None, format: str = "json") -> dict:
        """Control-flow graph. 'format' is one of: 'json', 'dot', 'mermaid'."""
        fmt, cos = _iter_target_cos(path, name)
        out = []
        for co in cos:
            cfg = stage_artifacts(path, co)["cfg"]
            if format == "dot":
                payload = _cfg_to_dot(cfg)
            elif format == "mermaid":
                payload = _cfg_to_mermaid(cfg)
            else:
                payload = _cfg_to_dict(cfg)
            out.append({"code_object": co.co_name, "cfg": payload})
        return {"format": fmt, "render": format, "code_objects": out}

    @mcp.tool()
    def stage_stack(path: str, name: str | None = None) -> dict:
        """Stack simulation per block: IN/OUT stacks, statements, conditions."""
        fmt, cos = _iter_target_cos(path, name)
        out = []
        for co in cos:
            art = stage_artifacts(path, co)
            out.append({
                "code_object": co.co_name,
                "blocks": _stack_summary(art["blocks"], art["stack_info"]),
            })
        return {"format": fmt, "code_objects": out}

    @mcp.tool()
    def stage_patterns(path: str, name: str | None = None) -> dict:
        """High-level patterns detected: ifs, loops, try-regions, short-circuits."""
        fmt, cos = _iter_target_cos(path, name)
        out = []
        for co in cos:
            art = stage_artifacts(path, co)
            out.append({
                "code_object": co.co_name,
                "patterns": _patterns_summary(art["patterns"] or {}),
            })
        return {"format": fmt, "code_objects": out}

    @mcp.tool()
    def stage_recovered_ast(path: str, name: str | None = None) -> dict:
        """Structures built by build_recovered_ast (try, loop, if, try-region)."""
        fmt, cos = _iter_target_cos(path, name)
        out = []
        for co in cos:
            art = stage_artifacts(path, co)
            out.append({
                "code_object": co.co_name,
                "structures": _recovered_ast_summary(art["recovered_ast"] or {}),
            })
        return {"format": fmt, "code_objects": out}

    @mcp.tool()
    def stage_gen_code(path: str) -> dict:
        """Final generated Python source (equivalent to decompile_to_source)."""
        out = run_full(path)
        return {"format": out["format"], **truncate_text(out["recovered"])}
