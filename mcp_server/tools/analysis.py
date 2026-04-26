"""Analysis tools: constants, strings, imports, exception handlers, stats."""

import os
import re

from ..runner import run_full
from ..pagination import paginate_list

_OPCODE_RE = re.compile(r"^[A-Z][A-Z_0-9]+$")


def _count_instructions(bc: str) -> int:
    count = 0
    for line in bc.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("Disassembly", "ExceptionTable", "(")):
            continue
        for p in stripped.split():
            if _OPCODE_RE.match(p) and len(p) > 2:
                count += 1
                break
    return count


def register(mcp):
    @mcp.tool()
    def list_constants(
        path: str,
        categories: list[str] | None = None,
        offset: int = 0,
        limit: int = 500,
    ) -> dict:
        """List constants in the bytecode, categorized by type (str, num, bytes, tuple, frozenset, None, bool, etc)."""
        from UI.ui_parsers import parse_all_constants
        out = run_full(path)
        cats = parse_all_constants(out["bytecode"])
        if categories:
            cats = {c: cats[c] for c in categories if c in cats}
        flat = []
        for cat, items in cats.items():
            for v in items:
                flat.append({"category": cat, "value": v})
        result = paginate_list(flat, offset=offset, limit=limit)
        result["by_category_counts"] = {c: len(v) for c, v in cats.items()}
        return result

    @mcp.tool()
    def list_strings(path: str, min_len: int = 1, offset: int = 0, limit: int = 500) -> dict:
        """List string constants only (optionally filtered by minimum length)."""
        from UI.ui_parsers import parse_all_constants
        out = run_full(path)
        cats = parse_all_constants(out["bytecode"])
        strings = [s for s in cats.get("str", []) if len(s) - 2 >= min_len]  # -2 to discount quotes
        return paginate_list(strings, offset=offset, limit=limit)

    @mcp.tool()
    def list_imports(path: str) -> dict:
        """List `import ...` / `from ... import ...` statements found in the recovered source."""
        out = run_full(path)
        imports = []
        for line in out["recovered"].splitlines():
            s = line.strip()
            if s.startswith("import ") or s.startswith("from "):
                imports.append(s)
        return {
            "count": len(imports),
            "imports": imports,
        }

    @mcp.tool()
    def list_exception_handlers(path: str) -> dict:
        """List exception table entries / SETUP_* from the disassembly."""
        from UI.ui_parsers import parse_exception_handlers
        out = run_full(path)
        handlers = parse_exception_handlers(out["bytecode"])
        return {"count": len(handlers), "handlers": handlers}

    @mcp.tool()
    def list_functions(path: str) -> dict:
        """List all top-level functions in the recovered source (name + line)."""
        import re as _re
        out = run_full(path)
        result = []
        for i, line in enumerate(out["recovered"].splitlines(), start=1):
            m = _re.match(r"^(\s*)def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", line)
            if m:
                indent = len(m.group(1))
                result.append({
                    "name": m.group(2),
                    "line": i,
                    "indent": indent,
                    "signature": m.group(0).strip(),
                })
        return {"count": len(result), "functions": result}

    @mcp.tool()
    def count_instructions(path: str) -> dict:
        """Approximate total number of opcodes in the disassembly."""
        out = run_full(path)
        return {"format": out["format"], "count": _count_instructions(out["bytecode"])}

    @mcp.tool()
    def count_functions(path: str) -> dict:
        """Count `def` statements in the recovered source."""
        out = run_full(path)
        n = sum(1 for line in out["recovered"].splitlines()
                if re.match(r"^\s*def\s+[A-Za-z_]\w*\s*\(", line))
        return {"count": n}

    @mcp.tool()
    def get_file_stats(path: str) -> dict:
        """Aggregate stats (analog to the GUI's StatsDialog): format, sizes, code object counts, imports, instructions."""
        from UI.ui_parsers import parse_all_constants, parse_mpy_summary
        out = run_full(path)
        meta = out["meta"] or {}
        mpy_info = meta.get("__mpy__")
        n_code_objects = sum(1 for k in meta if not k.startswith("__"))
        n_instr = _count_instructions(out["bytecode"])
        n_lines = len(out["recovered"].splitlines()) if out["recovered"].strip() else 0
        imports = [
            line.strip()
            for line in out["recovered"].splitlines()
            if line.strip().startswith(("import ", "from "))
        ]
        cats = parse_all_constants(out["bytecode"])
        size = os.path.getsize(path) if os.path.exists(path) else 0

        return {
            "format": out["format"],
            "file_size": size,
            "runtime": (
                f"MicroPython {mpy_info.get('version', '?')} ({mpy_info.get('arch', '?')})"
                if mpy_info else "CPython 3.12"
            ),
            "n_code_objects": n_code_objects,
            "n_instructions_approx": n_instr,
            "n_recovered_lines": n_lines,
            "n_imports": len(imports),
            "imports": imports[:50],
            "constants_by_category": {c: len(v) for c, v in cats.items()},
            "mpy_summary": (
                parse_mpy_summary(out["bytecode"], meta) if mpy_info else None
            ),
        }

    @mcp.tool()
    def get_mpy_summary(path: str) -> dict:
        """MicroPython-only summary string (version, arch, function counts)."""
        from UI.ui_parsers import parse_mpy_summary
        out = run_full(path)
        if not (out["meta"] or {}).get("__mpy__"):
            return {"error": "arquivo não é .mpy"}
        return {"summary": parse_mpy_summary(out["bytecode"], out["meta"])}
