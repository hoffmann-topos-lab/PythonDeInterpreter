"""Compare two binaries by diffing their recovered source / disassembly."""

import difflib

from ..runner import run_full
from ..pagination import truncate_text


def _unified(a: str, b: str, label_a: str, label_b: str, context: int) -> str:
    return "".join(difflib.unified_diff(
        a.splitlines(keepends=True),
        b.splitlines(keepends=True),
        fromfile=label_a,
        tofile=label_b,
        n=context,
    ))


def register(mcp):
    @mcp.tool()
    def diff_recovered(path_a: str, path_b: str, context: int = 3) -> dict:
        """Unified diff of the recovered Python source from two binaries."""
        a = run_full(path_a)
        b = run_full(path_b)
        text = _unified(a["recovered"], b["recovered"], path_a, path_b, context)
        return {"format_a": a["format"], "format_b": b["format"], **truncate_text(text)}

    @mcp.tool()
    def diff_bytecode(path_a: str, path_b: str, context: int = 3) -> dict:
        """Unified diff of the disassembly text from two binaries."""
        a = run_full(path_a)
        b = run_full(path_b)
        text = _unified(a["bytecode"], b["bytecode"], path_a, path_b, context)
        return {"format_a": a["format"], "format_b": b["format"], **truncate_text(text)}

    @mcp.tool()
    def diff_summary(path_a: str, path_b: str) -> dict:
        """High-level diff stats and function set delta for two binaries."""
        import re
        a = run_full(path_a)
        b = run_full(path_b)
        sm = difflib.SequenceMatcher(
            a=a["recovered"].splitlines(), b=b["recovered"].splitlines()
        )
        lines_a = a["recovered"].splitlines()
        lines_b = b["recovered"].splitlines()
        equal = sum(block.size for block in sm.get_matching_blocks())

        def_re = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(")
        funcs_a = {m.group(1) for line in lines_a if (m := def_re.match(line))}
        funcs_b = {m.group(1) for line in lines_b if (m := def_re.match(line))}
        return {
            "lines_a": len(lines_a),
            "lines_b": len(lines_b),
            "lines_equal": equal,
            "similarity_ratio": sm.ratio(),
            "functions_only_in_a": sorted(funcs_a - funcs_b),
            "functions_only_in_b": sorted(funcs_b - funcs_a),
            "functions_common": sorted(funcs_a & funcs_b),
        }
