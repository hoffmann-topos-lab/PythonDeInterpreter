"""Text search and cross-reference tools over the disassembly / recovered source."""

import re

from ..runner import run_full
from ..pagination import paginate_list


def _search_lines(text: str, query: str, regex: bool, case: bool,
                  panel: str, limit: int) -> list[dict]:
    flags = 0 if case else re.IGNORECASE
    if regex:
        pattern = re.compile(query, flags)
    else:
        pattern = re.compile(re.escape(query), flags)
    hits: list[dict] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            hits.append({"panel": panel, "line": i, "text": line})
            if len(hits) >= limit:
                break
    return hits


def register(mcp):
    @mcp.tool()
    def search_bytecode(
        path: str, query: str, regex: bool = False, case: bool = False,
        limit: int = 200,
    ) -> dict:
        """Search the bytecode disassembly. Returns list of {panel, line, text}."""
        out = run_full(path)
        hits = _search_lines(out["bytecode"], query, regex, case, "bytecode", limit)
        return {"query": query, "count": len(hits), "hits": hits}

    @mcp.tool()
    def search_recovered(
        path: str, query: str, regex: bool = False, case: bool = False,
        limit: int = 200,
    ) -> dict:
        """Search the recovered Python source."""
        out = run_full(path)
        hits = _search_lines(out["recovered"], query, regex, case, "recovered", limit)
        return {"query": query, "count": len(hits), "hits": hits}

    @mcp.tool()
    def find_xrefs(path: str, symbol: str, limit: int = 200) -> dict:
        """Word-boundary search for `symbol` in both bytecode and recovered (cross-references)."""
        out = run_full(path)
        pattern = re.compile(r"\b" + re.escape(symbol) + r"\b")
        hits = []
        for i, line in enumerate(out["bytecode"].splitlines(), start=1):
            if pattern.search(line):
                hits.append({"panel": "bytecode", "line": i, "text": line})
                if len(hits) >= limit:
                    break
        for i, line in enumerate(out["recovered"].splitlines(), start=1):
            if pattern.search(line):
                hits.append({"panel": "recovered", "line": i, "text": line})
                if len(hits) >= limit:
                    break
        return {"symbol": symbol, "count": len(hits), "hits": hits}

    @mcp.tool()
    def find_calls_to(path: str, name: str, limit: int = 200) -> dict:
        """Find call-sites `name(...)` in the recovered source."""
        out = run_full(path)
        pattern = re.compile(r"\b" + re.escape(name) + r"\s*\(")
        hits = []
        for i, line in enumerate(out["recovered"].splitlines(), start=1):
            if pattern.search(line):
                hits.append({"line": i, "text": line})
                if len(hits) >= limit:
                    break
        return {"name": name, "count": len(hits), "hits": hits}

    @mcp.tool()
    def find_string_references(path: str, literal: str, limit: int = 200) -> dict:
        """Find every occurrence of a string literal (exact match) in bytecode and recovered."""
        out = run_full(path)
        hits = []
        for panel, text in (("bytecode", out["bytecode"]), ("recovered", out["recovered"])):
            for i, line in enumerate(text.splitlines(), start=1):
                if literal in line:
                    hits.append({"panel": panel, "line": i, "text": line})
                    if len(hits) >= limit:
                        break
        return {"literal": literal, "count": len(hits), "hits": hits}

    @mcp.tool()
    def find_opcode_usage(
        path: str, opcode: str, offset: int = 0, limit: int = 500,
    ) -> dict:
        """Find every disassembly line that uses a given opcode (exact token match)."""
        out = run_full(path)
        pattern = re.compile(r"\b" + re.escape(opcode) + r"\b")
        hits = []
        for i, line in enumerate(out["bytecode"].splitlines(), start=1):
            if pattern.search(line):
                hits.append({"line": i, "text": line})
        return paginate_list(hits, offset=offset, limit=limit)
