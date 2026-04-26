from ..runner import run_full
from ..pagination import slice_text, truncate_text


def register(mcp):
    @mcp.tool()
    def decompile_file(path: str, max_chars: int = 200_000) -> dict:
        """Run the full decompiler pipeline on a .pyc or .mpy file.

        Returns {'format', 'bytecode' (truncated), 'recovered' (truncated), 'meta'}.
        Use get_bytecode_disassembly / decompile_to_source with offset for the full text.
        """
        out = run_full(path)
        return {
            "format": out["format"],
            "bytecode": truncate_text(out["bytecode"], max_chars),
            "recovered": truncate_text(out["recovered"], max_chars),
            "meta": out["meta"],
        }

    @mcp.tool()
    def decompile_to_source(
        path: str,
        apply_annotations: bool = False,
        offset: int = 0,
        limit: int = 200_000,
    ) -> dict:
        """Return only the recovered Python source. Supports paginated reads via offset/limit.

        If apply_annotations=True, any saved renames (<file>.annotations.json) are applied.
        """
        out = run_full(path)
        text = out["recovered"]
        if apply_annotations:
            from UI.annotations import load_annotations, apply_renames
            ann = load_annotations(path)
            text = apply_renames(text, ann.get("renames") or {})
        return slice_text(text, offset=offset, limit=limit)

    @mcp.tool()
    def get_bytecode_disassembly(path: str, offset: int = 0, limit: int = 200_000) -> dict:
        """Return only the bytecode disassembly text of a .pyc or .mpy. Paginated."""
        out = run_full(path)
        return slice_text(out["bytecode"], offset=offset, limit=limit)

    @mcp.tool()
    def get_engine_meta(path: str) -> dict:
        """Return the meta dict produced by the engine: per-code-object address/line map plus hierarchy."""
        out = run_full(path)
        return {"format": out["format"], "meta": out["meta"]}
