"""CRUD for annotations (renames, inline comments) stored alongside each binary."""

import os

from ..formats import require_path
from ..pagination import truncate_text


def _load(path: str) -> dict:
    from UI.annotations import load_annotations
    return load_annotations(path)


def _save(path: str, data: dict) -> None:
    from UI.annotations import save_annotations
    save_annotations(path, data)


def _ensure_panel(panel: str) -> str:
    if panel not in ("bc", "rc"):
        raise ValueError("panel deve ser 'bc' (bytecode) ou 'rc' (recovered)")
    return "comments_bc" if panel == "bc" else "comments_rc"


def register(mcp):
    @mcp.tool()
    def annotation_load(path: str) -> dict:
        """Load all annotations for a binary: {renames, renames_local, comments_bc, comments_rc}."""
        require_path(path)
        return _load(path)

    @mcp.tool()
    def annotation_list_renames(
        path: str, scope: str = "all", func: str | None = None,
    ) -> dict:
        """List renames. scope: 'global', 'local', or 'all'. 'func' filters local to a function name."""
        require_path(path)
        ann = _load(path)
        out = {}
        if scope in ("global", "all"):
            out["global"] = ann.get("renames", {})
        if scope in ("local", "all"):
            local = ann.get("renames_local", {})
            if func is not None:
                out["local"] = {func: local.get(func, {})}
            else:
                out["local"] = local
        return out

    @mcp.tool()
    def annotation_add_rename(
        path: str, old: str, new: str, scope: str = "global", func: str | None = None,
    ) -> dict:
        """Add or update a rename. scope='global' or 'local' (in which case 'func' is required)."""
        require_path(path)
        if scope == "local" and not func:
            raise ValueError("scope='local' exige 'func'")
        ann = _load(path)
        if scope == "global":
            ann.setdefault("renames", {})[old] = new
        else:
            locals_ = ann.setdefault("renames_local", {})
            locals_.setdefault(func, {})[old] = new
        _save(path, ann)
        return {"ok": True, "scope": scope, "func": func, "old": old, "new": new}

    @mcp.tool()
    def annotation_remove_rename(
        path: str, old: str, scope: str = "global", func: str | None = None,
    ) -> dict:
        """Remove a rename. scope='global' or 'local' (in which case 'func' is required)."""
        require_path(path)
        if scope == "local" and not func:
            raise ValueError("scope='local' exige 'func'")
        ann = _load(path)
        removed = False
        if scope == "global":
            g = ann.get("renames", {})
            if old in g:
                g.pop(old)
                removed = True
        else:
            locals_ = ann.get("renames_local", {})
            fmap = locals_.get(func, {})
            if old in fmap:
                fmap.pop(old)
                removed = True
                if not fmap:
                    locals_.pop(func, None)
        _save(path, ann)
        return {"ok": removed, "scope": scope, "func": func, "old": old}

    @mcp.tool()
    def annotation_list_comments(path: str, panel: str = "all") -> dict:
        """List comments. panel: 'bc' (bytecode), 'rc' (recovered) or 'all'."""
        require_path(path)
        ann = _load(path)
        out = {}
        if panel in ("bc", "all"):
            out["bytecode"] = ann.get("comments_bc", {})
        if panel in ("rc", "all"):
            out["recovered"] = ann.get("comments_rc", {})
        return out

    @mcp.tool()
    def annotation_add_comment(path: str, panel: str, line: int, text: str) -> dict:
        """Add an inline comment to a panel/line. panel='bc' or 'rc'; line is 1-based."""
        require_path(path)
        key = _ensure_panel(panel)
        ann = _load(path)
        ann.setdefault(key, {})[str(line)] = text
        _save(path, ann)
        return {"ok": True, "panel": panel, "line": line, "text": text}

    @mcp.tool()
    def annotation_remove_comment(path: str, panel: str, line: int) -> dict:
        """Remove a comment at panel/line."""
        require_path(path)
        key = _ensure_panel(panel)
        ann = _load(path)
        bucket = ann.get(key, {})
        removed = bucket.pop(str(line), None) is not None
        _save(path, ann)
        return {"ok": removed, "panel": panel, "line": line}

    @mcp.tool()
    def annotation_apply_to_source(path: str) -> dict:
        """Return the recovered source with global + local renames applied."""
        from ..runner import run_full
        from UI.annotations import apply_renames
        out = run_full(path)
        ann = _load(path)
        text = apply_renames(out["recovered"], ann.get("renames") or {})
        return {"name": os.path.basename(path), **truncate_text(text)}

    @mcp.tool()
    def annotation_clear(path: str) -> dict:
        """Delete all annotations (removes the <file>.annotations.json)."""
        require_path(path)
        _save(path, {"renames": {}, "renames_local": {}, "comments_bc": {}, "comments_rc": {}})
        return {"ok": True}
