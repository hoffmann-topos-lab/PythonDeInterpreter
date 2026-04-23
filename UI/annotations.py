import json
import os
import re

_EMPTY = {"renames": {}, "renames_local": {}, "comments_bc": {}, "comments_rc": {}}


def _annotations_path(binary_path: str) -> str:
    base = os.path.splitext(binary_path)[0]
    return base + ".annotations.json"

def load_annotations(binary_path: str) -> dict:
    path = _annotations_path(binary_path)
    if not os.path.exists(path):
        return dict(_EMPTY)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key in _EMPTY:
            data.setdefault(key, {})
        return data
    except (json.JSONDecodeError, OSError):
        return dict(_EMPTY)


def save_annotations(binary_path: str, data: dict):
    path = _annotations_path(binary_path)
    has_data = bool(
        data.get("renames") or data.get("renames_local")
        or data.get("comments_bc") or data.get("comments_rc")
    )
    if not has_data:
        if os.path.exists(path):
            os.remove(path)
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def apply_renames(text: str, renames: dict) -> str:
    for old_name, new_name in renames.items():
        text = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, text)
    return text


def apply_scoped_renames(text: str, global_renames: dict,
                         local_renames: dict,
                         line_to_func: dict | None = None,
                         func_name: str | None = None) -> str:
    if not global_renames and not local_renames:
        return text

    if func_name:
        merged = {**global_renames, **local_renames.get(func_name, {})}
        return apply_renames(text, merged) if merged else text

    lines = text.splitlines()
    result: list[str] = []
    for i, line in enumerate(lines):
        func = line_to_func.get(i) if line_to_func else None
        if func and func in local_renames:
            merged = {**global_renames, **local_renames[func]}
            result.append(apply_renames(line, merged))
        elif global_renames:
            result.append(apply_renames(line, global_renames))
        else:
            result.append(line)
    return "\n".join(result)
