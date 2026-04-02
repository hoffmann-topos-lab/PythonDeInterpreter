"""Persistência de anotações (renomeações e comentários) por arquivo binário.

As anotações são salvas em um .annotations.json ao lado do arquivo binário.
Estrutura:
    {
        "renames":     {"old_name": "new_name", ...},
        "comments_bc": {"line_1based": "texto do comentário", ...},
        "comments_rc": {"line_1based": "texto do comentário", ...}
    }
"""

import json
import os
import re

_EMPTY = {"renames": {}, "comments_bc": {}, "comments_rc": {}}


def _annotations_path(binary_path: str) -> str:
    base = os.path.splitext(binary_path)[0]
    return base + ".annotations.json"


def load_annotations(binary_path: str) -> dict:
    """Carrega anotações do arquivo JSON ao lado do binário."""
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
    """Salva anotações no arquivo JSON. Remove o arquivo se vazio."""
    path = _annotations_path(binary_path)
    has_data = bool(data.get("renames") or data.get("comments_bc") or data.get("comments_rc"))
    if not has_data:
        if os.path.exists(path):
            os.remove(path)
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def apply_renames(text: str, renames: dict) -> str:
    """Aplica renomeações ao texto usando substituição word-boundary."""
    for old_name, new_name in renames.items():
        text = re.sub(r"\b" + re.escape(old_name) + r"\b", new_name, text)
    return text
