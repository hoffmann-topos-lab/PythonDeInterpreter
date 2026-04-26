"""Utilities to discover and read sample files shipped in tests/."""

import os

from ..config import SAMPLES_DIR, PROJECT_ROOT
from ..formats import detect_format
from ..pagination import truncate_text


def _safe_name(name: str) -> str:
    if "/" in name or "\\" in name or name.startswith(".."):
        raise ValueError(f"nome de arquivo inválido: {name}")
    return name


def register(mcp):
    @mcp.tool()
    def list_sample_files() -> dict:
        """List sample binaries and source files under tests/."""
        if not SAMPLES_DIR.exists():
            return {"samples_dir": str(SAMPLES_DIR), "files": []}
        files = []
        for f in sorted(os.listdir(SAMPLES_DIR)):
            fp = SAMPLES_DIR / f
            if not fp.is_file():
                continue
            files.append({
                "name": f,
                "path": str(fp),
                "size": fp.stat().st_size,
                "ext": fp.suffix,
                "format": detect_format(str(fp)) if fp.suffix in (".pyc", ".mpy") else None,
            })
        return {"samples_dir": str(SAMPLES_DIR), "count": len(files), "files": files}

    @mcp.tool()
    def read_sample_source(name: str) -> dict:
        """Read a source file from tests/ (by bare filename, no slashes)."""
        n = _safe_name(name)
        fp = SAMPLES_DIR / n
        if not fp.exists() or not fp.is_file():
            raise FileNotFoundError(f"File not found in tests/: {n}")
        text = fp.read_text(encoding="utf-8", errors="replace")
        return {"name": n, "path": str(fp), **truncate_text(text)}

    @mcp.tool()
    def get_project_info() -> dict:
        """High-level project info: root path, supported formats, supported architectures."""
        from MicroPython.mpy_loader import ARCH_NAMES
        return {
            "project_root": str(PROJECT_ROOT),
            "samples_dir": str(SAMPLES_DIR),
            "supported_formats": [".pyc (CPython 3.12)", ".mpy (MicroPython v6.x)"],
            "supported_mpy_archs": list(ARCH_NAMES.values()),
            "engines": [
                "Decompiler/engine.py (CPython)",
                "MicroPython/mpy_engine.py (MicroPython)",
            ],
        }
