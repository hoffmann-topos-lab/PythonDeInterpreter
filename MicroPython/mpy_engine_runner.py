import os
import subprocess
from pathlib import Path

from UI.ui_config import (
    ENGINE_PYTHON,
    BYTECODE_MARKER,
    RECOVERED_MARKER,
    BYTECODE_META_MARKER,
)

_HERE        = Path(__file__).parent
PROJECT_ROOT = str(_HERE.parent)
MPY_ENGINE   = str(_HERE / "mpy_engine.py")


def run_mpy_engine(mpy_path: str) -> tuple[str, str, dict]:

    cmd  = [ENGINE_PYTHON, MPY_ENGINE, mpy_path]
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=PROJECT_ROOT,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            proc.stderr or proc.stdout or "Falha ao executar mpy_engine."
        )

    out  = proc.stdout or ""
    meta: dict = {}

    if BYTECODE_MARKER not in out or RECOVERED_MARKER not in out:
        return out.strip(), "", meta

    after_bc   = out.split(BYTECODE_MARKER, 1)[1]
    bc_part, rc_part = after_bc.split(RECOVERED_MARKER, 1)

    if BYTECODE_META_MARKER in bc_part:
        bc_txt, meta_txt = bc_part.split(BYTECODE_META_MARKER, 1)
        bc_txt   = bc_txt.strip()
        meta_txt = meta_txt.strip()

        for line in meta_txt.splitlines():
            if "|" not in line:
                continue
            if line.startswith("__hierarchy__|"):
                try:
                    import json
                    meta["__hierarchy__"] = json.loads(line[14:])
                except Exception:
                    pass
                continue
            parts = line.split("|", 2)
            if len(parts) != 3:
                continue
            name, addr, line_no = parts

            if name.strip() == "__mpy__":
                meta["__mpy__"] = {
                    "version": addr.strip(),  
                    "arch":    line_no.strip(),
                }
                continue

            try:
                meta[name.strip()] = {
                    "addr": addr.strip(),
                    "line": int(line_no.strip()),
                }
            except (ValueError, TypeError):
                pass
    else:
        bc_txt = bc_part.strip()

    return bc_txt, rc_part.strip(), meta
