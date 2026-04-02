import os
import subprocess
from UI.ui_config import (
    ENGINE_PYTHON,
    BYTECODE_MARKER,
    RECOVERED_MARKER,
    BYTECODE_META_MARKER,
)

BASE_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(BASE_DIR)
ENGINE_SCRIPT = os.path.join(BASE_DIR, "engine.py")


def run_engine(pyc_path: str) -> tuple[str, str, dict]:
    cmd = [ENGINE_PYTHON, ENGINE_SCRIPT, pyc_path, "--stage", "gen_code"]

    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=PROJECT_ROOT)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout or "Falha ao executar a engine.")

    out = proc.stdout or ""
    meta = {}

    if BYTECODE_MARKER in out and RECOVERED_MARKER in out:
        mid = out.split(BYTECODE_MARKER, 1)[1]
        bc_part, rc_part = mid.split(RECOVERED_MARKER, 1)

        if BYTECODE_META_MARKER in bc_part:
            bc_txt, meta_txt = bc_part.split(BYTECODE_META_MARKER, 1)
            bc_txt = bc_txt.strip()
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
                name, addr, line_no = line.split("|", 2)
                try:
                    meta[name.strip()] = {
                        "addr": addr.strip(),
                        "line": int(line_no.strip()),
                    }
                except Exception:
                    pass
        else:
            bc_txt = bc_part.strip()

        return bc_txt, rc_part.strip(), meta

    return out.strip(), "", meta
