from pathlib import Path


def detect_format(path: str) -> str:
    p = Path(path)
    if not p.exists() or not p.is_file():
        return "unknown"

    ext = p.suffix.lower()
    try:
        with open(p, "rb") as f:
            head = f.read(4)
    except OSError:
        return "unknown"

    if ext == ".mpy" and len(head) >= 2 and head[0] == 0x4D and head[1] == 6:
        return "mpy"
    if ext == ".pyc":
        return "pyc"
    if len(head) >= 2 and head[0] == 0x4D and head[1] == 6:
        return "mpy"
    return "unknown"


def require_path(path: str) -> Path:
    p = Path(path)
    if not p.is_absolute():
        raise ValueError(f"path must be absolute: {path}")
    if not p.exists():
        raise FileNotFoundError(f"file not found: {path}")
    if not p.is_file():
        raise ValueError(f"not a file: {path}")
    return p
