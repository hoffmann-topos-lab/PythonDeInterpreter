import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..formats import detect_format, require_path


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_pyc_header(path: str) -> dict:
    with open(path, "rb") as f:
        head = f.read(16)
    if len(head) < 16:
        raise ValueError("arquivo .pyc truncado")
    magic = int.from_bytes(head[:4], "little")
    flags = int.from_bytes(head[4:8], "little")
    field2 = int.from_bytes(head[8:12], "little")
    field3 = int.from_bytes(head[12:16], "little")
    result = {
        "magic_hex": f"0x{magic:08x}",
        "flags": flags,
        "hash_based": bool(flags & 1),
    }
    if flags & 1:
        result["source_hash"] = head[8:16].hex()
    else:
        result["mtime_unix"] = field2
        try:
            result["mtime_iso"] = datetime.fromtimestamp(field2, timezone.utc).isoformat()
        except (OSError, ValueError, OverflowError):
            pass
        result["source_size"] = field3
    return result


def _read_mpy_header(path: str) -> dict:
    from MicroPython.mpy_loader import ARCH_NAMES
    with open(path, "rb") as f:
        head = f.read(4)
    if len(head) < 4 or head[0] != 0x4D:
        raise ValueError("arquivo .mpy inválido")
    version = head[1]
    flags = head[2]
    smallint = head[3]
    arch_code = (flags >> 2) & 0x0F
    sub_version = flags & 0x03
    has_arch_flags = bool((flags >> 6) & 0x01)
    return {
        "version_major": version,
        "sub_version": sub_version,
        "version_label": f"v{version}.{sub_version}",
        "arch_code": arch_code,
        "arch_name": ARCH_NAMES.get(arch_code, f"unknown_{arch_code}"),
        "smallint_bits": smallint,
        "has_arch_flags": has_arch_flags,
    }


def register(mcp):
    @mcp.tool()
    def detect_file_format(path: str) -> dict:
        """Detect format of a bytecode file. Returns {'path', 'format'} where format is 'pyc', 'mpy', or 'unknown'."""
        return {"path": path, "format": detect_format(path)}

    @mcp.tool()
    def get_file_info(path: str) -> dict:
        """Get metadata for a binary file: size, mtime, SHA-256, detected format."""
        p = require_path(path)
        st = p.stat()
        return {
            "path": str(p.resolve()),
            "size": st.st_size,
            "mtime_unix": st.st_mtime,
            "mtime_iso": datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat(),
            "sha256": _sha256(str(p)),
            "format": detect_format(str(p)),
        }

    @mcp.tool()
    def get_pyc_header(path: str) -> dict:
        """Read the 16-byte header of a .pyc file: magic, flags, source mtime/size."""
        require_path(path)
        if detect_format(path) != "pyc":
            raise ValueError(f"arquivo não é .pyc: {path}")
        return _read_pyc_header(path)

    @mcp.tool()
    def get_mpy_header(path: str) -> dict:
        """Read the .mpy header: version, architecture, smallint bits."""
        require_path(path)
        if detect_format(path) != "mpy":
            raise ValueError(f"arquivo não é .mpy: {path}")
        return _read_mpy_header(path)

    @mcp.tool()
    def validate_file(path: str) -> dict:
        """Attempt to fully load the file. Returns {'ok', 'format', 'error'}."""
        p = Path(path)
        if not p.exists():
            return {"ok": False, "error": "não existe"}
        fmt = detect_format(path)
        try:
            if fmt == "pyc":
                from Decompiler.loader import load_code_object
                load_code_object(path)
                return {"ok": True, "format": "pyc", "error": None}
            if fmt == "mpy":
                from MicroPython.mpy_loader import load_mpy
                load_mpy(path)
                return {"ok": True, "format": "mpy", "error": None}
            return {"ok": False, "format": fmt, "error": "formato desconhecido"}
        except Exception as e:
            return {"ok": False, "format": fmt, "error": f"{type(e).__name__}: {e}"}
