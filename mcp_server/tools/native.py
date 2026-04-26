"""Native code disassembly (@micropython.native / @micropython.viper)."""

import base64

from ..runner import collect_mpy_code_objects, find_mpy_code_object, load_mpy_root
from ..formats import detect_format, require_path
from ..pagination import truncate_text


def _require_mpy(path: str) -> None:
    require_path(path)
    if detect_format(path) != "mpy":
        raise ValueError(f"tool disponível apenas para .mpy: {path}")


def _kind_name(kind: int) -> str:
    return {0: "bytecode", 1: "native", 2: "viper", 3: "asm"}.get(kind, f"kind_{kind}")


def register(mcp):
    @mcp.tool()
    def list_native_functions(path: str) -> dict:
        """List code objects that are native/viper/asm (machine code), with arch info."""
        _require_mpy(path)
        from MicroPython.mpy_loader import KIND_BYTECODE, ARCH_NAMES
        cos = collect_mpy_code_objects(path)
        out = []
        for co in cos:
            if getattr(co, "kind", KIND_BYTECODE) == KIND_BYTECODE:
                continue
            out.append({
                "name": co.co_name,
                "kind": _kind_name(co.kind),
                "arch_code": co.arch_code,
                "arch_name": ARCH_NAMES.get(co.arch_code, f"unknown_{co.arch_code}"),
                "n_bytes": len(co._native_code) if getattr(co, "_native_code", None) else 0,
                "prelude_offset": co._prelude_offset,
                "argcount": co.co_argcount,
                "varnames": list(co.co_varnames),
            })
        return {"count": len(out), "functions": out}

    @mcp.tool()
    def detect_architecture(path: str) -> dict:
        """Report the architecture encoded in the .mpy header."""
        _require_mpy(path)
        from MicroPython.mpy_loader import ARCH_NAMES
        data = load_mpy_root(path)
        header = data["header"]
        arch_code = header["arch_code"]
        return {
            "arch_code": arch_code,
            "arch_name": ARCH_NAMES.get(arch_code, f"unknown_{arch_code}"),
            "sub_version": header.get("sub_version"),
            "smallint_bits": header.get("smallint_bits"),
            "has_arch_flags": header.get("has_arch_flags"),
        }

    @mcp.tool()
    def disassemble_native_function(path: str, name: str) -> dict:
        """Disassemble the machine code of a native/viper function (x86/x64/ARM/Xtensa/RISC-V)."""
        _require_mpy(path)
        from MicroPython.mpy_loader import KIND_BYTECODE
        from NativeDisasm import disassemble_native
        co = find_mpy_code_object(path, name)
        if getattr(co, "kind", KIND_BYTECODE) == KIND_BYTECODE:
            raise ValueError(f"função '{name}' não é nativa (é bytecode)")
        code = getattr(co, "_native_code", b"")
        if not code:
            raise ValueError(f"função '{name}' não tem bytes nativos")
        text = disassemble_native(code, co.arch_code, co._prelude_offset)
        return {
            "name": name,
            "arch_code": co.arch_code,
            "kind": _kind_name(co.kind),
            "n_bytes": len(code),
            **truncate_text(text),
        }

    @mcp.tool()
    def dump_native_bytes(path: str, name: str, format: str = "hex") -> dict:
        """Return raw machine-code bytes of a native function. format: 'hex' or 'base64'."""
        _require_mpy(path)
        from MicroPython.mpy_loader import KIND_BYTECODE
        co = find_mpy_code_object(path, name)
        if getattr(co, "kind", KIND_BYTECODE) == KIND_BYTECODE:
            raise ValueError(f"função '{name}' não é nativa")
        code = bytes(getattr(co, "_native_code", b""))
        if format == "base64":
            payload = base64.b64encode(code).decode("ascii")
        else:
            payload = code.hex()
        return {
            "name": name,
            "format": format,
            "n_bytes": len(code),
            "prelude_offset": co._prelude_offset,
            "data": payload,
        }

    @mcp.tool()
    def strip_native_prelude(path: str, name: str, format: str = "hex") -> dict:
        """Return only the machine-code body (padding + prelude removed). format: 'hex' or 'base64'."""
        _require_mpy(path)
        from MicroPython.mpy_loader import KIND_BYTECODE
        from NativeDisasm import _get_padding
        co = find_mpy_code_object(path, name)
        if getattr(co, "kind", KIND_BYTECODE) == KIND_BYTECODE:
            raise ValueError(f"função '{name}' não é nativa")
        code = bytes(getattr(co, "_native_code", b""))
        start = _get_padding(co.arch_code)
        end = co._prelude_offset if co._prelude_offset > 0 else len(code)
        body = code[start:end]
        payload = base64.b64encode(body).decode("ascii") if format == "base64" else body.hex()
        return {
            "name": name,
            "arch_code": co.arch_code,
            "start_offset": start,
            "end_offset": end,
            "n_body_bytes": len(body),
            "data": payload,
        }
