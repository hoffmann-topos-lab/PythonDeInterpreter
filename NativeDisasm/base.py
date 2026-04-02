"""
Helpers comuns e hex dump fallback para disassembly de código nativo.
"""

import struct


# ---------------------------------------------------------------------------
# Helpers de leitura (little-endian)
# ---------------------------------------------------------------------------

def read_u8(data: bytes, offset: int) -> int:
    return data[offset]


def read_i8(data: bytes, offset: int) -> int:
    return struct.unpack_from("<b", data, offset)[0]


def read_u16_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def read_i16_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<h", data, offset)[0]


def read_u32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_i32_le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def sign_extend(value: int, bits: int) -> int:
    """Estende sinal de um valor de *bits* bits para inteiro Python."""
    sign_bit = 1 << (bits - 1)
    return (value ^ sign_bit) - sign_bit


# ---------------------------------------------------------------------------
# Hex dump fallback
# ---------------------------------------------------------------------------

_BYTES_PER_LINE = 16   # bytes por linha no hex dump


def hex_dump_fallback(code: bytes, start_offset: int = 0) -> list:
    """
    Gera um hex dump legível como fallback quando não há disassembler.

    Retorna lista de tuplas (offset, hex_bytes_str, text_repr).
    """
    result = []
    for i in range(0, len(code), _BYTES_PER_LINE):
        chunk = code[i:i + _BYTES_PER_LINE]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        result.append((start_offset + i, hex_str, ascii_str))
    return result


def format_hex_dump(code: bytes, start_offset: int = 0) -> str:
    """Formata hex dump como string multilinha."""
    lines = []
    for offset, hex_str, ascii_str in hex_dump_fallback(code, start_offset):
        lines.append(f"0x{offset:04x}:  {hex_str:<{_BYTES_PER_LINE * 3 - 1}s}  |{ascii_str}|")
    return "\n".join(lines)
