import re

_RE_DIS_HDR = re.compile(r"^Disassembly of <code object (\w+) at (0x[0-9a-fA-F]+),", re.M)
_RE_DEF = re.compile(r"^def\s+([A-Za-z_]\w*)\s*\(", re.M)
_RE_STR_CONST = re.compile(r"\(\s*('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")\s*\)")
_RE_NATIVE_KIND = re.compile(r"\(código (native|viper) —")


_RE_CONST_CPY = re.compile(r"LOAD_CONST\s+\d+\s+\((.+)\)\s*$", re.M)
_RE_CONST_MPY_INT = re.compile(r"LOAD_CONST_SMALL_INT\s+(.+)")
_RE_CONST_MPY_STR = re.compile(r"LOAD_CONST_STRING\s+(.+)")
_RE_CONST_MPY_OBJ = re.compile(r"LOAD_CONST_OBJ\s+(.+)")
_RE_CONST_MPY_SPECIAL = re.compile(r"LOAD_CONST_(NONE|TRUE|FALSE)")
_RE_EXC_ENTRY = re.compile(r"^\s+(\d+)\s+to\s+(\d+)\s+->\s+(\d+)\s+\[(\d+)\]", re.M)
_RE_SETUP_MPY = re.compile(
    r"^\s+(SETUP_EXCEPT|SETUP_FINALLY|SETUP_WITH)\s+(.+)",
    re.M,
)


_MPY_ARCH_LABELS: dict[str, str] = {
    "bytecode":  "bytecode puro",
    "x86":       "x86",
    "x64":       "x64",
    "armv6":     "armv6",
    "armv6m":    "armv6m (RP2040)",
    "armv7m":    "armv7m (RP2350/STM32)",
    "armv7em":   "armv7em (STM32/nRF52)",
    "armv7emsp": "armv7emsp",
    "armv7emdp": "armv7emdp",
    "xtensa":    "xtensa (ESP8266)",
    "xtensawin": "xtensawin (ESP32)",
    "rv32imc":   "rv32imc (ESP32-C3/C6)",
    "rv64imc":   "rv64imc",
}

def parse_bytecode(byte_txt: str):
    lines = byte_txt.splitlines()

    functions_by_name = {}
    addrs = []

    for i, line in enumerate(lines, start=1):
        m = _RE_DIS_HDR.match(line)
        if m:
            name, addr = m.group(1), m.group(2)
            functions_by_name[name] = {"addr": addr, "line": i}
            addrs.append((addr, name))

    seen = set()
    strings = []
    for line in lines:
        for m in _RE_STR_CONST.finditer(line):
            lit = m.group(1)
            if lit not in seen:
                seen.add(lit)
                strings.append(lit)

    return functions_by_name, addrs, strings

def split_recovered_functions(rec_txt: str):
    funcs = {}
    matches = list(_RE_DEF.finditer(rec_txt))
    if not matches:
        return funcs

    for idx, m in enumerate(matches):
        name = m.group(1)
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(rec_txt)
        funcs[name] = rec_txt[start:end].rstrip()

    return funcs


def _classify_const(val: str) -> str:
    if val == "None":
        return "None"
    if val in ("True", "False"):
        return "bool"
    if val.startswith(("'", '"')):
        return "str"
    if val.startswith(("b'", 'b"')):
        return "bytes"
    if val.startswith("(") and val.endswith(")"):
        return "tuple"
    if val.startswith("frozenset("):
        return "frozenset"
    try:
        float(val.replace("_", ""))
        return "num"
    except ValueError:
        return "outro"


def parse_all_constants(byte_txt: str) -> dict[str, list[str]]:

    seen: set[str] = set()
    cats: dict[str, list[str]] = {}

    def _add(cat: str, val: str):
        if val not in seen:
            seen.add(val)
            cats.setdefault(cat, []).append(val)

    for m in _RE_CONST_CPY.finditer(byte_txt):
        val = m.group(1).strip()
        _add(_classify_const(val), val)

    for m in _RE_CONST_MPY_INT.finditer(byte_txt):
        _add("num", m.group(1).strip())
    for m in _RE_CONST_MPY_STR.finditer(byte_txt):
        _add("str", m.group(1).strip())
    for m in _RE_CONST_MPY_OBJ.finditer(byte_txt):
        val = m.group(1).strip()
        _add(_classify_const(val), val)
    for m in _RE_CONST_MPY_SPECIAL.finditer(byte_txt):
        word = m.group(1)
        if word == "NONE":
            _add("None", "None")
        elif word == "TRUE":
            _add("bool", "True")
        else:
            _add("bool", "False")

    return cats


def parse_exception_handlers(byte_txt: str) -> list[dict]:

    handlers: list[dict] = []
    lines = byte_txt.splitlines()
    current_func = "<module>"

    for i, line in enumerate(lines):
        m = _RE_DIS_HDR.match(line)
        if m:
            current_func = m.group(1)

        stripped = line.strip()

        m = _RE_EXC_ENTRY.match(line)
        if m:
            handlers.append({
                "type": "except",
                "func": current_func,
                "detail": f"try {m.group(1)}\u2192{m.group(2)} \u2192 handler {m.group(3)} [depth {m.group(4)}]",
                "line": i + 1,
            })
            continue

        m_mpy = _RE_SETUP_MPY.match(line)
        if m_mpy:
            kind = m_mpy.group(1).replace("SETUP_", "").lower()
            handlers.append({
                "type": kind,
                "func": current_func,
                "detail": stripped,
                "line": i + 1,
            })

    return handlers


def parse_mpy_summary(byte_txt: str, meta: dict) -> str:

    mpy_info = meta.get("__mpy__", {})
    version  = mpy_info.get("version", "?")
    arch_raw = mpy_info.get("arch", "?")
    arch     = _MPY_ARCH_LABELS.get(arch_raw, arch_raw)

    n_total = sum(1 for k in meta if k != "__mpy__")
    n_native = len(_RE_NATIVE_KIND.findall(byte_txt))

    parts = [f"MicroPython {version}", arch]
    if n_total:
        label = "função" if n_total == 1 else "funções"
        parts.append(f"{n_total} {label}")
    if n_native:
        label = "nativa" if n_native == 1 else "nativas"
        parts.append(f"{n_native} {label}")

    return " · ".join(parts)
    "rv64imc":   "rv64imc",
}


def parse_bytecode(byte_txt: str):
    lines = byte_txt.splitlines()

    functions_by_name = {}
    addrs = []

    for i, line in enumerate(lines, start=1):
        m = _RE_DIS_HDR.match(line)
        if m:
            name, addr = m.group(1), m.group(2)
            functions_by_name[name] = {"addr": addr, "line": i}
            addrs.append((addr, name))

    seen = set()
    strings = []
    for line in lines:
        for m in _RE_STR_CONST.finditer(line):
            lit = m.group(1)
            if lit not in seen:
                seen.add(lit)
                strings.append(lit)

    return functions_by_name, addrs, strings


def split_recovered_functions(rec_txt: str):
    funcs = {}
    matches = list(_RE_DEF.finditer(rec_txt))
    if not matches:
        return funcs

    for idx, m in enumerate(matches):
        name = m.group(1)
        start = m.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(rec_txt)
        funcs[name] = rec_txt[start:end].rstrip()

    return funcs


def _classify_const(val: str) -> str:
    """Classifica o tipo de uma constante pelo seu repr."""
    if val == "None":
        return "None"
    if val in ("True", "False"):
        return "bool"
    if val.startswith(("'", '"')):
        return "str"
    if val.startswith(("b'", 'b"')):
        return "bytes"
    if val.startswith("(") and val.endswith(")"):
        return "tuple"
    if val.startswith("frozenset("):
        return "frozenset"
    try:
        float(val.replace("_", ""))
        return "num"
    except ValueError:
        return "outro"


def parse_all_constants(byte_txt: str) -> dict[str, list[str]]:
    """Extrai todas as constantes do bytecode, categorizadas.

    Retorna dict: {"str": [...], "num": [...], "bytes": [...], ...}
    """
    seen: set[str] = set()
    cats: dict[str, list[str]] = {}

    def _add(cat: str, val: str):
        if val not in seen:
            seen.add(val)
            cats.setdefault(cat, []).append(val)

    # CPython
    for m in _RE_CONST_CPY.finditer(byte_txt):
        val = m.group(1).strip()
        _add(_classify_const(val), val)

    # MicroPython
    for m in _RE_CONST_MPY_INT.finditer(byte_txt):
        _add("num", m.group(1).strip())
    for m in _RE_CONST_MPY_STR.finditer(byte_txt):
        _add("str", m.group(1).strip())
    for m in _RE_CONST_MPY_OBJ.finditer(byte_txt):
        val = m.group(1).strip()
        _add(_classify_const(val), val)
    for m in _RE_CONST_MPY_SPECIAL.finditer(byte_txt):
        word = m.group(1)
        if word == "NONE":
            _add("None", "None")
        elif word == "TRUE":
            _add("bool", "True")
        else:
            _add("bool", "False")

    return cats


def parse_exception_handlers(byte_txt: str) -> list[dict]:
    """Extrai informações de exception handlers do bytecode.

    Retorna lista de dicts: {"type", "func", "detail", "line"}
    """
    handlers: list[dict] = []
    lines = byte_txt.splitlines()
    current_func = "<module>"

    for i, line in enumerate(lines):
        m = _RE_DIS_HDR.match(line)
        if m:
            current_func = m.group(1)

        stripped = line.strip()

        # CPython ExceptionTable entries (match on raw line with leading whitespace)
        m = _RE_EXC_ENTRY.match(line)
        if m:
            handlers.append({
                "type": "except",
                "func": current_func,
                "detail": f"try {m.group(1)}\u2192{m.group(2)} \u2192 handler {m.group(3)} [depth {m.group(4)}]",
                "line": i + 1,
            })
            continue

        # MicroPython SETUP_* instructions
        m_mpy = _RE_SETUP_MPY.match(line)
        if m_mpy:
            kind = m_mpy.group(1).replace("SETUP_", "").lower()
            handlers.append({
                "type": kind,
                "func": current_func,
                "detail": stripped,
                "line": i + 1,
            })

    return handlers


def parse_mpy_summary(byte_txt: str, meta: dict) -> str:
    """Retorna uma string de resumo para arquivos .mpy.

    Exemplo: 'MicroPython v6.3 · xtensawin (ESP32) · 3 funções · 1 nativa'
    """
    mpy_info = meta.get("__mpy__", {})
    version  = mpy_info.get("version", "?")
    arch_raw = mpy_info.get("arch", "?")
    arch     = _MPY_ARCH_LABELS.get(arch_raw, arch_raw)

    # Total de code objects (entradas do meta excluindo __mpy__)
    n_total = sum(1 for k in meta if k != "__mpy__")

    # Conta funções native/viper pelo texto do bytecode
    n_native = len(_RE_NATIVE_KIND.findall(byte_txt))

    parts = [f"MicroPython {version}", arch]
    if n_total:
        label = "função" if n_total == 1 else "funções"
        parts.append(f"{n_total} {label}")
    if n_native:
        label = "nativa" if n_native == 1 else "nativas"
        parts.append(f"{n_native} {label}")

    return " · ".join(parts)
