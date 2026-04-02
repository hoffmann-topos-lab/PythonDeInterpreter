from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import QApplication


def _is_dark() -> bool:
    """Detecta se o sistema está em modo escuro via QPalette."""
    app = QApplication.instance()
    if app is None:
        return False
    bg = app.palette().color(app.palette().ColorRole.Window)
    return bg.lightness() < 128


def _fmt(color_hex: str, bold: bool = False, italic: bool = False) -> QTextCharFormat:
    f = QTextCharFormat()
    f.setForeground(QColor(color_hex))
    if bold:
        f.setFontWeight(QFont.Weight.Bold)
    if italic:
        f.setFontItalic(True)
    return f


# ─────────────────────────────────────────────────────────────
# BytecodeHighlighter
# ─────────────────────────────────────────────────────────────

class BytecodeHighlighter(QSyntaxHighlighter):
    """Highlight para o painel de bytecode (saída do dis)."""

    def __init__(self, document):
        super().__init__(document)
        dark = _is_dark()

        if dark:
            c_header = "#dcdcaa"   # amarelo — cabeçalho "Disassembly of"
            c_opcode = "#9cdcfe"   # azul-claro — LOAD_FAST, BINARY_OP...
            c_jump   = "#f44747"   # vermelho — marcador >>
            c_parens = "#ce9178"   # laranja — argval entre parênteses
            c_number = "#b5cea8"   # verde-claro — offsets e argumentos
            c_sep    = "#505050"   # cinza-escuro — linhas "---"
        else:
            c_header = "#795e26"   # marrom
            c_opcode = "#0070c1"   # azul
            c_jump   = "#e51400"   # vermelho
            c_parens = "#a31515"   # vermelho-escuro
            c_number = "#098658"   # verde-escuro
            c_sep    = "#aaaaaa"   # cinza

        # A ordem importa: regras posteriores sobrescrevem as anteriores.
        self._rules = [
            # Separadores (---  ou ===)
            (QRegularExpression(r"^[-=]{3,}.*"), _fmt(c_sep, italic=True)),
            # Cabeçalho de seção
            (QRegularExpression(r"^Disassembly of.*"), _fmt(c_header, bold=True)),
            # Números (offsets, args) — antes dos opcodes para ser sobrescrito
            (QRegularExpression(r"\b\d+\b"), _fmt(c_number)),
            # Opcodes: palavras em MAIÚSCULAS com 3+ chars
            (QRegularExpression(r"\b[A-Z][A-Z_]{2,}\b"), _fmt(c_opcode, bold=True)),
            # Argval entre parênteses — sobrescreve opcodes internos aos parens
            (QRegularExpression(r"\([^)]*\)"), _fmt(c_parens)),
            # Marcador de jump target
            (QRegularExpression(r">>"), _fmt(c_jump, bold=True)),
        ]

    def highlightBlock(self, text: str):
        for pattern, fmt in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


# ─────────────────────────────────────────────────────────────
# PythonHighlighter
# ─────────────────────────────────────────────────────────────

_KEYWORDS = [
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield",
]

_BUILTINS = [
    "abs", "all", "any", "bin", "bool", "breakpoint", "bytearray", "bytes",
    "callable", "chr", "compile", "complex", "delattr", "dict", "dir",
    "divmod", "enumerate", "eval", "exec", "filter", "float", "format",
    "frozenset", "getattr", "globals", "hasattr", "hash", "help", "hex",
    "id", "input", "int", "isinstance", "issubclass", "iter", "len", "list",
    "locals", "map", "max", "memoryview", "min", "next", "object", "oct",
    "open", "ord", "pow", "print", "property", "range", "repr", "reversed",
    "round", "set", "setattr", "slice", "sorted", "staticmethod", "str",
    "sum", "super", "tuple", "type", "vars", "zip",
]


class PythonHighlighter(QSyntaxHighlighter):
    """Highlight para o painel de código Python recuperado.

    Passo 1 — keywords, builtins, números, decoradores (regex simples).
    Passo 1b — linhas de assembly nativo (0x...: mnemonic operands).
    Passo 2 — strings (simples e triple-quoted com estado entre blocos) e
               comentários sobrescrevem o passo 1.
    """

    _STATE_NORMAL    = 0
    _STATE_TRIPLE_SQ = 1   # dentro de '''
    _STATE_TRIPLE_DQ = 2   # dentro de \"\"\"

    def __init__(self, document):
        super().__init__(document)
        dark = _is_dark()

        if dark:
            c_keyword   = "#569cd6"
            c_builtin   = "#4ec9b0"
            c_number    = "#b5cea8"
            c_decorator = "#dcdcaa"
            c_string    = "#ce9178"
            c_comment   = "#6a9955"
            c_asm_addr  = "#858585"   # cinza — endereço 0x...:
            c_asm_mnem  = "#9cdcfe"   # azul-claro — mnemonic (como opcodes)
            c_asm_reg   = "#4ec9b0"   # teal — registradores
        else:
            c_keyword   = "#0000ff"
            c_builtin   = "#267f99"
            c_number    = "#098658"
            c_decorator = "#795e26"
            c_string    = "#a31515"
            c_comment   = "#008000"
            c_asm_addr  = "#888888"   # cinza
            c_asm_mnem  = "#0070c1"   # azul — mnemonic
            c_asm_reg   = "#267f99"   # teal — registradores

        self._fmt_string  = _fmt(c_string)
        self._fmt_comment = _fmt(c_comment, italic=True)
        self._fmt_asm_addr = _fmt(c_asm_addr)
        self._fmt_asm_mnem = _fmt(c_asm_mnem, bold=True)
        self._fmt_asm_reg  = _fmt(c_asm_reg)
        self._fmt_asm_num  = _fmt(c_number)

        kw_re = "|".join(rf"\b{k}\b" for k in _KEYWORDS)
        bi_re = "|".join(rf"\b{b}\b" for b in _BUILTINS)

        self._syntax_rules = [
            (QRegularExpression(r"@[\w.]+"),           _fmt(c_decorator)),
            (QRegularExpression(kw_re),                _fmt(c_keyword, bold=True)),
            (QRegularExpression(bi_re),                _fmt(c_builtin)),
            (QRegularExpression(r"\b\d+\.?\d*([eE][+-]?\d+)?\b"), _fmt(c_number)),
        ]

        # Regex para detectar linhas de assembly: "  0xNNNN:  ..."
        self._re_asm_line = QRegularExpression(r"^\s+0x[0-9a-f]+:")
        # Componentes de uma linha de assembly
        self._re_asm_addr = QRegularExpression(r"0x[0-9a-f]+:")
        self._re_asm_mnem = QRegularExpression(
            r"(?<=:\s{2})[a-z][a-z0-9.]+")
        # Registradores assembly (x86: rax-r15, ARM: r0-r15/sp/lr/pc,
        # Xtensa: a0-a15, RISC-V: zero/ra/sp/gp/tp/a0-a7/s0-s11/t0-t6)
        self._re_asm_reg = QRegularExpression(
            r"\b("
            r"r[0-9]{1,2}[dwb]?|[re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|[re]?ip|"
            r"sp|lr|pc|"
            r"a[0-9]|a1[0-5]|"
            r"zero|ra|gp|tp|"
            r"s[0-9]|s1[01]|"
            r"t[0-6]"
            r")\b")
        # Números em assembly (hex e decimais, incluindo negativos)
        self._re_asm_num = QRegularExpression(
            r"(?<![a-z])(?:0x[0-9a-f]+|-?\d+)(?![a-z:])")

    # ------------------------------------------------------------------

    def highlightBlock(self, text: str):
        self.setCurrentBlockState(self._STATE_NORMAL)

        # Verifica se é uma linha de assembly nativo
        if self._re_asm_line.match(text).hasMatch():
            self._apply_asm_highlight(text)
            return

        # Passo 1: elementos sintáticos (sem strings nem comentários)
        for pattern, fmt in self._syntax_rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)

        # Passo 2: strings e comentários (sobrescrevem passo 1)
        self._apply_strings_and_comments(text)

    def _apply_asm_highlight(self, text: str):
        """Aplica highlighting específico para linhas de assembly nativo."""
        # Endereço (0x....:)
        m = self._re_asm_addr.match(text, text.index("0x"))
        if m.hasMatch():
            self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_addr)

        # Mnemonic
        it = self._re_asm_mnem.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_mnem)

        # Registradores
        it = self._re_asm_reg.globalMatch(text)
        while it.hasNext():
            m = it.next()
            # Não colorir dentro do endereço (antes do ':')
            colon_pos = text.find(":")
            if m.capturedStart() > colon_pos:
                self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_reg)

        # Números (hex e decimais nos operandos)
        it = self._re_asm_num.globalMatch(text)
        while it.hasNext():
            m = it.next()
            # Pula o endereço no início (já colorido acima)
            colon_pos = text.find(":")
            if m.capturedStart() > colon_pos:
                self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_num)

    def _apply_strings_and_comments(self, text: str):
        prev = self.previousBlockState()

        # Continuação de string triple do bloco anterior
        if prev == self._STATE_TRIPLE_SQ:
            start = self._continue_triple(text, "'''", self._STATE_TRIPLE_SQ)
            if start == -1:
                return
        elif prev == self._STATE_TRIPLE_DQ:
            start = self._continue_triple(text, '"""', self._STATE_TRIPLE_DQ)
            if start == -1:
                return
        else:
            start = 0

        i = start
        while i < len(text):
            c = text[i]

            # Comentário: # até o fim da linha
            if c == "#":
                self.setFormat(i, len(text) - i, self._fmt_comment)
                return

            # Prefixo opcional de string: f, b, r, rb, fr, ... (case-insensitive)
            prefix_len = 0
            if c.lower() in ("f", "b", "r") and i + 1 < len(text):
                if text[i + 1] in ('"', "'"):
                    prefix_len = 1
                elif text[i + 1].lower() in ("b", "r", "f") and i + 2 < len(text) and text[i + 2] in ('"', "'"):
                    prefix_len = 2

            q_start = i + prefix_len
            if q_start < len(text) and text[q_start] in ('"', "'"):
                quote = text[q_start]

                # Triple-quoted?
                if text[q_start: q_start + 3] == quote * 3:
                    state_id = self._STATE_TRIPLE_DQ if quote == '"' else self._STATE_TRIPLE_SQ
                    j = text.find(quote * 3, q_start + 3)
                    if j == -1:
                        # String continua no próximo bloco
                        self.setFormat(i, len(text) - i, self._fmt_string)
                        self.setCurrentBlockState(state_id)
                        return
                    self.setFormat(i, j + 3 - i, self._fmt_string)
                    i = j + 3
                    continue

                # Single-line string
                j = q_start + 1
                while j < len(text):
                    if text[j] == "\\":
                        j += 2
                        continue
                    if text[j] == quote:
                        j += 1
                        break
                    j += 1
                self.setFormat(i, j - i, self._fmt_string)
                i = j
                continue

            i += 1

    def _continue_triple(self, text: str, delim: str, state_id: int) -> int:
        """Aplica formato de string ao início do bloco até o delimitador de fechamento.

        Retorna o índice a partir do qual continuar o parsing normal,
        ou -1 se o bloco inteiro ainda está dentro da string.
        """
        end = text.find(delim)
        if end == -1:
            self.setFormat(0, len(text), self._fmt_string)
            self.setCurrentBlockState(state_id)
            return -1
        self.setFormat(0, end + len(delim), self._fmt_string)
        return end + len(delim)
