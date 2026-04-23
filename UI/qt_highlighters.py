from PySide6.QtCore import QRegularExpression
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat
from PySide6.QtWidgets import QApplication


def _is_dark() -> bool:
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


class BytecodeHighlighter(QSyntaxHighlighter):

    def __init__(self, document):
        super().__init__(document)
        dark = _is_dark()

        if dark:
            c_header = "#dcdcaa"  
            c_opcode = "#9cdcfe"   
            c_jump   = "#f44747"  
            c_parens = "#ce9178"  
            c_number = "#b5cea8"   
            c_sep    = "#505050"   
        else:
            c_header = "#795e26"   
            c_opcode = "#0070c1"   
            c_jump   = "#e51400"   
            c_parens = "#a31515"   
            c_number = "#098658"   
            c_sep    = "#aaaaaa"   

        self._rules = [
            (QRegularExpression(r"^[-=]{3,}.*"), _fmt(c_sep, italic=True)),
            (QRegularExpression(r"^Disassembly of.*"), _fmt(c_header, bold=True)),
            (QRegularExpression(r"\b\d+\b"), _fmt(c_number)),
            (QRegularExpression(r"\b[A-Z][A-Z_]{2,}\b"), _fmt(c_opcode, bold=True)),
            (QRegularExpression(r"\([^)]*\)"), _fmt(c_parens)),
            (QRegularExpression(r">>"), _fmt(c_jump, bold=True)),
        ]

    def highlightBlock(self, text: str):
        for pattern, fmt in self._rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)



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

    _STATE_NORMAL    = 0
    _STATE_TRIPLE_SQ = 1  
    _STATE_TRIPLE_DQ = 2  

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
            c_asm_addr  = "#858585"  
            c_asm_mnem  = "#9cdcfe"   
            c_asm_reg   = "#4ec9b0"  
        else:
            c_keyword   = "#0000ff"
            c_builtin   = "#267f99"
            c_number    = "#098658"
            c_decorator = "#795e26"
            c_string    = "#a31515"
            c_comment   = "#008000"
            c_asm_addr  = "#888888"  
            c_asm_mnem  = "#0070c1"   
            c_asm_reg   = "#267f99"   

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

        self._re_asm_line = QRegularExpression(r"^\s+0x[0-9a-f]+:")
        self._re_asm_addr = QRegularExpression(r"0x[0-9a-f]+:")
        self._re_asm_mnem = QRegularExpression(
            r"(?<=:\s{2})[a-z][a-z0-9.]+")

        self._re_asm_reg = QRegularExpression(
            r"\b("
            r"r[0-9]{1,2}[dwb]?|[re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|[re]?ip|"
            r"sp|lr|pc|"
            r"a[0-9]|a1[0-5]|"
            r"zero|ra|gp|tp|"
            r"s[0-9]|s1[01]|"
            r"t[0-6]"
            r")\b")
        self._re_asm_num = QRegularExpression(
            r"(?<![a-z])(?:0x[0-9a-f]+|-?\d+)(?![a-z:])")


    def highlightBlock(self, text: str):
        self.setCurrentBlockState(self._STATE_NORMAL)

        if self._re_asm_line.match(text).hasMatch():
            self._apply_asm_highlight(text)
            return
        for pattern, fmt in self._syntax_rules:
            it = pattern.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)

        self._apply_strings_and_comments(text)

    def _apply_asm_highlight(self, text: str):

        m = self._re_asm_addr.match(text, text.index("0x"))
        if m.hasMatch():
            self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_addr)

        it = self._re_asm_mnem.globalMatch(text)
        while it.hasNext():
            m = it.next()
            self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_mnem)

        it = self._re_asm_reg.globalMatch(text)
        while it.hasNext():
            m = it.next()
            colon_pos = text.find(":")
            if m.capturedStart() > colon_pos:
                self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_reg)

        it = self._re_asm_num.globalMatch(text)
        while it.hasNext():
            m = it.next()
            colon_pos = text.find(":")
            if m.capturedStart() > colon_pos:
                self.setFormat(m.capturedStart(), m.capturedLength(), self._fmt_asm_num)

    def _apply_strings_and_comments(self, text: str):
        prev = self.previousBlockState()
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

            if c == "#":
                self.setFormat(i, len(text) - i, self._fmt_comment)
                return

            prefix_len = 0
            if c.lower() in ("f", "b", "r") and i + 1 < len(text):
                if text[i + 1] in ('"', "'"):
                    prefix_len = 1
                elif text[i + 1].lower() in ("b", "r", "f") and i + 2 < len(text) and text[i + 2] in ('"', "'"):
                    prefix_len = 2

            q_start = i + prefix_len
            if q_start < len(text) and text[q_start] in ('"', "'"):
                quote = text[q_start]

                if text[q_start: q_start + 3] == quote * 3:
                    state_id = self._STATE_TRIPLE_DQ if quote == '"' else self._STATE_TRIPLE_SQ
                    j = text.find(quote * 3, q_start + 3)
                    if j == -1:
                        self.setFormat(i, len(text) - i, self._fmt_string)
                        self.setCurrentBlockState(state_id)
                        return
                    self.setFormat(i, j + 3 - i, self._fmt_string)
                    i = j + 3
                    continue

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

        end = text.find(delim)
        if end == -1:
            self.setFormat(0, len(text), self._fmt_string)
            self.setCurrentBlockState(state_id)
            return -1
        self.setFormat(0, end + len(delim), self._fmt_string)
        return end + len(delim)
