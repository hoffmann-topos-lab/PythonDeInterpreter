"""Diálogo de comparação (diff) entre duas decompilações."""

import difflib

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QSplitter,
    QTextEdit, QVBoxLayout,
)

_COLOR_ADD = "#1a3a1a"
_COLOR_DEL = "#3a1a1a"
_COLOR_CHG = "#3a3a1a"
_COLOR_ADD_LIGHT = "#d4ffd4"
_COLOR_DEL_LIGHT = "#ffd4d4"
_COLOR_CHG_LIGHT = "#ffffd4"


def _is_dark() -> bool:
    from UI.qt_highlighters import _is_dark as _dark
    return _dark()


class DiffView(QDialog):
    """Compara o código recuperado de dois arquivos lado a lado."""

    def __init__(self, parent, text_a: str, text_b: str,
                 label_a: str = "Arquivo A", label_b: str = "Arquivo B"):
        super().__init__(parent)
        self.setWindowTitle("Comparação de decompilações")
        self.resize(1200, 700)

        layout = QVBoxLayout(self)

        # Resumo
        self._lbl_summary = QLabel()
        layout.addWidget(self._lbl_summary)

        # Side-by-side
        splitter = QSplitter(Qt.Orientation.Horizontal)

        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        # Lado A
        left = QVBoxLayout()
        left_w = self._make_container(left)
        self._lbl_a = QLabel(f"<b>{label_a}</b>")
        left.addWidget(self._lbl_a)
        self._text_a = QPlainTextEdit()
        self._text_a.setReadOnly(True)
        self._text_a.setFont(mono)
        left.addWidget(self._text_a)
        splitter.addWidget(left_w)

        # Lado B
        right = QVBoxLayout()
        right_w = self._make_container(right)
        self._lbl_b = QLabel(f"<b>{label_b}</b>")
        right.addWidget(self._lbl_b)
        self._text_b = QPlainTextEdit()
        self._text_b.setReadOnly(True)
        self._text_b.setFont(mono)
        right.addWidget(self._text_b)
        splitter.addWidget(right_w)

        layout.addWidget(splitter)

        # Scroll sincronizado
        self._text_a.verticalScrollBar().valueChanged.connect(
            self._text_b.verticalScrollBar().setValue)
        self._text_b.verticalScrollBar().valueChanged.connect(
            self._text_a.verticalScrollBar().setValue)

        # Computa e exibe diff
        self._compute_diff(text_a, text_b)

    @staticmethod
    def _make_container(layout):
        from PySide6.QtWidgets import QWidget
        w = QWidget()
        w.setLayout(layout)
        return w

    def _compute_diff(self, text_a: str, text_b: str):
        lines_a = text_a.splitlines()
        lines_b = text_b.splitlines()

        sm = difflib.SequenceMatcher(None, lines_a, lines_b)
        opcodes = sm.get_opcodes()

        # Constrói textos alinhados
        aligned_a = []
        aligned_b = []
        marks_a = []  # "equal", "delete", "replace"
        marks_b = []  # "equal", "insert", "replace"

        n_add = 0
        n_del = 0
        n_chg = 0

        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "equal":
                for k in range(i2 - i1):
                    aligned_a.append(lines_a[i1 + k])
                    aligned_b.append(lines_b[j1 + k])
                    marks_a.append("equal")
                    marks_b.append("equal")
            elif tag == "replace":
                n_chg += max(i2 - i1, j2 - j1)
                max_len = max(i2 - i1, j2 - j1)
                for k in range(max_len):
                    if i1 + k < i2:
                        aligned_a.append(lines_a[i1 + k])
                    else:
                        aligned_a.append("")
                    if j1 + k < j2:
                        aligned_b.append(lines_b[j1 + k])
                    else:
                        aligned_b.append("")
                    marks_a.append("replace")
                    marks_b.append("replace")
            elif tag == "delete":
                n_del += i2 - i1
                for k in range(i2 - i1):
                    aligned_a.append(lines_a[i1 + k])
                    aligned_b.append("")
                    marks_a.append("delete")
                    marks_b.append("delete")
            elif tag == "insert":
                n_add += j2 - j1
                for k in range(j2 - j1):
                    aligned_a.append("")
                    aligned_b.append(lines_b[j1 + k])
                    marks_a.append("insert")
                    marks_b.append("insert")

        self._text_a.setPlainText("\n".join(aligned_a))
        self._text_b.setPlainText("\n".join(aligned_b))

        # Aplica highlights
        dark = _is_dark()
        c_add = _COLOR_ADD if dark else _COLOR_ADD_LIGHT
        c_del = _COLOR_DEL if dark else _COLOR_DEL_LIGHT
        c_chg = _COLOR_CHG if dark else _COLOR_CHG_LIGHT

        self._apply_marks(self._text_a, marks_a, {"delete": c_del, "replace": c_chg})
        self._apply_marks(self._text_b, marks_b, {"insert": c_add, "replace": c_chg})

        total = n_add + n_del + n_chg
        self._lbl_summary.setText(
            f"{total} linhas alteradas: "
            f"<span style='color:green'>+{n_add}</span> adicionadas, "
            f"<span style='color:red'>-{n_del}</span> removidas, "
            f"<span style='color:orange'>~{n_chg}</span> modificadas"
        )

    @staticmethod
    def _apply_marks(text_edit: QPlainTextEdit, marks: list[str],
                     color_map: dict[str, str]):
        selections = []
        doc = text_edit.document()
        for i, mark in enumerate(marks):
            if mark == "equal":
                continue
            color = color_map.get(mark)
            if not color:
                continue
            block = doc.findBlockByNumber(i)
            if not block.isValid():
                continue
            cursor = QTextCursor(block)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(color))
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            sel.cursor = cursor
            selections.append(sel)
        text_edit.setExtraSelections(selections)
