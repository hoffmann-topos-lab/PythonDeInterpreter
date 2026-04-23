import difflib
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFontDatabase, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QLabel, QPlainTextEdit, QSplitter,
    QTextEdit, QVBoxLayout,
)


_COLOR_SAME_DARK = "#1a3a1a"
_COLOR_DIFF_DARK = "#3a1a1a"
_COLOR_SAME_LIGHT = "#d4ffd4"
_COLOR_DIFF_LIGHT = "#ffd4d4"


def _is_dark() -> bool:
    from UI.qt_highlighters import _is_dark as _dark
    return _dark()


class DiffView(QDialog):

    def __init__(self, parent, text_a: str, text_b: str,
                 label_a: str = "A", label_b: str = "B"):
        super().__init__(parent)
        self.setWindowTitle(f"Bin Diff — {label_a} ↔ {label_b}")

        pw = parent.width() if parent else 800
        ph = parent.height() if parent else 600
        self.resize(int(pw * 0.75), int(ph * 0.75))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        summary_frame = QFrame()
        summary_frame.setFrameShape(QFrame.Shape.StyledPanel)
        summary_frame.setStyleSheet(
            "QFrame { background: #1e1e1e; border: 1px solid #333; border-radius: 4px; }"
            if _is_dark() else
            "QFrame { background: #f5f5f5; border: 1px solid #ccc; border-radius: 4px; }"
        )
        summary_lay = QHBoxLayout(summary_frame)
        summary_lay.setContentsMargins(16, 10, 16, 10)

        self._lbl_equal = QLabel()
        self._lbl_equal.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_diff = QLabel()
        self._lbl_diff.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_total = QLabel()
        self._lbl_total.setAlignment(Qt.AlignmentFlag.AlignCenter)

        summary_lay.addWidget(self._lbl_equal, 1)
        summary_lay.addWidget(self._lbl_diff, 1)
        summary_lay.addWidget(self._lbl_total, 1)
        layout.addWidget(summary_frame)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(3)

        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        self._text_a = QPlainTextEdit()
        self._text_a.setReadOnly(True)
        self._text_a.setFont(mono)
        self._text_a.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._text_a.document().setDocumentMargin(2)
        splitter.addWidget(self._text_a)

        self._text_b = QPlainTextEdit()
        self._text_b.setReadOnly(True)
        self._text_b.setFont(mono)
        self._text_b.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self._text_b.document().setDocumentMargin(2)
        splitter.addWidget(self._text_b)
        layout.addWidget(splitter, 1)
        self._text_a.verticalScrollBar().valueChanged.connect(
            self._text_b.verticalScrollBar().setValue)
        self._text_b.verticalScrollBar().valueChanged.connect(
            self._text_a.verticalScrollBar().setValue)

        self._compute_diff(text_a, text_b)

    def _compute_diff(self, text_a: str, text_b: str):
        lines_a = text_a.splitlines()
        lines_b = text_b.splitlines()

        sm = difflib.SequenceMatcher(None, lines_a, lines_b)
        opcodes = sm.get_opcodes()

        aligned_a: list[str] = []
        aligned_b: list[str] = []
        marks_a: list[bool] = []  
        marks_b: list[bool] = []

        n_equal = 0
        n_diff = 0

        for tag, i1, i2, j1, j2 in opcodes:
            if tag == "equal":
                for k in range(i2 - i1):
                    aligned_a.append(lines_a[i1 + k])
                    aligned_b.append(lines_b[j1 + k])
                    marks_a.append(True)
                    marks_b.append(True)
                n_equal += i2 - i1
            elif tag == "replace":
                max_len = max(i2 - i1, j2 - j1)
                for k in range(max_len):
                    aligned_a.append(lines_a[i1 + k] if i1 + k < i2 else "")
                    aligned_b.append(lines_b[j1 + k] if j1 + k < j2 else "")
                    marks_a.append(False)
                    marks_b.append(False)
                n_diff += max_len
            elif tag == "delete":
                for k in range(i2 - i1):
                    aligned_a.append(lines_a[i1 + k])
                    aligned_b.append("")
                    marks_a.append(False)
                    marks_b.append(False)
                n_diff += i2 - i1
            elif tag == "insert":
                for k in range(j2 - j1):
                    aligned_a.append("")
                    aligned_b.append(lines_b[j1 + k])
                    marks_a.append(False)
                    marks_b.append(False)
                n_diff += j2 - j1

        self._text_a.setPlainText("\n".join(aligned_a))
        self._text_b.setPlainText("\n".join(aligned_b))

        dark = _is_dark()
        c_same = _COLOR_SAME_DARK if dark else _COLOR_SAME_LIGHT
        c_diff = _COLOR_DIFF_DARK if dark else _COLOR_DIFF_LIGHT

        self._apply_colors(self._text_a, marks_a, c_same, c_diff)
        self._apply_colors(self._text_b, marks_b, c_same, c_diff)

        total = n_equal + n_diff
        self._lbl_equal.setText(
            f"<span style='color:#4caf50; font-size:18px; font-weight:bold;'>{n_equal}</span>"
            f"<br><span style='font-size:11px;'>linhas iguais</span>"
        )
        self._lbl_diff.setText(
            f"<span style='color:#f44336; font-size:18px; font-weight:bold;'>{n_diff}</span>"
            f"<br><span style='font-size:11px;'>linhas diferentes</span>"
        )
        self._lbl_total.setText(
            f"<span style='font-size:18px; font-weight:bold;'>{total}</span>"
            f"<br><span style='font-size:11px;'>total</span>"
        )

    @staticmethod
    def _apply_colors(text_edit: QPlainTextEdit, marks: list[bool],
                      color_same: str, color_diff: str):
        selections = []
        doc = text_edit.document()
        for i, is_equal in enumerate(marks):
            block = doc.findBlockByNumber(i)
            if not block.isValid():
                continue
            cursor = QTextCursor(block)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(color_same if is_equal else color_diff))
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            sel.cursor = cursor
            selections.append(sel)
        text_edit.setExtraSelections(selections)
