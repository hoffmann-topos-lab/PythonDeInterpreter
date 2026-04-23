import sys
import io
import traceback

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QFontDatabase, QTextCursor
from PySide6.QtWidgets import QPlainTextEdit


class PythonConsole(QPlainTextEdit):

    PROMPT = ">>> "
    CONT = "... "

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))

        self._namespace: dict = {"__builtins__": __builtins__}
        self._history: list[str] = []
        self._hist_idx: int = -1
        self._current_input: str = ""

        self.appendPlainText("Console Python — variáveis: app, bytecode, recovered, meta")
        self._show_prompt()

    def set_namespace(self, ns: dict):
        self._namespace.update(ns)

    def _show_prompt(self):
        self.appendPlainText(self.PROMPT)
        self.moveCursor(QTextCursor.MoveOperation.End)

    def _current_line(self) -> str:
        line = self.textCursor().block().text()
        if line.startswith(self.PROMPT):
            return line[len(self.PROMPT):]
        if line.startswith(self.CONT):
            return line[len(self.CONT):]
        return line

    def _replace_current_line(self, text: str):
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                            QTextCursor.MoveMode.KeepAnchor)
        block_text = cursor.selectedText()
        if block_text.startswith(self.PROMPT):
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cursor.movePosition(QTextCursor.MoveOperation.Right,
                                QTextCursor.MoveMode.MoveAnchor,
                                len(self.PROMPT))
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
        cursor.insertText(text)
        self.setTextCursor(cursor)

    def keyPressEvent(self, event):
        cursor = self.textCursor()

        if cursor.blockNumber() < self.document().blockCount() - 1:
            self.moveCursor(QTextCursor.MoveOperation.End)

        key = event.key()

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            code = self._current_line()
            self.moveCursor(QTextCursor.MoveOperation.End)
            self.insertPlainText("\n")
            if code.strip():
                self._history.append(code)
                self._hist_idx = -1
                self._execute(code)
            self._show_prompt()
            return

        if key == Qt.Key.Key_Up:
            if self._history:
                if self._hist_idx == -1:
                    self._current_input = self._current_line()
                    self._hist_idx = len(self._history) - 1
                elif self._hist_idx > 0:
                    self._hist_idx -= 1
                self._replace_current_line(self._history[self._hist_idx])
            return

        if key == Qt.Key.Key_Down:
            if self._hist_idx >= 0:
                self._hist_idx += 1
                if self._hist_idx >= len(self._history):
                    self._hist_idx = -1
                    self._replace_current_line(self._current_input)
                else:
                    self._replace_current_line(self._history[self._hist_idx])
            return

        if key == Qt.Key.Key_Backspace:
            block_text = cursor.block().text()
            col = cursor.positionInBlock()
            prompt_len = len(self.PROMPT)
            if col <= prompt_len and block_text.startswith(self.PROMPT):
                return

        if key == Qt.Key.Key_Home:
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cursor.movePosition(QTextCursor.MoveOperation.Right,
                                QTextCursor.MoveMode.MoveAnchor,
                                len(self.PROMPT))
            self.setTextCursor(cursor)
            return

        super().keyPressEvent(event)

    def _execute(self, code: str):
        """Executa código Python e exibe o resultado."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        try:
            try:
                result = eval(code, self._namespace)
                if result is not None:
                    print(repr(result))
            except SyntaxError:
                exec(code, self._namespace)
        except Exception:
            traceback.print_exc(file=stderr_capture)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        output = stdout_capture.getvalue()
        errors = stderr_capture.getvalue()

        if output.strip():
            self.insertPlainText(output.rstrip("\n"))
            self.insertPlainText("\n")
        if errors.strip():
            self.insertPlainText(errors.rstrip("\n"))
            self.insertPlainText("\n")

    def _show_prompt(self):
        self.appendPlainText(self.PROMPT)
        self.moveCursor(QTextCursor.MoveOperation.End)

    def _current_line(self) -> str:
        """Retorna o texto da linha atual (sem o prompt)."""
        line = self.textCursor().block().text()
        if line.startswith(self.PROMPT):
            return line[len(self.PROMPT):]
        if line.startswith(self.CONT):
            return line[len(self.CONT):]
        return line

    def _replace_current_line(self, text: str):
        """Substitui o texto da linha atual (após o prompt)."""
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
        cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                            QTextCursor.MoveMode.KeepAnchor)
        block_text = cursor.selectedText()
        if block_text.startswith(self.PROMPT):
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cursor.movePosition(QTextCursor.MoveOperation.Right,
                                QTextCursor.MoveMode.MoveAnchor,
                                len(self.PROMPT))
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
        cursor.insertText(text)
        self.setTextCursor(cursor)

    def keyPressEvent(self, event):
        cursor = self.textCursor()

        # Garante que o cursor está na última linha
        if cursor.blockNumber() < self.document().blockCount() - 1:
            self.moveCursor(QTextCursor.MoveOperation.End)

        key = event.key()

        if key in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            code = self._current_line()
            self.moveCursor(QTextCursor.MoveOperation.End)
            self.insertPlainText("\n")
            if code.strip():
                self._history.append(code)
                self._hist_idx = -1
                self._execute(code)
            self._show_prompt()
            return

        if key == Qt.Key.Key_Up:
            if self._history:
                if self._hist_idx == -1:
                    self._current_input = self._current_line()
                    self._hist_idx = len(self._history) - 1
                elif self._hist_idx > 0:
                    self._hist_idx -= 1
                self._replace_current_line(self._history[self._hist_idx])
            return

        if key == Qt.Key.Key_Down:
            if self._hist_idx >= 0:
                self._hist_idx += 1
                if self._hist_idx >= len(self._history):
                    self._hist_idx = -1
                    self._replace_current_line(self._current_input)
                else:
                    self._replace_current_line(self._history[self._hist_idx])
            return

        if key == Qt.Key.Key_Backspace:
            # Não permite apagar o prompt
            block_text = cursor.block().text()
            col = cursor.positionInBlock()
            prompt_len = len(self.PROMPT)
            if col <= prompt_len and block_text.startswith(self.PROMPT):
                return

        if key == Qt.Key.Key_Home:
            # Move para depois do prompt
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cursor.movePosition(QTextCursor.MoveOperation.Right,
                                QTextCursor.MoveMode.MoveAnchor,
                                len(self.PROMPT))
            self.setTextCursor(cursor)
            return

        super().keyPressEvent(event)

    def _execute(self, code: str):
        """Executa código Python e exibe o resultado."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture

        try:
            # Tenta como expressão primeiro (eval)
            try:
                result = eval(code, self._namespace)
                if result is not None:
                    print(repr(result))
            except SyntaxError:
                # Tenta como statement (exec)
                exec(code, self._namespace)
        except Exception:
            traceback.print_exc(file=stderr_capture)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        output = stdout_capture.getvalue()
        errors = stderr_capture.getvalue()

        if output.strip():
            self.insertPlainText(output.rstrip("\n"))
            self.insertPlainText("\n")
        if errors.strip():
            self.insertPlainText(errors.rstrip("\n"))
            self.insertPlainText("\n")
