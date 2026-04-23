import os
import re

from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QListWidget, QTabWidget,
    QVBoxLayout, QWidget,
)


class StatsDialog(QDialog):

    def __init__(self, parent, bytecode_text: str, recovered_text: str,
                 meta: dict, file_path: str, elapsed: float):
        super().__init__(parent)
        self.setWindowTitle("Estatísticas do bytecode")
        self.resize(620, 480)

        layout = QVBoxLayout(self)
        tabs = QTabWidget()
        layout.addWidget(tabs)

        tabs.addTab(
            self._build_general(bytecode_text, recovered_text, meta, file_path, elapsed),
            "Geral",
        )
        tabs.addTab(self._build_imports(recovered_text), "Imports")


    def _build_general(self, bc, rc, meta, path, elapsed):
        w = QWidget()
        lay = QVBoxLayout(w)

        name = os.path.basename(path)
        size = os.path.getsize(path) if os.path.exists(path) else 0
        if size < 1024:
            sz = f"{size} B"
        elif size < 1024 * 1024:
            sz = f"{size / 1024:.1f} KB"
        else:
            sz = f"{size / (1024 * 1024):.1f} MB"

        mpy = meta.get("__mpy__")
        if mpy:
            version = f"MicroPython {mpy.get('version', '?')} ({mpy.get('arch', '?')})"
        else:
            version = "CPython 3.12"

        n_code_objects = sum(1 for k in meta if not k.startswith("__"))
        n_instructions = self._count_instructions(bc)
        n_lines_rc = len(rc.splitlines()) if rc.strip() else 0

        info = [
            ("Arquivo", f"{name} ({sz})"),
            ("Formato", version),
            ("Code objects", str(n_code_objects)),
            ("Instruções (aprox.)", str(n_instructions)),
            ("Linhas recuperadas", str(n_lines_rc)),
            ("Tempo de recuperação", f"{elapsed:.2f}s"),
        ]
        for label, value in info:
            row = QHBoxLayout()
            lbl = QLabel(f"<b>{label}:</b>")
            lbl.setFixedWidth(180)
            val = QLabel(value)
            row.addWidget(lbl)
            row.addWidget(val, 1)
            lay.addLayout(row)

        lay.addStretch()
        return w


    def _build_imports(self, rc):
        w = QWidget()
        lay = QVBoxLayout(w)

        imports = []
        for line in rc.splitlines():
            stripped = line.strip()
            if stripped.startswith("import ") or stripped.startswith("from "):
                imports.append(stripped)

        if not imports:
            lay.addWidget(QLabel("Nenhum import encontrado."))
        else:
            lay.addWidget(QLabel(f"<b>{len(imports)} imports encontrados:</b>"))
            lst = QListWidget()
            lst.addItems(imports)
            lay.addWidget(lst)

        lay.addStretch()
        return w

    @staticmethod
    def _count_instructions(bc: str) -> int:
        count = 0
        for line in bc.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("Disassembly", "ExceptionTable", "(")):
                continue
            parts = stripped.split()
            for p in parts:
                if p == p.upper() and len(p) > 2 and re.match(r"[A-Z][A-Z_0-9]+$", p):
                    count += 1
                    break
        return count
