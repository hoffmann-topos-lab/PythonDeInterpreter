import os
import re
import time
import json
import hashlib

from PySide6.QtCore import Qt, QEvent, QSettings
from PySide6.QtGui import (
    QAction, QColor, QFont, QFontDatabase, QKeySequence,
    QTextCharFormat, QTextCursor, QTextDocument,
)
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QFileDialog, QGroupBox, QHBoxLayout,
    QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMessageBox, QPlainTextEdit, QPushButton, QSplitter,
    QStackedWidget, QTabBar, QTextEdit, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from UI.ui_config import (
    APP_TITLE, SUPPORTED_HINT, SUPPORTED_EXTENSIONS, FILE_FILTER,
    GUTTER, LEFT_WIDTH,
)
from UI.ui_parsers import (
    parse_bytecode, split_recovered_functions, parse_mpy_summary,
    parse_all_constants, parse_exception_handlers,
)
from UI.annotations import load_annotations, save_annotations, apply_renames
from UI.stats_dialog import StatsDialog
from UI.cfg_view import CfgView
from UI.diff_view import DiffView
from UI.console import PythonConsole
from UI.qt_highlighters import BytecodeHighlighter, PythonHighlighter, _is_dark
from UI.qt_engine_worker import EngineWorker
from Decompiler.engine_runner import run_engine
from MicroPython.mpy_engine_runner import run_mpy_engine
from NativeDisasm.base import format_hex_dump

_MAX_RECENT = 10

# Prefixos por tipo de code object na árvore
_TYPE_PREFIX = {
    "class":    "\u25C6 ",   # ◆
    "function": "\u0192 ",   # ƒ
    "lambda":   "\u03BB ",   # λ
    "genexpr":  "\u2218 ",   # ∘
    "listcomp": "\u2218 ",
    "setcomp":  "\u2218 ",
    "dictcomp": "\u2218 ",
}


def _detect_format(path: str) -> str:
    """Detecta o formato do arquivo pelo conteúdo e extensão."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pyc":
        return "cpython"
    if ext == ".mpy":
        with open(path, "rb") as f:
            b = f.read(2)
        if len(b) >= 2 and b[0] == 0x4D and b[1] == 6:
            return "micropython"
        ver = b[1] if len(b) >= 2 else "?"
        raise ValueError(f"Versão .mpy não suportada: {ver} (suportado: v6)")
    raise ValueError(f"Extensão não suportada: {ext}")


# ------------------------------------------------------------------
# Widget de busca textual (Ctrl+F)
# ------------------------------------------------------------------

class SearchBar(QWidget):
    """Barra de busca para um QPlainTextEdit."""

    def __init__(self, target: QPlainTextEdit, parent=None):
        super().__init__(parent)
        self._target = target
        self._matches: list[QTextCursor] = []
        self._current = -1

        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 2, 0, 2)

        self._input = QLineEdit()
        self._input.setPlaceholderText("Buscar...")
        self._input.setClearButtonEnabled(True)
        self._input.textChanged.connect(self._find_all)
        self._input.returnPressed.connect(self.find_next)
        self._input.installEventFilter(self)

        self._lbl = QLabel()
        self._lbl.setFixedWidth(80)
        self._lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_prev = QPushButton("\u25C0")
        btn_prev.setFixedWidth(28)
        btn_prev.setToolTip("Anterior (Shift+Enter)")
        btn_prev.clicked.connect(self.find_prev)

        btn_next = QPushButton("\u25B6")
        btn_next.setFixedWidth(28)
        btn_next.setToolTip("Próximo (Enter)")
        btn_next.clicked.connect(self.find_next)

        self._chk_case = QCheckBox("Aa")
        self._chk_case.setToolTip("Case-sensitive")
        self._chk_case.toggled.connect(self._find_all)

        btn_close = QPushButton("\u2715")
        btn_close.setFixedWidth(28)
        btn_close.setToolTip("Fechar (Esc)")
        btn_close.clicked.connect(self.hide_bar)

        lay.addWidget(self._input, 1)
        lay.addWidget(self._lbl)
        lay.addWidget(btn_prev)
        lay.addWidget(btn_next)
        lay.addWidget(self._chk_case)
        lay.addWidget(btn_close)

        self.setVisible(False)

    def show_bar(self):
        self.setVisible(True)
        self._input.setFocus()
        self._input.selectAll()
        if self._input.text():
            self._find_all()

    def hide_bar(self):
        self.setVisible(False)
        self._target.setExtraSelections([])
        self._matches.clear()
        self._current = -1
        self._lbl.setText("")
        self._target.setFocus()

    def find_next(self):
        if not self._matches:
            return
        self._current = (self._current + 1) % len(self._matches)
        self._apply_highlights()

    def find_prev(self):
        if not self._matches:
            return
        self._current = (self._current - 1) % len(self._matches)
        self._apply_highlights()

    def eventFilter(self, obj, event):
        if obj is self._input and event.type() == QEvent.Type.KeyPress:
            if event.key() == Qt.Key.Key_Escape:
                self.hide_bar()
                return True
            if (event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
                    and event.modifiers() & Qt.KeyboardModifier.ShiftModifier):
                self.find_prev()
                return True
        return super().eventFilter(obj, event)

    def _find_all(self):
        self._target.setExtraSelections([])
        self._matches.clear()
        self._current = -1
        text = self._input.text()
        if not text:
            self._lbl.setText("")
            return
        doc = self._target.document()
        case = self._chk_case.isChecked()
        pos = 0
        while True:
            if case:
                cur = doc.find(text, pos, QTextDocument.FindFlag.FindCaseSensitively)
            else:
                cur = doc.find(text, pos)
            if cur.isNull():
                break
            self._matches.append(QTextCursor(cur))
            new_pos = cur.selectionEnd()
            if new_pos == pos:
                break
            pos = new_pos
        if not self._matches:
            self._lbl.setText("0 resultados")
            return
        self._current = 0
        self._apply_highlights()

    def _apply_highlights(self):
        hl = "#7a6300" if _is_dark() else "#ffe080"
        cur_hl = "#ff6600" if _is_dark() else "#ff9900"
        selections = []
        for i, c in enumerate(self._matches):
            sel = QTextEdit.ExtraSelection()
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(cur_hl if i == self._current else hl))
            sel.format = fmt
            sel.cursor = c
            selections.append(sel)
        self._target.setExtraSelections(selections)
        self._lbl.setText(f"{self._current + 1}/{len(self._matches)}")
        if 0 <= self._current < len(self._matches):
            self._target.setTextCursor(self._matches[self._current])
            self._target.ensureCursorVisible()


# ------------------------------------------------------------------
# Janela principal
# ------------------------------------------------------------------

class MainWindow(QMainWindow):

    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setAcceptDrops(True)

        # --- dados ---
        self.bytecode_meta: dict = {}
        self._func_meta: dict    = {}
        self._addr_items: list   = []
        self._strings: list      = []
        self._recovered_funcs: dict = {}
        self._recovered_full: str   = ""
        self._worker: EngineWorker | None = None
        self._load_start: float = 0.0
        self._bookmarks: list = []
        self._annotations: dict = {"renames": {}, "comments_bc": {}, "comments_rc": {}}
        self._settings = QSettings("PythonDecompiler", "PythonDecompiler")

        # Navegação bidirecional
        self._sync_nav: bool = True
        self._sync_guard: bool = False
        self._bc_line_to_func: dict[int, str] = {}
        self._rc_line_to_func: dict[int, str] = {}

        # Sessões (múltiplas abas)
        self._sessions: dict[int, dict] = {}
        self._next_sid: int = 0
        self._active_sid: int = -1

        self._build_ui()
        self._build_menus()
        self._setup_statusbar()
        self._show_splash()

    # ------------------------------------------------------------------
    # Construção da UI
    # ------------------------------------------------------------------

    def _build_ui(self):
        self._stack = QStackedWidget()
        self.setCentralWidget(self._stack)
        self._stack.addWidget(self._build_splash())  # página 0
        self._stack.addWidget(self._build_main())    # página 1

        # Overlay de drag-and-drop
        self._drop_overlay = QLabel("Solte o arquivo aqui", self)
        self._drop_overlay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = self._drop_overlay.font()
        font.setPointSize(24)
        self._drop_overlay.setFont(font)
        self._drop_overlay.setStyleSheet(
            "background-color: rgba(0, 120, 215, 30);"
            "border: 3px dashed rgba(0, 120, 215, 180);"
            "color: rgba(0, 120, 215, 200);"
            "border-radius: 12px;"
        )
        self._drop_overlay.setVisible(False)

    def _build_splash(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setAlignment(Qt.AlignmentFlag.AlignCenter)

        font_title = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font_title.setPointSize(28)
        font_title.setWeight(QFont.Weight.Bold)

        lbl_title = QLabel(APP_TITLE)
        lbl_title.setFont(font_title)
        lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_sub = QLabel("Carregue um arquivo .pyc ou .mpy para reconstruir o código Python.")
        lbl_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        lbl_hint = QLabel("Arraste um arquivo ou use Ctrl+O")
        lbl_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_hint.setStyleSheet("color: gray;")

        self._btn_splash_open = QPushButton("Abrir arquivo")
        self._btn_splash_open.setFixedWidth(200)
        self._btn_splash_open.clicked.connect(self.pick_and_load)

        outer.addWidget(lbl_title)
        outer.addSpacing(10)
        outer.addWidget(lbl_sub)
        outer.addSpacing(6)
        outer.addWidget(lbl_hint)
        outer.addSpacing(20)
        outer.addWidget(self._btn_splash_open, alignment=Qt.AlignmentFlag.AlignCenter)
        return page

    def _build_main(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(GUTTER, GUTTER, GUTTER, GUTTER)
        root.setSpacing(GUTTER)

        # ---- Topbar ----
        topbar = QWidget()
        hbox = QHBoxLayout(topbar)
        hbox.setContentsMargins(0, 0, 0, 0)

        self._path_input = QLineEdit()
        self._path_input.setReadOnly(True)
        self._path_input.setPlaceholderText("Nenhum arquivo carregado")

        self._btn_open   = QPushButton("Abrir arquivo")
        self._btn_reload = QPushButton("Recarregar")
        self._btn_close_tab = QPushButton("Fechar aba")

        self._btn_open.clicked.connect(self.pick_and_load)
        self._btn_reload.clicked.connect(self.reload_current)
        self._btn_close_tab.clicked.connect(self._close_current_tab)

        hbox.addWidget(self._path_input)
        hbox.addWidget(self._btn_open)
        hbox.addWidget(self._btn_reload)
        hbox.addWidget(self._btn_close_tab)

        # Tab bar
        self._tab_bar = QTabBar()
        self._tab_bar.setTabsClosable(True)
        self._tab_bar.setMovable(True)
        self._tab_bar.setExpanding(False)
        self._tab_bar.currentChanged.connect(self._switch_tab)
        self._tab_bar.tabCloseRequested.connect(self._close_tab)

        # ---- Splitter horizontal (3 painéis) ----
        h_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Painel esquerdo — listas (layout original)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(GUTTER)

        self._tree_consts  = QTreeWidget()
        self._tree_consts.setHeaderHidden(True)
        self._tree_funcs   = QTreeWidget()
        self._tree_funcs.setHeaderHidden(True)
        self._list_addrs   = QListWidget()
        self._list_bookmarks = QListWidget()

        # Widgets extras (Fase 4) — não visíveis no painel, acessíveis via código
        self._tree_handlers = QTreeWidget()
        self._tree_handlers.setHeaderHidden(True)
        self._list_comments = QListWidget()

        self._lbl_format_info = QLabel("")
        self._lbl_format_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._lbl_format_info.setVisible(False)

        left_layout.addWidget(self._lbl_format_info)
        left_layout.addWidget(self._make_group("Constantes", self._tree_consts))
        left_layout.addWidget(self._make_group("Code Objects", self._tree_funcs))
        left_layout.addWidget(self._make_group("Endereços",  self._list_addrs))
        left_layout.addWidget(self._make_group("Bookmarks",  self._list_bookmarks))

        self._tree_funcs.currentItemChanged.connect(self._on_func_select)
        self._tree_consts.currentItemChanged.connect(self._on_const_select)
        self._list_addrs.currentItemChanged.connect(self._on_addr_select)
        self._list_bookmarks.itemClicked.connect(self._on_bookmark_click)
        self._list_comments.itemClicked.connect(self._on_comment_click)

        # Painel central — Bytecode (com SearchBar)
        mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)

        self._byte_text = QPlainTextEdit()
        self._byte_text.setReadOnly(True)
        self._byte_text.setFont(mono)
        self._bc_highlighter = BytecodeHighlighter(self._byte_text.document())
        self._byte_text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._byte_text.customContextMenuRequested.connect(self._bytecode_context_menu)
        self._byte_text.cursorPositionChanged.connect(self._on_byte_cursor_moved)
        self._byte_text.installEventFilter(self)
        self._byte_search = SearchBar(self._byte_text)

        byte_group = QGroupBox("Bytecode")
        byte_lay = QVBoxLayout(byte_group)
        byte_lay.setContentsMargins(4, 4, 4, 4)
        byte_lay.addWidget(self._byte_search)
        byte_lay.addWidget(self._byte_text)

        # Painel direito — Código recuperado (com SearchBar)
        self._rec_text = QPlainTextEdit()
        self._rec_text.setReadOnly(True)
        self._rec_text.setFont(mono)
        self._py_highlighter = PythonHighlighter(self._rec_text.document())
        self._rec_text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._rec_text.customContextMenuRequested.connect(self._recovered_context_menu)
        self._rec_text.cursorPositionChanged.connect(self._on_rec_cursor_moved)
        self._rec_text.installEventFilter(self)
        self._rec_search = SearchBar(self._rec_text)

        rec_group = QGroupBox("Código recuperado")
        rec_lay = QVBoxLayout(rec_group)
        rec_lay.setContentsMargins(4, 4, 4, 4)
        rec_lay.addWidget(self._rec_search)
        rec_lay.addWidget(self._rec_text)

        h_splitter.addWidget(left)
        h_splitter.addWidget(byte_group)
        h_splitter.addWidget(rec_group)
        h_splitter.setSizes([LEFT_WIDTH, 540, 540])
        h_splitter.setStretchFactor(0, 0)
        h_splitter.setStretchFactor(1, 1)
        h_splitter.setStretchFactor(2, 1)

        # ---- Painel inferior — Hex Dump (esquerda) + Comentários (direita) ----
        self._hex_text = QPlainTextEdit()
        self._hex_text.setReadOnly(True)
        self._hex_text.setFont(mono)
        self._hex_text.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._hex_text.customContextMenuRequested.connect(self._hex_context_menu)
        self._hex_group = self._make_group("Hex Dump", self._hex_text)

        comments_group = self._make_group("Comentários", self._list_comments)

        # Console Python
        self._console = PythonConsole()
        console_group = self._make_group("Console Python", self._console)
        console_group.setVisible(False)
        self._console_group = console_group

        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        bottom_splitter.addWidget(self._hex_group)
        bottom_splitter.addWidget(comments_group)
        bottom_splitter.addWidget(console_group)
        bottom_splitter.setSizes([500, 250, 250])
        bottom_splitter.setStretchFactor(0, 1)
        bottom_splitter.setStretchFactor(1, 0)
        bottom_splitter.setStretchFactor(2, 0)

        # ---- Splitter vertical ----
        v_splitter = QSplitter(Qt.Orientation.Vertical)
        v_splitter.addWidget(h_splitter)
        v_splitter.addWidget(bottom_splitter)
        v_splitter.setSizes([600, 200])
        v_splitter.setStretchFactor(0, 1)
        v_splitter.setStretchFactor(1, 0)

        root.addWidget(topbar)
        root.addWidget(self._tab_bar)
        root.addWidget(v_splitter)
        return page

    @staticmethod
    def _make_group(title: str, widget: QWidget) -> QGroupBox:
        box = QGroupBox(title)
        lay = QVBoxLayout(box)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.addWidget(widget)
        return box

    # ------------------------------------------------------------------
    # Barra de menus + atalhos
    # ------------------------------------------------------------------

    def _build_menus(self):
        menubar = self.menuBar()

        # --- Arquivo ---
        file_menu = menubar.addMenu("&Arquivo")

        act = file_menu.addAction("&Abrir...")
        act.setShortcut(QKeySequence("Ctrl+O"))
        act.triggered.connect(self.pick_and_load)

        act = file_menu.addAction("&Recarregar")
        act.setShortcut(QKeySequence("Ctrl+R"))
        act.triggered.connect(self.reload_current)

        act = file_menu.addAction("&Salvar código...")
        act.setShortcut(QKeySequence("Ctrl+S"))
        act.triggered.connect(self._save_recovered)

        file_menu.addSeparator()

        act = file_menu.addAction("&Comparar...")
        act.setShortcut(QKeySequence("Ctrl+D"))
        act.triggered.connect(self._compare_files)

        file_menu.addSeparator()
        self._recent_menu = file_menu.addMenu("Arquivos &recentes")
        file_menu.addSeparator()

        act = file_menu.addAction("Fechar a&ba")
        act.setShortcut(QKeySequence("Ctrl+W"))
        act.triggered.connect(self._close_current_tab)

        act = file_menu.addAction("&Sair")
        act.setShortcut(QKeySequence("Ctrl+Q"))
        act.triggered.connect(self.close)

        # --- Editar ---
        edit_menu = menubar.addMenu("&Editar")

        act = edit_menu.addAction("&Buscar...")
        act.setShortcut(QKeySequence("Ctrl+F"))
        act.triggered.connect(self._toggle_search)

        act = edit_menu.addAction("Alternar &Bookmark")
        act.setShortcut(QKeySequence("Ctrl+B"))
        act.triggered.connect(self._toggle_bookmark)

        edit_menu.addSeparator()

        act = edit_menu.addAction("Re&nomear... (N)")
        act.triggered.connect(self._rename_at_cursor)

        act = edit_menu.addAction("&Comentar... (;)")
        act.triggered.connect(self._add_comment)

        # --- Visualizar ---
        view_menu = menubar.addMenu("&Visualizar")

        self._act_hex = view_menu.addAction("Painel &Hex Dump")
        self._act_hex.setCheckable(True)
        self._act_hex.setChecked(True)
        self._act_hex.triggered.connect(self._toggle_hex_panel)

        self._act_sync = view_menu.addAction("&Sincronizar navegação")
        self._act_sync.setCheckable(True)
        self._act_sync.setChecked(True)
        self._act_sync.triggered.connect(self._toggle_sync_nav)

        view_menu.addSeparator()

        act = view_menu.addAction("&Estatísticas...")
        act.setShortcut(QKeySequence("Ctrl+I"))
        act.triggered.connect(self._show_stats)

        act = view_menu.addAction("&Grafo de fluxo (CFG)...")
        act.triggered.connect(self._show_cfg)

        self._act_console = view_menu.addAction("Console &Python")
        self._act_console.setCheckable(True)
        self._act_console.setChecked(False)
        self._act_console.setShortcut(QKeySequence("F12"))
        self._act_console.triggered.connect(self._toggle_console)

        # --- Ajuda ---
        help_menu = menubar.addMenu("Aj&uda")
        act = help_menu.addAction("&Sobre")
        act.triggered.connect(self._show_about)
        act = help_menu.addAction("&Atalhos de teclado")
        act.triggered.connect(self._show_shortcuts)

        self._update_recent_menu()

    def _toggle_search(self):
        focus = QApplication.focusWidget()
        rec_focused = (focus is self._rec_text or
                       (focus is not None and self._rec_search.isAncestorOf(focus)))
        if rec_focused:
            self._rec_search.show_bar()
        else:
            self._byte_search.show_bar()

    def _toggle_hex_panel(self, checked: bool):
        self._hex_group.setVisible(checked)

    def _toggle_sync_nav(self, checked: bool):
        self._sync_nav = checked

    def _show_about(self):
        QMessageBox.about(
            self, "Sobre",
            f"<h3>{APP_TITLE}</h3>"
            "<p>Decompilador de bytecode Python 3.12 e MicroPython (.mpy v6).</p>"
            "<p>Suporta arquivos .pyc (CPython 3.12) e .mpy (MicroPython v6).</p>",
        )

    def _show_shortcuts(self):
        QMessageBox.information(
            self, "Atalhos de teclado",
            "<table>"
            "<tr><td><b>Ctrl+O</b></td><td>&nbsp;&nbsp;Abrir arquivo</td></tr>"
            "<tr><td><b>Ctrl+R</b></td><td>&nbsp;&nbsp;Recarregar</td></tr>"
            "<tr><td><b>Ctrl+S</b></td><td>&nbsp;&nbsp;Salvar código recuperado</td></tr>"
            "<tr><td><b>Ctrl+F</b></td><td>&nbsp;&nbsp;Buscar no painel</td></tr>"
            "<tr><td><b>Ctrl+B</b></td><td>&nbsp;&nbsp;Alternar bookmark</td></tr>"
            "<tr><td><b>Ctrl+I</b></td><td>&nbsp;&nbsp;Estatísticas</td></tr>"
            "<tr><td><b>N</b></td><td>&nbsp;&nbsp;Renomear (no painel de código)</td></tr>"
            "<tr><td><b>;</b></td><td>&nbsp;&nbsp;Adicionar comentário</td></tr>"
            "<tr><td><b>Ctrl+W</b></td><td>&nbsp;&nbsp;Fechar aba</td></tr>"
            "<tr><td><b>Ctrl+D</b></td><td>&nbsp;&nbsp;Comparar arquivos</td></tr>"
            "<tr><td><b>F12</b></td><td>&nbsp;&nbsp;Console Python</td></tr>"
            "<tr><td><b>Ctrl+Q</b></td><td>&nbsp;&nbsp;Sair</td></tr>"
            "<tr><td><b>Enter</b></td><td>&nbsp;&nbsp;Próximo resultado</td></tr>"
            "<tr><td><b>Shift+Enter</b></td><td>&nbsp;&nbsp;Resultado anterior</td></tr>"
            "<tr><td><b>Esc</b></td><td>&nbsp;&nbsp;Fechar busca</td></tr>"
            "</table>",
        )

    # ------------------------------------------------------------------
    # Status bar
    # ------------------------------------------------------------------

    def _setup_statusbar(self):
        self._status_file  = QLabel("")
        self._status_stats = QLabel("")
        self._status_time  = QLabel("")
        bar = self.statusBar()
        bar.addWidget(self._status_file, 1)
        bar.addWidget(self._status_stats, 1)
        bar.addPermanentWidget(self._status_time)

    def _update_statusbar(self):
        path = self._path_input.text()
        if not path or not os.path.exists(path):
            return
        name = os.path.basename(path)
        size = os.path.getsize(path)
        if size < 1024:
            sz = f"{size} B"
        elif size < 1024 * 1024:
            sz = f"{size / 1024:.1f} KB"
        else:
            sz = f"{size / (1024 * 1024):.1f} MB"
        self._status_file.setText(f"  {name} \u00b7 {sz}")
        n_funcs = len(self._recovered_funcs)
        n_objs  = len(self._addr_items)
        self._status_stats.setText(f"{n_objs} code objects \u00b7 {n_funcs} funções")
        elapsed = time.perf_counter() - self._load_start
        self._status_time.setText(f"Recuperado em {elapsed:.2f}s  ")

    # ------------------------------------------------------------------
    # Drag-and-drop
    # ------------------------------------------------------------------

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            for url in event.mimeData().urls():
                ext = os.path.splitext(url.toLocalFile())[1].lower()
                if ext in SUPPORTED_EXTENSIONS:
                    event.acceptProposedAction()
                    self._drop_overlay.setGeometry(self.rect())
                    self._drop_overlay.setVisible(True)
                    self._drop_overlay.raise_()
                    return
        event.ignore()

    def dragMoveEvent(self, event):
        event.acceptProposedAction()

    def dragLeaveEvent(self, event):
        self._drop_overlay.setVisible(False)

    def dropEvent(self, event):
        self._drop_overlay.setVisible(False)
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            ext = os.path.splitext(path)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                event.acceptProposedAction()
                self.load_file(path)
                return
        event.ignore()

    # ------------------------------------------------------------------
    # Navegação entre páginas
    # ------------------------------------------------------------------

    def _show_splash(self):
        self._stack.setCurrentIndex(0)
        self.resize(700, 400)

    def _show_main(self):
        self._stack.setCurrentIndex(1)
        self.resize(1400, 800)

    # ------------------------------------------------------------------
    # Ações
    # ------------------------------------------------------------------

    def pick_and_load(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Selecione um arquivo de bytecode", "",
            FILE_FILTER + ";;Todos (*.*)",
        )
        if path:
            self.load_file(path)

    def reload_current(self):
        path = self._path_input.text().strip()
        if path:
            self.load_file(path)

    def load_file(self, path: str):
        if not os.path.exists(path):
            QMessageBox.critical(self, "Erro", "Arquivo não encontrado.")
            return
        try:
            fmt = _detect_format(path)
        except ValueError as exc:
            QMessageBox.critical(self, "Formato não suportado", str(exc))
            return

        # Verifica se já está aberto em alguma aba
        for i in range(self._tab_bar.count()):
            sid = self._tab_bar.tabData(i)
            if self._sessions.get(sid, {}).get("path") == path:
                self._tab_bar.setCurrentIndex(i)
                return

        if self._tab_bar.count() >= 10:
            QMessageBox.warning(self, "Limite", "Máximo de 10 abas simultâneas.")
            return

        runner = run_engine if fmt == "cpython" else run_mpy_engine
        if self._worker and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait()

        # Salva sessão atual antes de trocar
        if self._active_sid >= 0:
            self._save_session(self._active_sid)

        # Cria nova aba
        sid = self._next_sid
        self._next_sid += 1
        self._sessions[sid] = {"path": path}
        self._tab_bar.blockSignals(True)
        idx = self._tab_bar.addTab(os.path.basename(path))
        self._tab_bar.setTabData(idx, sid)
        self._tab_bar.setTabToolTip(idx, path)
        self._tab_bar.setCurrentIndex(idx)
        self._tab_bar.blockSignals(False)
        self._active_sid = sid

        self._path_input.setText(path)
        self._show_main()
        self._set_busy(True)
        self._load_start = time.perf_counter()

        with open(path, "rb") as f:
            raw_bytes = f.read()
        self._hex_text.setPlainText(format_hex_dump(raw_bytes))

        self._worker = EngineWorker(path, runner=runner)
        self._worker.result.connect(self._on_engine_result)
        self._worker.error.connect(self._on_engine_error)
        self._worker.start()
        self._add_to_recent(path)

    def _set_busy(self, busy: bool):
        if busy:
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        else:
            QApplication.restoreOverrideCursor()
        for btn in (self._btn_open, self._btn_reload, self._btn_close_tab, self._btn_splash_open):
            btn.setEnabled(not busy)

    def _on_engine_result(self, byte_txt: str, rec_txt: str, meta: dict):
        self._set_busy(False)
        self.bytecode_meta = meta

        self._byte_text.setPlainText(byte_txt)
        self._rec_text.setPlainText(rec_txt)

        self._func_meta, self._addr_items, self._strings = parse_bytecode(byte_txt)
        self._recovered_funcs = split_recovered_functions(rec_txt)
        self._recovered_full  = rec_txt

        if meta.get("__mpy__"):
            self._lbl_format_info.setText(parse_mpy_summary(byte_txt, meta))
            self._lbl_format_info.setVisible(True)
        else:
            self._lbl_format_info.setVisible(False)

        self._populate_lists()
        self._build_line_maps()
        self._update_statusbar()
        self._load_bookmarks()
        self._load_annotations()
        self._render_comment_highlights()

        # Atualiza namespace do console
        self._console.set_namespace({
            "app": self, "bytecode": byte_txt,
            "recovered": rec_txt, "meta": meta,
        })

    def _on_engine_error(self, msg: str):
        self._set_busy(False)
        # Remove a aba que falhou
        if self._active_sid >= 0:
            for i in range(self._tab_bar.count()):
                if self._tab_bar.tabData(i) == self._active_sid:
                    self._sessions.pop(self._active_sid, None)
                    self._tab_bar.blockSignals(True)
                    self._tab_bar.removeTab(i)
                    self._tab_bar.blockSignals(False)
                    break
            if self._tab_bar.count() == 0:
                self._active_sid = -1
                self._show_splash()
            else:
                idx = self._tab_bar.currentIndex()
                self._active_sid = self._tab_bar.tabData(idx) if idx >= 0 else -1
                if self._active_sid >= 0:
                    self._restore_session(self._active_sid)
        QMessageBox.critical(
            self, "Incompatível",
            f"Falha ao processar o bytecode.\n\n{SUPPORTED_HINT}\n\n{msg}",
        )

    # ------------------------------------------------------------------
    # População das listas e árvore
    # ------------------------------------------------------------------

    def _populate_lists(self):
        # Constantes (categorizada)
        self._tree_consts.clear()
        bc_text = self._byte_text.toPlainText()
        cats = parse_all_constants(bc_text)
        _CAT_LABELS = {
            "str": "Strings", "num": "Números", "bytes": "Bytes",
            "tuple": "Tuplas", "frozenset": "Frozensets",
            "bool": "Booleanos", "None": "None", "outro": "Outros",
        }
        for cat, values in cats.items():
            label = _CAT_LABELS.get(cat, cat)
            parent = QTreeWidgetItem(self._tree_consts, [f"{label} ({len(values)})"])
            parent.setData(0, Qt.ItemDataRole.UserRole, None)
            for v in values:
                child = QTreeWidgetItem(parent, [v])
                child.setData(0, Qt.ItemDataRole.UserRole, v)
        self._tree_consts.expandAll()

        # Árvore hierárquica de code objects
        self._tree_funcs.clear()
        self._view_all_item = QTreeWidgetItem(self._tree_funcs, ["\u2039View All\u203a"])
        self._view_all_item.setData(0, Qt.ItemDataRole.UserRole, "__view_all__")

        hierarchy = self.bytecode_meta.get("__hierarchy__")
        if hierarchy and hierarchy.get("children"):
            self._build_tree_from_hierarchy(self._tree_funcs, hierarchy.get("children", []))
        else:
            # Fallback: lista flat
            for name in sorted(self._recovered_funcs.keys()):
                item = QTreeWidgetItem(self._tree_funcs, [f"\u0192 {name}"])
                item.setData(0, Qt.ItemDataRole.UserRole, name)

        self._tree_funcs.expandAll()
        self._tree_funcs.setCurrentItem(self._view_all_item)

        self._list_addrs.clear()
        for addr, name in self._addr_items:
            self._list_addrs.addItem(f"{addr}  {name}")

        # Exception handlers
        self._tree_handlers.clear()
        self._handlers = parse_exception_handlers(bc_text)
        _TYPE_ICONS = {"except": "E", "finally": "F", "with": "W"}
        func_groups: dict[str, QTreeWidgetItem] = {}
        for h in self._handlers:
            func = h["func"]
            if func not in func_groups:
                func_groups[func] = QTreeWidgetItem(self._tree_handlers, [func])
                func_groups[func].setData(0, Qt.ItemDataRole.UserRole, None)
            icon = _TYPE_ICONS.get(h["type"], "?")
            item = QTreeWidgetItem(func_groups[func], [f"[{icon}] {h['detail']}"])
            item.setData(0, Qt.ItemDataRole.UserRole, h["line"])
        self._tree_handlers.expandAll()

    def _build_tree_from_hierarchy(self, parent, children):
        for child in children:
            name = child.get("name", "?")
            obj_type = child.get("type", "function")
            prefix = _TYPE_PREFIX.get(obj_type, "")
            display = f"{prefix}{name}"

            item = QTreeWidgetItem(parent, [display])
            item.setData(0, Qt.ItemDataRole.UserRole, name)

            if child.get("children"):
                self._build_tree_from_hierarchy(item, child["children"])

    # ------------------------------------------------------------------
    # Navegação nas listas
    # ------------------------------------------------------------------

    def _on_const_select(self, current: QTreeWidgetItem | None, _prev):
        if current is None:
            return
        val = current.data(0, Qt.ItemDataRole.UserRole)
        if val is None:
            return
        self._scroll_to_in_bytecode(val)

    def _on_handler_select(self, current: QTreeWidgetItem | None, _prev):
        if current is None:
            return
        line = current.data(0, Qt.ItemDataRole.UserRole)
        if line is None:
            return
        self._scroll_to_line(line)

    def _on_func_select(self, current: QTreeWidgetItem | None, _prev):
        if current is None:
            return
        name = current.data(0, Qt.ItemDataRole.UserRole)
        if not name or name == "__view_all__":
            self._rec_text.setPlainText(self._recovered_full)
            return

        code = self._recovered_funcs.get(name, "")
        if code:
            self._sync_guard = True
            self._rec_text.setPlainText(code)
            self._sync_guard = False
        else:
            # Code object sem código recuperado individual (lambda, genexpr...)
            # Mostra tudo e tenta navegar ao bytecode
            self._rec_text.setPlainText(self._recovered_full)

        meta = self._func_meta.get(name)
        if meta and meta.get("addr"):
            self._scroll_to_in_bytecode(meta["addr"])

    def _on_addr_select(self, current: QListWidgetItem | None, _prev):
        if current is None:
            return
        parts = current.text().split(maxsplit=1)
        if len(parts) != 2:
            return
        addr, name = parts
        info = self.bytecode_meta.get(name)
        if info and info.get("line"):
            self._scroll_to_line(info["line"])
            return
        self._scroll_to_in_bytecode(f"Disassembly of <code object {name} at {addr}")

    # ------------------------------------------------------------------
    # Navegação bidirecional (sync)
    # ------------------------------------------------------------------

    def _build_line_maps(self):
        """Constrói mapeamento linha→função para ambos os painéis."""
        # Bytecode: cada code object vai do seu header até o próximo
        self._bc_line_to_func = {}
        entries = []
        for _addr, name in self._addr_items:
            meta = self._func_meta.get(name, {})
            line = meta.get("line")
            if line is not None:
                entries.append((line - 1, name))  # 0-based
        entries.sort()
        total_bc = self._byte_text.document().blockCount()
        for i, (start, name) in enumerate(entries):
            end = entries[i + 1][0] if i + 1 < len(entries) else total_bc
            for ln in range(start, end):
                self._bc_line_to_func[ln] = name

        # Recovered: cada função vai do início da sua def até a próxima
        self._rc_line_to_func = {}
        for name, text in self._recovered_funcs.items():
            pos = self._recovered_full.find(text)
            if pos < 0:
                continue
            start_line = self._recovered_full[:pos].count("\n")
            n_lines = text.count("\n") + 1
            for ln in range(start_line, start_line + n_lines):
                self._rc_line_to_func[ln] = name

    def _on_byte_cursor_moved(self):
        """Quando o cursor se move no bytecode, destaca a função correspondente no código."""
        if self._sync_guard or not self._sync_nav:
            return
        line = self._byte_text.textCursor().blockNumber()
        name = self._bc_line_to_func.get(line)
        if not name:
            return
        # Destaca a faixa da função no painel de código recuperado
        self._highlight_func_in_recovered(name)

    def _on_rec_cursor_moved(self):
        """Quando o cursor se move no código, destaca a seção correspondente no bytecode."""
        if self._sync_guard or not self._sync_nav:
            return
        line = self._rec_text.textCursor().blockNumber()
        # Calcula a linha absoluta no texto completo quando View All está ativo
        name = self._rc_line_to_func.get(line)
        if not name:
            return
        # Destaca a faixa do code object no bytecode
        self._highlight_func_in_bytecode(name)

    def _highlight_func_in_recovered(self, name: str):
        """Aplica highlight sutil na faixa da função no painel de código."""
        text = self._recovered_funcs.get(name)
        if not text:
            return
        pos = self._recovered_full.find(text)
        if pos < 0:
            return
        # Só funciona no modo "View All"
        current = self._tree_funcs.currentItem()
        if current and current.data(0, Qt.ItemDataRole.UserRole) != "__view_all__":
            return

        start_line = self._recovered_full[:pos].count("\n")
        n_lines = text.count("\n") + 1
        hl_color = "#1a3a5a" if _is_dark() else "#d0e8ff"
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(hl_color))

        selections = []
        doc = self._rec_text.document()
        for ln in range(start_line, start_line + n_lines):
            block = doc.findBlockByNumber(ln)
            if not block.isValid():
                continue
            cursor = QTextCursor(block)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            sel.cursor = cursor
            selections.append(sel)
        self._rec_text.setExtraSelections(selections)

    def _highlight_func_in_bytecode(self, name: str):
        """Aplica highlight sutil na faixa do code object no bytecode."""
        meta = self._func_meta.get(name, {})
        start = meta.get("line")
        if start is None:
            return
        start -= 1  # 0-based

        # Acha o fim da seção (próximo header ou fim do texto)
        entries = sorted(
            (m.get("line", 0) - 1 for n, m in self._func_meta.items() if m.get("line")),
        )
        end = self._byte_text.document().blockCount()
        for e in entries:
            if e > start:
                end = e
                break

        hl_color = "#1a3a5a" if _is_dark() else "#d0e8ff"
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(hl_color))

        selections = []
        doc = self._byte_text.document()
        for ln in range(start, end):
            block = doc.findBlockByNumber(ln)
            if not block.isValid():
                continue
            cursor = QTextCursor(block)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            sel.cursor = cursor
            selections.append(sel)
        self._byte_text.setExtraSelections(selections)

    # ------------------------------------------------------------------
    # Helpers de scroll/highlight no painel de bytecode
    # ------------------------------------------------------------------

    def _scroll_to_in_bytecode(self, needle: str):
        self._byte_text.setExtraSelections([])
        cursor = self._byte_text.document().find(needle)
        if cursor.isNull():
            return
        hl_color = "#7a6300" if _is_dark() else "#ffe080"
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(hl_color))
        sel = QTextEdit.ExtraSelection()
        sel.format = fmt
        sel.cursor = cursor
        self._byte_text.setExtraSelections([sel])
        self._byte_text.setTextCursor(cursor)
        self._byte_text.ensureCursorVisible()

    def _scroll_to_line(self, line_no: int):
        block = self._byte_text.document().findBlockByLineNumber(line_no - 1)
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        self._byte_text.setTextCursor(cursor)
        self._byte_text.ensureCursorVisible()

    # ------------------------------------------------------------------
    # Exportar código recuperado (Save As)
    # ------------------------------------------------------------------

    def _save_recovered(self):
        text = self._rec_text.toPlainText()
        if not text.strip():
            self.statusBar().showMessage("Nenhum código para salvar.", 3000)
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Salvar código recuperado", "",
            "Python Files (*.py);;Text Files (*.txt);;Todos (*.*)",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        self.statusBar().showMessage(f"Salvo em {path}", 5000)

    # ------------------------------------------------------------------
    # Histórico de arquivos recentes
    # ------------------------------------------------------------------

    def _add_to_recent(self, path: str):
        recent = self._settings.value("recent_files", [])
        if not isinstance(recent, list):
            recent = [recent] if recent else []
        if path in recent:
            recent.remove(path)
        recent.insert(0, path)
        recent = recent[:_MAX_RECENT]
        self._settings.setValue("recent_files", recent)
        self._update_recent_menu()

    def _update_recent_menu(self):
        self._recent_menu.clear()
        recent = self._settings.value("recent_files", [])
        if not isinstance(recent, list):
            recent = [recent] if recent else []
        recent = [p for p in recent if os.path.exists(p)]
        if not recent:
            act = self._recent_menu.addAction("(vazio)")
            act.setEnabled(False)
            return
        for path in recent:
            name = os.path.basename(path)
            act = self._recent_menu.addAction(f"{name}  \u2014  {path}")
            act.triggered.connect(lambda checked, p=path: self.load_file(p))
        self._recent_menu.addSeparator()
        act = self._recent_menu.addAction("Limpar histórico")
        act.triggered.connect(self._clear_recent)

    def _clear_recent(self):
        self._settings.setValue("recent_files", [])
        self._update_recent_menu()

    # ------------------------------------------------------------------
    # Bookmarks
    # ------------------------------------------------------------------

    def _bm_key(self) -> str | None:
        path = self._path_input.text()
        if not path:
            return None
        h = hashlib.sha256(path.encode()).hexdigest()[:16]
        return f"bookmarks/{h}"

    def _toggle_bookmark(self):
        focus = QApplication.focusWidget()
        if focus is self._rec_text:
            panel = "recovered"
            text_edit = self._rec_text
        elif focus is self._byte_text:
            panel = "bytecode"
            text_edit = self._byte_text
        else:
            self.statusBar().showMessage(
                "Clique no painel de bytecode ou código antes de adicionar um bookmark.", 3000)
            return

        line = text_edit.textCursor().blockNumber()
        block_text = text_edit.document().findBlockByNumber(line).text()[:60].strip()

        for i, bm in enumerate(self._bookmarks):
            if bm["panel"] == panel and bm["line"] == line:
                self._bookmarks.pop(i)
                self._refresh_bookmarks()
                self._save_bookmarks()
                self.statusBar().showMessage("Bookmark removido.", 2000)
                return

        prefix = "BC" if panel == "bytecode" else "RC"
        self._bookmarks.append({
            "panel": panel, "line": line,
            "label": f"[{prefix}] L{line + 1}: {block_text}",
        })
        self._refresh_bookmarks()
        self._save_bookmarks()
        self.statusBar().showMessage("Bookmark adicionado.", 2000)

    def _on_bookmark_click(self, item: QListWidgetItem):
        idx = self._list_bookmarks.row(item)
        if idx < 0 or idx >= len(self._bookmarks):
            return
        bm = self._bookmarks[idx]

        if bm["panel"] == "recovered":
            self._tree_funcs.setCurrentItem(self._view_all_item)
            target = self._rec_text
        else:
            target = self._byte_text

        block = target.document().findBlockByNumber(bm["line"])
        if block.isValid():
            cursor = QTextCursor(block)
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                QTextCursor.MoveMode.KeepAnchor)
            target.setTextCursor(cursor)
            target.setFocus()
            target.centerCursor()

            hl_color = "#7a6300" if _is_dark() else "#ffe080"
            fmt = QTextCharFormat()
            fmt.setBackground(QColor(hl_color))
            sel = QTextEdit.ExtraSelection()
            sel.format = fmt
            sel.cursor = cursor
            target.setExtraSelections([sel])

    def _refresh_bookmarks(self):
        self._list_bookmarks.clear()
        for bm in self._bookmarks:
            self._list_bookmarks.addItem(bm["label"])

    def _save_bookmarks(self):
        key = self._bm_key()
        if key:
            self._settings.setValue(key, json.dumps(self._bookmarks))

    def _load_bookmarks(self):
        self._bookmarks = []
        key = self._bm_key()
        if key:
            raw = self._settings.value(key, "[]")
            try:
                self._bookmarks = json.loads(raw) if isinstance(raw, str) else []
            except (json.JSONDecodeError, TypeError):
                self._bookmarks = []
        self._refresh_bookmarks()

    # ------------------------------------------------------------------
    # Menus de contexto (Copy as...)
    # ------------------------------------------------------------------

    def _bytecode_context_menu(self, pos):
        menu = self._byte_text.createStandardContextMenu()
        menu.addSeparator()
        act = menu.addAction("Copiar como Markdown")
        act.triggered.connect(lambda: self._copy_as_markdown(self._byte_text))

        cursor = self._byte_text.cursorForPosition(pos)
        cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        word = cursor.selectedText().strip()
        if word:
            menu.addSeparator()
            act = menu.addAction(f"Buscar referências de '{word}'")
            act.triggered.connect(lambda: self._show_xrefs(word))

        act = menu.addAction("Comentar...")
        act.triggered.connect(self._add_comment)

        menu.exec(self._byte_text.mapToGlobal(pos))

    def _recovered_context_menu(self, pos):
        menu = self._rec_text.createStandardContextMenu()
        menu.addSeparator()
        act = menu.addAction("Copiar como Markdown")
        act.triggered.connect(lambda: self._copy_as_markdown(self._rec_text, "python"))
        act = menu.addAction("Copiar função inteira")
        act.triggered.connect(self._copy_current_function)
        menu.addSeparator()

        cursor = self._rec_text.cursorForPosition(pos)
        cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        word = cursor.selectedText().strip()
        if word:
            act = menu.addAction(f"Buscar referências de '{word}'")
            act.triggered.connect(lambda: self._show_xrefs(word))

        act = menu.addAction("Renomear...")
        act.triggered.connect(self._rename_at_cursor)
        act = menu.addAction("Comentar...")
        act.triggered.connect(self._add_comment)

        menu.exec(self._rec_text.mapToGlobal(pos))

    def _hex_context_menu(self, pos):
        menu = self._hex_text.createStandardContextMenu()
        menu.addSeparator()
        act = menu.addAction("Copiar somente hex")
        act.triggered.connect(self._copy_hex_only)
        menu.exec(self._hex_text.mapToGlobal(pos))

    def _copy_as_markdown(self, text_edit: QPlainTextEdit, lang: str = ""):
        cursor = text_edit.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText().replace("\u2029", "\n")
        else:
            text = text_edit.toPlainText()
        QApplication.clipboard().setText(f"```{lang}\n{text}\n```")
        self.statusBar().showMessage("Copiado como Markdown.", 2000)

    def _copy_current_function(self):
        item = self._tree_funcs.currentItem()
        if item is None:
            return
        name = item.data(0, Qt.ItemDataRole.UserRole)
        if not name or name == "__view_all__":
            text = self._recovered_full
            display = "tudo"
        else:
            text = self._recovered_funcs.get(name, "")
            display = name
        QApplication.clipboard().setText(text)
        self.statusBar().showMessage(f"Função copiada: {display}", 2000)

    def _copy_hex_only(self):
        cursor = self._hex_text.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText().replace("\u2029", "\n")
        else:
            text = self._hex_text.toPlainText()
        lines = []
        for line in text.split("\n"):
            if "|" in line:
                hex_part = line.split("|")[0]
                parts = hex_part.split("  ", 1)
                if len(parts) > 1:
                    lines.append(parts[1].strip())
            elif line.strip():
                lines.append(line.strip())
        QApplication.clipboard().setText("\n".join(lines))
        self.statusBar().showMessage("Hex copiado.", 2000)

    # ------------------------------------------------------------------
    # Event filter (atalhos N e ; nos painéis de texto)
    # ------------------------------------------------------------------

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.KeyPress and obj in (self._byte_text, self._rec_text):
            if event.key() == Qt.Key.Key_N and not event.modifiers():
                self._rename_at_cursor()
                return True
            if event.key() == Qt.Key.Key_Semicolon and not event.modifiers():
                self._add_comment()
                return True
        return super().eventFilter(obj, event)

    # ------------------------------------------------------------------
    # Renomear variáveis/funções (#10)
    # ------------------------------------------------------------------

    def _rename_at_cursor(self):
        """Renomeia o identificador sob o cursor no código recuperado."""
        focus = QApplication.focusWidget()
        if focus is self._rec_text:
            text_edit = self._rec_text
        elif focus is self._byte_text:
            text_edit = self._byte_text
        else:
            text_edit = self._rec_text

        cursor = text_edit.textCursor()
        cursor.select(QTextCursor.SelectionType.WordUnderCursor)
        old_name = cursor.selectedText().strip()

        if not old_name:
            self.statusBar().showMessage("Posicione o cursor sobre um identificador.", 3000)
            return

        new_name, ok = QInputDialog.getText(
            self, "Renomear", f"Renomear '{old_name}' para:", text=old_name,
        )
        if not ok or not new_name.strip() or new_name.strip() == old_name:
            return

        new_name = new_name.strip()
        self._annotations["renames"][old_name] = new_name
        self._save_current_annotations()
        self._apply_renames_to_display()
        self.statusBar().showMessage(f"Renomeado: {old_name} \u2192 {new_name}", 3000)

    def _apply_renames_to_display(self):
        """Aplica todas as renomeações ao texto recuperado exibido."""
        renames = self._annotations.get("renames", {})
        if not renames:
            return

        # Aplica ao texto completo
        displayed = apply_renames(self._recovered_full, renames)

        # Verifica se está em View All ou função específica
        current = self._tree_funcs.currentItem()
        if current and current.data(0, Qt.ItemDataRole.UserRole) != "__view_all__":
            name = current.data(0, Qt.ItemDataRole.UserRole)
            func_code = self._recovered_funcs.get(name, "")
            if func_code:
                displayed = apply_renames(func_code, renames)

        self._sync_guard = True
        self._rec_text.setPlainText(displayed)
        self._sync_guard = False

    # ------------------------------------------------------------------
    # Comentários (#11)
    # ------------------------------------------------------------------

    def _add_comment(self):
        """Adiciona ou edita um comentário na linha atual."""
        focus = QApplication.focusWidget()
        if focus is self._rec_text:
            panel = "comments_rc"
            text_edit = self._rec_text
            prefix = "RC"
        elif focus is self._byte_text:
            panel = "comments_bc"
            text_edit = self._byte_text
            prefix = "BC"
        else:
            self.statusBar().showMessage(
                "Clique no painel de bytecode ou código antes de comentar.", 3000)
            return

        line = text_edit.textCursor().blockNumber()
        key = str(line + 1)  # 1-based
        existing = self._annotations.get(panel, {}).get(key, "")

        comment, ok = QInputDialog.getText(
            self, "Comentário", f"Comentário para [{prefix}] L{line + 1}:",
            text=existing,
        )
        if not ok:
            return

        if comment.strip():
            self._annotations.setdefault(panel, {})[key] = comment.strip()
        else:
            self._annotations.get(panel, {}).pop(key, None)

        self._save_current_annotations()
        self._render_comment_highlights()
        self._refresh_comments_list()
        self.statusBar().showMessage("Comentário salvo.", 2000)

    def _render_comment_highlights(self):
        """Aplica highlights verdes nas linhas com comentários."""
        hl_color = "#1a3a2a" if _is_dark() else "#d0f0d0"
        fmt = QTextCharFormat()
        fmt.setBackground(QColor(hl_color))

        for panel, text_edit in [("comments_bc", self._byte_text),
                                  ("comments_rc", self._rec_text)]:
            comments = self._annotations.get(panel, {})
            selections = []
            doc = text_edit.document()
            for key, comment_text in comments.items():
                try:
                    line = int(key) - 1  # 0-based
                except ValueError:
                    continue
                block = doc.findBlockByNumber(line)
                if not block.isValid():
                    continue
                cursor = QTextCursor(block)
                cursor.movePosition(QTextCursor.MoveOperation.EndOfBlock,
                                    QTextCursor.MoveMode.KeepAnchor)
                sel = QTextEdit.ExtraSelection()
                sel.format = fmt
                sel.cursor = cursor
                selections.append(sel)

                # Tooltip no bloco
                block_data = block.text()
                # Não há API nativa de tooltip por bloco no QPlainTextEdit,
                # mas podemos usar setToolTip no formato
                fmt_tip = QTextCharFormat()
                fmt_tip.setBackground(QColor(hl_color))
                fmt_tip.setToolTip(f"# {comment_text}")
                sel_tip = QTextEdit.ExtraSelection()
                sel_tip.format = fmt_tip
                sel_tip.cursor = cursor
                selections[-1] = sel_tip

            text_edit.setExtraSelections(selections)

    def _refresh_comments_list(self):
        """Atualiza a lista de comentários no painel esquerdo."""
        self._list_comments.clear()
        for panel, prefix in [("comments_bc", "BC"), ("comments_rc", "RC")]:
            comments = self._annotations.get(panel, {})
            for key in sorted(comments.keys(), key=lambda k: int(k) if k.isdigit() else 0):
                text = comments[key]
                self._list_comments.addItem(f"[{prefix}] L{key}: {text}")

    def _on_comment_click(self, item: QListWidgetItem):
        """Navega ao clicar em um comentário na lista."""
        text = item.text()
        if text.startswith("[BC]"):
            target = self._byte_text
        elif text.startswith("[RC]"):
            target = self._rec_text
            self._tree_funcs.setCurrentItem(self._view_all_item)
        else:
            return

        # Extrai número da linha

        m = re.search(r"L(\d+):", text)
        if not m:
            return
        line = int(m.group(1)) - 1  # 0-based

        block = target.document().findBlockByNumber(line)
        if block.isValid():
            cursor = QTextCursor(block)
            target.setTextCursor(cursor)
            target.setFocus()
            target.centerCursor()

    # ------------------------------------------------------------------
    # Anotações — persistência
    # ------------------------------------------------------------------

    def _load_annotations(self):
        """Carrega anotações do arquivo .annotations.json."""
        path = self._path_input.text()
        if not path:
            self._annotations = {"renames": {}, "comments_bc": {}, "comments_rc": {}}
            return
        self._annotations = load_annotations(path)
        if self._annotations.get("renames"):
            self._apply_renames_to_display()
        self._refresh_comments_list()

    def _save_current_annotations(self):
        """Salva anotações no arquivo .annotations.json."""
        path = self._path_input.text()
        if path:
            save_annotations(path, self._annotations)

    # ------------------------------------------------------------------
    # Cross-references (#8)
    # ------------------------------------------------------------------

    def _show_xrefs(self, word: str):
        """Busca e exibe todas as referências a 'word' nos dois painéis."""
        results = []

        for panel_name, text_edit in [("Bytecode", self._byte_text),
                                       ("Código", self._rec_text)]:
            doc = text_edit.document()
            block = doc.begin()
            while block.isValid():
                line_text = block.text()
                # Busca word-boundary
        
                if re.search(r"\b" + re.escape(word) + r"\b", line_text):
                    line_no = block.blockNumber() + 1
                    results.append((panel_name, line_no, line_text.strip()[:80], text_edit))
                block = block.next()

        if not results:
            self.statusBar().showMessage(f"Nenhuma referência a '{word}' encontrada.", 3000)
            return

        dlg = QDialog(self)
        dlg.setWindowTitle(f"Referências a '{word}' ({len(results)})")
        dlg.resize(650, 400)
        lay = QVBoxLayout(dlg)

        lbl = QLabel(f"<b>{len(results)} referências a '{word}':</b>")
        lay.addWidget(lbl)

        lst = QListWidget()
        for panel_name, line_no, text, _ in results:
            lst.addItem(f"[{panel_name}] L{line_no}: {text}")
        lay.addWidget(lst)

        def on_double_click(item):
            idx = lst.row(item)
            _, line_no, _, text_edit = results[idx]
            block = text_edit.document().findBlockByNumber(line_no - 1)
            if block.isValid():
                c = QTextCursor(block)
                text_edit.setTextCursor(c)
                text_edit.setFocus()
                text_edit.centerCursor()

        lst.itemDoubleClicked.connect(on_double_click)
        dlg.exec()

    # ------------------------------------------------------------------
    # Estatísticas (#15)
    # ------------------------------------------------------------------

    def _show_stats(self):
        """Abre o diálogo de estatísticas do bytecode."""
        bc = self._byte_text.toPlainText()
        rc = self._rec_text.toPlainText()
        if not bc.strip():
            self.statusBar().showMessage("Nenhum bytecode carregado.", 3000)
            return
        elapsed = time.perf_counter() - self._load_start
        path = self._path_input.text()
        dlg = StatsDialog(self, bc, rc, self.bytecode_meta, path, elapsed)
        dlg.exec()

    # ------------------------------------------------------------------
    # Gerenciamento de sessões (múltiplas abas)
    # ------------------------------------------------------------------

    def _save_session(self, sid: int):
        """Captura o estado atual nos dados da sessão."""
        s = self._sessions.get(sid)
        if s is None:
            return
        s["byte_txt"] = self._byte_text.toPlainText()
        s["rec_txt"] = self._rec_text.toPlainText()
        s["hex_txt"] = self._hex_text.toPlainText()
        s["bytecode_meta"] = self.bytecode_meta
        s["func_meta"] = self._func_meta
        s["addr_items"] = self._addr_items
        s["strings"] = self._strings
        s["recovered_funcs"] = self._recovered_funcs
        s["recovered_full"] = self._recovered_full
        s["bookmarks"] = self._bookmarks
        s["annotations"] = self._annotations
        s["bc_line_to_func"] = self._bc_line_to_func
        s["rc_line_to_func"] = self._rc_line_to_func
        s["handlers"] = getattr(self, "_handlers", [])
        s["format_info"] = self._lbl_format_info.text()
        s["format_visible"] = self._lbl_format_info.isVisible()
        s["load_start"] = self._load_start
        s["byte_scroll"] = self._byte_text.verticalScrollBar().value()
        s["rec_scroll"] = self._rec_text.verticalScrollBar().value()
        s["hex_scroll"] = self._hex_text.verticalScrollBar().value()

    def _restore_session(self, sid: int):
        """Restaura o estado da sessão nos widgets."""
        s = self._sessions.get(sid)
        if s is None or "byte_txt" not in s:
            return
        self._path_input.setText(s.get("path", ""))
        self._sync_guard = True
        self._byte_text.setPlainText(s.get("byte_txt", ""))
        self._rec_text.setPlainText(s.get("rec_txt", ""))
        self._hex_text.setPlainText(s.get("hex_txt", ""))
        self._sync_guard = False

        self.bytecode_meta = s.get("bytecode_meta", {})
        self._func_meta = s.get("func_meta", {})
        self._addr_items = s.get("addr_items", [])
        self._strings = s.get("strings", [])
        self._recovered_funcs = s.get("recovered_funcs", {})
        self._recovered_full = s.get("recovered_full", "")
        self._bookmarks = s.get("bookmarks", [])
        self._annotations = s.get("annotations", {"renames": {}, "comments_bc": {}, "comments_rc": {}})
        self._bc_line_to_func = s.get("bc_line_to_func", {})
        self._rc_line_to_func = s.get("rc_line_to_func", {})
        self._handlers = s.get("handlers", [])
        self._load_start = s.get("load_start", 0.0)

        fi = s.get("format_info", "")
        self._lbl_format_info.setText(fi)
        self._lbl_format_info.setVisible(s.get("format_visible", False))

        self._populate_lists()
        self._render_comment_highlights()
        self._refresh_comments_list()
        self._update_statusbar()

        # Restaura posições de scroll
        self._byte_text.verticalScrollBar().setValue(s.get("byte_scroll", 0))
        self._rec_text.verticalScrollBar().setValue(s.get("rec_scroll", 0))
        self._hex_text.verticalScrollBar().setValue(s.get("hex_scroll", 0))

        self._console.set_namespace({
            "app": self, "bytecode": s.get("byte_txt", ""),
            "recovered": s.get("rec_txt", ""), "meta": self.bytecode_meta,
        })

    def _switch_tab(self, idx: int):
        """Troca para a aba indicada."""
        if idx < 0:
            return
        new_sid = self._tab_bar.tabData(idx)
        if new_sid is None or new_sid == self._active_sid:
            return
        if self._active_sid >= 0:
            self._save_session(self._active_sid)
        self._active_sid = new_sid
        self._restore_session(new_sid)
        self._show_main()

    def _close_tab(self, idx: int):
        """Fecha a aba indicada."""
        sid = self._tab_bar.tabData(idx)
        session = self._sessions.get(sid, {})
        path = session.get("path", "")
        if path and session.get("annotations"):
            save_annotations(path, session["annotations"])

        self._sessions.pop(sid, None)
        self._tab_bar.blockSignals(True)
        self._tab_bar.removeTab(idx)
        self._tab_bar.blockSignals(False)

        if self._tab_bar.count() == 0:
            self._active_sid = -1
            self._show_splash()
        else:
            new_idx = self._tab_bar.currentIndex()
            new_sid = self._tab_bar.tabData(new_idx) if new_idx >= 0 else None
            if new_sid is not None and new_sid != self._active_sid:
                self._active_sid = new_sid
                self._restore_session(new_sid)

    def _close_current_tab(self):
        """Fecha a aba ativa."""
        idx = self._tab_bar.currentIndex()
        if idx >= 0:
            self._close_tab(idx)
        else:
            self._show_splash()

    # ------------------------------------------------------------------
    # Grafo de fluxo (CFG) (#12)
    # ------------------------------------------------------------------

    def _show_cfg(self):
        """Abre o diálogo de CFG."""
        if not self._func_meta:
            self.statusBar().showMessage("Nenhum bytecode carregado.", 3000)
            return
        dlg = CfgView(self, self._byte_text.toPlainText(), self._func_meta)
        dlg.exec()

    # ------------------------------------------------------------------
    # Diff (#13)
    # ------------------------------------------------------------------

    def _compare_files(self):
        """Abre um segundo arquivo e compara com o atual."""
        current_rc = self._rec_text.toPlainText()
        if not current_rc.strip():
            self.statusBar().showMessage("Carregue um arquivo antes de comparar.", 3000)
            return

        path, _ = QFileDialog.getOpenFileName(
            self, "Selecione o arquivo para comparar", "",
            FILE_FILTER + ";;Todos (*.*)",
        )
        if not path:
            return

        try:
            fmt = _detect_format(path)
        except ValueError as exc:
            QMessageBox.critical(self, "Formato não suportado", str(exc))
            return

        runner = run_engine if fmt == "cpython" else run_mpy_engine
        try:
            _, other_rc, _ = runner(path)
        except RuntimeError as exc:
            QMessageBox.critical(self, "Erro", str(exc))
            return

        label_a = os.path.basename(self._path_input.text())
        label_b = os.path.basename(path)
        dlg = DiffView(self, current_rc, other_rc, label_a, label_b)
        dlg.exec()

    # ------------------------------------------------------------------
    # Console Python (#20)
    # ------------------------------------------------------------------

    def _toggle_console(self, checked: bool):
        self._console_group.setVisible(checked)
        if checked:
            self._console.setFocus()

    # ------------------------------------------------------------------
    # Encerramento
    # ------------------------------------------------------------------

    def closeEvent(self, event):
        # Salva anotações de todas as sessões
        if self._active_sid >= 0:
            self._save_session(self._active_sid)
        for sid, session in self._sessions.items():
            path = session.get("path", "")
            annotations = session.get("annotations", {})
            if path and annotations:
                save_annotations(path, annotations)
        if self._worker and self._worker.isRunning():
            self._worker.quit()
            self._worker.wait()
        super().closeEvent(event)
