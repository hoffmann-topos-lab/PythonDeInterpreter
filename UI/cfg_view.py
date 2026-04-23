import math
import re
from collections import defaultdict, deque

from PySide6.QtCore import Qt, QPointF, QRectF, QTimer
from PySide6.QtGui import (
    QBrush, QColor, QFont, QKeySequence, QPainter, QPainterPath,
    QPen, QPolygonF, QShortcut,
)
from PySide6.QtWidgets import (
    QComboBox, QDialog, QGraphicsScene, QGraphicsView, QHBoxLayout,
    QLabel, QPushButton, QVBoxLayout,
)

BLOCK_MIN_W = 340
BLOCK_PAD_X = 8
BLOCK_PAD_Y = 4
HEADER_H = 20
LINE_H = 15
LAYER_GAP_Y = 55
NODE_GAP_X = 80
EDGE_WIDTH = 2.0
ARROW_SIZE = 9
CHAR_W_EST = 7.0  

EDGE_TAKEN = "taken"             
EDGE_NOT_TAKEN = "not_taken"      
EDGE_UNCONDITIONAL = "unconditional"  
EDGE_BACK = "back"                
EDGE_EXCEPTION = "exception"      


_CONDITIONAL_JUMPS = {
    "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE",
    "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP",
    "FOR_ITER", "SEND",
}
_UNCONDITIONAL_JUMPS = {
    "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP",
}
_SETUP_JUMPS = {
    "SETUP_EXCEPT", "SETUP_FINALLY", "SETUP_WITH", "POP_EXCEPT_JUMP",
}
_JUMP_OPS = _CONDITIONAL_JUMPS | _UNCONDITIONAL_JUMPS | _SETUP_JUMPS
_RETURN_OPS = {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}

_RE_INSTR_CPY = re.compile(
    r"^\s*(\d+)?\s+(?:>>\s*)?(\d+)\s+([A-Z][A-Z_0-9]+)\s*(.*)?$"
)
_RE_INSTR_MPY = re.compile(
    r"^\s{2,4}([A-Z][A-Z_0-9]+)\s*(.*)?$"
)
_RE_JUMP_TARGET = re.compile(r"\(to (\d+)\)")
_RE_EXC_ENTRY = re.compile(r"(\d+)\s+to\s+(\d+)\s*->\s*(\d+)")

def _colors():
    dark = _is_dark()
    if dark:
        return {
            "block_bg":         QColor("#1e1e1e"),
            "block_border":     QColor("#555555"),
            "header_bg":        QColor("#264f78"),
            "header_text":      QColor("#ffffff"),
            "instr_text":       QColor("#d4d4d4"),
            "jump_text":        QColor("#c586c0"),
            "entry_border":     QColor("#608b4e"),
            EDGE_TAKEN:         QColor("#4ec9b0"),
            EDGE_NOT_TAKEN:     QColor("#f14c4c"),
            EDGE_UNCONDITIONAL: QColor("#569cd6"),
            EDGE_BACK:          QColor("#dcdcaa"),
            EDGE_EXCEPTION:     QColor("#c586c0"),
        }
    return {
        "block_bg":         QColor("#ffffff"),
        "block_border":     QColor("#bbbbbb"),
        "header_bg":        QColor("#0066cc"),
        "header_text":      QColor("#ffffff"),
        "instr_text":       QColor("#1e1e1e"),
        "jump_text":        QColor("#af00db"),
        "entry_border":     QColor("#388e3c"),
        EDGE_TAKEN:         QColor("#16825d"),
        EDGE_NOT_TAKEN:     QColor("#cd3131"),
        EDGE_UNCONDITIONAL: QColor("#0451a5"),
        EDGE_BACK:          QColor("#795e26"),
        EDGE_EXCEPTION:     QColor("#af00db"),
    }


def _extract_function_text(full_text: str, func_name: str,
                           func_meta: dict) -> str:
    meta = func_meta.get(func_name)
    if not meta:
        return ""
    start_line = meta.get("line", 1) - 1
    lines = full_text.splitlines()
    end_line = len(lines)
    for name, m in func_meta.items():
        if name == func_name:
            continue
        ln = m.get("line", 0) - 1
        if ln > start_line:
            end_line = min(end_line, ln)
    return "\n".join(lines[start_line + 1:end_line])


def _parse_instructions(text: str) -> list[dict]:
    instructions = []
    offset_counter = 0
    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped.strip():
            continue
        tok = stripped.strip()
        if tok.startswith(("Disassembly", "ExceptionTable", "(", "[")):
            continue
        if _RE_EXC_ENTRY.match(tok):
            continue
        m = _RE_INSTR_CPY.match(stripped)
        if m:
            offset = int(m.group(2))
            opname = m.group(3)
            argstr = (m.group(4) or "").strip()
            target = None
            tm = _RE_JUMP_TARGET.search(argstr)
            if tm:
                target = int(tm.group(1))
            instructions.append({
                "offset": offset, "opname": opname,
                "argstr": argstr, "target": target,
            })
            continue
        m = _RE_INSTR_MPY.match(stripped)
        if m:
            opname = m.group(1)
            argstr = (m.group(2) or "").strip()
            target = None
            tm2 = re.search(r"->\s*(\d+)", argstr)
            if tm2:
                target = int(tm2.group(1))
            instructions.append({
                "offset": offset_counter, "opname": opname,
                "argstr": argstr, "target": target,
            })
            offset_counter += 2
            continue
    return instructions


def _parse_exception_table(text: str) -> list[tuple[int, int, int]]:
    entries = []
    in_table = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("ExceptionTable"):
            in_table = True
            continue
        if in_table:
            m = _RE_EXC_ENTRY.match(stripped)
            if m:
                entries.append((int(m.group(1)), int(m.group(2)),
                                int(m.group(3))))
            elif stripped and not stripped[0].isdigit():
                in_table = False
    seen: set[tuple[int, int]] = set()
    unique = []
    for s, e, h in entries:
        key = (s, h)
        if key not in seen:
            seen.add(key)
            unique.append((s, e, h))
    return unique


def _build_cfg(instructions: list[dict],
               exc_entries: list[tuple[int, int, int]],
               ) -> tuple[list[dict], list[dict]]:

    if not instructions:
        return [], []

    leaders: set[int] = {0}
    offset_set = {inst["offset"] for inst in instructions}

    for i, inst in enumerate(instructions):
        if inst["target"] is not None and inst["target"] in offset_set:
            leaders.add(inst["target"])
        if inst["opname"] in _JUMP_OPS or inst["opname"] in _RETURN_OPS:
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["offset"])

    for _, _, handler in exc_entries:
        if handler in offset_set:
            leaders.add(handler)

    leaders_sorted = sorted(leaders)
    leader_to_block = {off: idx for idx, off in enumerate(leaders_sorted)}

    blocks: list[dict] = []
    for bid, leader in enumerate(leaders_sorted):
        next_leader = (leaders_sorted[bid + 1]
                       if bid + 1 < len(leaders_sorted) else float("inf"))
        block_instrs: list[str] = []
        last_op = ""
        last_offset = leader
        for inst in instructions:
            if inst["offset"] < leader or inst["offset"] >= next_leader:
                continue
            label = f"{inst['offset']:>4d}  {inst['opname']}"
            if inst["argstr"]:
                label += f"  {inst['argstr'][:42]}"
            block_instrs.append(label)
            last_op = inst["opname"]
            last_offset = inst["offset"]
        blocks.append({
            "id": bid, "start": leader, "end": last_offset,
            "instructions": block_instrs, "last_op": last_op,
        })

    edges: list[dict] = []
    for bid, leader in enumerate(leaders_sorted):
        next_leader = (leaders_sorted[bid + 1]
                       if bid + 1 < len(leaders_sorted) else float("inf"))
        last_inst = None
        for inst in reversed(instructions):
            if leader <= inst["offset"] < next_leader:
                last_inst = inst
                break
        if last_inst is None:
            continue

        op = last_inst["opname"]
        is_cond = op in _CONDITIONAL_JUMPS
        is_setup = op in _SETUP_JUMPS

        if (last_inst["target"] is not None
                and last_inst["target"] in leader_to_block):
            target_bid = leader_to_block[last_inst["target"]]
            if is_setup:
                etype = EDGE_EXCEPTION
            elif last_inst["target"] <= last_inst["offset"]:
                etype = EDGE_BACK
            elif is_cond:
                etype = EDGE_TAKEN
            else:
                etype = EDGE_UNCONDITIONAL
            edges.append({"from": bid, "to": target_bid, "type": etype})

        if op not in _UNCONDITIONAL_JUMPS and op not in _RETURN_OPS:
            if bid + 1 < len(blocks):
                if is_cond:
                    etype = EDGE_NOT_TAKEN
                else:
                    etype = EDGE_UNCONDITIONAL
                edges.append({"from": bid, "to": bid + 1, "type": etype})

    exc_seen: set[tuple[int, int]] = set()
    for start, _end, handler in exc_entries:
        if handler not in leader_to_block:
            continue
        handler_bid = leader_to_block[handler]
        source_bid = 0
        for bid in range(len(leaders_sorted) - 1, -1, -1):
            if leaders_sorted[bid] <= start:
                source_bid = bid
                break
        if source_bid == handler_bid:
            continue
        key = (source_bid, handler_bid)
        if key in exc_seen:
            continue
        if any(e["from"] == source_bid and e["to"] == handler_bid
               for e in edges):
            continue
        exc_seen.add(key)
        edges.append({"from": source_bid, "to": handler_bid,
                       "type": EDGE_EXCEPTION})

    return blocks, edges


def _block_dims(block: dict) -> tuple[float, float]:
    """Retorna (largura, altura) de um bloco."""
    n = len(block["instructions"])
    max_len = max((len(l) for l in block["instructions"]), default=10)
    w = max(BLOCK_MIN_W, max_len * CHAR_W_EST + BLOCK_PAD_X * 2)
    h = HEADER_H + max(n, 1) * LINE_H + BLOCK_PAD_Y * 2
    return w, h


def _layout_blocks(blocks: list[dict], edges: list[dict],
                   ) -> dict[int, tuple[float, float]]:
    if not blocks:
        return {}

    blocks_by_id = {b["id"]: b for b in blocks}

    forward_edges = [
        e for e in edges
        if blocks_by_id[e["to"]]["start"] > blocks_by_id[e["from"]]["start"]
    ]

    fwd_adj: dict[int, list[int]] = defaultdict(list)
    fwd_rev: dict[int, list[int]] = defaultdict(list)
    for e in forward_edges:
        fwd_adj[e["from"]].append(e["to"])
        fwd_rev[e["to"]].append(e["from"])

    layers: dict[int, int] = {}

    def _assign(bid: int, visiting: set[int] | None = None) -> int:
        if bid in layers:
            return layers[bid]
        if visiting is None:
            visiting = set()
        if bid in visiting:
            layers[bid] = 0
            return 0
        visiting.add(bid)
        parents = fwd_rev.get(bid, [])
        if not parents:
            layers[bid] = 0
        else:
            layers[bid] = max(_assign(p, visiting) for p in parents) + 1
        visiting.discard(bid)
        return layers[bid]

    for b in blocks:
        _assign(b["id"])

    max_layer = max(layers.values(), default=0)
    for b in blocks:
        if b["id"] not in layers:
            max_layer += 1
            layers[b["id"]] = max_layer

    by_layer: dict[int, list[int]] = defaultdict(list)
    for bid, layer in layers.items():
        by_layer[layer].append(bid)

    all_rev: dict[int, list[int]] = defaultdict(list)
    for e in edges:
        all_rev[e["to"]].append(e["from"])

    positions_order: dict[int, float] = {}

    for layer in sorted(by_layer.keys()):
        bids = by_layer[layer]
        if layer == 0:
            bids.sort(key=lambda b: blocks_by_id[b]["start"])
        else:
            def _bary(bid: int) -> float:
                parents = [positions_order[p] for p in all_rev[bid]
                           if p in positions_order]
                return sum(parents) / len(parents) if parents else float("inf")
            bids.sort(key=_bary)
        for i, bid in enumerate(bids):
            positions_order[bid] = float(i)
        by_layer[layer] = bids

    all_adj: dict[int, list[int]] = defaultdict(list)
    for e in edges:
        all_adj[e["from"]].append(e["to"])

    for layer in sorted(by_layer.keys(), reverse=True):
        bids = by_layer[layer]
        if len(bids) <= 1:
            continue

        def _bary_down(bid: int) -> float:
            children = [positions_order[c] for c in all_adj[bid]
                        if c in positions_order]
            return sum(children) / len(children) if children else \
                positions_order.get(bid, float("inf"))
        bids.sort(key=_bary_down)
        for i, bid in enumerate(bids):
            positions_order[bid] = float(i)
        by_layer[layer] = bids

    dims = {b["id"]: _block_dims(b) for b in blocks}

    layer_y: dict[int, float] = {}
    cum_y = 0.0
    for layer in sorted(by_layer.keys()):
        layer_y[layer] = cum_y
        max_h = max(dims[bid][1] for bid in by_layer[layer])
        cum_y += max_h + LAYER_GAP_Y

    positions: dict[int, tuple[float, float]] = {}
    for layer in sorted(by_layer.keys()):
        bids = by_layer[layer]
        total_w = (sum(dims[bid][0] for bid in bids)
                   + max(0, len(bids) - 1) * NODE_GAP_X)
        x = -total_w / 2
        for bid in bids:
            w, _h = dims[bid]
            positions[bid] = (x, layer_y[layer])
            x += w + NODE_GAP_X

    return positions



class CfgGraphicsView(QGraphicsView):

    MIN_SCALE = 0.1
    MAX_SCALE = 8.0
    ZOOM_STEP = 1.2

    def __init__(self, scene, parent=None):
        super().__init__(scene, parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(
            QGraphicsView.ViewportAnchor.AnchorUnderMouse)

    def wheelEvent(self, event):
        if event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            if event.angleDelta().y() > 0:
                self.zoom_in()
            else:
                self.zoom_out()
            event.accept()
        else:
            super().wheelEvent(event)

    def zoom_in(self):
        if self.transform().m11() * self.ZOOM_STEP > self.MAX_SCALE:
            return
        self.scale(self.ZOOM_STEP, self.ZOOM_STEP)

    def zoom_out(self):
        if self.transform().m11() / self.ZOOM_STEP < self.MIN_SCALE:
            return
        self.scale(1 / self.ZOOM_STEP, 1 / self.ZOOM_STEP)

    def reset_zoom(self):
        self.resetTransform()

    def fit_all(self):
        scene = self.scene()
        if scene is None:
            return
        rect = scene.itemsBoundingRect()
        if rect.isEmpty():
            return
        rect.adjust(-40, -40, 40, 40)
        self.fitInView(rect, Qt.AspectRatioMode.KeepAspectRatio)



class CfgView(QDialog):

    def __init__(self, parent, bytecode_text: str, func_meta: dict):
        super().__init__(parent)
        self.setWindowTitle("Grafo de Controle de Fluxo (CFG)")
        self.resize(1100, 800)

        self._bytecode_text = bytecode_text
        self._func_meta = func_meta

        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        top.addWidget(QLabel("Função:"))
        self._combo = QComboBox()
        for name in sorted(func_meta.keys()):
            self._combo.addItem(name)
        self._combo.currentTextChanged.connect(self._on_select)
        top.addWidget(self._combo, 1)

        top.addSpacing(16)
        self._btn_zoom_out = QPushButton("\u2212")
        self._btn_zoom_out.setFixedWidth(32)
        self._btn_zoom_out.setToolTip("Zoom out (Ctrl+-)")
        self._btn_zoom_reset = QPushButton("100%")
        self._btn_zoom_reset.setFixedWidth(52)
        self._btn_zoom_reset.setToolTip("Reset zoom (Ctrl+0)")
        self._btn_fit = QPushButton("Fit")
        self._btn_fit.setFixedWidth(42)
        self._btn_fit.setToolTip("Ajustar à janela (Ctrl+F)")
        self._btn_zoom_in = QPushButton("+")
        self._btn_zoom_in.setFixedWidth(32)
        self._btn_zoom_in.setToolTip("Zoom in (Ctrl++)")

        for btn in (self._btn_zoom_out, self._btn_zoom_reset,
                    self._btn_fit, self._btn_zoom_in):
            top.addWidget(btn)
        layout.addLayout(top)

        self._scene = QGraphicsScene()
        self._view = CfgGraphicsView(self._scene)
        layout.addWidget(self._view)

        self._btn_zoom_out.clicked.connect(self._view.zoom_out)
        self._btn_zoom_in.clicked.connect(self._view.zoom_in)
        self._btn_zoom_reset.clicked.connect(self._view.reset_zoom)
        self._btn_fit.clicked.connect(self._view.fit_all)

        for seq, slot in (
            ("Ctrl++", self._view.zoom_in),
            ("Ctrl+=", self._view.zoom_in),
            ("Ctrl+-", self._view.zoom_out),
            ("Ctrl+0", self._view.reset_zoom),
            ("Ctrl+F", self._view.fit_all),
        ):
            sc = QShortcut(QKeySequence(seq), self)
            sc.activated.connect(slot)

        colors = _colors()
        legend = QHBoxLayout()
        for label, key in [
            ("Sim (Y)", EDGE_TAKEN),
            ("Não (N)", EDGE_NOT_TAKEN),
            ("Incondicional", EDGE_UNCONDITIONAL),
            ("Loop", EDGE_BACK),
            ("Exceção", EDGE_EXCEPTION),
        ]:
            c = colors[key].name()
            lbl = QLabel(f"<span style='color:{c}'>\u2588\u2588</span> {label}")
            legend.addWidget(lbl)
        legend.addStretch()
        layout.addLayout(legend)

        if self._combo.count() > 0:
            self._on_select(self._combo.currentText())

    def showEvent(self, event):
        super().showEvent(event)
        QTimer.singleShot(0, self._view.fit_all)


    def _on_select(self, func_name: str):
        self._scene.clear()
        text = _extract_function_text(
            self._bytecode_text, func_name, self._func_meta)
        if not text:
            return

        instructions = _parse_instructions(text)
        if not instructions:
            return

        exc_entries = _parse_exception_table(text)
        blocks, edges = _build_cfg(instructions, exc_entries)
        if not blocks:
            return

        positions = _layout_blocks(blocks, edges)
        self._render(blocks, edges, positions)

        rect = self._scene.itemsBoundingRect()
        rect.adjust(-60, -60, 60, 60)
        self._scene.setSceneRect(rect)
        self._view.fit_all()



    def _render(self, blocks, edges, positions):
        colors = _colors()
        mono = QFont("Courier", 9)
        mono_bold = QFont("Courier", 9, QFont.Weight.Bold)

        block_rects: dict[int, QRectF] = {}

        for block in blocks:
            bid = block["id"]
            if bid not in positions:
                continue
            x, y = positions[bid]
            w, h = _block_dims(block)

            if bid == 0:
                border_pen = QPen(colors["entry_border"], 2.5)
            else:
                border_pen = QPen(colors["block_border"], 1.5)

            self._scene.addRect(x, y, w, h, border_pen,
                                QBrush(colors["block_bg"]))

            self._scene.addRect(
                x + 1, y + 1, w - 2, HEADER_H - 1,
                QPen(Qt.PenStyle.NoPen), QBrush(colors["header_bg"]))

            ht = self._scene.addText(f"loc_{block['start']}", mono_bold)
            ht.setDefaultTextColor(colors["header_text"])
            ht.setPos(x + BLOCK_PAD_X, y + 1)


            n_instr = len(block["instructions"])
            for i, instr_text in enumerate(block["instructions"]):
                it = self._scene.addText(instr_text, mono)
                is_last = (i == n_instr - 1)
                if is_last and block["last_op"] in (_JUMP_OPS | _RETURN_OPS):
                    it.setDefaultTextColor(colors["jump_text"])
                else:
                    it.setDefaultTextColor(colors["instr_text"])
                it.setPos(x + BLOCK_PAD_X,
                          y + HEADER_H + BLOCK_PAD_Y + i * LINE_H)

            block_rects[bid] = QRectF(x, y, w, h)

        if not block_rects:
            return

        out_edges: dict[int, list[dict]] = defaultdict(list)
        in_edges: dict[int, list[dict]] = defaultdict(list)
        for edge in edges:
            out_edges[edge["from"]].append(edge)
            in_edges[edge["to"]].append(edge)

        scene_right = max(r.right() for r in block_rects.values())
        scene_left = min(r.left() for r in block_rects.values())
        back_channel_idx = 0
        exc_channel_idx = 0

        for bid in out_edges:
            out_edges[bid].sort(key=lambda e: (
                1 if e["type"] in (EDGE_EXCEPTION, EDGE_BACK) else 0,
                block_rects[e["to"]].center().x()
                    if e["to"] in block_rects else 0,
            ))
        for bid in in_edges:
            in_edges[bid].sort(key=lambda e: (
                1 if e["type"] in (EDGE_EXCEPTION, EDGE_BACK) else 0,
                block_rects[e["from"]].center().x()
                    if e["from"] in block_rects else 0,
            ))

        for edge in edges:
            src_rect = block_rects.get(edge["from"])
            dst_rect = block_rects.get(edge["to"])
            if not src_rect or not dst_rect:
                continue

            etype = edge["type"]
            color = colors.get(etype, QColor("#888"))

            siblings = out_edges[edge["from"]]
            n_out = len(siblings)
            s_idx = siblings.index(edge)
            if n_out == 1:
                exit_x = src_rect.center().x()
            else:
                frac = (s_idx + 1) / (n_out + 1)
                exit_x = src_rect.left() + src_rect.width() * frac
            exit_y = src_rect.bottom()

            in_sibs = in_edges[edge["to"]]
            n_in = len(in_sibs)
            t_idx = in_sibs.index(edge)
            if n_in == 1:
                entry_x = dst_rect.center().x()
            else:
                frac = (t_idx + 1) / (n_in + 1)
                entry_x = dst_rect.left() + dst_rect.width() * frac
            entry_y = dst_rect.top()

            is_back = dst_rect.top() <= src_rect.top()
            is_exc = (etype == EDGE_EXCEPTION)

            if is_exc:
                exc_channel_idx += 1
                ch = scene_right + 25 + exc_channel_idx * 22
                if is_back:
                    points = _route_backward(
                        exit_x, exit_y, entry_x, entry_y, ch)
                else:
                    points = _route_via_channel(
                        exit_x, exit_y, entry_x, entry_y, ch)
            elif is_back:
                back_channel_idx += 1
                if back_channel_idx % 2 == 1:
                    ch = scene_left - 25 - (back_channel_idx // 2) * 22
                else:
                    ch = scene_right + 25 + (back_channel_idx // 2) * 22
                points = _route_backward(
                    exit_x, exit_y, entry_x, entry_y, ch)
            else:
                points = _route_forward(exit_x, exit_y, entry_x, entry_y)

            dashed = is_exc
            self._draw_path(points, color, dashed=dashed)
            self._draw_arrow(points, color)

            if etype == EDGE_TAKEN:
                self._draw_label("Y", exit_x + 4, exit_y + 2, color, mono)
            elif etype == EDGE_NOT_TAKEN:
                self._draw_label("N", exit_x + 4, exit_y + 2, color, mono)
            elif etype == EDGE_BACK:
                self._draw_label("\u21BA", exit_x + 4, exit_y + 2,
                                 color, mono)
            elif etype == EDGE_EXCEPTION:
                self._draw_label("exc", exit_x + 4, exit_y + 2,
                                 color, mono)


    def _draw_path(self, points: list[tuple[float, float]],
                   color: QColor, dashed: bool = False):

        RADIUS = 8
        pen = QPen(color, EDGE_WIDTH)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        if dashed:
            pen.setStyle(Qt.PenStyle.DashLine)
            pen.setDashPattern([6, 4])

        path = QPainterPath()
        path.moveTo(*points[0])

        if len(points) <= 2:
            path.lineTo(*points[-1])
            self._scene.addPath(path, pen, QBrush(Qt.BrushStyle.NoBrush))
            return

        for i in range(1, len(points) - 1):
            px, py = points[i - 1]
            cx, cy = points[i]
            nx, ny = points[i + 1]

            dx1, dy1 = cx - px, cy - py
            dx2, dy2 = nx - cx, ny - cy
            len1 = math.hypot(dx1, dy1)
            len2 = math.hypot(dx2, dy2)

            if len1 < 1 or len2 < 1:
                path.lineTo(cx, cy)
                continue

            r = min(RADIUS, len1 / 2, len2 / 2)
            bx = cx - (dx1 / len1) * r
            by = cy - (dy1 / len1) * r
            ax = cx + (dx2 / len2) * r
            ay = cy + (dy2 / len2) * r

            path.lineTo(bx, by)
            path.quadTo(cx, cy, ax, ay)

        path.lineTo(*points[-1])
        self._scene.addPath(path, pen, QBrush(Qt.BrushStyle.NoBrush))

    def _draw_arrow(self, points: list[tuple[float, float]],
                    color: QColor):
        if len(points) < 2:
            return
        tip = QPointF(*points[-1])
        tail = QPointF(*points[-2])
        dx = tip.x() - tail.x()
        dy = tip.y() - tail.y()
        length = math.hypot(dx, dy)
        if length < 1:
            return
        dx /= length
        dy /= length
        px, py = -dy, dx
        size = ARROW_SIZE
        w = size * 0.5
        p1 = QPointF(tip.x() - size * dx + w * px,
                      tip.y() - size * dy + w * py)
        p2 = QPointF(tip.x() - size * dx - w * px,
                      tip.y() - size * dy - w * py)
        self._scene.addPolygon(
            QPolygonF([tip, p1, p2]), QPen(color, 1), QBrush(color))

    def _draw_label(self, text: str, x: float, y: float,
                    color: QColor, font: QFont):
        lbl = self._scene.addText(text, font)
        lbl.setDefaultTextColor(color)
        lbl.setPos(x, y)


def _route_forward(sx: float, sy: float,
                   tx: float, ty: float) -> list[tuple[float, float]]:
    if abs(sx - tx) < 2:
        return [(sx, sy), (sx, ty)]
    jog_y = sy + min(22, (ty - sy) * 0.35)
    return [(sx, sy), (sx, jog_y), (tx, jog_y), (tx, ty)]


def _route_via_channel(sx: float, sy: float,
                       tx: float, ty: float,
                       channel: float) -> list[tuple[float, float]]:
    return [
        (sx, sy), (sx, sy + 15),
        (channel, sy + 15), (channel, ty - 15),
        (tx, ty - 15), (tx, ty),
    ]

def _route_backward(sx: float, sy: float,
                    tx: float, ty: float,
                    channel: float) -> list[tuple[float, float]]:

    return [
        (sx, sy), (sx, sy + 15),
        (channel, sy + 15), (channel, ty - 15),
        (tx, ty - 15), (tx, ty),
    ]



def _is_dark() -> bool:
    from UI.qt_highlighters import _is_dark as _dark
    return _dark()
    r"^\s{2,4}([A-Z][A-Z_0-9]+)\s*(.*)?$"
)
# Jump targets no CPython: (to N) ou >> offset
_RE_JUMP_TARGET = re.compile(r"\(to (\d+)\)")
_RE_JUMP_LABEL = re.compile(r"^>>\s*(\d+)")

# Opcodes de jump
_JUMP_OPS = {
    "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT",
    "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE",
    "POP_JUMP_IF_NOT_NONE", "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP",
    "FOR_ITER", "SEND", "JUMP",
    # MicroPython
    "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE", "JUMP", "FOR_ITER",
    "POP_EXCEPT_JUMP", "SETUP_EXCEPT", "SETUP_FINALLY", "SETUP_WITH",
}
_RETURN_OPS = {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}
_UNCONDITIONAL = {"JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP"}


# ------------------------------------------------------------------
# Parsing
# ------------------------------------------------------------------

def _extract_function_text(full_text: str, func_name: str, func_meta: dict) -> str:
    """Extrai as linhas de bytecode de uma função específica."""
    meta = func_meta.get(func_name)
    if not meta:
        return ""
    start_line = meta.get("line", 1) - 1  # 0-based
    lines = full_text.splitlines()

    # Acha o fim: próximo header ou fim do texto
    end_line = len(lines)
    for name, m in func_meta.items():
        if name == func_name:
            continue
        ln = m.get("line", 0) - 1
        if ln > start_line:
            end_line = min(end_line, ln)

    return "\n".join(lines[start_line + 1:end_line])  # Pula o header


def _parse_instructions(text: str) -> list[dict]:
    """Parseia instruções de bytecode do texto (CPython ou MicroPython)."""
    instructions = []
    offset_counter = 0

    for line in text.splitlines():
        line_stripped = line.rstrip()
        if not line_stripped.strip():
            continue
        if line_stripped.strip().startswith(("Disassembly", "ExceptionTable", "(")):
            continue

        # Tenta CPython
        m = _RE_INSTR_CPY.match(line_stripped)
        if m:
            offset = int(m.group(2))
            opname = m.group(3)
            argstr = (m.group(4) or "").strip()
            # Extrai target de jump
            target = None
            tm = _RE_JUMP_TARGET.search(argstr)
            if tm:
                target = int(tm.group(1))
            instructions.append({
                "offset": offset, "opname": opname,
                "argstr": argstr, "target": target,
            })
            continue

        # Tenta MicroPython
        m = _RE_INSTR_MPY.match(line_stripped)
        if m:
            opname = m.group(1)
            argstr = (m.group(2) or "").strip()
            target = None
            # MicroPython jump targets: "-> N"
            tm2 = re.search(r"->\s*(\d+)", argstr)
            if tm2:
                target = int(tm2.group(1))
            instructions.append({
                "offset": offset_counter, "opname": opname,
                "argstr": argstr, "target": target,
            })
            offset_counter += 2
            continue

    return instructions


def _build_cfg(instructions: list[dict]) -> tuple[list[dict], list[dict]]:
    """Constrói blocos básicos e arestas a partir das instruções.

    Retorna: (blocks, edges)
        blocks: [{"id": int, "start": int, "instructions": [str, ...]}]
        edges:  [{"from": int, "to": int, "type": "fall"|"jump"|"exception"}]
    """
    if not instructions:
        return [], []

    # Identifica líderes (inícios de bloco)
    leaders = {0}  # Primeiro offset é sempre líder
    offsets = [inst["offset"] for inst in instructions]
    offset_set = set(offsets)

    for i, inst in enumerate(instructions):
        if inst["target"] is not None and inst["target"] in offset_set:
            leaders.add(inst["target"])
        if inst["opname"] in _JUMP_OPS or inst["opname"] in _RETURN_OPS:
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["offset"])

    leaders = sorted(leaders)
    leader_to_block = {off: idx for idx, off in enumerate(leaders)}

    # Constrói blocos
    blocks = []
    for bid, leader in enumerate(leaders):
        block_instrs = []
        for inst in instructions:
            if inst["offset"] < leader:
                continue
            if inst["offset"] >= leader:
                next_leader = leaders[bid + 1] if bid + 1 < len(leaders) else float("inf")
                if inst["offset"] >= next_leader:
                    break
                label = f"{inst['offset']:>4d}  {inst['opname']}"
                if inst["argstr"]:
                    label += f"  {inst['argstr'][:30]}"
                block_instrs.append(label)
        blocks.append({"id": bid, "start": leader, "instructions": block_instrs})

    # Constrói arestas
    edges = []
    for bid, leader in enumerate(leaders):
        next_leader = leaders[bid + 1] if bid + 1 < len(leaders) else float("inf")
        # Última instrução do bloco
        last_inst = None
        for inst in reversed(instructions):
            if leader <= inst["offset"] < next_leader:
                last_inst = inst
                break
        if last_inst is None:
            continue

        # Aresta de jump
        if last_inst["target"] is not None and last_inst["target"] in leader_to_block:
            target_bid = leader_to_block[last_inst["target"]]
            etype = "exception" if "SETUP" in last_inst["opname"] else "jump"
            edges.append({"from": bid, "to": target_bid, "type": etype})

        # Aresta fall-through
        if last_inst["opname"] not in _UNCONDITIONAL and last_inst["opname"] not in _RETURN_OPS:
            if bid + 1 < len(blocks):
                edges.append({"from": bid, "to": bid + 1, "type": "fall"})

    return blocks, edges


# ------------------------------------------------------------------
# Layout
# ------------------------------------------------------------------

def _layout_blocks(blocks: list[dict], edges: list[dict]) -> dict[int, tuple[float, float]]:
    """Calcula posições (x, y) via BFS layering."""
    if not blocks:
        return {}

    n = len(blocks)
    adj = defaultdict(list)
    for e in edges:
        adj[e["from"]].append(e["to"])

    # BFS layer assignment
    layers: dict[int, int] = {}
    queue = deque([0])
    layers[0] = 0
    while queue:
        bid = queue.popleft()
        for nid in adj[bid]:
            if nid not in layers:
                layers[nid] = layers[bid] + 1
                queue.append(nid)
    # Nós não alcançáveis
    for b in blocks:
        if b["id"] not in layers:
            layers[b["id"]] = max(layers.values(), default=0) + 1

    # Agrupar por layer
    by_layer: dict[int, list[int]] = defaultdict(list)
    for bid, layer in layers.items():
        by_layer[layer].append(bid)

    positions = {}
    for layer, bids in sorted(by_layer.items()):
        bids.sort()
        total_w = len(bids) * BLOCK_W + (len(bids) - 1) * NODE_GAP_X
        start_x = -total_w / 2
        for i, bid in enumerate(bids):
            # Altura do bloco
            n_lines = len(blocks[bid]["instructions"]) if bid < len(blocks) else 1
            block_h = max(n_lines * LINE_H + BLOCK_PAD * 2, 40)
            x = start_x + i * (BLOCK_W + NODE_GAP_X)
            y = layer * (80 + LAYER_GAP_Y)  # 80 = altura média
            positions[bid] = (x, y)

    return positions


# ------------------------------------------------------------------
# Renderização
# ------------------------------------------------------------------

def _block_height(block: dict) -> float:
    return max(len(block["instructions"]) * LINE_H + BLOCK_PAD * 2, 40)


class CfgView(QDialog):
    """Diálogo com visualização do CFG de uma função."""

    def __init__(self, parent, bytecode_text: str, func_meta: dict):
        super().__init__(parent)
        self.setWindowTitle("Grafo de Controle de Fluxo (CFG)")
        self.resize(950, 700)

        self._bytecode_text = bytecode_text
        self._func_meta = func_meta

        layout = QVBoxLayout(self)

        # Seletor de função
        top = QHBoxLayout()
        top.addWidget(QLabel("Função:"))
        self._combo = QComboBox()
        for name in sorted(func_meta.keys()):
            self._combo.addItem(name)
        self._combo.currentTextChanged.connect(self._on_select)
        top.addWidget(self._combo, 1)
        layout.addLayout(top)

        # View
        self._scene = QGraphicsScene()
        self._view = QGraphicsView(self._scene)
        self._view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._view.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        layout.addWidget(self._view)

        # Legenda
        legend = QHBoxLayout()
        for label, color in [("Fall-through", "#4CAF50"), ("Jump", "#F44336"),
                              ("Exceção", "#2196F3")]:
            lbl = QLabel(f"<span style='color:{color}'>\u2588\u2588</span> {label}")
            legend.addWidget(lbl)
        legend.addStretch()
        layout.addLayout(legend)

        if self._combo.count() > 0:
            self._on_select(self._combo.currentText())

    def _on_select(self, func_name: str):
        self._scene.clear()
        text = _extract_function_text(self._bytecode_text, func_name, self._func_meta)
        if not text:
            return
        instructions = _parse_instructions(text)
        if not instructions:
            return
        blocks, edges = _build_cfg(instructions)
        if not blocks:
            return
        positions = _layout_blocks(blocks, edges)
        self._render(blocks, edges, positions)
        self._view.fitInView(self._scene.sceneRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def _render(self, blocks, edges, positions):
        mono = QFont("Courier", 9)
        bg_color = QColor("#2d2d30") if _is_dark() else QColor("#f5f5f5")
        border_color = QColor("#666") if _is_dark() else QColor("#333")
        text_color = QColor("#d4d4d4") if _is_dark() else QColor("#1e1e1e")

        block_rects: dict[int, QRectF] = {}

        # Desenha blocos
        for block in blocks:
            bid = block["id"]
            if bid not in positions:
                continue
            x, y = positions[bid]
            h = _block_height(block)

            rect = self._scene.addRect(
                x, y, BLOCK_W, h,
                QPen(border_color, 1.5),
                QBrush(bg_color),
            )
            block_rects[bid] = QRectF(x, y, BLOCK_W, h)

            # Header
            header = self._scene.addText(f"Block {bid} (offset {block['start']})", mono)
            header.setDefaultTextColor(QColor("#569cd6") if _is_dark() else QColor("#0066cc"))
            header.setPos(x + 4, y + 2)

            # Instruções
            for i, instr_text in enumerate(block["instructions"]):
                item = self._scene.addText(instr_text, mono)
                item.setDefaultTextColor(text_color)
                item.setPos(x + 6, y + BLOCK_PAD + LINE_H + i * LINE_H)

        # Desenha arestas
        for edge in edges:
            src_rect = block_rects.get(edge["from"])
            dst_rect = block_rects.get(edge["to"])
            if not src_rect or not dst_rect:
                continue

            color = _EDGE_COLORS.get(edge["type"], QColor("#888"))
            pen = QPen(color, 2)

            # Ponto de saída: centro-inferior do bloco fonte
            src_x = src_rect.center().x()
            src_y = src_rect.bottom()

            # Ponto de entrada: centro-superior do bloco destino
            dst_x = dst_rect.center().x()
            dst_y = dst_rect.top()

            # Back-edge: se destino está acima, desloca para a lateral
            if dst_y <= src_y:
                # Sai pela direita, entra pela esquerda
                src_x = src_rect.right() + 5
                src_y = src_rect.center().y()
                dst_x = dst_rect.left() - 5
                dst_y = dst_rect.center().y()

                mid_x = max(src_x, dst_x) + 30
                self._scene.addLine(src_x, src_y, mid_x, src_y, pen)
                self._scene.addLine(mid_x, src_y, mid_x, dst_y, pen)
                self._scene.addLine(mid_x, dst_y, dst_x, dst_y, pen)
                self._draw_arrow(QPointF(dst_x, dst_y), QPointF(dst_x - 1, dst_y), color)
            else:
                self._scene.addLine(src_x, src_y, dst_x, dst_y, pen)
                self._draw_arrow(QPointF(dst_x, dst_y), QPointF(src_x, src_y), color)

    def _draw_arrow(self, tip: QPointF, origin: QPointF, color: QColor):
        """Desenha uma seta na ponta da aresta."""
        import math
        dx = tip.x() - origin.x()
        dy = tip.y() - origin.y()
        length = math.sqrt(dx * dx + dy * dy)
        if length < 1:
            return
        dx /= length
        dy /= length

        size = 8
        p1 = QPointF(tip.x() - size * (dx + dy * 0.5),
                      tip.y() - size * (dy - dx * 0.5))
        p2 = QPointF(tip.x() - size * (dx - dy * 0.5),
                      tip.y() - size * (dy + dx * 0.5))

        poly = QPolygonF([tip, p1, p2])
        self._scene.addPolygon(poly, QPen(color), QBrush(color))


def _is_dark() -> bool:
    from UI.qt_highlighters import _is_dark as _dark
    return _dark()
