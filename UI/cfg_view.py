"""Visualizador de grafo de controle de fluxo (CFG).

Parseia o disassembly textual para extrair blocos básicos e arestas,
depois renderiza o grafo em um QGraphicsView.
"""

import re
from collections import defaultdict, deque

from PySide6.QtCore import Qt, QPointF, QRectF
from PySide6.QtGui import QColor, QPen, QBrush, QFont, QPolygonF, QPainter
from PySide6.QtWidgets import (
    QComboBox, QDialog, QGraphicsLineItem, QGraphicsRectItem,
    QGraphicsScene, QGraphicsTextItem, QGraphicsView, QHBoxLayout,
    QLabel, QVBoxLayout,
)

BLOCK_W = 300
BLOCK_PAD = 10
LINE_H = 14
LAYER_GAP_Y = 60
NODE_GAP_X = 40

_EDGE_COLORS = {
    "fall": QColor("#4CAF50"),     # verde
    "jump": QColor("#F44336"),     # vermelho
    "exception": QColor("#2196F3"),  # azul
}

# Regex para parsear instruções do dis output
# CPython: "  line?  offset  OPNAME  arg  (detail)"
_RE_INSTR_CPY = re.compile(
    r"^\s*(\d+)?\s+(\d+)\s+([A-Z][A-Z_0-9]+)\s*(.*)?$"
)
# MicroPython: "  OPNAME  arg"
_RE_INSTR_MPY = re.compile(
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
