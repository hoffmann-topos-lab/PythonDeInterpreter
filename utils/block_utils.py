from typing import Optional, Callable, Any


def build_block_by_id(blocks: list) -> dict:
    """Mapeia block id -> block dict."""
    return {b["id"]: b for b in blocks}


def build_offset_to_block(blocks: list) -> dict:
    """Mapeia offset de instrução -> block id."""
    result = {}
    for b in blocks:
        for ins in b.get("instructions", []) or []:
            result[ins["offset"]] = b["id"]
    return result


def build_predecessor_map(blocks: list, cfg: dict) -> dict:
    """Mapeia block id -> set de predecessores."""
    preds = {b["id"]: set() for b in blocks}
    for src, succs in cfg.items():
        for dst in succs:
            if dst in preds:
                preds[dst].add(src)
    return preds


def get_block_instrs(block: dict) -> list:
    """Retorna a lista de instruções de um bloco (nunca None)."""
    return block.get("instructions", []) or []


def get_block_opnames(block: dict) -> list:
    """Retorna a lista de opnames das instruções de um bloco."""
    return [ins["opname"] for ins in get_block_instrs(block)]


# Opcodes de salto condicional (POP_JUMP_IF_*)
COND_JUMP_OPS = frozenset({
    "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_NONE",
    "POP_JUMP_IF_NOT_NONE",
})


def get_last_jump_target(block: dict) -> Optional[int]:
    """Retorna o jump_target do último opcode condicional do bloco, ou None."""
    for ins in reversed(get_block_instrs(block)):
        if ins["opname"] in COND_JUMP_OPS:
            return ins.get("jump_target")
    return None


def get_jump_target_bid(block: dict, offset_to_block: dict) -> Optional[int]:
    """Retorna o block id alvo do último salto condicional, ou None."""
    jt = get_last_jump_target(block)
    return offset_to_block.get(jt) if jt is not None else None


# ---------------------------------------------------------------------------
# Helpers de acesso a stack_info
# ---------------------------------------------------------------------------

def get_stack_info(node: dict) -> dict:
    """Extrai o dict stack_info de um nó (suporta nó direto ou aninhado em recovered_ast)."""
    return node.get("stack_info") or (node.get("recovered_ast") or {}).get("stack_info") or {}


def si_block_statements(si: dict, bid: Any) -> list:
    """Retorna a lista de statements do bloco bid (nunca None)."""
    bs = si.get("block_statements") or {}
    return list(bs.get(bid) or [])


def si_block_conditions(si: dict, bid: Any) -> list:
    """Retorna a lista de condições do bloco bid (nunca None)."""
    bc = si.get("block_conditions") or {}
    return list(bc.get(bid) or [])


def si_in_stack(si: dict, bid: Any) -> list:
    """Retorna a lista in_stack do bloco bid (nunca None)."""
    ins = si.get("in_stack") or {}
    return list(ins.get(bid, []))


def si_out_stack(si: dict, bid: Any) -> list:
    """Retorna a lista out_stack do bloco bid (nunca None)."""
    outs = si.get("out_stack") or {}
    return list(outs.get(bid, []))


def si_all_block_statements(si: dict) -> dict:
    """Retorna o dict completo block_statements (nunca None)."""
    return si.get("block_statements") or {}


def si_all_block_conditions(si: dict) -> dict:
    """Retorna o dict completo block_conditions (nunca None)."""
    return si.get("block_conditions") or {}


# Wrappers node-nível (compatíveis com a API original de codegen.py)

def get_block_statements(node: dict, bid: Any) -> list:
    return si_block_statements(get_stack_info(node), bid)


def get_block_condition(node: dict, bid: Any, idx: int = 0):
    conds = si_block_conditions(get_stack_info(node), bid)
    return conds[idx] if idx < len(conds) else None


def get_in_stack(node: dict, bid: Any) -> list:
    return si_in_stack(get_stack_info(node), bid)


def get_out_stack(node: dict, bid: Any) -> list:
    return si_out_stack(get_stack_info(node), bid)


def bfs_walk(
    start_bids,
    cfg: dict,
    stop_fn: Optional[Callable] = None,
    filter_fn: Optional[Callable] = None,
) -> set:
    """BFS genérico sobre o CFG.

    Parâmetros:
        start_bids: IDs iniciais (já incluídos no resultado).
        cfg:        grafo de fluxo de controle {bid: set(successors)}.
        stop_fn:    stop_fn(bid) -> bool — não visita nem propaga a partir de bid.
        filter_fn:  filter_fn(bid) -> bool — inclui bid no resultado e propaga;
                    quando None, todos os nós visitados são incluídos.

    Retorna:
        set de block ids visitados que passaram pelo filter_fn (+ start_bids).
    """
    visited = set(start_bids)
    queue = list(start_bids)
    result = set(start_bids)
    while queue:
        cur = queue.pop()
        for nxt in cfg.get(cur, set()):
            if nxt in visited:
                continue
            visited.add(nxt)
            if stop_fn is not None and stop_fn(nxt):
                continue
            if filter_fn is None or filter_fn(nxt):
                result.add(nxt)
                queue.append(nxt)
    return result
