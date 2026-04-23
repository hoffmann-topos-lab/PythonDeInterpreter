from typing import Optional, Callable, Any


def build_block_by_id(blocks: list) -> dict:
    return {b["id"]: b for b in blocks}


def build_offset_to_block(blocks: list) -> dict:
    result = {}
    for b in blocks:
        for ins in b.get("instructions", []) or []:
            result[ins["offset"]] = b["id"]
    return result


def build_predecessor_map(blocks: list, cfg: dict) -> dict:
    preds = {b["id"]: set() for b in blocks}
    for src, succs in cfg.items():
        for dst in succs:
            if dst in preds:
                preds[dst].add(src)
    return preds


def get_block_instrs(block: dict) -> list:
    return block.get("instructions", []) or []


def get_block_opnames(block: dict) -> list:
    return [ins["opname"] for ins in get_block_instrs(block)]


COND_JUMP_OPS = frozenset({
    "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_NONE",
    "POP_JUMP_IF_NOT_NONE",
})


def get_last_jump_target(block: dict) -> Optional[int]:
    for ins in reversed(get_block_instrs(block)):
        if ins["opname"] in COND_JUMP_OPS:
            return ins.get("jump_target")
    return None


def get_jump_target_bid(block: dict, offset_to_block: dict) -> Optional[int]:
    jt = get_last_jump_target(block)
    return offset_to_block.get(jt) if jt is not None else None




def get_stack_info(node: dict) -> dict:
    return node.get("stack_info") or (node.get("recovered_ast") or {}).get("stack_info") or {}


def si_block_statements(si: dict, bid: Any) -> list:
    bs = si.get("block_statements") or {}
    return list(bs.get(bid) or [])


def si_block_conditions(si: dict, bid: Any) -> list:
    bc = si.get("block_conditions") or {}
    return list(bc.get(bid) or [])


def si_in_stack(si: dict, bid: Any) -> list:
    ins = si.get("in_stack") or {}
    return list(ins.get(bid, []))


def si_out_stack(si: dict, bid: Any) -> list:
    outs = si.get("out_stack") or {}
    return list(outs.get(bid, []))


def si_all_block_statements(si: dict) -> dict:
    return si.get("block_statements") or {}


def si_all_block_conditions(si: dict) -> dict:
    return si.get("block_conditions") or {}

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
