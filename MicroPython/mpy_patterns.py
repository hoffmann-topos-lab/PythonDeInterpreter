from utils.block_utils import (
    build_block_by_id,
    build_offset_to_block,
    build_predecessor_map,
    get_block_instrs,
    get_block_opnames,
    bfs_walk,
)


_MPY_COND_JUMPS = frozenset({"POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE"})
_MPY_SHORT_CIRCUIT_JUMPS = frozenset({"JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP"})
_SETUP_EXCEPT_OPS  = frozenset({"SETUP_EXCEPT"})
_SETUP_FINALLY_OPS = frozenset({"SETUP_FINALLY"})
_SETUP_WITH_OPS    = frozenset({"SETUP_WITH"})
_SETUP_OPS         = _SETUP_EXCEPT_OPS | _SETUP_FINALLY_OPS | _SETUP_WITH_OPS
_MPY_TERMINATORS = frozenset({"JUMP", "RETURN_VALUE", "RAISE_LAST", "RAISE_OBJ", "RAISE_FROM"})

_WITH_CLEANUP_OPS = frozenset({
    "POP_TOP", "POP_EXCEPT_JUMP", "JUMP",
    "WITH_CLEANUP", "END_FINALLY",
    "LOAD_FAST_N", "LOAD_FAST_MULTI", "LOAD_NAME", "LOAD_GLOBAL",
    "STORE_FAST_N", "STORE_FAST_MULTI", "RETURN_VALUE",
})


def _is_mpy_cond_jump(opname: str) -> bool:
    return opname in _MPY_COND_JUMPS

def _mpy_jump_on_true(opname: str):
    if opname == "POP_JUMP_IF_TRUE":
        return True
    if opname == "POP_JUMP_IF_FALSE":
        return False
    return None


def _block_start(block) -> int:
    if block is None:
        return 0
    return block.get("start_offset", 0)


def _classify_mpy_handler(setup_op: str, handler_bid: int, block_by_id: dict) -> dict:

    handler_b = block_by_id.get(handler_bid, {})
    handler_ops = set(get_block_opnames(handler_b))
    handler_instrs = get_block_instrs(handler_b)
    is_with_handler = (setup_op == "SETUP_WITH") or ("WITH_CLEANUP" in handler_ops)
    is_except  = (setup_op == "SETUP_EXCEPT")  and not is_with_handler
    is_cleanup = (setup_op == "SETUP_FINALLY") and not is_with_handler
    is_exc_var_cleanup = False
    if is_cleanup and "END_FINALLY" in handler_ops and "DELETE_FAST" in handler_ops:
        allowed = {"LOAD_CONST_NONE", "LOAD_CONST", "STORE_FAST_MULTI", "STORE_FAST_N",
                   "DELETE_FAST", "END_FINALLY", "NOP", "POP_EXCEPT_JUMP", "JUMP"}
        has_store = ("STORE_FAST_MULTI" in handler_ops) or ("STORE_FAST_N" in handler_ops)
        if handler_ops.issubset(allowed) and has_store:
            store_var = None
            del_var = None
            for ins in handler_instrs:
                if ins.get("opname") in ("STORE_FAST_MULTI", "STORE_FAST_N") and store_var is None:
                    store_var = ins.get("argrepr") or str(ins.get("argval", ""))
                elif ins.get("opname") == "DELETE_FAST" and del_var is None:
                    del_var = ins.get("argrepr") or str(ins.get("argval", ""))
            if store_var and store_var == del_var:
                is_exc_var_cleanup = True

    return {
        "is_except":         is_except,
        "is_cleanup":        is_cleanup,
        "is_with_handler":   is_with_handler,
        "is_gen_cleanup":    False,
        "is_exc_var_cleanup": is_exc_var_cleanup,
        "is_with_reraise":   False,
        "is_comp_restore":   False,
        "is_cleanup_throw":  False,
        "is_async_for_exit": False,
    }

def detect_mpy_patterns(blocks, cfg, stack_info, code_obj, debug=False):

    if debug:
        name = getattr(code_obj, "co_name", "<?>")
        print(f"[DEBUG MPY PAT] detect_mpy_patterns: {name}")

    block_by_id    = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)
    preds          = build_predecessor_map(blocks, cfg)

    patterns = {
        "ifs":                      [],
        "loops":                    [],
        "short_circuit_candidates": [],
        "short_circuit_blocks":     set(),
        "try_regions":              [],
        "with_regions":             [],
        "with_handler_blocks":      set(),
        "assert_patterns":          [],
        "match_chains":             [],
        "match_regions":            [],
        "seq_match_chains":         [],
        "comprehensions":           [],
    }

    handler_block_ids: set  = set()
    exc_related_blocks: set = set()

    _handler_setup_map: dict = {}

    for b in blocks:
        bid = b["id"]
        for instr in get_block_instrs(b):
            op = instr["opname"]
            if op not in _SETUP_OPS:
                continue
            handler_off = instr.get("jump_target")
            if handler_off is None:
                continue
            handler_bid = offset_to_block.get(handler_off)
            if handler_bid is None:
                continue
            handler_block_ids.add(handler_bid)
            exc_related_blocks.add(handler_bid)
            _handler_setup_map.setdefault(handler_bid, []).append({
                "setup_op":  op,
                "setup_off": instr["offset"],
                "setup_bid": bid,
            })

    for b in blocks:
        bid   = b["id"]
        instrs = get_block_instrs(b)
        for instr in instrs:
            op = instr["opname"]
            if op not in (_SETUP_EXCEPT_OPS | _SETUP_FINALLY_OPS):
                continue

            setup_off   = instr["offset"]
            handler_off = instr.get("jump_target")
            if handler_off is None:
                continue
            handler_bid = offset_to_block.get(handler_off)
            if handler_bid is None:
                continue

            protected = sorted(
                blk["id"] for blk in blocks
                if _block_start(blk) > setup_off and _block_start(blk) < handler_off
            )
            exc_related_blocks.update(protected)

            hcls = _classify_mpy_handler(op, handler_bid, block_by_id)
            handler_entry = {
                "handler_offset": handler_off,
                "handler_block":  handler_bid,
                "lasti":          False,
                **hcls,
            }

            patterns["try_regions"].append({
                "type":             "try_region_group",
                "range":            (setup_off + 1, handler_off),
                "depth":            0,
                "protected_blocks": protected,
                "handlers":         [handler_entry],
            })

            if debug:
                print(
                    f"[DEBUG MPY PAT] TRY-REGION ({op}): "
                    f"[{setup_off+1},{handler_off}) "
                    f"handler={handler_bid} protected={protected}"
                )

    with_regions: list = []
    with_handler_block_ids: set = set()

    _SKIP_OPS_AFTER_SETUP_WITH = {"POP_TOP", "DUP_TOP"}

    for b in blocks:
        bid    = b["id"]
        instrs = get_block_instrs(b)

        for i, instr in enumerate(instrs):
            if instr["opname"] != "SETUP_WITH":
                continue

            setup_off   = instr["offset"]
            handler_off = instr.get("jump_target")
            if handler_off is None:
                continue
            handler_bid = offset_to_block.get(handler_off)
            if handler_bid is None:
                continue

            with_handler_block_ids.add(handler_bid)
            as_var = None
            for next_instr in instrs[i + 1:]:
                nop = next_instr["opname"]
                if nop in ("STORE_FAST_N", "STORE_FAST_MULTI", "STORE_NAME", "STORE_GLOBAL"):
                    as_var = (
                        next_instr.get("argrepr")
                        or str(next_instr.get("argval", "?"))
                    )
                    break
                if nop not in _SKIP_OPS_AFTER_SETUP_WITH:
                    break

            if as_var is None:
                for succ_bid in cfg.get(bid, set()):
                    succ_b = block_by_id.get(succ_bid)
                    if succ_b is None:
                        continue
                    for si in get_block_instrs(succ_b):
                        sop = si["opname"]
                        if sop in ("STORE_FAST_N", "STORE_FAST_MULTI", "STORE_NAME"):
                            as_var = si.get("argrepr") or str(si.get("argval", "?"))
                            break
                        if sop not in _SKIP_OPS_AFTER_SETUP_WITH:
                            break
                    if as_var is not None:
                        break

            protected = sorted(
                blk["id"] for blk in blocks
                if _block_start(blk) > setup_off and _block_start(blk) < handler_off
            )

            with_regions.append({
                "type":             "with",
                "block":            bid,
                "offset":           setup_off,
                "as_var":           as_var,
                "protected_blocks": protected,
                "handler_block":    handler_bid,
            })

            if debug:
                print(
                    f"[DEBUG MPY PAT] WITH: bloco {bid} offset={setup_off} "
                    f"as_var={as_var} handler={handler_bid} prot={protected}"
                )

    with_body_bids: set = set()
    for wr in with_regions:
        with_body_bids.update(wr.get("protected_blocks", []))
        with_body_bids.add(wr.get("block", -1))

    with_handler_block_ids |= bfs_walk(
        with_handler_block_ids,
        cfg,
        stop_fn=lambda bid: bid in with_body_bids,
        filter_fn=lambda bid: set(
            get_block_opnames(block_by_id.get(bid, {}))
        ).issubset(_WITH_CLEANUP_OPS),
    )

    patterns["with_regions"]        = with_regions
    patterns["with_handler_blocks"] = with_handler_block_ids
    exc_related_blocks.update(with_handler_block_ids)


    def _promote_loop_header(dst_bid: int) -> int:
        dst_start = _block_start(block_by_id.get(dst_bid))
        best = None
        for p in preds.get(dst_bid, set()):
            if p in handler_block_ids or p in exc_related_blocks:
                continue
            pb    = block_by_id.get(p) or {}
            pins  = get_block_instrs(pb)
            if not pins:
                continue
            li = pins[-1]
            op = li.get("opname")
            if not op or not _is_mpy_cond_jump(op):
                continue
            succs = list(cfg.get(p, ()))
            if len(succs) != 2 or dst_bid not in succs:
                continue
            others = [x for x in succs if x != dst_bid]
            if not any(_block_start(block_by_id.get(o)) >= dst_start for o in others):
                continue
            pstart = _block_start(pb)
            if best is None or pstart < best[0]:
                best = (pstart, p)
        return best[1] if best else dst_bid

    def _looks_like_loop_header(bid: int) -> bool:
        ps = {
            p for p in preds.get(bid, set())
            if p not in handler_block_ids and p not in exc_related_blocks
        }
        ss = {
            s for s in cfg.get(bid, set())
            if s not in handler_block_ids and s not in exc_related_blocks
        }
        if len(ps) >= 2 or len(ss) >= 2:
            return True
        b = block_by_id.get(bid) or {}
        return any(ins["opname"] == "FOR_ITER" for ins in get_block_instrs(b))

    seen_loops: set = set()

    for src, succs in cfg.items():
        src_start = _block_start(block_by_id.get(src))
        for dst in succs:
            dst_start = _block_start(block_by_id.get(dst))
            if dst_start > src_start:
                continue 
            if src in handler_block_ids or dst in handler_block_ids:
                continue
            if src in exc_related_blocks or dst in exc_related_blocks:
                continue

            promoted = _promote_loop_header(dst)
            if not _looks_like_loop_header(promoted) and not _looks_like_loop_header(dst):
                continue
            loop_key = (src, promoted)
            if loop_key in seen_loops:
                continue
            seen_loops.add(loop_key)

            header_ops = get_block_opnames(block_by_id.get(promoted) or {})
            is_for = "FOR_ITER" in header_ops

            patterns["loops"].append({
                "type":          "loop_back_edge",
                "header":        promoted,
                "body_entry":    dst,
                "latch":         src,
                "header_start":  _block_start(block_by_id.get(promoted)),
                "latch_start":   src_start,
                "is_async_for":  False,  
                "is_for":        is_for,
            })

            if debug:
                print(
                    f"[DEBUG MPY PAT] LOOP: latch {src} -> header {promoted} "
                    f"(body_entry={dst}, is_for={is_for})"
                )

    for b in blocks:
        bid    = b["id"]
        instrs = get_block_instrs(b)
        if not instrs:
            continue
        last = instrs[-1]
        op   = last.get("opname")
        if not op or not _is_mpy_cond_jump(op):
            continue

        succs = [
            s for s in cfg.get(bid, set())
            if s not in handler_block_ids and s not in exc_related_blocks
        ]
        if len(succs) != 2:
            continue

        jt_off     = last.get("jump_target")
        jump_block = offset_to_block.get(jt_off) if jt_off is not None else None
        fall_block = None

        if jump_block is not None:
            others     = [s for s in succs if s != jump_block]
            fall_block = others[0] if others else None
        else:
            sorted_succs = sorted(succs, key=lambda s: _block_start(block_by_id.get(s)))
            fall_block   = sorted_succs[0]  if sorted_succs          else None
            jump_block   = sorted_succs[1]  if len(sorted_succs) > 1 else None

        sem        = _mpy_jump_on_true(op)
        true_succ  = false_succ = None
        if sem is True:
            true_succ, false_succ = jump_block, fall_block
        elif sem is False:
            true_succ, false_succ = fall_block, jump_block

        patterns["ifs"].append({
            "type":               "if",
            "cond_block":         bid,
            "jump_block":         jump_block,
            "fall_block":         fall_block,
            "true_succ":          true_succ,
            "false_succ":         false_succ,
            "jump_target_offset": jt_off,
            "opcode":             op,
        })

        if debug:
            print(
                f"[DEBUG MPY PAT] IF: bloco {bid} ({op}) -> "
                f"jump {jump_block}, fall {fall_block}, "
                f"true={true_succ}, false={false_succ}"
            )

    for b in blocks:
        bid    = b["id"]
        instrs = get_block_instrs(b)
        if not instrs:
            continue
        last = instrs[-1]
        op   = last.get("opname")
        if op not in _MPY_SHORT_CIRCUIT_JUMPS:
            continue

        jt_off     = last.get("jump_target")
        jump_block = offset_to_block.get(jt_off) if jt_off is not None else None

        succs      = list(cfg.get(bid, set()))
        fall_block = None
        if jump_block is not None:
            others     = [s for s in succs if s != jump_block]
            fall_block = others[0] if others else None

        patterns["short_circuit_blocks"].add(bid)
        if fall_block is not None:
            patterns["short_circuit_blocks"].add(fall_block)

        is_and = (op == "JUMP_IF_FALSE_OR_POP")

        patterns["short_circuit_candidates"].append({
            "type":       "short_circuit",
            "block":      bid,
            "jump_block": jump_block,
            "fall_block": fall_block,
            "is_and":     is_and,
            "opcode":     op,
        })

        if debug:
            sc_name = "AND" if is_and else "OR"
            print(
                f"[DEBUG MPY PAT] SHORT-CIRCUIT ({sc_name}): bloco {bid} "
                f"jump={jump_block} fall={fall_block}"
            )


    scope_flags  = getattr(code_obj, "scope_flags", 0)
    is_generator = bool(scope_flags & 0x01)   
    if is_generator and debug:
        print(f"[DEBUG MPY PAT] GENERATOR: {getattr(code_obj, 'co_name', '?')}")


    loop_headers_seen: set = set()
    comprehensions: list   = []

    for lp in patterns["loops"]:
        header_bid = lp["header"]
        if header_bid in loop_headers_seen:
            continue

        body_bids: set = set()
        for other_lp in patterns["loops"]:
            if other_lp["header"] == header_bid:
                body_bids.add(other_lp["latch"])
                body_bids.add(other_lp.get("body_entry", -1))

        has_store_comp = any(
            ins["opname"] == "STORE_COMP"
            for bid in body_bids
            for ins in get_block_instrs(block_by_id.get(bid, {}))
        )

        if has_store_comp:
            loop_headers_seen.add(header_bid)
            comprehensions.append({
                "type":      "comprehension",  
                "header":    header_bid,
                "loop_info": lp,
            })
            if debug:
                print(f"[DEBUG MPY PAT] COMPREHENSION: header={header_bid}")

    patterns["comprehensions"] = comprehensions

    if debug:
        print(
            f"[DEBUG MPY PAT] Resumo: "
            f"ifs={len(patterns['ifs'])} "
            f"loops={len(patterns['loops'])} "
            f"try_regions={len(patterns['try_regions'])} "
            f"with_regions={len(patterns['with_regions'])} "
            f"sc_blocks={len(patterns['short_circuit_blocks'])} "
            f"comprehensions={len(patterns['comprehensions'])}"
        )

    return patterns
