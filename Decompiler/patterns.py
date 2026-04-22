
import dis
from typing import Dict, List, Set, Any
from utils.block_utils import (
    build_block_by_id, build_offset_to_block, build_predecessor_map,
    get_block_instrs, get_block_opnames, get_last_jump_target, bfs_walk,
)
from utils.handler_classify import classify_handler_block as _classify_block


def is_cond_jump(opname: str) -> bool:
    return opname.startswith("POP_JUMP") and "IF_" in opname


def jump_on_true(opname: str):
    if "IF_NOT_NONE" in opname:
        return True
    if "IF_NONE" in opname:
        return False
    if "IF_TRUE" in opname:
        return True
    if "IF_FALSE" in opname:
        return False
    return None


def block_span_exclusive(b: dict):
    start = b.get("start_offset", 0)
    instrs = get_block_instrs(b)
    if instrs:
        last_off = instrs[-1]["offset"]
        end_excl = last_off + 2
    else:
        end_excl = (b.get("end_offset", start) or start) + 1
    return start, end_excl


def _is_seq_match_start(b_sm: dict) -> bool:
    ops_sm = get_block_opnames(b_sm)
    return "MATCH_SEQUENCE" in ops_sm and any(
        op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE") for op in ops_sm
    )


def _get_match_succ_fail(b_chk: dict, cfg: dict, offset_to_block: dict):
    instrs_chk = get_block_instrs(b_chk)
    bid_chk = b_chk["id"]
    last_cond = None
    for ins in reversed(instrs_chk):
        if ins["opname"] in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE"):
            last_cond = ins
            break
    if last_cond is None:
        return None, None
    jt_off = last_cond.get("jump_target")
    if jt_off is None:
        return None, None
    fail_bid = offset_to_block.get(jt_off)
    succs_chk = cfg.get(bid_chk, set())
    success_bid = next((s for s in succs_chk if s != fail_bid), None)
    return success_bid, fail_bid


def _is_match_case_block(b_chk: dict, cfg: dict, block_by_id: dict, offset_to_block: dict) -> bool:
    instrs_chk = get_block_instrs(b_chk)
    copy1_idx = None
    for idx, ins in enumerate(instrs_chk):
        if ins["opname"] == "COPY" and ins.get("arg") == 1:
            copy1_idx = idx
            break
    if copy1_idx is None:
        return False

    if any(instrs_chk[j]["opname"] == "COMPARE_OP" for j in range(copy1_idx)):
        return False
    ops_chk = [i["opname"] for i in instrs_chk]
    if not any(op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE") for op in ops_chk):
        return False
    success_bid, fail_bid = _get_match_succ_fail(b_chk, cfg, offset_to_block)
    if success_bid is None or fail_bid is None:
        return False

    if fail_bid in cfg.get(success_bid, set()):
        return False
    succ0 = block_by_id.get(success_bid)
    if not succ0:
        return False
    s0_ops = [i["opname"] for i in get_block_instrs(succ0)
              if i["opname"] not in ("RESUME", "NOP")]
    return bool(s0_ops) and s0_ops[0] in ("POP_TOP", "UNPACK_SEQUENCE")


def detect_high_level_patterns(blocks, cfg, stack_info, code_obj, debug=True):
    if debug:
        print(f"[DEBUG] detect_high_level_patterns: {code_obj.co_name}")

    block_by_id = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)
    preds = build_predecessor_map(blocks, cfg)

    patterns = {"ifs": [], "loops": [], "short_circuit_candidates": [],
                "short_circuit_blocks": set(), "try_regions": []}

    handler_block_ids = set()
    exc_related_blocks = set()

    entries = list(dis.Bytecode(code_obj).exception_entries)

    grouped = {}
    for e in entries:
        handler = offset_to_block.get(e.target)
        if handler is None:
            continue
        grouped.setdefault((e.start, e.end, e.depth), []).append((e, handler))

    def classify_handler_block(handler_bid: int):
        return _classify_block(block_by_id.get(handler_bid) or {})

    seen = set()
    for (start, end, depth), lst in grouped.items():
        handlers = []
        for e, handler_bid in lst:
            key = (start, end, e.target, depth, e.lasti, handler_bid)
            if key in seen:
                continue
            seen.add(key)
            handlers.append((e, handler_bid))

        protected = []
        for b in blocks:
            bs, bex = block_span_exclusive(b)
            if bs >= start and bs < end:
                protected.append(b["id"])
        protected = sorted(set(protected))

        handler_infos = []
        for e, handler_bid in handlers:
            hcls = classify_handler_block(handler_bid)
            handler_infos.append({
                "handler_offset": e.target,
                "handler_block": handler_bid,
                "lasti": e.lasti,
                "is_except": hcls["is_except"],
                "is_cleanup": hcls["is_cleanup"],
                "is_gen_cleanup": hcls.get("is_gen_cleanup", False),
                "is_exc_var_cleanup": hcls.get("is_exc_var_cleanup", False),
                "is_with_handler": hcls.get("is_with_handler", False),
                "is_with_reraise": hcls.get("is_with_reraise", False),
                "is_comp_restore": hcls.get("is_comp_restore", False),
                "is_cleanup_throw": hcls.get("is_cleanup_throw", False),
                "is_async_for_exit": hcls.get("is_async_for_exit", False),
            })

        if all(h.get("is_gen_cleanup") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping generator cleanup try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        if all(h.get("is_cleanup_throw") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping cleanup_throw try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        if all(h.get("is_async_for_exit") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping async_for_exit try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        if all(h.get("is_exc_var_cleanup") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping exc var cleanup try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        if all(h.get("is_with_handler") or h.get("is_with_reraise") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping with handler try_region [{start},{end})")
            continue

        if all(h.get("is_comp_restore") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping comprehension restore try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        for h in handler_infos:
            handler_block_ids.add(h["handler_block"])
            exc_related_blocks.add(h["handler_block"])
        exc_related_blocks.update(protected)

        patterns["try_regions"].append({
            "type": "try_region_group",
            "range": (start, end),
            "depth": depth,
            "protected_blocks": protected,
            "handlers": handler_infos,
        })

        if debug:
            hs = ", ".join(f"{h['handler_block']}@{h['handler_offset']}" for h in handler_infos)
            print(f"[DEBUG] TRY-REGION: [{start},{end}) depth={depth} handlers={hs} protected={protected}")

    with_regions = []
    for b in blocks:
        instrs = b.get("instructions", []) or []
        for i, ins in enumerate(instrs):
            if ins["opname"] not in ("BEFORE_WITH", "BEFORE_ASYNC_WITH"):
                continue

            is_async = ins["opname"] == "BEFORE_ASYNC_WITH"
            with_start = ins["offset"]

            with_entry = None
            for e in entries:
                if e.start < with_start:
                    continue
                handler_bid_tmp = offset_to_block.get(e.target)
                handler_b_tmp = block_by_id.get(handler_bid_tmp) if handler_bid_tmp is not None else None
                if handler_b_tmp is None:
                    continue
                h_ops_tmp = [i["opname"] for i in (handler_b_tmp.get("instructions") or [])]
                if "WITH_EXCEPT_START" in h_ops_tmp:
                    with_entry = e
                    break
            if with_entry is None:
                for e in entries:
                    if e.start >= with_start and e.start <= with_start + 10:
                        with_entry = e
                        break

            as_var = None
            remaining_instrs = instrs[i + 1:]
            skip_ops = {"POP_TOP", "NOP", "CACHE", "GET_AWAITABLE", "SEND", "END_SEND", "RESUME"}
            for next_ins in remaining_instrs:
                if next_ins["opname"] in ("STORE_FAST", "STORE_NAME"):
                    as_var = next_ins.get("argval")
                    break
                if next_ins["opname"] not in skip_ops:
                    break

            if as_var is None:
                for succ_bid in cfg.get(b["id"], set()):
                    succ_b = block_by_id.get(succ_bid)
                    if succ_b is None:
                        continue
                    succ_instrs = succ_b.get("instructions", []) or []
                    for si in succ_instrs:
                        if si["opname"] in ("STORE_FAST", "STORE_NAME"):
                            as_var = si.get("argval")
                            break
                        if si["opname"] not in skip_ops:
                            break
                    if as_var is not None:
                        break

            prot = []
            if with_entry:
                for blk in blocks:
                    bs, bex = block_span_exclusive(blk)
                    if bs >= with_entry.start and bs < with_entry.end:
                        prot.append(blk["id"])

            handler_bid = offset_to_block.get(with_entry.target) if with_entry else None

            with_regions.append({
                "type": "async_with" if is_async else "with",
                "block": b["id"],
                "offset": with_start,
                "as_var": as_var,
                "protected_blocks": sorted(set(prot)),
                "handler_block": handler_bid,
            })

            if debug:
                wtype = "ASYNC WITH" if is_async else "WITH"
                print(f"[DEBUG] {wtype}: bloco {b['id']} offset={with_start} as_var={as_var} prot={sorted(set(prot))}")

    with_handler_block_ids = set()
    for wr in with_regions:
        hb = wr.get("handler_block")
        if hb is not None:
            with_handler_block_ids.add(hb)

    _pure_plumbing_ops = {"POP_TOP", "POP_EXCEPT", "NOP", "COPY", "RERAISE",
                          "PUSH_EXC_INFO", "WITH_EXCEPT_START",
                          "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT",
                          "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE",
                          "LOAD_CONST", "STORE_FAST", "DELETE_FAST",
                          "LOAD_FAST", "LOAD_FAST_CHECK", "SWAP", "RETURN_CONST"}
    for e in entries:
        handler_bid = offset_to_block.get(e.target)
        if handler_bid is None:
            continue
        prot_bids = set()
        for blk in blocks:
            bs, bex = block_span_exclusive(blk)
            if bs >= e.start and bs < e.end:
                prot_bids.add(blk["id"])
        if not (prot_bids & with_handler_block_ids):
            continue
        cand_ops = set(get_block_opnames(block_by_id.get(handler_bid, {})))
        if "CHECK_EXC_MATCH" in cand_ops:
            continue
        if not cand_ops.issubset(_pure_plumbing_ops):
            continue
        with_handler_block_ids.add(handler_bid)

    with_body_bids = set()
    for wr in with_regions:
        with_body_bids.update(wr.get("protected_blocks", []))
        with_body_bids.add(wr.get("block", -1))

    cleanup_ops = {"POP_TOP", "POP_EXCEPT", "NOP", "JUMP_FORWARD", "JUMP_BACKWARD",
                   "LOAD_FAST", "LOAD_FAST_CHECK", "RETURN_VALUE", "RETURN_CONST",
                   "COPY", "RERAISE", "JUMP_BACKWARD_NO_INTERRUPT",
                   "LOAD_CONST", "CALL", "STORE_FAST", "STORE_NAME", "SWAP",
                   "PUSH_EXC_INFO", "WITH_EXCEPT_START", "POP_JUMP_IF_TRUE",
                   "POP_JUMP_IF_FALSE"}
    with_handler_block_ids |= bfs_walk(
        with_handler_block_ids,
        cfg,
        stop_fn=lambda bid: bid in with_body_bids,
        filter_fn=lambda bid: set(get_block_opnames(block_by_id.get(bid, {}))).issubset(cleanup_ops),
    )

    patterns["with_regions"] = with_regions
    patterns["with_handler_blocks"] = with_handler_block_ids
    exc_related_blocks.update(with_handler_block_ids)

    def last_instr(bid):
        b = block_by_id.get(bid) or {}
        ins = b.get("instructions", []) or []
        return ins[-1] if ins else None

    def promote_loop_header(dst_bid: int):
      
        dst_start = (block_by_id.get(dst_bid) or {}).get("start_offset", 10**18)
        best = None
        for p in preds.get(dst_bid, set()):
            if p in handler_block_ids or p in exc_related_blocks:
                continue
            pb = block_by_id.get(p) or {}
            pins = pb.get("instructions", []) or []
            if not pins:
                continue
            li = pins[-1]
            op = li.get("opname")
            if not op or not is_cond_jump(op):
                continue

            succs = list(cfg.get(p, ()))
            if len(succs) != 2:
                continue
            if dst_bid not in succs:
                continue

            other = [x for x in succs if x != dst_bid]
            if not other:
                continue
            ok = False
            for o in other:
                os = (block_by_id.get(o) or {}).get("start_offset", 10**18)
                if os >= dst_start:
                    ok = True
            if not ok:
                continue

            pstart = pb.get("start_offset", 10**18)
            if best is None or pstart < best[0]:
                best = (pstart, p)

        return best[1] if best else dst_bid

    def looks_like_loop_header(bid):
        ps = {p for p in preds.get(bid, set()) if p not in handler_block_ids and p not in exc_related_blocks}
        ss = {s for s in cfg.get(bid, set()) if s not in handler_block_ids and s not in exc_related_blocks}

        if len(ps) >= 2:
            return True
        if len(ss) >= 2:
            return True

        b = block_by_id.get(bid) or {}
        instrs = b.get("instructions", []) or []
        return any(i.get("opname") == "FOR_ITER" for i in instrs)

    for src, succs in cfg.items():
        src_start = block_by_id.get(src, {}).get("start_offset", 10**18)
        for dst in succs:
            dst_start = block_by_id.get(dst, {}).get("start_offset", 10**18)
            if dst_start <= src_start:
                if src in handler_block_ids or dst in handler_block_ids:
                    continue
                if src in exc_related_blocks or dst in exc_related_blocks:
                    continue
                if not looks_like_loop_header(dst):
                    continue

                promoted = promote_loop_header(dst)

                header_b = block_by_id.get(promoted, {})
                header_ops = [ins["opname"] for ins in (header_b.get("instructions", []) or [])]
                is_async_for = "GET_ANEXT" in header_ops

                patterns["loops"].append({
                    "type": "loop_back_edge",
                    "header": promoted,
                    "body_entry": dst,
                    "latch": src,
                    "header_start": block_by_id.get(promoted, {}).get("start_offset", dst_start),
                    "latch_start": src_start,
                    "is_async_for": is_async_for,
                })
                if debug:
                    print(f"[DEBUG] LOOP: latch bloco {src} -> header bloco {promoted} (body_entry={dst})")
    ternary_ancestors = stack_info.get("ternary_ancestors", set()) if isinstance(stack_info, dict) else set()

    for b in blocks:
        bid = b["id"]
        instrs = b.get("instructions", []) or []
        if not instrs:
            continue
        last = instrs[-1]
        op = last.get("opname")
        if not op or not is_cond_jump(op):
            continue

        if bid in ternary_ancestors:
            continue

        succs = [s for s in cfg.get(bid, set())
                 if s not in handler_block_ids and s not in exc_related_blocks]
        if len(succs) != 2:
            continue

        jt_off = last.get("jump_target")
        jump_block = offset_to_block.get(jt_off) if jt_off is not None else None
        fall_block = None
        if jump_block is not None:
            other = [s for s in succs if s != jump_block]
            fall_block = other[0] if other else None

        sem = jump_on_true(op)
        true_succ = false_succ = None
        if sem is True:
            true_succ, false_succ = jump_block, fall_block
        elif sem is False:
            true_succ, false_succ = fall_block, jump_block

        is_sc = False
        if len(instrs) >= 2:
            prev = instrs[-2]
            if prev.get("opname") == "COPY" and prev.get("arg") == 1 and fall_block is not None:
                fall_b = block_by_id.get(fall_block, {})
                fall_instrs = fall_b.get("instructions", []) or []
                if fall_instrs and fall_instrs[0].get("opname") == "POP_TOP":
                    is_sc = True
                    patterns["short_circuit_blocks"].add(bid)
                    patterns["short_circuit_blocks"].add(fall_block)
                    if debug:
                        print(f"[DEBUG] SHORT-CIRCUIT: bloco {bid} e fall {fall_block} ({op}) suprimidos")

        patterns["ifs"].append({
            "type": "if",
            "cond_block": bid,
            "jump_block": jump_block,
            "fall_block": fall_block,
            "true_succ": true_succ,
            "false_succ": false_succ,
            "jump_target_offset": jt_off,
            "opcode": op,
        })

        if debug and not is_sc:
            print(f"[DEBUG] IF: bloco {bid} ({op}) -> jump {jump_block}, fall {fall_block}, true={true_succ}, false={false_succ}")


    assert_patterns = []
    for b in blocks:
        instrs = b.get("instructions", []) or []
        opnames = [ins["opname"] for ins in instrs]

        if "LOAD_ASSERTION_ERROR" in opnames:
            for pred_bid in preds.get(b["id"], set()):
                pred_b = block_by_id.get(pred_bid, {})
                pred_instrs = pred_b.get("instructions", []) or []
                if pred_instrs:
                    last = pred_instrs[-1]
                    last_op = last.get("opname", "")
                    if last_op.startswith("POP_JUMP") and "IF_TRUE" in last_op:
                        assert_patterns.append({
                            "type": "assert",
                            "cond_block": pred_bid,
                            "fail_block": b["id"],
                            "jump_target": last.get("jump_target"),
                        })
                        if debug:
                            print(f"[DEBUG] ASSERT: cond_block={pred_bid} fail_block={b['id']}")

    patterns["assert_patterns"] = assert_patterns


    def _extract_literal_val(instrs_chk):
        for idx, ins in enumerate(instrs_chk):
            if ins["opname"] == "COMPARE_OP" and (ins.get("argval") or "").startswith("=="):
                for j in range(idx - 1, -1, -1):
                    prev = instrs_chk[j]
                    if prev["opname"] == "LOAD_CONST":
                        return prev.get("argval")
                    if prev["opname"] not in ("COPY", "RESUME", "NOP"):
                        break
        return None

    def _extract_class_info(instrs_chk, success_b_chk):
        ops_chk = [i["opname"] for i in instrs_chk]
        if "MATCH_CLASS" not in ops_chk:
            return None, []
        cls_name = None
        for idx, ins in enumerate(instrs_chk):
            if ins["opname"] == "MATCH_CLASS":
                for j in range(idx - 1, -1, -1):
                    prev = instrs_chk[j]
                    if prev["opname"] in ("LOAD_GLOBAL", "LOAD_NAME"):
                        cls_name = prev.get("argval") or "?"
                        break
                    if prev["opname"] not in ("LOAD_CONST", "RESUME", "NOP"):
                        break
                break
        captures = []
        if success_b_chk:
            body_instrs = success_b_chk.get("instructions") or []
            if any(i["opname"] == "UNPACK_SEQUENCE" for i in body_instrs):
                for bi in body_instrs:
                    if bi["opname"] == "STORE_FAST":
                        captures.append(bi.get("argval", "?"))
        return cls_name, captures


    match_case_bids = set()
    for b in blocks:
        if _is_match_case_block(b, cfg, block_by_id, offset_to_block):
            match_case_bids.add(b["id"])

    def _get_fail_bid(bid_f):
        b_f = block_by_id.get(bid_f)
        if b_f is None:
            return None
        _, fail = _get_match_succ_fail(b_f, cfg, offset_to_block)
        return fail

    mid_chain_bids = set()
    for bid_m in match_case_bids:
        fb = _get_fail_bid(bid_m)
        if fb is not None and fb in match_case_bids:
            mid_chain_bids.add(fb)

    start_bids_m = match_case_bids - mid_chain_bids

    match_chains = []
    for start_bid in sorted(start_bids_m):
        chain_cases = []
        cur_bid = start_bid
        while cur_bid is not None and cur_bid in match_case_bids:
            b_cur = block_by_id[cur_bid]
            instrs_cur = b_cur.get("instructions", []) or []
            ops_cur = [i["opname"] for i in instrs_cur]
            success_bid, fail_bid = _get_match_succ_fail(b_cur, cfg, offset_to_block)
            success_b = block_by_id.get(success_bid) if success_bid is not None else None

            if "MATCH_CLASS" in ops_cur:
                cls_name, captures = _extract_class_info(instrs_cur, success_b)
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "class", "class_name": cls_name or "?",
                         "captures": captures}
            elif "MATCH_SEQUENCE" in ops_cur:
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "sequence"}
            elif "MATCH_MAPPING" in ops_cur:
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "mapping"}
            else:
                lit_val = _extract_literal_val(instrs_cur)
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "literal", "literal_value": lit_val}

            chain_cases.append(entry)
            cur_bid = fail_bid

        if chain_cases and cur_bid is not None:
            b_trail = block_by_id.get(cur_bid)
            if b_trail is not None:
                instrs_trail = b_trail.get("instructions", []) or []
                ops_trail = [i["opname"] for i in instrs_trail]
                has_copy = any(op == "COPY" and i.get("arg") == 1
                               for op, i in zip(ops_trail, instrs_trail))
                has_cmp_eq = any(i["opname"] == "COMPARE_OP"
                                 and (i.get("argval") or "").startswith("==")
                                 for i in instrs_trail)
                has_pjf = any(op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE")
                              for op in ops_trail)
                if (not has_copy) and has_cmp_eq and has_pjf:
                    success_t, fail_t = _get_match_succ_fail(b_trail, cfg, offset_to_block)
                    if success_t is not None and fail_t is not None:
                        lit_val_t = _extract_literal_val(instrs_trail)
                        chain_cases.append({
                            "cond_block": cur_bid,
                            "body_block": success_t,
                            "pattern_type": "literal",
                            "literal_value": lit_val_t,
                        })
                        cur_bid = fail_t

        if chain_cases:
            match_chains.append({
                "type": "match_chain",
                "first_block": start_bid,
                "cases": chain_cases,
                "default_block": cur_bid,
            })
            if debug:
                pts = [c["pattern_type"] for c in chain_cases]
                print(f"[DEBUG] MATCH CHAIN: start={start_bid}, cases={pts}, default={cur_bid}")

    chain_block_ids = set()
    for mc in match_chains:
        for case in mc.get("cases", []):
            chain_block_ids.add(case["cond_block"])
            if case.get("body_block") is not None:
                chain_block_ids.add(case["body_block"])
        if mc.get("default_block") is not None:
            chain_block_ids.add(mc["default_block"])

    match_regions = []
    for b in blocks:
        if b["id"] in chain_block_ids:
            continue
        instrs = b.get("instructions", []) or []
        for i, ins in enumerate(instrs):
            if ins["opname"] == "COPY" and ins.get("arg") == 1:
                if i + 1 < len(instrs) and instrs[i + 1]["opname"].startswith("MATCH_"):
                    match_regions.append({
                        "type": "match_case_arm",
                        "block": b["id"],
                        "match_type": instrs[i + 1]["opname"],
                        "offset": ins["offset"],
                    })
                    if debug:
                        print(f"[DEBUG] MATCH ARM: bloco {b['id']} tipo={instrs[i + 1]['opname']}")

    patterns["match_regions"] = match_regions
    patterns["match_chains"] = match_chains


    def _trace_seq_success_chain(start_bsm):
        cur_sm = start_bsm
        chain_sm = []
        visited_sm = set()
        while cur_sm is not None and cur_sm not in visited_sm:
            visited_sm.add(cur_sm)
            chain_sm.append(cur_sm)
            b_cur_sm = block_by_id.get(cur_sm)
            if b_cur_sm is None:
                break
            jt_off_sm = get_last_jump_target(b_cur_sm)
            if jt_off_sm is None:
                break 
            fail_sm = offset_to_block.get(jt_off_sm)
            succs_sm = cfg.get(cur_sm, set())
            fall_sm = next((s for s in succs_sm if s != fail_sm), None)
            if fall_sm is None:
                break
            cur_sm = fall_sm
        return chain_sm

    def _get_seq_length(chain_bids_sm):
        for bid_sm in chain_bids_sm:
            b_sm = block_by_id.get(bid_sm)
            if b_sm is None:
                continue
            instrs_sm = b_sm.get("instructions") or []
            ops_sm = [i["opname"] for i in instrs_sm]
            if "GET_LEN" in ops_sm:
                for i_sm, ins_sm in enumerate(instrs_sm):
                    if ins_sm["opname"] == "GET_LEN":
                        for j_sm in range(i_sm + 1, len(instrs_sm)):
                            if instrs_sm[j_sm]["opname"] == "LOAD_CONST":
                                return instrs_sm[j_sm].get("argval")
        return None

    seq_match_starts = [b["id"] for b in blocks if _is_seq_match_start(b)]
    seq_start_set_sm = set(seq_match_starts)

    seq_match_chains = []
    if seq_match_starts:
        sm_chain_cases = []
        visited_sm_starts = set()
        cur_sm_start = seq_match_starts[0]

        while cur_sm_start is not None and cur_sm_start not in visited_sm_starts:
            visited_sm_starts.add(cur_sm_start)
            b_sm_start = block_by_id.get(cur_sm_start)
            if b_sm_start is None:
                break

            jt_off_sm = get_last_jump_target(b_sm_start)
            fail_all_sm = offset_to_block.get(jt_off_sm) if jt_off_sm is not None else None

            chain_bids_sm = _trace_seq_success_chain(cur_sm_start)
            body_bid_sm = chain_bids_sm[-1] if chain_bids_sm else None
            n_sm = _get_seq_length(chain_bids_sm)

            sm_chain_cases.append({
                "start_bid": cur_sm_start,
                "fail_all_bid": fail_all_sm,
                "body_bid": body_bid_sm,
                "all_bids": set(chain_bids_sm),
                "n": n_sm,
            })

            next_sm_start = None
            if fail_all_sm in seq_start_set_sm and fail_all_sm not in visited_sm_starts:
                next_sm_start = fail_all_sm
            elif fail_all_sm is not None:
                for s_sm in cfg.get(fail_all_sm, set()):
                    if s_sm in seq_start_set_sm and s_sm not in visited_sm_starts:
                        next_sm_start = s_sm
                        break
            cur_sm_start = next_sm_start

        if sm_chain_cases:
            last_fail_sm = sm_chain_cases[-1]["fail_all_bid"]
            all_sm_bids = set()
            for c_sm in sm_chain_cases:
                all_sm_bids.update(c_sm["all_bids"])
                if c_sm["fail_all_bid"] is not None:
                    all_sm_bids.add(c_sm["fail_all_bid"])
            if last_fail_sm is not None:
                all_sm_bids.add(last_fail_sm)

            seq_match_chains.append({
                "type": "seq_match_chain",
                "first_block": seq_match_starts[0],
                "cases": sm_chain_cases,
                "default_block": last_fail_sm,
                "all_blocks": all_sm_bids,
            })
            if debug:
                print(f"[DEBUG] SEQ MATCH CHAIN: {len(sm_chain_cases)} cases, default={last_fail_sm}")

    patterns["seq_match_chains"] = seq_match_chains

    def _is_map_match_start(b_mm):
        ops_mm = get_block_opnames(b_mm)
        return "MATCH_MAPPING" in ops_mm and any(
            op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE") for op in ops_mm
        )

    def _trace_map_success_chain(start_bmm):
        cur_mm = start_bmm
        chain_mm = []
        visited_mm = set()
        while cur_mm is not None and cur_mm not in visited_mm:
            visited_mm.add(cur_mm)
            chain_mm.append(cur_mm)
            b_cur_mm = block_by_id.get(cur_mm)
            if b_cur_mm is None:
                break
            jt_off_mm = get_last_jump_target(b_cur_mm)
            if jt_off_mm is None:
                break
            fail_mm = offset_to_block.get(jt_off_mm)
            succs_mm = cfg.get(cur_mm, set())
            fall_mm = next((s for s in succs_mm if s != fail_mm), None)
            if fall_mm is None:
                break
            cur_mm = fall_mm
        return chain_mm

    def _extract_map_pattern(chain_bids_mm):
        keys_tuple = None
        for bid in chain_bids_mm:
            b_ = block_by_id.get(bid)
            if not b_:
                continue
            instrs = b_.get("instructions", []) or []
            for idx, ins in enumerate(instrs):
                if ins["opname"] == "MATCH_KEYS":
                    for j in range(idx - 1, -1, -1):
                        if instrs[j]["opname"] == "LOAD_CONST":
                            keys_tuple = instrs[j].get("argval")
                            break
                    break
            if keys_tuple is not None:
                break
        if not isinstance(keys_tuple, tuple):
            return None, 0, 0

        all_post = []
        for bid in chain_bids_mm:
            b_ = block_by_id.get(bid)
            if not b_:
                continue
            for ins in (b_.get("instructions") or []):
                all_post.append((bid, ins))

        unpack_idx = None
        for i, (_, ins) in enumerate(all_post):
            if ins["opname"] == "UNPACK_SEQUENCE":
                unpack_idx = i
                break
        if unpack_idx is None:
            return None, 0, 0

        per_key_ops = [] 
        rest_name = None

        i = unpack_idx + 1
        while i < len(all_post):
            bid_i, ins = all_post[i]
            on = ins["opname"]
            if on == "LOAD_CONST" and i + 1 < len(all_post) \
                    and all_post[i + 1][1]["opname"] == "COMPARE_OP":
                per_key_ops.append(("literal", ins.get("argval")))
                i += 2
                if i < len(all_post) and all_post[i][1]["opname"].startswith("POP_JUMP"):
                    i += 1
                continue
            if on == "STORE_FAST":
                per_key_ops.append(("bind", ins.get("argval")))
                i += 1
                continue
            if on == "BUILD_MAP":
                for j in range(i + 1, min(i + 12, len(all_post))):
                    if all_post[j][1]["opname"] == "STORE_FAST":
                        rest_name = all_post[j][1].get("argval")
                        i = j + 1
                        break
                else:
                    i += 1
                continue
            if on in ("POP_TOP", "NOP", "RESUME", "UNPACK_SEQUENCE",
                      "COPY", "SWAP", "DICT_UPDATE", "DELETE_SUBSCR"):
                i += 1
                continue
            break

        parts = []
        for i_k, key in enumerate(keys_tuple):
            if i_k < len(per_key_ops):
                kind_k, val_k = per_key_ops[i_k]
                if kind_k == "literal":
                    parts.append(f"{repr(key)}: {repr(val_k)}")
                else:
                    parts.append(f"{repr(key)}: {val_k}")
            else:
                parts.append(f"{repr(key)}: _")
        if rest_name:
            parts.append(f"**{rest_name}")
        pattern_str = "{" + ", ".join(parts) + "}"

        if rest_name:
            n_bindings = len(keys_tuple) + 1
        else:
            n_bindings = sum(1 for k, _ in per_key_ops if k == "bind")
        return pattern_str, n_bindings, 0

    map_match_chains = []
    map_match_starts = [b["id"] for b in blocks if _is_map_match_start(b)]
    mm_covered = set()
    if map_match_starts:
        mm_start_set = set(map_match_starts)
        visited_mm = set()
        mm_start_first = min(map_match_starts)
        cur_mm_start = mm_start_first
        mm_cases = []
        while cur_mm_start is not None and cur_mm_start not in visited_mm:
            visited_mm.add(cur_mm_start)
            b_mm_start = block_by_id.get(cur_mm_start)
            if b_mm_start is None:
                break
            jt_off_mm0 = get_last_jump_target(b_mm_start)
            fail_all_mm = offset_to_block.get(jt_off_mm0) if jt_off_mm0 is not None else None

            chain_bids_mm = _trace_map_success_chain(cur_mm_start)
            body_bid_mm = chain_bids_mm[-1] if chain_bids_mm else None
            pat_str, n_binds, _ = _extract_map_pattern(chain_bids_mm)

            if pat_str is None:
                break

            mm_cases.append({
                "start_bid": cur_mm_start,
                "fail_all_bid": fail_all_mm,
                "body_bid": body_bid_mm,
                "all_bids": set(chain_bids_mm),
                "pattern_str": pat_str,
                "n_bindings": n_binds,
            })

            next_mm_start = None
            if fail_all_mm is not None:
                if fail_all_mm in mm_start_set and fail_all_mm not in visited_mm:
                    next_mm_start = fail_all_mm
                else:
                    for s_mm in cfg.get(fail_all_mm, set()):
                        if s_mm in mm_start_set and s_mm not in visited_mm:
                            next_mm_start = s_mm
                            break
            cur_mm_start = next_mm_start

        if mm_cases:
            last_fail_mm = mm_cases[-1]["fail_all_bid"]
            all_mm_bids = set()
            for c_mm in mm_cases:
                all_mm_bids.update(c_mm["all_bids"])
                if c_mm["fail_all_bid"] is not None:
                    all_mm_bids.add(c_mm["fail_all_bid"])
            if last_fail_mm is not None:
                all_mm_bids.add(last_fail_mm)

            map_match_chains.append({
                "type": "map_match_chain",
                "first_block": mm_start_first,
                "cases": mm_cases,
                "default_block": last_fail_mm,
                "all_blocks": all_mm_bids,
            })
            mm_covered = all_mm_bids
            if debug:
                print(f"[DEBUG] MAP MATCH CHAIN: {len(mm_cases)} cases, default={last_fail_mm}")

    patterns["map_match_chains"] = map_match_chains

    if mm_covered:
        patterns["match_chains"] = [
            mc for mc in patterns.get("match_chains", [])
            if mc.get("first_block") not in mm_covered
            and not any(c.get("cond_block") in mm_covered
                        for c in mc.get("cases", []))
        ]
        patterns["match_regions"] = [
            mr for mr in patterns.get("match_regions", [])
            if mr.get("block") not in mm_covered
        ]

    comprehensions = []
    loop_headers_seen = set()
    for lp in patterns.get("loops", []):
        header_bid = lp["header"]
        if header_bid in loop_headers_seen:
            continue

        body_bids = set()
        for other_lp in patterns.get("loops", []):
            if other_lp["header"] == header_bid:
                body_bids.add(other_lp["latch"])
                body_bids.add(other_lp.get("body_entry", -1))


        comp_type = None
        for bid in body_bids:
            blk = block_by_id.get(bid, {})
            for instr in (blk.get("instructions", []) or []):
                if instr["opname"] == "LIST_APPEND":
                    comp_type = "listcomp"
                elif instr["opname"] == "SET_ADD":
                    comp_type = "setcomp"
                elif instr["opname"] == "MAP_ADD":
                    comp_type = "dictcomp"

        if comp_type:
            loop_headers_seen.add(header_bid)
            comprehensions.append({
                "type": comp_type,
                "header": header_bid,
                "loop_info": lp,
            })
            if debug:
                print(f"[DEBUG] COMPREHENSION: {comp_type} header={header_bid}")

    patterns["comprehensions"] = comprehensions

    return patterns
    return start, end_excl


def _is_seq_match_start(b_sm: dict) -> bool:
    """Bloco inicia um case de sequência se tem MATCH_SEQUENCE + POP_JUMP_IF_FALSE."""
    ops_sm = get_block_opnames(b_sm)
    return "MATCH_SEQUENCE" in ops_sm and any(
        op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE") for op in ops_sm
    )


def _get_match_succ_fail(b_chk: dict, cfg: dict, offset_to_block: dict):
    """Retorna (success_bid, fail_bid) para um bloco com POP_JUMP_IF_FALSE/NONE.
    success = fall-through (condição verdadeira = case match),
    fail = jump target (próximo case ou default)."""
    instrs_chk = get_block_instrs(b_chk)
    bid_chk = b_chk["id"]
    last_cond = None
    for ins in reversed(instrs_chk):
        if ins["opname"] in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE"):
            last_cond = ins
            break
    if last_cond is None:
        return None, None
    jt_off = last_cond.get("jump_target")
    if jt_off is None:
        return None, None
    fail_bid = offset_to_block.get(jt_off)
    succs_chk = cfg.get(bid_chk, set())
    success_bid = next((s for s in succs_chk if s != fail_bid), None)
    return success_bid, fail_bid


def _is_match_case_block(b_chk: dict, cfg: dict, block_by_id: dict, offset_to_block: dict) -> bool:
    instrs_chk = get_block_instrs(b_chk)
    # Encontra o primeiro COPY 1
    copy1_idx = None
    for idx, ins in enumerate(instrs_chk):
        if ins["opname"] == "COPY" and ins.get("arg") == 1:
            copy1_idx = idx
            break
    if copy1_idx is None:
        return False
    # COPY 1 precedido por COMPARE_OP → short-circuit encadeado (1 < x < 10), não match
    if any(instrs_chk[j]["opname"] == "COMPARE_OP" for j in range(copy1_idx)):
        return False
    ops_chk = [i["opname"] for i in instrs_chk]
    if not any(op in ("POP_JUMP_IF_FALSE", "POP_JUMP_IF_NONE") for op in ops_chk):
        return False
    success_bid, fail_bid = _get_match_succ_fail(b_chk, cfg, offset_to_block)
    if success_bid is None or fail_bid is None:
        return False
    # Em short-circuit (a and b), ramo de sucesso converge de volta no failure_bid.
    # Em match case, ramos são independentes.
    if fail_bid in cfg.get(success_bid, set()):
        return False
    succ0 = block_by_id.get(success_bid)
    if not succ0:
        return False
    s0_ops = [i["opname"] for i in get_block_instrs(succ0)
              if i["opname"] not in ("RESUME", "NOP")]
    return bool(s0_ops) and s0_ops[0] in ("POP_TOP", "UNPACK_SEQUENCE")


def detect_high_level_patterns(blocks, cfg, stack_info, code_obj, debug=True):
    if debug:
        print(f"[DEBUG] detect_high_level_patterns: {code_obj.co_name}")

    block_by_id = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)
    preds = build_predecessor_map(blocks, cfg)

    patterns = {"ifs": [], "loops": [], "short_circuit_candidates": [],
                "short_circuit_blocks": set(), "try_regions": []}

    handler_block_ids = set()
    exc_related_blocks = set()

    entries = list(dis.Bytecode(code_obj).exception_entries)

    grouped = {}
    for e in entries:
        handler = offset_to_block.get(e.target)
        if handler is None:
            continue
        grouped.setdefault((e.start, e.end, e.depth), []).append((e, handler))

    def classify_handler_block(handler_bid: int):
        return _classify_block(block_by_id.get(handler_bid) or {})

    seen = set()
    for (start, end, depth), lst in grouped.items():
        handlers = []
        for e, handler_bid in lst:
            key = (start, end, e.target, depth, e.lasti, handler_bid)
            if key in seen:
                continue
            seen.add(key)
            handlers.append((e, handler_bid))

        protected = []
        for b in blocks:
            bs, bex = block_span_exclusive(b)
            if bs >= start and bs < end:
                protected.append(b["id"])
        protected = sorted(set(protected))

        # Classifica todos os handlers primeiro, antes de decidir se atualiza exc_related_blocks
        handler_infos = []
        for e, handler_bid in handlers:
            hcls = classify_handler_block(handler_bid)
            handler_infos.append({
                "handler_offset": e.target,
                "handler_block": handler_bid,
                "lasti": e.lasti,
                "is_except": hcls["is_except"],
                "is_cleanup": hcls["is_cleanup"],
                "is_gen_cleanup": hcls.get("is_gen_cleanup", False),
                "is_exc_var_cleanup": hcls.get("is_exc_var_cleanup", False),
                "is_with_handler": hcls.get("is_with_handler", False),
                "is_with_reraise": hcls.get("is_with_reraise", False),
                "is_comp_restore": hcls.get("is_comp_restore", False),
                "is_cleanup_throw": hcls.get("is_cleanup_throw", False),
                "is_async_for_exit": hcls.get("is_async_for_exit", False),
            })

        # Filtra try_regions de generator/coroutine plumbing
        if all(h.get("is_gen_cleanup") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping generator cleanup try_region [{start},{end})")
            # Registra handler blocks para que edges de exceção sejam filtrados em detecção de ifs
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        # Filtra try_regions de CLEANUP_THROW (await/yield from coroutine exception cleanup)
        if all(h.get("is_cleanup_throw") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping cleanup_throw try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        # Filtra try_regions de END_ASYNC_FOR (async for StopAsyncIteration plumbing)
        # NÃO adiciona protected_blocks a exc_related_blocks — necessário para detecção do loop
        if all(h.get("is_async_for_exit") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping async_for_exit try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        # Filtra try_regions de cleanup de variável de exceção
        if all(h.get("is_exc_var_cleanup") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping exc var cleanup try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        # Filtra try_regions de with handler (WITH_EXCEPT_START ou reraise de with)
        if all(h.get("is_with_handler") or h.get("is_with_reraise") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping with handler try_region [{start},{end})")
            continue

        # Filtra try_regions de comprehension restore (PEP 709): STORE_FAST + RERAISE
        # Não adiciona blocos protegidos a exc_related_blocks para não bloquear detecção do loop
        if all(h.get("is_comp_restore") for h in handler_infos):
            if debug:
                print(f"[DEBUG] Skipping comprehension restore try_region [{start},{end})")
            for h in handler_infos:
                handler_block_ids.add(h["handler_block"])
                exc_related_blocks.add(h["handler_block"])
            continue

        # Não filtrou: registra handler_block_ids e exc_related_blocks normalmente
        for h in handler_infos:
            handler_block_ids.add(h["handler_block"])
            exc_related_blocks.add(h["handler_block"])
        exc_related_blocks.update(protected)

        patterns["try_regions"].append({
            "type": "try_region_group",
            "range": (start, end),
            "depth": depth,
            "protected_blocks": protected,
            "handlers": handler_infos,
        })

        if debug:
            hs = ", ".join(f"{h['handler_block']}@{h['handler_offset']}" for h in handler_infos)
            print(f"[DEBUG] TRY-REGION: [{start},{end}) depth={depth} handlers={hs} protected={protected}")


    # ---- WITH / ASYNC WITH DETECTION ----
    with_regions = []
    for b in blocks:
        instrs = b.get("instructions", []) or []
        for i, ins in enumerate(instrs):
            if ins["opname"] not in ("BEFORE_WITH", "BEFORE_ASYNC_WITH"):
                continue

            is_async = ins["opname"] == "BEFORE_ASYNC_WITH"
            with_start = ins["offset"]

            # Encontra a exception entry que protege o corpo do with.
            # Para BEFORE_WITH: entry começa perto do opcode.
            # Para BEFORE_ASYNC_WITH: entry começa após o SEND loop do __aenter__
            # (muito depois do BEFORE_ASYNC_WITH). Usamos WITH_EXCEPT_START no handler
            # como marcador definitivo.
            with_entry = None
            for e in entries:
                if e.start < with_start:
                    continue
                handler_bid_tmp = offset_to_block.get(e.target)
                handler_b_tmp = block_by_id.get(handler_bid_tmp) if handler_bid_tmp is not None else None
                if handler_b_tmp is None:
                    continue
                h_ops_tmp = [i["opname"] for i in (handler_b_tmp.get("instructions") or [])]
                if "WITH_EXCEPT_START" in h_ops_tmp:
                    with_entry = e
                    break
            # Fallback: abordagem original (para casos sem WITH_EXCEPT_START claro)
            if with_entry is None:
                for e in entries:
                    if e.start >= with_start and e.start <= with_start + 10:
                        with_entry = e
                        break

            # Extrai "as var" do STORE_FAST após BEFORE_WITH
            # Pode estar no mesmo bloco ou no bloco seguinte (BEFORE_WITH é geralmente o último opcode)
            as_var = None
            remaining_instrs = instrs[i + 1:]
            skip_ops = {"POP_TOP", "NOP", "CACHE", "GET_AWAITABLE", "SEND", "END_SEND", "RESUME"}
            for next_ins in remaining_instrs:
                if next_ins["opname"] in ("STORE_FAST", "STORE_NAME"):
                    as_var = next_ins.get("argval")
                    break
                if next_ins["opname"] not in skip_ops:
                    break
            # Se não encontrou no mesmo bloco, procura no bloco seguinte via CFG
            if as_var is None:
                for succ_bid in cfg.get(b["id"], set()):
                    succ_b = block_by_id.get(succ_bid)
                    if succ_b is None:
                        continue
                    succ_instrs = succ_b.get("instructions", []) or []
                    for si in succ_instrs:
                        if si["opname"] in ("STORE_FAST", "STORE_NAME"):
                            as_var = si.get("argval")
                            break
                        if si["opname"] not in skip_ops:
                            break
                    if as_var is not None:
                        break

            # Blocos protegidos pelo with
            prot = []
            if with_entry:
                for blk in blocks:
                    bs, bex = block_span_exclusive(blk)
                    if bs >= with_entry.start and bs < with_entry.end:
                        prot.append(blk["id"])

            handler_bid = offset_to_block.get(with_entry.target) if with_entry else None

            with_regions.append({
                "type": "async_with" if is_async else "with",
                "block": b["id"],
                "offset": with_start,
                "as_var": as_var,
                "protected_blocks": sorted(set(prot)),
                "handler_block": handler_bid,
            })

            if debug:
                wtype = "ASYNC WITH" if is_async else "WITH"
                print(f"[DEBUG] {wtype}: bloco {b['id']} offset={with_start} as_var={as_var} prot={sorted(set(prot))}")

    # Coleta TODOS os blocos de plumbing de with (handlers + reraise)
    with_handler_block_ids = set()
    for wr in with_regions:
        hb = wr.get("handler_block")
        if hb is not None:
            with_handler_block_ids.add(hb)
    # Adiciona blocos handler-of-handler: entries cujo range protegido inclui um with handler
    for e in entries:
        handler_bid = offset_to_block.get(e.target)
        if handler_bid is None:
            continue
        prot_bids = set()
        for blk in blocks:
            bs, bex = block_span_exclusive(blk)
            if bs >= e.start and bs < e.end:
                prot_bids.add(blk["id"])
        if prot_bids & with_handler_block_ids:
            with_handler_block_ids.add(handler_bid)

    # Blocos protegidos por algum with (body)
    with_body_bids = set()
    for wr in with_regions:
        with_body_bids.update(wr.get("protected_blocks", []))
        with_body_bids.add(wr.get("block", -1))

    # Walk transitivo: inclui todos os sucessores dos handler blocks que são
    # cleanup/plumbing (não são body de with nem blocos anteriores ao handler)
    cleanup_ops = {"POP_TOP", "POP_EXCEPT", "NOP", "JUMP_FORWARD", "JUMP_BACKWARD",
                   "LOAD_FAST", "LOAD_FAST_CHECK", "RETURN_VALUE", "RETURN_CONST",
                   "COPY", "RERAISE", "JUMP_BACKWARD_NO_INTERRUPT",
                   "LOAD_CONST", "CALL", "STORE_FAST", "STORE_NAME", "SWAP",
                   "PUSH_EXC_INFO", "WITH_EXCEPT_START", "POP_JUMP_IF_TRUE",
                   "POP_JUMP_IF_FALSE"}
    with_handler_block_ids |= bfs_walk(
        with_handler_block_ids,
        cfg,
        stop_fn=lambda bid: bid in with_body_bids,
        filter_fn=lambda bid: set(get_block_opnames(block_by_id.get(bid, {}))).issubset(cleanup_ops),
    )

    patterns["with_regions"] = with_regions
    patterns["with_handler_blocks"] = with_handler_block_ids
    exc_related_blocks.update(with_handler_block_ids)

    def last_instr(bid):
        b = block_by_id.get(bid) or {}
        ins = b.get("instructions", []) or []
        return ins[-1] if ins else None

    def promote_loop_header(dst_bid: int):
      
        dst_start = (block_by_id.get(dst_bid) or {}).get("start_offset", 10**18)
        best = None
        for p in preds.get(dst_bid, set()):
            if p in handler_block_ids or p in exc_related_blocks:
                continue
            pb = block_by_id.get(p) or {}
            pins = pb.get("instructions", []) or []
            if not pins:
                continue
            li = pins[-1]
            op = li.get("opname")
            if not op or not is_cond_jump(op):
                continue

            succs = list(cfg.get(p, ()))
            if len(succs) != 2:
                continue
            if dst_bid not in succs:
                continue

            other = [x for x in succs if x != dst_bid]
            if not other:
                continue
            ok = False
            for o in other:
                os = (block_by_id.get(o) or {}).get("start_offset", 10**18)
                if os >= dst_start:
                    ok = True
            if not ok:
                continue

            pstart = pb.get("start_offset", 10**18)
            if best is None or pstart < best[0]:
                best = (pstart, p)

        return best[1] if best else dst_bid

    def looks_like_loop_header(bid):
        ps = {p for p in preds.get(bid, set()) if p not in handler_block_ids and p not in exc_related_blocks}
        ss = {s for s in cfg.get(bid, set()) if s not in handler_block_ids and s not in exc_related_blocks}

        if len(ps) >= 2:
            return True
        if len(ss) >= 2:
            return True

        b = block_by_id.get(bid) or {}
        instrs = b.get("instructions", []) or []
        return any(i.get("opname") == "FOR_ITER" for i in instrs)

    for src, succs in cfg.items():
        src_start = block_by_id.get(src, {}).get("start_offset", 10**18)
        for dst in succs:
            dst_start = block_by_id.get(dst, {}).get("start_offset", 10**18)
            if dst_start <= src_start:
                if src in handler_block_ids or dst in handler_block_ids:
                    continue
                if src in exc_related_blocks or dst in exc_related_blocks:
                    continue
                if not looks_like_loop_header(dst):
                    continue

                promoted = promote_loop_header(dst)

                # Verifica se é async for
                header_b = block_by_id.get(promoted, {})
                header_ops = [ins["opname"] for ins in (header_b.get("instructions", []) or [])]
                is_async_for = "GET_ANEXT" in header_ops

                patterns["loops"].append({
                    "type": "loop_back_edge",
                    "header": promoted,
                    "body_entry": dst,
                    "latch": src,
                    "header_start": block_by_id.get(promoted, {}).get("start_offset", dst_start),
                    "latch_start": src_start,
                    "is_async_for": is_async_for,
                })
                if debug:
                    print(f"[DEBUG] LOOP: latch bloco {src} -> header bloco {promoted} (body_entry={dst})")
    for b in blocks:
        bid = b["id"]
        instrs = b.get("instructions", []) or []
        if not instrs:
            continue
        last = instrs[-1]
        op = last.get("opname")
        if not op or not is_cond_jump(op):
            continue

        # Filtra exception edges (handler/exc_related) — igual à detecção de loops
        succs = [s for s in cfg.get(bid, set())
                 if s not in handler_block_ids and s not in exc_related_blocks]
        if len(succs) != 2:
            continue

        jt_off = last.get("jump_target")
        jump_block = offset_to_block.get(jt_off) if jt_off is not None else None
        fall_block = None
        if jump_block is not None:
            other = [s for s in succs if s != jump_block]
            fall_block = other[0] if other else None

        sem = jump_on_true(op)
        true_succ = false_succ = None
        if sem is True:
            true_succ, false_succ = jump_block, fall_block
        elif sem is False:
            true_succ, false_succ = fall_block, jump_block

        # Detecta padrão short-circuit: COPY 1 + POP_JUMP_IF_* + fall-through começa com POP_TOP
        is_sc = False
        if len(instrs) >= 2:
            prev = instrs[-2]
            if prev.get("opname") == "COPY" and prev.get("arg") == 1 and fall_block is not None:
                fall_b = block_by_id.get(fall_block, {})
                fall_instrs = fall_b.get("instructions", []) or []
                if fall_instrs and fall_instrs[0].get("opname") == "POP_TOP":
                    is_sc = True
                    patterns["short_circuit_blocks"].add(bid)
                    patterns["short_circuit_blocks"].add(fall_block)
                    if debug:
                        print(f"[DEBUG] SHORT-CIRCUIT: bloco {bid} e fall {fall_block} ({op}) suprimidos")

        patterns["ifs"].append({
            "type": "if",
            "cond_block": bid,
            "jump_block": jump_block,
            "fall_block": fall_block,
            "true_succ": true_succ,
            "false_succ": false_succ,
            "jump_target_offset": jt_off,
            "opcode": op,
        })

        if debug and not is_sc:
            print(f"[DEBUG] IF: bloco {bid} ({op}) -> jump {jump_block}, fall {fall_block}, true={true_succ}, false={false_succ}")


    # ---- ASSERT DETECTION ----
    assert_patterns = []
    for b in blocks:
        instrs = b.get("instructions", []) or []
        opnames = [ins["opname"] for ins in instrs]

        if "LOAD_ASSERTION_ERROR" in opnames:
            for pred_bid in preds.get(b["id"], set()):
                pred_b = block_by_id.get(pred_bid, {})
                pred_instrs = pred_b.get("instructions", []) or []
                if pred_instrs:
                    last = pred_instrs[-1]
                    last_op = last.get("opname", "")
                    if last_op.startswith("POP_JUMP") and "IF_TRUE" in last_op:
                        assert_patterns.append({
                            "type": "assert",
                            "cond_block": pred_bid,
                            "fail_block": b["id"],
                            "jump_target": last.get("jump_target"),
                        })
                        if debug:
                            print(f"[DEBUG] ASSERT: cond_block={pred_bid} fail_block={b['id']}")

    patterns["assert_patterns"] = assert_patterns

    # ---- MATCH/CASE DETECTION ----
    # Detecta "match case blocks" (MCBs): blocos com COPY 1 + jump condicional onde
    # o ramo de sucesso (fall-through) começa com POP_TOP ou UNPACK_SEQUENCE.

    def _extract_literal_val(instrs_chk):
        for idx, ins in enumerate(instrs_chk):
            if ins["opname"] == "COMPARE_OP" and (ins.get("argval") or "").startswith("=="):
                for j in range(idx - 1, -1, -1):
                    prev = instrs_chk[j]
                    if prev["opname"] == "LOAD_CONST":
                        return prev.get("argval")
                    if prev["opname"] not in ("COPY", "RESUME", "NOP"):
                        break
        return None

    def _extract_class_info(instrs_chk, success_b_chk):
        ops_chk = [i["opname"] for i in instrs_chk]
        if "MATCH_CLASS" not in ops_chk:
            return None, []
        cls_name = None
        for idx, ins in enumerate(instrs_chk):
            if ins["opname"] == "MATCH_CLASS":
                for j in range(idx - 1, -1, -1):
                    prev = instrs_chk[j]
                    if prev["opname"] in ("LOAD_GLOBAL", "LOAD_NAME"):
                        cls_name = prev.get("argval") or "?"
                        break
                    if prev["opname"] not in ("LOAD_CONST", "RESUME", "NOP"):
                        break
                break
        captures = []
        if success_b_chk:
            body_instrs = success_b_chk.get("instructions") or []
            if any(i["opname"] == "UNPACK_SEQUENCE" for i in body_instrs):
                for bi in body_instrs:
                    if bi["opname"] == "STORE_FAST":
                        captures.append(bi.get("argval", "?"))
        return cls_name, captures

    # Identifica todos os MCBs
    match_case_bids = set()
    for b in blocks:
        if _is_match_case_block(b, cfg, block_by_id, offset_to_block):
            match_case_bids.add(b["id"])

    def _get_fail_bid(bid_f):
        b_f = block_by_id.get(bid_f)
        if b_f is None:
            return None
        _, fail = _get_match_succ_fail(b_f, cfg, offset_to_block)
        return fail

    # MCBs que são o "failure branch" de outro MCB (meio da cadeia)
    mid_chain_bids = set()
    for bid_m in match_case_bids:
        fb = _get_fail_bid(bid_m)
        if fb is not None and fb in match_case_bids:
            mid_chain_bids.add(fb)

    start_bids_m = match_case_bids - mid_chain_bids

    match_chains = []
    for start_bid in sorted(start_bids_m):
        chain_cases = []
        cur_bid = start_bid
        while cur_bid is not None and cur_bid in match_case_bids:
            b_cur = block_by_id[cur_bid]
            instrs_cur = b_cur.get("instructions", []) or []
            ops_cur = [i["opname"] for i in instrs_cur]
            success_bid, fail_bid = _get_match_succ_fail(b_cur, cfg, offset_to_block)
            success_b = block_by_id.get(success_bid) if success_bid is not None else None

            if "MATCH_CLASS" in ops_cur:
                cls_name, captures = _extract_class_info(instrs_cur, success_b)
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "class", "class_name": cls_name or "?",
                         "captures": captures}
            elif "MATCH_SEQUENCE" in ops_cur:
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "sequence"}
            elif "MATCH_MAPPING" in ops_cur:
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "mapping"}
            else:
                lit_val = _extract_literal_val(instrs_cur)
                entry = {"cond_block": cur_bid, "body_block": success_bid,
                         "pattern_type": "literal", "literal_value": lit_val}

            chain_cases.append(entry)
            cur_bid = fail_bid

        if chain_cases:
            match_chains.append({
                "type": "match_chain",
                "first_block": start_bid,
                "cases": chain_cases,
                "default_block": cur_bid,
            })
            if debug:
                pts = [c["pattern_type"] for c in chain_cases]
                print(f"[DEBUG] MATCH CHAIN: start={start_bid}, cases={pts}, default={cur_bid}")

    # Legacy match_regions: padrões complexos (multi-bloco por case, ex: block_match_complex)
    # Exclui blocos já cobertos por match_chains
    chain_block_ids = set()
    for mc in match_chains:
        for case in mc.get("cases", []):
            chain_block_ids.add(case["cond_block"])
            if case.get("body_block") is not None:
                chain_block_ids.add(case["body_block"])
        if mc.get("default_block") is not None:
            chain_block_ids.add(mc["default_block"])

    match_regions = []
    for b in blocks:
        if b["id"] in chain_block_ids:
            continue
        instrs = b.get("instructions", []) or []
        for i, ins in enumerate(instrs):
            if ins["opname"] == "COPY" and ins.get("arg") == 1:
                if i + 1 < len(instrs) and instrs[i + 1]["opname"].startswith("MATCH_"):
                    match_regions.append({
                        "type": "match_case_arm",
                        "block": b["id"],
                        "match_type": instrs[i + 1]["opname"],
                        "offset": ins["offset"],
                    })
                    if debug:
                        print(f"[DEBUG] MATCH ARM: bloco {b['id']} tipo={instrs[i + 1]['opname']}")

    patterns["match_regions"] = match_regions
    patterns["match_chains"] = match_chains

    # ---- SEQ MATCH CHAIN DETECTION ----
    # Detecta padrões multi-bloco de match/case com MATCH_SEQUENCE (ex: block_match_complex).
    # Cada case de sequência gera múltiplos BBs: MATCH_SEQ → GET_LEN → UNPACK → element checks → body.

    def _trace_seq_success_chain(start_bsm):
        """Traça a cadeia de fall-through a partir de start_bsm até o bloco-corpo (sem mais POP_JUMP)."""
        cur_sm = start_bsm
        chain_sm = []
        visited_sm = set()
        while cur_sm is not None and cur_sm not in visited_sm:
            visited_sm.add(cur_sm)
            chain_sm.append(cur_sm)
            b_cur_sm = block_by_id.get(cur_sm)
            if b_cur_sm is None:
                break
            jt_off_sm = get_last_jump_target(b_cur_sm)
            if jt_off_sm is None:
                break  # Sem jump condicional — este é o corpo
            fail_sm = offset_to_block.get(jt_off_sm)
            succs_sm = cfg.get(cur_sm, set())
            fall_sm = next((s for s in succs_sm if s != fail_sm), None)
            if fall_sm is None:
                break
            cur_sm = fall_sm
        return chain_sm

    def _get_seq_length(chain_bids_sm):
        """Extrai o comprimento n do bloco GET_LEN na cadeia de sucesso."""
        for bid_sm in chain_bids_sm:
            b_sm = block_by_id.get(bid_sm)
            if b_sm is None:
                continue
            instrs_sm = b_sm.get("instructions") or []
            ops_sm = [i["opname"] for i in instrs_sm]
            if "GET_LEN" in ops_sm:
                for i_sm, ins_sm in enumerate(instrs_sm):
                    if ins_sm["opname"] == "GET_LEN":
                        for j_sm in range(i_sm + 1, len(instrs_sm)):
                            if instrs_sm[j_sm]["opname"] == "LOAD_CONST":
                                return instrs_sm[j_sm].get("argval")
        return None

    seq_match_starts = [b["id"] for b in blocks if _is_seq_match_start(b)]
    seq_start_set_sm = set(seq_match_starts)

    seq_match_chains = []
    if seq_match_starts:
        # Blocos já cobertos por match_chains simples não entram aqui
        sm_chain_cases = []
        visited_sm_starts = set()
        cur_sm_start = seq_match_starts[0]

        while cur_sm_start is not None and cur_sm_start not in visited_sm_starts:
            visited_sm_starts.add(cur_sm_start)
            b_sm_start = block_by_id.get(cur_sm_start)
            if b_sm_start is None:
                break

            jt_off_sm = get_last_jump_target(b_sm_start)
            fail_all_sm = offset_to_block.get(jt_off_sm) if jt_off_sm is not None else None

            chain_bids_sm = _trace_seq_success_chain(cur_sm_start)
            body_bid_sm = chain_bids_sm[-1] if chain_bids_sm else None
            n_sm = _get_seq_length(chain_bids_sm)

            sm_chain_cases.append({
                "start_bid": cur_sm_start,
                "fail_all_bid": fail_all_sm,
                "body_bid": body_bid_sm,
                "all_bids": set(chain_bids_sm),
                "n": n_sm,
            })

            # Próximo case: fail_all pode ser ele mesmo um seq start, ou ter um sucessor que é
            next_sm_start = None
            if fail_all_sm in seq_start_set_sm and fail_all_sm not in visited_sm_starts:
                next_sm_start = fail_all_sm
            elif fail_all_sm is not None:
                for s_sm in cfg.get(fail_all_sm, set()):
                    if s_sm in seq_start_set_sm and s_sm not in visited_sm_starts:
                        next_sm_start = s_sm
                        break
            cur_sm_start = next_sm_start

        if sm_chain_cases:
            last_fail_sm = sm_chain_cases[-1]["fail_all_bid"]
            all_sm_bids = set()
            for c_sm in sm_chain_cases:
                all_sm_bids.update(c_sm["all_bids"])
                if c_sm["fail_all_bid"] is not None:
                    all_sm_bids.add(c_sm["fail_all_bid"])
            if last_fail_sm is not None:
                all_sm_bids.add(last_fail_sm)

            seq_match_chains.append({
                "type": "seq_match_chain",
                "first_block": seq_match_starts[0],
                "cases": sm_chain_cases,
                "default_block": last_fail_sm,
                "all_blocks": all_sm_bids,
            })
            if debug:
                print(f"[DEBUG] SEQ MATCH CHAIN: {len(sm_chain_cases)} cases, default={last_fail_sm}")

    patterns["seq_match_chains"] = seq_match_chains

    # ---- COMPREHENSION DETECTION ----
    comprehensions = []
    loop_headers_seen = set()
    for lp in patterns.get("loops", []):
        header_bid = lp["header"]
        if header_bid in loop_headers_seen:
            continue

        # Coleta blocos do corpo do loop
        body_bids = set()
        for other_lp in patterns.get("loops", []):
            if other_lp["header"] == header_bid:
                body_bids.add(other_lp["latch"])
                body_bids.add(other_lp.get("body_entry", -1))

        # Verifica LIST_APPEND/SET_ADD/MAP_ADD/YIELD_VALUE no corpo
        comp_type = None
        for bid in body_bids:
            blk = block_by_id.get(bid, {})
            for instr in (blk.get("instructions", []) or []):
                if instr["opname"] == "LIST_APPEND":
                    comp_type = "listcomp"
                elif instr["opname"] == "SET_ADD":
                    comp_type = "setcomp"
                elif instr["opname"] == "MAP_ADD":
                    comp_type = "dictcomp"

        if comp_type:
            loop_headers_seen.add(header_bid)
            comprehensions.append({
                "type": comp_type,
                "header": header_bid,
                "loop_info": lp,
            })
            if debug:
                print(f"[DEBUG] COMPREHENSION: {comp_type} header={header_bid}")

    patterns["comprehensions"] = comprehensions

    return patterns
