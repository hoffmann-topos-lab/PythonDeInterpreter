from typing import List, Dict, Any, Optional, Tuple
from utils.ir import Expr, Stmt, expr_repr, stmt_repr
from utils.block_utils import (
    build_block_by_id, build_offset_to_block, build_predecessor_map,
    get_block_opnames,
)

def simulate_stack(blocks, cfg, instructions, code_obj, debug=True, max_iters=2000):
    if debug:
        print("[DEBUG] Iniciando simulação de pilha")

    def expr_key(e, depth=4):
        if e is None:
            return ("none",)
        if not isinstance(e, Expr):
            return ("obj", type(e).__name__)
        if depth <= 0:
            return ("expr", e.kind)

        v = e.value
        if isinstance(v, (int, float, str, bool, type(None))):
            vkey = ("val", v)
        elif isinstance(v, tuple) and all(isinstance(x, (int, float, str, bool, type(None))) for x in v):
            vkey = ("valtuple", v)
        else:
            vkey = ("valtype", type(v).__name__)

        args_key = tuple(expr_key(a, depth - 1) for a in (e.args or ()))
        okey = tuple(sorted(e.origins)) if getattr(e, "origins", None) else ()
        return ("expr", e.kind, vkey, args_key, okey)

    def atomize(v):
        if v is None:
            return ("none",)
        if isinstance(v, Expr):
            return expr_key(v, depth=4)
        return ("obj", type(v).__name__)

    def stack_fingerprint(stack):
        return tuple(atomize(v) for v in stack)

    in_stack = {b["id"]: [] for b in blocks}
    out_stack = {b["id"]: [] for b in blocks}
    in_fp = {b["id"]: None for b in blocks}
    out_fp = {b["id"]: None for b in blocks}

    block_statements = {b["id"]: [] for b in blocks}
    block_conditions = {b["id"]: [] for b in blocks}

    preds_map = build_predecessor_map(blocks, cfg)

    entry = blocks[0]["id"]
    in_stack[entry] = []
    in_fp[entry] = stack_fingerprint([])

    blocks_sorted = sorted(blocks, key=lambda b: b["start_offset"])

    TERMINATOR_OPS = {"RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"}

    changed = True
    it = 0

    while changed:
        it += 1
        if it > max_iters:
            if debug:
                print(f"[DEBUG] Max iters atingido ({max_iters}); interrompendo fixpoint")
            break

        changed = False

        for block in blocks_sorted:
            bid = block["id"]

            preds = list(preds_map.get(bid, ()))
            if preds:
                stacks = [out_stack[p] for p in preds if out_fp.get(p) is not None]
                merged_in = merge_stacks(stacks, debug=False) if stacks else []
            else:
                merged_in = in_stack[bid] if in_fp[bid] is not None else []

            merged_fp = stack_fingerprint(merged_in)
            if in_fp[bid] != merged_fp:
                in_stack[bid] = list(merged_in)
                in_fp[bid] = merged_fp
                changed = True

            cur_stack = list(in_stack[bid])
            stmts = []
            conds = []

            for instr in block["instructions"]:
                simulate_instruction(instr, cur_stack, stmts, conds, debug=False)

            ops_in_block = {ins["opname"] for ins in block.get("instructions", [])}


            ret_expr = None
            for v in cur_stack[::-1]:
                if isinstance(v, Expr) and v.kind == "return_value":
                    ret_expr = v
                    break

            if ret_expr is not None:
                is_loop_cleanup = block.get("loop_after") is not None
                val = ret_expr.args[0] if ret_expr.args else None

                is_none = (
                    val is None
                    or (isinstance(val, Expr) and val.kind == "const" and val.value is None)
                )

                has_real_stmt = any(s.kind not in ("del",) for s in stmts)

                if not is_loop_cleanup:
                    if not is_none:
                        stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))
                    else:
                        if not has_real_stmt:
                            stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))

                cur_stack = [
                    v for v in cur_stack
                    if not (isinstance(v, Expr) and v.kind == "return_value")
                ]

            block_statements[bid] = stmts
            block_conditions[bid] = conds

            terminated = (
                bool(ops_in_block & TERMINATOR_OPS)
                or any(s.kind in ("return", "raise", "reraise") for s in stmts)
            )

            if terminated:
                if out_fp[bid] is not None:
                    out_stack[bid] = []
                    out_fp[bid] = None
                    changed = True
            else:
                cur_fp = stack_fingerprint(cur_stack)
                if out_fp[bid] != cur_fp:
                    out_stack[bid] = cur_stack
                    out_fp[bid] = cur_fp
                    changed = True

    if debug:
        print("[DEBUG] Simulação de pilha finalizada")

    _fix_short_circuit(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=debug)
    _fix_comprehensions(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=debug)
    ternary_ancestors = _fix_ternary_phi(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=debug)
    yield_from_blocks = _fix_yield_from(blocks, cfg, block_statements, in_stack, out_stack, debug=debug)

    return {
        "in_stack": in_stack,
        "out_stack": out_stack,
        "in_fp": in_fp,
        "out_fp": out_fp,
        "block_statements": block_statements,
        "block_conditions": block_conditions,
        "yield_from_blocks": yield_from_blocks,
        "ternary_ancestors": ternary_ancestors,
    }

def _fix_short_circuit(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=False):
    block_by_id = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)

    def _subst_expr(e, old_obj, new_expr):
        if e is None or not isinstance(e, Expr):
            return e
        if e is old_obj:
            return new_expr
        if not e.args:
            return e
        new_args = tuple(_subst_expr(a, old_obj, new_expr) for a in e.args)
        if any(na is not e.args[i] for i, na in enumerate(new_args)):
            return Expr(kind=e.kind, value=e.value, args=new_args, origins=e.origins)
        return e

    def _subst_stmt(s, old_obj, new_expr):
        if not isinstance(s, Stmt):
            return s
        new_e = _subst_expr(s.expr, old_obj, new_expr) if s.expr is not None else s.expr
        new_x = _subst_expr(s.extra, old_obj, new_expr) if isinstance(s.extra, Expr) else s.extra
        if new_e is s.expr and new_x is s.extra:
            return s
        return Stmt(kind=s.kind, target=s.target, expr=new_e, extra=new_x, origins=s.origins)

    def _subst_everywhere(old_obj, new_expr, skip_bid=None):
        for bid2 in list(in_stack.keys()):
            if bid2 == skip_bid:
                continue
            in_stack[bid2] = [_subst_expr(v, old_obj, new_expr) for v in in_stack[bid2]]
        for bid2 in list(out_stack.keys()):
            if bid2 == skip_bid:
                continue
            out_stack[bid2] = [_subst_expr(v, old_obj, new_expr) for v in out_stack[bid2]]
        for bid2 in list(block_statements.keys()):
            block_statements[bid2] = [_subst_stmt(s, old_obj, new_expr) for s in (block_statements[bid2] or [])]
        for bid2 in list(block_conditions.keys()):
            block_conditions[bid2] = [_subst_expr(v, old_obj, new_expr) for v in (block_conditions[bid2] or [])]

    sc_items = [] 
    for b in blocks:
        bid = b["id"]
        instrs = b.get("instructions", []) or []
        if len(instrs) < 2:
            continue
        last = instrs[-1]
        prev = instrs[-2]
        op_last = last.get("opname", "")
        op_prev = prev.get("opname", "")

        if not (op_last.startswith("POP_JUMP") and "IF_" in op_last):
            continue
        if op_prev != "COPY" or prev.get("arg") != 1:
            continue

        is_and = "IF_FALSE" in op_last
        is_or = "IF_TRUE" in op_last
        if not (is_and or is_or):
            continue
        op = "and" if is_and else "or"

        jump_off = last.get("jump_target")
        jump_bid = offset_to_block.get(jump_off) if jump_off is not None else None

        succs = list(cfg.get(bid, set()))
        fall_bid = next((s for s in succs if s != jump_bid), None)
        if fall_bid is None:
            continue

        fall_b = block_by_id.get(fall_bid, {})
        fall_instrs = fall_b.get("instructions", []) or []
        if not fall_instrs or fall_instrs[0].get("opname") != "POP_TOP":
            continue

        fall_succs = set(cfg.get(fall_bid, set()))
        sc_succs = set(cfg.get(bid, set()))
        candidates = fall_succs | (sc_succs - {fall_bid})

        primary_merge = jump_bid if jump_bid is not None else 10**9
        sc_items.append((bid, op, jump_bid, fall_bid, primary_merge, candidates))

    sc_items.sort(key=lambda t: (t[4], -t[0]))

    def _replace_phi_in_stack(stk, old_a, old_b, new_expr):
        new_stk = list(stk)
        a_repr = expr_repr(old_a)
        b_repr = expr_repr(old_b)
        for i, v in enumerate(new_stk):
            if not (isinstance(v, Expr) and v.kind == "phi"):
                continue
            phi_args = v.args or ()
            phi_reprs = [expr_repr(x) for x in phi_args]
            a_matched = a_repr in phi_reprs
            b_matched = b_repr in phi_reprs

            if len(phi_args) <= 2:
                if a_matched or b_matched:
                    new_stk[i] = new_expr
                    return new_stk, True, v
                continue
            if a_matched and b_matched:
                remaining = tuple(
                    x for x, xr in zip(phi_args, phi_reprs)
                    if xr != a_repr and xr != b_repr
                )
                new_args = (new_expr,) + remaining
                if len(new_args) == 1:
                    new_stk[i] = new_args[0]
                else:
                    new_stk[i] = Expr(kind="phi", value=v.value, args=new_args, origins=v.origins)
                return new_stk, True, v
        return new_stk, False, None

    for bid, op, jump_bid, fall_bid, primary_merge, candidates in sc_items:
        a_stack = out_stack.get(bid, [])
        b_stack = out_stack.get(fall_bid, [])
        if not a_stack:
            continue
        a_val = a_stack[-1]
        b_val_default = b_stack[-1] if b_stack else None
        if b_val_default is None:
            for s in reversed(block_statements.get(fall_bid, []) or []):
                if isinstance(s, Stmt) and s.kind == "return" and s.expr is not None:
                    b_val_default = s.expr
                    break
        if a_val is None or b_val_default is None:
            continue

        patched_any = False
        for merge_bid in candidates:
            merge_in = in_stack.get(merge_bid, [])

            b_val = b_val_default
            for v in merge_in:
                if not (isinstance(v, Expr) and v.kind == "phi"):
                    continue
                phi_args = v.args or ()
                a_repr_tmp = expr_repr(a_val)
                phi_reprs = [expr_repr(x) for x in phi_args]
                if a_repr_tmp in phi_reprs:
                    others = [phi_args[i] for i, r in enumerate(phi_reprs) if r != a_repr_tmp]
                    if len(others) == 1:
                        b_val = others[0]
                break

            sc_expr = Expr(kind="binop", value=op, args=(a_val, b_val), origins=frozenset())

            new_merge, patched, old_phi_obj = _replace_phi_in_stack(
                merge_in, a_val, b_val, sc_expr
            )
            if not patched:
                continue
            in_stack[merge_bid] = new_merge

            merge_b = block_by_id.get(merge_bid, {})
            new_stmts = []
            new_conds = []
            cur_stk = list(new_merge)
            for instr in merge_b.get("instructions", []) or []:
                simulate_instruction(instr, cur_stk, new_stmts, new_conds, debug=False)
            ret_expr = None
            for v in cur_stk[::-1]:
                if isinstance(v, Expr) and v.kind == "return_value":
                    ret_expr = v
                    break
            if ret_expr is not None:
                val = ret_expr.args[0] if ret_expr.args else None
                is_none = (val is None or (isinstance(val, Expr) and val.kind == "const" and val.value is None))
                if not is_none:
                    new_stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))
                elif not any(s.kind not in ("del",) for s in new_stmts):
                    new_stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))
            block_statements[merge_bid] = new_stmts
            block_conditions[merge_bid] = new_conds
            out_stack[merge_bid] = [v for v in cur_stk if not (isinstance(v, Expr) and v.kind == "return_value")]

            if old_phi_obj is not None:
                _subst_everywhere(old_phi_obj, sc_expr, skip_bid=merge_bid)

            fall_stmts_list = block_statements.get(fall_bid, []) or []
            if fall_stmts_list:
                first = fall_stmts_list[0]
                if (isinstance(first, Stmt) and first.kind == "expr"
                        and isinstance(first.expr, Expr)
                        and first.expr.kind in ("phi", "binop")):
                    block_statements[fall_bid] = fall_stmts_list[1:]

            patched_any = True
            if debug:
                print(f"[DEBUG] short-circuit {op}: patched phi em bloco {merge_bid}")

        if not patched_any and jump_bid is not None:
            jump_stmts = block_statements.get(jump_bid, []) or []
            fall_stmts = block_statements.get(fall_bid, []) or []
            def _last_return(stmts_list):
                for s in reversed(stmts_list):
                    if isinstance(s, Stmt) and s.kind == "return":
                        return s
                return None
            jump_ret = _last_return(jump_stmts)
            fall_ret = _last_return(fall_stmts)
            if jump_ret is not None and fall_ret is not None:
                a_repr = expr_repr(a_val)
                b_repr = expr_repr(b_val_default)
                jump_ret_repr = expr_repr(jump_ret.expr) if jump_ret.expr is not None else ""
                fall_ret_repr = expr_repr(fall_ret.expr) if fall_ret.expr is not None else ""
                if jump_ret_repr == a_repr and fall_ret_repr == b_repr:
                    sc_expr = Expr(kind="binop", value=op, args=(a_val, b_val_default), origins=frozenset())
                    new_ret = Stmt(kind="return", expr=sc_expr, origins=jump_ret.origins)
                    new_jump_stmts = [s for s in jump_stmts if s is not jump_ret] + [new_ret]
                    block_statements[jump_bid] = new_jump_stmts
                    if debug:
                        print(f"[DEBUG] short-circuit {op}: combined returns de jump={jump_bid} e fall={fall_bid}")


def _fix_comprehensions(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=False):
    block_by_id = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)
    succs = {bid: set(cfg.get(bid, set())) for bid in block_by_id}
    preds = build_predecessor_map(blocks, cfg)

    def block_opnames(bid):
        return get_block_opnames(block_by_id.get(bid, {}))

    def _subst_expr(e, pred, replacement):
        if not isinstance(e, Expr):
            return e
        if pred(e):
            return replacement
        if not e.args:
            return e
        new_args = tuple(_subst_expr(a, pred, replacement) for a in e.args)
        if any(na is not e.args[i] for i, na in enumerate(new_args)):
            return Expr(kind=e.kind, value=e.value, args=new_args, origins=e.origins)
        return e

    def _subst_stmt(s, pred, replacement):
        if not isinstance(s, Stmt):
            return s
        new_e = _subst_expr(s.expr, pred, replacement) if s.expr is not None else s.expr
        new_x = _subst_expr(s.extra, pred, replacement) if isinstance(s.extra, Expr) else s.extra
        if new_e is s.expr and new_x is s.extra:
            return s
        return Stmt(kind=s.kind, target=s.target, expr=new_e, extra=new_x, origins=s.origins)

    def _subst_everywhere(pred, replacement):
        for bid2 in list(in_stack.keys()):
            in_stack[bid2] = [_subst_expr(v, pred, replacement) for v in in_stack[bid2]]
        for bid2 in list(out_stack.keys()):
            out_stack[bid2] = [_subst_expr(v, pred, replacement) for v in out_stack[bid2]]
        for bid2 in list(block_statements.keys()):
            block_statements[bid2] = [_subst_stmt(s, pred, replacement) for s in (block_statements[bid2] or [])]
        for bid2 in list(block_conditions.keys()):
            block_conditions[bid2] = [_subst_expr(v, pred, replacement) for v in (block_conditions[bid2] or [])]

    def _is_leaf_accum(e, kind, elem_reprs):

        if not isinstance(e, Expr):
            return False
        if e.kind == "list":
            if kind != "list":
                return False
            if not e.args:
                return True
            return all(expr_repr(a) == elem_reprs[0] for a in e.args)
        if e.kind == "set":
            if kind != "set":
                return False
            if not e.args:
                return True
            return all(expr_repr(a) == elem_reprs[0] for a in e.args)
        if e.kind == "dict":
            if kind != "dict":
                return False
            if not e.args:
                return True
            if len(e.args) % 2 != 0:
                return False
            for i in range(0, len(e.args), 2):
                if (expr_repr(e.args[i]) != elem_reprs[0]
                        or expr_repr(e.args[i + 1]) != elem_reprs[1]):
                    return False
            return True
        append_kinds = {"list": "list_append", "set": "set_add", "dict": "map_add"}
        want = append_kinds[kind]
        if e.kind == want:
            if kind == "dict":
                if len(e.args) < 3:
                    return False
                if not _is_leaf_accum(e.args[0], kind, elem_reprs):
                    return False
                return (expr_repr(e.args[1]) == elem_reprs[0]
                        and expr_repr(e.args[2]) == elem_reprs[1])
            if len(e.args) < 2:
                return False
            if not _is_leaf_accum(e.args[0], kind, elem_reprs):
                return False
            return expr_repr(e.args[1]) == elem_reprs[0]
        if e.kind == "phi":
            args = e.args or ()
            if not args:
                return False
            return all(_is_leaf_accum(a, kind, elem_reprs) for a in args)
        return False

    def _find_append_by_jumpback(header_bid):
        header_offset = block_by_id.get(header_bid, {}).get("start_offset")
        if header_offset is None:
            return None
        append_map = {"LIST_APPEND": "list", "SET_ADD": "set", "MAP_ADD": "dict"}
        for b2 in blocks:
            instrs2 = b2.get("instructions", []) or []
            has_append = None
            has_jumpback = False
            for ins in instrs2:
                on = ins["opname"]
                if on in append_map:
                    has_append = append_map[on]
                if on in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
                    if ins.get("argval") == header_offset:
                        has_jumpback = True
            if has_append and has_jumpback:
                return (b2["id"], has_append)
        return None

    HEADER_OPS = {"FOR_ITER", "GET_ANEXT"}

    def _collect_candidates():
        candidates = []
        for b in blocks:
            bid = b["id"]
            ops = block_opnames(bid)
            if "LOAD_FAST_AND_CLEAR" not in ops:
                continue
            lfc_vars = []
            for ins in b.get("instructions", []) or []:
                if ins["opname"] == "LOAD_FAST_AND_CLEAR":
                    v = ins.get("argval") or ins.get("argrepr")
                    if v:
                        lfc_vars.append(v)
            if not lfc_vars:
                continue
            from collections import deque
            q = deque([bid])
            seen = {bid}
            build_bid = None
            build_kind = None
            header_bid = None
            while q:
                cur = q.popleft()
                cur_ops = set(block_opnames(cur))
                if build_bid is None:
                    if "BUILD_LIST" in cur_ops:
                        build_bid = cur
                        build_kind = "list"
                    elif "BUILD_SET" in cur_ops:
                        build_bid = cur
                        build_kind = "set"
                    elif "BUILD_MAP" in cur_ops:
                        build_bid = cur
                        build_kind = "dict"
                if build_bid is not None:
                    for op in HEADER_OPS:
                        if op in cur_ops:
                            header_bid = cur
                            break
                if header_bid is not None:
                    break
                for s in succs.get(cur, set()):
                    if s not in seen:
                        seen.add(s)
                        q.append(s)
            if build_bid is None or header_bid is None:
                continue
            is_async = "GET_ANEXT" in set(block_opnames(header_bid))
            ab = _find_append_by_jumpback(header_bid)
            if ab is None:
                continue
            body_bid, comp_kind = ab
            candidates.append({
                "lfc_bid": bid,
                "lfc_vars": lfc_vars,
                "build_bid": build_bid,
                "header_bid": header_bid,
                "body_bid": body_bid,
                "kind": comp_kind,
                "is_async": is_async,
            })
        return candidates

    candidates = _collect_candidates()
    candidates.sort(key=lambda c: -block_by_id.get(c["header_bid"], {}).get("start_offset", 0))

    for cand in candidates:
        bid = cand["lfc_bid"]
        lfc_vars = cand["lfc_vars"]
        lfc_var = lfc_vars[0]
        build_bid = cand["build_bid"]
        header_bid = cand["header_bid"]
        body_bid = cand["body_bid"]
        comp_kind = cand["kind"]
        is_async = cand["is_async"]

        if debug:
            print(f"[DEBUG] comprehension: lfc_var={lfc_var} build={build_bid} header={header_bid} body={body_bid} kind={comp_kind} async={is_async}")

        body_instrs = block_by_id.get(body_bid, {}).get("instructions", []) or []
        append_ops = {"list": "LIST_APPEND", "set": "SET_ADD", "dict": "MAP_ADD"}
        append_op = append_ops[comp_kind]

        body_in = in_stack.get(body_bid, [])
        cur_stk = list(body_in)
        stmts_tmp = []
        conds_tmp = []
        comp_element = None
        comp_cond = None
        comp_key = None  
        comp_val = None   

        for ins in body_instrs:
            op = ins["opname"]
            if op == append_op:
                if comp_kind == "dict":
                  
                    if len(cur_stk) >= 2:
                        k_e = cur_stk[-2]
                        v_e = cur_stk[-1]
                        if isinstance(k_e, Expr) and isinstance(v_e, Expr):
                            comp_key = k_e
                            comp_val = v_e
                            comp_element = comp_key 
                else:
                    if cur_stk:
                        comp_element = cur_stk[-1]
                        if not isinstance(comp_element, Expr):
                            comp_element = None
                break
            simulate_instruction(ins, cur_stk, stmts_tmp, conds_tmp, debug=False)

        if comp_element is None:
            continue

        comp_filter_bid = None
        for filter_bid in succs.get(header_bid, set()):
            if filter_bid == body_bid:
                continue
            filter_ops = set(block_opnames(filter_bid))
            if any(op.startswith("POP_JUMP") for op in filter_ops):
                filter_conds = block_conditions.get(filter_bid, [])
                if filter_conds:
                    comp_cond = filter_conds[0]
                    comp_filter_bid = filter_bid
                    break

        if comp_cond is not None and comp_filter_bid is not None:
            fstmts = block_statements.get(comp_filter_bid, []) or []
            walrus_assigns = []
            for _fst in fstmts:
                if (isinstance(_fst, Stmt) and _fst.kind == "assign"
                        and _fst.target and isinstance(_fst.expr, Expr)):
                    walrus_assigns.append((_fst.target, _fst.expr))
            if walrus_assigns:
                def _subst_walrus(e, target, inner):
                    if not isinstance(e, Expr):
                        return e, False
                    if e is inner:
                        return Expr(kind="walrus", value=target,
                                    args=(inner,), origins=frozenset()), True
                    if not e.args:
                        return e, False
                    new_args = []
                    changed = False
                    for ch in e.args:
                        new_ch, ch_changed = _subst_walrus(ch, target, inner)
                        new_args.append(new_ch)
                        changed = changed or ch_changed
                    if changed:
                        return Expr(kind=e.kind, value=e.value,
                                    args=tuple(new_args), origins=e.origins), True
                    return e, False
                for _tgt, _inner in walrus_assigns:
                    new_cond, did_subst = _subst_walrus(comp_cond, _tgt, _inner)
                    if did_subst:
                        comp_cond = new_cond

        header_in = in_stack.get(header_bid, [])
        iterable_expr = None
        want_iter_kinds = {"aiter"} if is_async else {"iter"}
        for v in reversed(header_in):
            if isinstance(v, Expr) and v.kind in want_iter_kinds:
                iterable_expr = v.args[0] if v.args else v
                break
        if iterable_expr is None:
            continue


        def _extract_loop_vars_from_header(hdr_bid, inner_body_bid):
            hdr_succs = list(succs.get(hdr_bid, set()))
            hdr_succs.sort(key=lambda b: block_by_id.get(b, {}).get("start_offset", 0))
            store_vars = []
            had_unpack = False
            for cur in hdr_succs:
                if cur == hdr_bid:
                    continue
                cur_instrs = block_by_id.get(cur, {}).get("instructions", []) or []
                first_real = next((ins["opname"] for ins in cur_instrs), None)
                if first_real in ("END_FOR", "END_ASYNC_FOR", "SWAP", "POP_TOP"):
                    continue
                local_stores = []
                local_unpack = False
                for ins in cur_instrs:
                    on = ins["opname"]
                    if on == "UNPACK_SEQUENCE":
                        local_unpack = True
                    elif on == "STORE_FAST":
                        v = ins.get("argval") or ins.get("argrepr")
                        if v:
                            local_stores.append(v)
                    elif on in ("LOAD_FAST", "LOAD_CONST", "LOAD_GLOBAL", "LOAD_DEREF",
                                "LOAD_ATTR", "COMPARE_OP", "CALL", "BINARY_OP", "BINARY_SUBSCR",
                                append_op, "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE",
                                "END_FOR", "END_ASYNC_FOR", "SWAP"):
                        break
                if local_stores:
                    store_vars = local_stores
                    had_unpack = local_unpack
                    break
            return store_vars, had_unpack

        store_vars, had_unpack = _extract_loop_vars_from_header(header_bid, body_bid)
        if store_vars:
            if had_unpack and len(store_vars) >= 2:
                loop_var_str = ", ".join(store_vars)
            elif len(store_vars) == 1:
                loop_var_str = store_vars[0]
            else:
                loop_var_str = ", ".join(store_vars)
        else:
            loop_var_str = ", ".join(lfc_vars) if len(lfc_vars) >= 2 else lfc_var


        lv_for_comp = ("async " + loop_var_str) if is_async else loop_var_str
        if comp_kind == "list":
            comp_args = (comp_element, iterable_expr) if comp_cond is None else (comp_element, iterable_expr, comp_cond)
            comp_expr = Expr(kind="list_comp", value=lv_for_comp, args=comp_args, origins=frozenset())
        elif comp_kind == "set":
            comp_args = (comp_element, iterable_expr) if comp_cond is None else (comp_element, iterable_expr, comp_cond)
            comp_expr = Expr(kind="set_comp", value=lv_for_comp, args=comp_args, origins=frozenset())
        else: 
            if comp_key is None or comp_val is None:
                continue
            lv = ("async " + loop_var_str) if is_async else loop_var_str
            comp_args = (comp_key, comp_val, iterable_expr) if comp_cond is None else (comp_key, comp_val, iterable_expr, comp_cond)
            comp_expr = Expr(kind="dict_comp", value=lv, args=comp_args, origins=frozenset())

        exit_end_ops = {"END_ASYNC_FOR"} if is_async else {"END_FOR"}
        exit_bid = None
        for s in succs.get(header_bid, set()):
            if s == body_bid:
                continue
            s_ops = set(block_opnames(s))
            if s_ops & exit_end_ops:
                exit_bid = s
                break
        if exit_bid is None:
            for b2 in blocks:
                ops2 = set(get_block_opnames(b2))
                if ops2 & exit_end_ops:
                    exit_bid = b2["id"]
                    break
        if exit_bid is None:
            for s in succs.get(header_bid, set()):
                if s == body_bid:
                    continue
                s_ops = set(block_opnames(s))
                if "RERAISE" in s_ops or "JUMP_BACKWARD" in s_ops:
                    continue
                exit_bid = s
                break
        if exit_bid is None:
            for s in succs.get(header_bid, set()):
                if s != body_bid:
                    exit_bid = s
                    break

        if debug:
            print(f"[DEBUG] comprehension exit_bid={exit_bid}")
        result_bid = exit_bid
        result_target = None
        search_bids = [exit_bid] if exit_bid is not None else []
        if exit_bid is not None:
            for s in succs.get(exit_bid, set()):
                s_ops = set(block_opnames(s))
                if "RERAISE" not in s_ops:
                    search_bids.append(s)
            for s in succs.get(exit_bid, set()):
                s_ops = set(block_opnames(s))
                if "RERAISE" in s_ops:
                    search_bids.append(s)

        def _is_accum_phi(expr):
            if not isinstance(expr, Expr) or expr.kind != "phi":
                return False
            phi_args = expr.args or ()
            for pa in phi_args:
                if isinstance(pa, Expr) and pa.kind in ("list", "list_append", "set", "set_add", "dict", "map_add"):
                    return True
                if isinstance(pa, Expr) and pa.kind == "phi":
                    return True
            return len(phi_args) >= 2

        result_kind = None  
        for sb in search_bids:
            if sb is None:
                continue
            stmts_here = block_statements.get(sb, [])
            for st in stmts_here:
                if not isinstance(st, Stmt):
                    continue
                if not isinstance(st.expr, Expr):
                    continue
                if st.kind == "assign" and _is_accum_phi(st.expr):
                    result_target = st.target
                    result_kind = "assign"
                    result_bid = sb
                    break
                if st.kind == "return" and _is_accum_phi(st.expr):
                    result_target = "__return__"
                    result_kind = "return"
                    result_bid = sb
                    break
            if result_target:
                break

        if result_target is None:
            if debug:
                print(f"[DEBUG] comprehension: não encontrou result_target")
            continue

        old_stmts = block_statements.get(result_bid, [])
        new_stmts = []
        patched = False
        for st in old_stmts:
            if not patched and isinstance(st, Stmt) and isinstance(st.expr, Expr) and st.expr.kind == "phi":
                if result_kind == "return" and st.kind == "return":
                    new_stmts.append(Stmt(kind="return", target=st.target, expr=comp_expr,
                                          origins=st.origins))
                    patched = True
                elif result_kind == "assign" and st.kind == "assign" and st.target == result_target:
                    new_stmts.append(Stmt(kind="assign", target=result_target, expr=comp_expr,
                                          origins=st.origins))
                    patched = True
                else:
                    new_stmts.append(st)
            else:
                new_stmts.append(st)

        if patched:
            block_statements[result_bid] = new_stmts
            if debug:
                print(f"[DEBUG] comprehension: {result_target} = {comp_kind}_comp em bloco {result_bid}")

            if comp_kind == "dict":
                elem_reprs = (expr_repr(comp_key), expr_repr(comp_val))
            else:
                elem_reprs = (expr_repr(comp_element),)

            def _matches_inner_accum(e, _k=comp_kind, _reprs=elem_reprs):
                return _is_leaf_accum(e, _k, _reprs)
            _subst_everywhere(_matches_inner_accum, comp_expr)

            comp_internal = {build_bid, header_bid, body_bid}
            if exit_bid is not None:
                comp_internal.add(exit_bid)
            visit_q = list(succs.get(header_bid, set()))
            while visit_q:
                vb = visit_q.pop()
                if vb in comp_internal:
                    continue
                comp_internal.add(vb)
                for s in succs.get(vb, set()):
                    if s != header_bid and s not in comp_internal:
                        visit_q.append(s)
            comp_internal.discard(result_bid)

            for cib in comp_internal:
                block_statements[cib] = []
                block_conditions.pop(cib, None)


def _fix_ternary_phi(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=False):
    block_by_id = build_block_by_id(blocks)
    preds_map = build_predecessor_map(blocks, cfg)

    def block_opnames(bid):
        return get_block_opnames(block_by_id.get(bid, {}))

    def _last_cond_jump_op(bid):
        instrs = block_by_id.get(bid, {}).get("instructions", []) or []
        for ins in reversed(instrs):
            op = ins["opname"]
            if op.startswith("POP_JUMP") and "IF_" in op:
                return op
        return None

    def _jump_target_bid(bid):
        instrs = block_by_id.get(bid, {}).get("instructions", []) or []
        for ins in reversed(instrs):
            op = ins["opname"]
            if op.startswith("POP_JUMP") and "IF_" in op:
                tgt = ins.get("argval")
                if isinstance(tgt, int):
                    for b2 in blocks:
                        if b2.get("start_offset") == tgt:
                            return b2["id"]
                return None
        return None

    def _subst_expr(e, old_obj, new_expr):
        if e is None or not isinstance(e, Expr):
            return e
        if e is old_obj:
            return new_expr
        if not e.args:
            return e
        new_args = tuple(_subst_expr(a, old_obj, new_expr) for a in e.args)
        if any(na is not e.args[i] for i, na in enumerate(new_args)):
            return Expr(kind=e.kind, value=e.value, args=new_args, origins=e.origins)
        return e

    def _subst_stmt(s, old_obj, new_expr):
        if not isinstance(s, Stmt):
            return s
        new_e = _subst_expr(s.expr, old_obj, new_expr) if s.expr is not None else s.expr
        new_x = _subst_expr(s.extra, old_obj, new_expr) if isinstance(s.extra, Expr) else s.extra
        if new_e is s.expr and new_x is s.extra:
            return s
        return Stmt(kind=s.kind, target=s.target, expr=new_e, extra=new_x, origins=s.origins)

    def _subst_everywhere(old_obj, new_expr):
        for bid2 in list(in_stack.keys()):
            in_stack[bid2] = [_subst_expr(v, old_obj, new_expr) for v in in_stack[bid2]]
        for bid2 in list(out_stack.keys()):
            out_stack[bid2] = [_subst_expr(v, old_obj, new_expr) for v in out_stack[bid2]]
        for bid2 in list(block_statements.keys()):
            block_statements[bid2] = [_subst_stmt(s, old_obj, new_expr) for s in (block_statements[bid2] or [])]
        for bid2 in list(block_conditions.keys()):
            block_conditions[bid2] = [_subst_expr(v, old_obj, new_expr) for v in (block_conditions[bid2] or [])]

    ternary_ancestors = set()
    phi_candidates = []
    for bid, stk in in_stack.items():
        for v in stk:
            if isinstance(v, Expr) and v.kind == "phi" and len(v.args or ()) == 2:
                phi_candidates.append((v, bid))

    seen_ids = set()
    uniq = []
    for (p, b) in phi_candidates:
        if id(p) in seen_ids:
            continue
        seen_ids.add(id(p))
        uniq.append((p, b))

    for phi_obj, merge_bid in uniq:
        preds = list(preds_map.get(merge_bid, ()))
        if len(preds) != 2:
            continue
        p1, p2 = preds[0], preds[1]
        preds_p1 = set(preds_map.get(p1, ()))
        preds_p2 = set(preds_map.get(p2, ()))
        common = preds_p1 & preds_p2
        cand_ancestors = list(common)
        if p1 in preds_p2:
            cand_ancestors.append(p1)
        if p2 in preds_p1:
            cand_ancestors.append(p2)
        ancestor = None
        for a in cand_ancestors:
            if _last_cond_jump_op(a) is not None:
                ancestor = a
                break
        if ancestor is None:
            continue

        op_a = _last_cond_jump_op(ancestor)
        jt = jump_target_bid = _jump_target_bid(ancestor)
        succs_a = list(cfg.get(ancestor, set()))
        if len(succs_a) != 2:
            continue
        fall_bid = next((s for s in succs_a if s != jump_target_bid), None)
        if fall_bid is None:
            continue

        def _reaches(src, dst, seen=None):
            if seen is None:
                seen = set()
            if src == dst:
                return True
            if src in seen:
                return False
            seen.add(src)
            for s in cfg.get(src, set()):
                if _reaches(s, dst, seen):
                    return True
            return False

        def _pred_side(pred_bid):
            if pred_bid == fall_bid:
                return "fall"
            if pred_bid == jump_target_bid:
                return "jump"
            from_fall = _reaches(fall_bid, pred_bid)
            from_jump = _reaches(jump_target_bid, pred_bid)
            if from_fall and not from_jump:
                return "fall"
            if from_jump and not from_fall:
                return "jump"
            return None

        side_p1 = _pred_side(p1)
        side_p2 = _pred_side(p2)
        if side_p1 is None or side_p2 is None or side_p1 == side_p2:
            continue

        conds = block_conditions.get(ancestor) or []
        if not conds:
            continue
        cond_expr = conds[-1]

        if "IF_FALSE" in op_a or "IF_NONE" in op_a:
            then_side, else_side = "fall", "jump"
        else:
            then_side, else_side = "jump", "fall"

        side_to_pred = {side_p1: p1, side_p2: p2}
        then_pred = side_to_pred.get(then_side)
        else_pred = side_to_pred.get(else_side)
        if then_pred is None or else_pred is None:
            continue

        phi_args = list(phi_obj.args)
        then_out = out_stack.get(then_pred) or []
        else_out = out_stack.get(else_pred) or []
        then_top = then_out[-1] if then_out else None
        else_top = else_out[-1] if else_out else None

        def _match(top, args):
            if top is None:
                return None
            for a in args:
                if a is top:
                    return a
            try:
                tr = expr_repr(top)
            except Exception:
                return None
            for a in args:
                try:
                    if expr_repr(a) == tr:
                        return a
                except Exception:
                    pass
            return None

        then_val = _match(then_top, phi_args)
        else_val = _match(else_top, phi_args)
        if then_val is None or else_val is None or then_val is else_val:
            continue

        ternary = Expr(kind="ternary", args=(cond_expr, then_val, else_val), origins=frozenset())
        _subst_everywhere(phi_obj, ternary)
        ternary_ancestors.add(ancestor)
        block_conditions[ancestor] = []
        if debug:
            print(f"[DEBUG] phi→ternary em merge={merge_bid} ancestor={ancestor}")

    return ternary_ancestors


def _fix_yield_from(blocks, cfg, block_statements, in_stack, out_stack, debug=False):
    block_by_id = build_block_by_id(blocks)

    def block_opnames(bid):
        return get_block_opnames(block_by_id.get(bid, {}))

    yield_from_internal = set()

    for b in blocks:
        bid = b["id"]
        ops = block_opnames(bid)
        is_await = "GET_AWAITABLE" in ops
        is_anext = "GET_ANEXT" in ops
        if "GET_YIELD_FROM_ITER" not in ops and not is_await and not is_anext:
            continue


        out = out_stack.get(bid, [])
        iterable_expr = None
        if is_anext:

            for v in reversed(out):
                if isinstance(v, Expr) and v.kind == "anext" and v.args:
                    aiter_obj = v.args[0]
                    if isinstance(aiter_obj, Expr) and aiter_obj.kind == "aiter" and aiter_obj.args:
                        iterable_expr = aiter_obj.args[0]
                    else:
                        iterable_expr = aiter_obj
                    break
        else:
            target_kind = "await" if is_await else "yield_from_iter"
            for v in reversed(out):
                if isinstance(v, Expr) and v.kind == target_kind and v.args:
                    iterable_expr = v.args[0]
                    break
        if iterable_expr is None:
            continue

        send_bid = None
        for succ in cfg.get(bid, set()):
            s_ops = block_opnames(succ)
            if "SEND" in s_ops:
                send_bid = succ
                break
        if send_bid is None:
            continue

        end_send_bid = None
        for ins in (block_by_id.get(send_bid, {}).get("instructions", []) or []):
            if ins["opname"] == "SEND":
                jt = ins.get("jump_target")
                if jt is not None:
                    for succ in cfg.get(send_bid, set()):
                        succ_instrs = block_by_id.get(succ, {}).get("instructions", []) or []
                        if succ_instrs and succ_instrs[0].get("offset") == jt:
                            end_send_bid = succ
                            break
                break

        def _is_stop_bid(sid):
            if sid == end_send_bid:
                return True
            if "END_ASYNC_FOR" in block_opnames(sid):
                return True
            return False

        internal = set()
        work = [send_bid]
        while work:
            cur = work.pop()
            if cur in internal or _is_stop_bid(cur):
                continue
            internal.add(cur)
            for succ in cfg.get(cur, set()):
                if succ not in internal and not _is_stop_bid(succ):
                    work.append(succ)

        if end_send_bid is not None:
            end_instrs = block_by_id.get(end_send_bid, {}).get("instructions", []) or []
            pure_infra = True
            for ins in end_instrs:
                op_i = ins["opname"]
                if op_i in ("END_SEND", "POP_TOP", "NOP", "RESUME"):
                    continue
                if op_i == "RETURN_CONST" and ins.get("argval") is None:
                    continue 
                pure_infra = False
                break
            if pure_infra:
                internal.add(end_send_bid)

        yf_target = None
        store_bid = None  
        if end_send_bid is not None and end_send_bid not in internal:
            store_bid = end_send_bid
        elif end_send_bid is not None and end_send_bid in internal:
            for succ in cfg.get(end_send_bid, set()):
                if succ not in internal and not _is_stop_bid(succ):
                    store_bid = succ
                    break

        if store_bid is not None:
            for ins in (block_by_id.get(store_bid, {}).get("instructions", []) or []):
                if ins["opname"] == "END_SEND":
                    continue
                if ins["opname"] in ("STORE_FAST", "STORE_NAME", "STORE_DEREF"):
                    yf_target = ins.get("argval") or str(ins.get("arg", ""))
                break   

            if yf_target is not None:
                old_stmts = list(block_statements.get(store_bid, []))
                new_stmts = [s for s in old_stmts
                             if not (isinstance(s, Stmt) and s.kind == "assign"
                                     and s.target == yf_target)]
                block_statements[store_bid] = new_stmts

        if is_await:
            is_aexit_await = any(
                ins["opname"] == "GET_AWAITABLE" and ins.get("arg", 0) == 2
                for ins in (block_by_id.get(bid, {}).get("instructions", []) or [])
            )
            if is_aexit_await:
                yield_from_internal.update(internal)
                yield_from_internal.add(bid)
                if end_send_bid is not None:
                    yield_from_internal.add(end_send_bid)
                    _aexit_cleanup_ops = frozenset({
                        "END_SEND", "POP_TOP", "POP_EXCEPT", "NOP", "COPY",
                        "RERAISE", "RETURN_CONST", "RETURN_VALUE",
                        "POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE",
                        "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "CLEANUP_THROW",
                    })
                    cwork = list(cfg.get(end_send_bid, set()))
                    cseen = set(yield_from_internal)
                    cseen.add(end_send_bid)
                    while cwork:
                        cb = cwork.pop()
                        if cb in cseen:
                            continue
                        cseen.add(cb)
                        cb_ops = {i["opname"] for i in (block_by_id.get(cb, {}).get("instructions") or [])}
                        if cb_ops and cb_ops.issubset(_aexit_cleanup_ops):
                            yield_from_internal.add(cb)
                            for s in cfg.get(cb, set()):
                                if s not in cseen:
                                    cwork.append(s)
                continue  

        stmt_kind = "async_for_item" if is_anext else ("await" if is_await else "yield_from")
        stmt = Stmt(kind=stmt_kind, expr=iterable_expr, target=yf_target, extra=None, origins=frozenset())
        block_statements[bid] = list(block_statements.get(bid, [])) + [stmt]
        yield_from_internal.update(internal)

    return yield_from_internal


def merge_stacks(stacks, debug=False):
    if not stacks:
        return []

    max_len = max(len(s) for s in stacks)

    merged = []
    for i in range(max_len):
        vals = []
        seen = set()

        for st in stacks:
            if i >= len(st):
                continue

            v = st[i]
            if not isinstance(v, Expr):
                v = Expr(kind="unknown", origins=frozenset({("obj", type(v).__name__)}))

            key = (v.kind, v.value, v.args, v.origins)
            if key not in seen:
                vals.append(v)
                seen.add(key)

        if not vals:
            continue

        merged_val = vals[0] if len(vals) == 1 else Expr(kind="phi", args=tuple(vals), origins=frozenset())
        merged.append(merged_val)

        if debug:
            try:
                print(f"[DEBUG] JOIN slot {i}: {expr_repr(merged_val)}")
            except Exception:
                pass

    return merged

def _binop_symbol(instr: dict) -> str:
    ar = instr.get("argrepr")
    if ar:
        return ar
    return "?"

def simulate_instruction(instr, stack: List[Expr], stmts: List[Stmt], block_conds: List[Expr], debug=False):
    op = instr["opname"]
    off = instr["offset"]

    def push(e: Expr):
        stack.append(e)
        if debug:
            print(f"[DEBUG] PUSH {expr_repr(e)}")

    def pop() -> Optional[Expr]:
        if stack:
            return stack.pop()
        if debug:
            print("[DEBUG] POP em pilha vazia (ignorado)")
        return None

    def pop_n(n: int) -> List[Expr]:
        out = []
        for _ in range(n):
            v = pop()
            out.append(v if v is not None else Expr(kind="unknown", origins=frozenset({off})))
        return out

    def unknown():
        return Expr(kind="unknown", origins=frozenset({off}))

    if op in ("RESUME", "CACHE", "NOP"):
        return

    if op == "PUSH_EXC_INFO":

        prev_exc = Expr(kind="exc", value="prev_exc", origins=frozenset({off}))
        new_exc  = Expr(kind="exc", value="exc",      origins=frozenset({off}))
        push(prev_exc)  
        push(new_exc)    
        return

    if op == "CHECK_EXC_MATCH":
        exc_type = pop() or unknown()
        exc = stack[-1] if stack else unknown()
        push(Expr(kind="exc_match", args=(exc, exc_type), origins=frozenset({off})))
        return

    if op == "POP_EXCEPT":
        if stack:
            pop()
        return

    if op == "RERAISE":
        stmts.append(Stmt(kind="reraise", expr=None, origins=frozenset({off})))
        stack.clear()
        return

    if op == "COPY":
        n = instr.get("arg") or 0
        idx = -n
        if n > 0 and (-idx) <= len(stack):
            push(stack[idx])
        else:
            push(unknown())
        return

    if op == "SWAP":
        n = instr.get("arg") or 0
        if n <= 1:
            return
        i = -1
        j = -n
        if (-j) <= len(stack):
            stack[i], stack[j] = stack[j], stack[i]
        return

    if op == "DELETE_FAST":
        target = str(instr.get("argval"))
        stmts.append(Stmt(kind="del", target=target, origins=frozenset({off})))
        return

    if op == "PUSH_NULL":
        push(Expr(kind="null", origins=frozenset({off})))
        return

    if op == "LOAD_CONST":
        push(Expr(kind="const", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op in ("LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"):
        if op == "LOAD_GLOBAL":
            raw_arg = instr.get("arg") or 0
            if raw_arg & 1:
                push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op == "LOAD_ATTR":
        obj = pop() or unknown()
        attr_name = instr.get("argval")
        raw_arg = instr.get("arg") or 0
        is_method = bool(raw_arg & 1)
        if is_method:
            push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr_name, args=(obj,), origins=frozenset({off})))
        return

    if op == "LOAD_CLOSURE":
        push(Expr(kind="closure_var", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op in ("LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR"):
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op == "LOAD_SUPER_ATTR":
        self_val = pop() or unknown()
        self_type = pop() or unknown()
        super_fn = pop() or unknown()
        attr_name = instr.get("argval")
        super_call = Expr(kind="call", args=(Expr(kind="name", value="super", origins=frozenset({off})),), origins=frozenset({off}))
        push(Expr(kind="attr", value=attr_name, args=(super_call,), origins=frozenset({off})))
        return

    if op == "LOAD_ASSERTION_ERROR":
        push(Expr(kind="name", value="AssertionError", origins=frozenset({off})))
        return

    if op == "LOAD_BUILD_CLASS":
        push(Expr(kind="name", value="__build_class__", origins=frozenset({off})))
        return

    if op == "LOAD_LOCALS":
        push(Expr(kind="call", args=(Expr(kind="name", value="locals", origins=frozenset({off})),), origins=frozenset({off})))
        return

    if op == "LOAD_METHOD":
        obj = pop() or unknown()
        attr_name = instr.get("argval")
        push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr_name, args=(obj,), origins=frozenset({off})))
        return

    if op in ("LOAD_SUPER_METHOD", "LOAD_ZERO_SUPER_METHOD"):
        self_val = pop() or unknown()
        self_type = pop() or unknown()
        super_fn = pop() or unknown()
        attr_name = instr.get("argval")
        super_call = Expr(kind="call", args=(Expr(kind="name", value="super", origins=frozenset({off})),), origins=frozenset({off}))
        push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr_name, args=(super_call,), origins=frozenset({off})))
        return

    if op == "LOAD_ZERO_SUPER_ATTR":
        self_val = pop() or unknown()
        self_type = pop() or unknown()
        super_fn = pop() or unknown()
        attr_name = instr.get("argval")
        super_call = Expr(kind="call", args=(Expr(kind="name", value="super", origins=frozenset({off})),), origins=frozenset({off}))
        push(Expr(kind="attr", value=attr_name, args=(super_call,), origins=frozenset({off})))
        return

    if op in ("LOAD_FROM_DICT_OR_DEREF", "LOAD_FROM_DICT_OR_GLOBALS"):
        pop()  
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op.startswith("LOAD_"):
        push(unknown())
        return

    if op == "GET_ITER":
        it_src = pop() or unknown()
        push(Expr(kind="iter", args=(it_src,), origins=frozenset({off})))
        return

    if op == "FOR_ITER":
        it = stack[-1] if stack else unknown()
        push(Expr(kind="next", args=(it,), origins=frozenset({off})))
        return

    if op == "BUILD_LIST":
        n = instr.get("arg") or 0
        elems = list(reversed(pop_n(n)))
        push(Expr(kind="list", args=tuple(elems), origins=frozenset({off})))
        return

    if op == "BUILD_TUPLE":
        n = instr.get("arg") or 0
        elems = list(reversed(pop_n(n)))
        push(Expr(kind="tuple", args=tuple(elems), origins=frozenset({off})))
        return

    if op == "BINARY_SUBSCR":
        key = pop() or unknown()
        obj = pop() or unknown()
        push(Expr(kind="subscr", args=(obj, key), origins=frozenset({off})))
        return

    if op == "STORE_SUBSCR":
        key = pop() or unknown()
        obj = pop() or unknown()
        val = pop() or unknown()
        target_repr = f"{expr_repr(obj)}[{expr_repr(key)}]"
        if (isinstance(val, Expr) and val.kind == "binop"
                and isinstance(val.value, str) and val.value.endswith("=")
                and val.value != "==" and val.value != "!=" and val.value != "<="
                and val.value != ">="):
            a0 = val.args[0] if val.args else None
            if (isinstance(a0, Expr) and a0.kind == "subscr"
                    and len(a0.args) >= 2
                    and expr_repr(a0.args[0]) == expr_repr(obj)
                    and expr_repr(a0.args[1]) == expr_repr(key)):
                stmts.append(Stmt(kind="augassign", target=target_repr,
                                  expr=val.args[1], extra=val.value,
                                  origins=frozenset({off})))
                return
        stmts.append(Stmt(kind="store_subscr", target=target_repr, expr=val, origins=frozenset({off})))
        return

    if op == "DELETE_SUBSCR":
        key = pop() or unknown()
        obj = pop() or unknown()
        target_repr = f"{expr_repr(obj)}[{expr_repr(key)}]"
        stmts.append(Stmt(kind="del_subscr", target=target_repr, origins=frozenset({off})))
        return

    if op == "BINARY_SLICE":
        end = pop() or unknown()
        start = pop() or unknown()
        obj = pop() or unknown()
        sl = Expr(kind="slice", args=(start, end), origins=frozenset({off}))
        push(Expr(kind="subscr", args=(obj, sl), origins=frozenset({off})))
        return

    if op == "STORE_SLICE":
        end = pop() or unknown()
        start = pop() or unknown()
        obj = pop() or unknown()
        val = pop() or unknown()
        def _sl_repr(s):
            if isinstance(s, Expr) and s.kind == "const" and s.value is None:
                return ""
            return expr_repr(s)
        target_repr = f"{expr_repr(obj)}[{_sl_repr(start)}:{_sl_repr(end)}]"
        stmts.append(Stmt(kind="store_subscr", target=target_repr, expr=val, origins=frozenset({off})))
        return

    if op == "BUILD_SLICE":
        n = instr.get("arg") or 2
        if n == 3:
            step = pop() or unknown()
            end = pop() or unknown()
            start = pop() or unknown()
            push(Expr(kind="slice", args=(start, end, step), origins=frozenset({off})))
        else:
            end = pop() or unknown()
            start = pop() or unknown()
            push(Expr(kind="slice", args=(start, end), origins=frozenset({off})))
        return

    if op == "UNARY_NEGATIVE":
        val = pop() or unknown()
        push(Expr(kind="unary", value="-", args=(val,), origins=frozenset({off})))
        return

    if op == "UNARY_NOT":
        val = pop() or unknown()
        push(Expr(kind="unary", value="not", args=(val,), origins=frozenset({off})))
        return

    if op == "UNARY_INVERT":
        val = pop() or unknown()
        push(Expr(kind="unary", value="~", args=(val,), origins=frozenset({off})))
        return

    if op == "IS_OP":
        b = pop() or unknown()
        a = pop() or unknown()
        invert = instr.get("arg", 0)
        push(Expr(kind="is", value=invert, args=(a, b), origins=frozenset({off})))
        return

    if op == "CONTAINS_OP":
        b = pop() or unknown()
        a = pop() or unknown()
        invert = instr.get("arg", 0)
        push(Expr(kind="contains", value=invert, args=(a, b), origins=frozenset({off})))
        return

    if op == "END_FOR":
        pop()
        pop()
        return

    if op == "BUILD_SET":
        n = instr.get("arg") or 0
        elems = list(reversed(pop_n(n)))
        push(Expr(kind="set", args=tuple(elems), origins=frozenset({off})))
        return

    if op == "BUILD_MAP":
        n = instr.get("arg") or 0
        items = list(reversed(pop_n(2 * n)))
        push(Expr(kind="dict", args=tuple(items), origins=frozenset({off})))
        return

    if op == "BUILD_CONST_KEY_MAP":
        n = instr.get("arg") or 0
        keys_tuple = pop() or unknown()
        vals = list(reversed(pop_n(n)))
        if isinstance(keys_tuple, Expr) and keys_tuple.kind == "const" and isinstance(keys_tuple.value, tuple):
            items = []
            for i, k in enumerate(keys_tuple.value):
                items.append(Expr(kind="const", value=k, origins=frozenset({off})))
                items.append(vals[i] if i < len(vals) else unknown())
            push(Expr(kind="dict", args=tuple(items), origins=frozenset({off})))
        else:
            push(Expr(kind="dict", args=tuple(vals), value="const_keys", origins=frozenset({off})))
        return

    if op == "MAP_ADD":
        n = instr.get("arg") or 0
        val = pop() or unknown()
        key = pop() or unknown()
        idx = -(n)
        if -idx <= len(stack) and isinstance(stack[idx], Expr) and stack[idx].kind == "dict":
            d = stack[idx]
            stack[idx] = Expr(kind="dict", args=tuple(d.args) + (key, val), origins=d.origins | frozenset({off}))
        return

    if op == "SET_ADD":
        n = instr.get("arg") or 0
        item = pop() or unknown()
        idx = -(n)
        if -idx <= len(stack) and isinstance(stack[idx], Expr) and stack[idx].kind == "set":
            s = stack[idx]
            stack[idx] = Expr(kind="set", args=tuple(s.args) + (item,), origins=s.origins | frozenset({off}))
        return

    if op in ("DICT_MERGE", "DICT_UPDATE"):
        n = instr.get("arg") or 0
        update = pop() or unknown()
        idx = -(n)
        if -idx <= len(stack):
            d = stack[idx]
            d_args = tuple(getattr(d, 'args', ()))
            if isinstance(update, Expr) and update.kind == "dict":
                has_inner_unpack = False
                for i in range(0, len(update.args), 2):
                    k_e = update.args[i] if i < len(update.args) else None
                    if isinstance(k_e, Expr) and k_e.kind == "const" and k_e.value is None:
                        has_inner_unpack = True
                        break
                if not has_inner_unpack:
                    stack[idx] = Expr(kind="dict", args=d_args + tuple(update.args),
                                       value="unpack", origins=frozenset({off}))
                    return
            stack[idx] = Expr(kind="dict", args=d_args + (
                Expr(kind="const", value=None, origins=frozenset({off})),
                update,
            ), value="unpack", origins=frozenset({off}))
        return

    if op == "SET_UPDATE":
        n = instr.get("arg") or 0
        update = pop() or unknown()
        idx = -(n)
        if -idx <= len(stack):
            s = stack[idx]
            if isinstance(update, Expr) and update.kind == "const" and isinstance(update.value, frozenset):
                new_elems = tuple(
                    Expr(kind="const", value=v, origins=frozenset({off}))
                    for v in sorted(update.value, key=repr)
                )
                stack[idx] = Expr(kind="set", args=tuple(getattr(s, 'args', ())) + new_elems, origins=frozenset({off}))
            else:

                starred = Expr(kind="starred", args=(update,), origins=frozenset({off}))
                stack[idx] = Expr(kind="set", args=tuple(getattr(s, 'args', ())) + (starred,), origins=frozenset({off}))
        return
    if op == "BUILD_STRING":
        n = instr.get("arg") or 0
        parts = list(reversed(pop_n(n)))
        push(Expr(kind="fstring", args=tuple(parts), origins=frozenset({off})))
        return

    if op == "FORMAT_SIMPLE":
        val = pop() or unknown()
        push(Expr(kind="format", value=None, args=(val,), origins=frozenset({off})))
        return

    if op == "FORMAT_WITH_SPEC":
        spec = pop() or unknown()
        val = pop() or unknown()
        spec_str = spec.value if isinstance(spec, Expr) and spec.kind == "const" else expr_repr(spec)
        push(Expr(kind="format", value=spec_str, args=(val,), origins=frozenset({off})))
        return

    if op == "FORMAT_VALUE":
        flags = instr.get("arg") or 0
        has_spec = bool(flags & 0x04)
        conversion = flags & 0x03
        spec = pop() if has_spec else None
        val = pop() or unknown()
        args_list = [val]
        if conversion:
            args_list.append(Expr(kind="const", value=conversion, origins=frozenset({off})))
        spec_val = None
        if spec and isinstance(spec, Expr) and spec.kind == "const":
            spec_val = spec.value
        push(Expr(kind="format", value=spec_val, args=tuple(args_list), origins=frozenset({off})))
        return

    if op == "CONVERT_VALUE":
        val = pop() or unknown()
        conversion = instr.get("arg", 0)
        conv_expr = Expr(kind="const", value=conversion, origins=frozenset({off}))
        push(Expr(kind="format", value=None, args=(val, conv_expr), origins=frozenset({off})))
        return

    if op == "UNPACK_SEQUENCE":
        n = instr.get("arg") or 0
        seq = pop() or unknown()
        for i in range(n - 1, -1, -1):
            push(Expr(kind="unpack", value=i, args=(seq,), origins=frozenset({off})))
        return

    if op == "UNPACK_EX":
        arg = instr.get("arg") or 0
        before = arg & 0xFF
        after = (arg >> 8) & 0xFF
        seq = pop() or unknown()
        total = before + 1 + after
        for i in range(total - 1, -1, -1):
            if i == before:
                push(Expr(kind="starred", args=(Expr(kind="unpack", value=i, args=(seq,), origins=frozenset({off})),), origins=frozenset({off})))
            else:
                push(Expr(kind="unpack", value=i, args=(seq,), origins=frozenset({off})))
        return

    if op == "IMPORT_NAME":
        fromlist = pop() or unknown()
        level = pop() or unknown()
        module_name = instr.get("argval")
        push(Expr(kind="import", value=module_name, args=(level, fromlist), origins=frozenset({off})))
        return

    if op == "IMPORT_FROM":
        module = stack[-1] if stack else unknown()
        attr_name = instr.get("argval")
        push(Expr(kind="import_from", value=attr_name, args=(module,), origins=frozenset({off})))
        return

    if op == "IMPORT_STAR":
        module = pop() or unknown()
        module_name = module.value if isinstance(module, Expr) and module.kind == "import" else "?"
        stmts.append(Stmt(kind="import_star", target=str(module_name), origins=frozenset({off})))
        return

    if op == "MAKE_FUNCTION":
        flags = instr.get("arg") or 0
        code = pop() or unknown()
        closure = None
        annotations = None
        kwdefaults = None
        defaults = None
        if flags & 0x08:
            closure = pop()  
        if flags & 0x04:
            annotations = pop() 
        if flags & 0x02:
            kwdefaults = pop()  
        if flags & 0x01:
            defaults = pop()  
        push(Expr(kind="make_function", value=flags, args=(code, defaults, kwdefaults, annotations), origins=frozenset({off})))
        return

    if op in ("MAKE_CELL", "COPY_FREE_VARS"):
        return

    if op == "BEFORE_WITH":
        ctx = pop() or unknown()
        push(Expr(kind="with_exit", args=(ctx,), origins=frozenset({off})))
        push(Expr(kind="with_enter", args=(ctx,), origins=frozenset({off})))
        return

    if op == "WITH_EXCEPT_START":
        if stack:
            exc = pop() or unknown()
            push(Expr(kind="with_cleanup", args=(exc,), origins=frozenset({off})))
        return

    if op == "RETURN_GENERATOR":
        return

    if op == "YIELD_VALUE":
        val = pop() or unknown()
        push(Expr(kind="yield", args=(val,), origins=frozenset({off})))
        return

    if op == "SEND":
        val = pop() or unknown()
        return

    if op == "END_SEND":
        val = pop() or unknown()
        if stack:
            pop()
        push(val)
        return

    if op == "GET_AWAITABLE":
        iterable = pop() or unknown()
        push(Expr(kind="await", args=(iterable,), origins=frozenset({off})))
        return

    if op == "GET_AITER":
        obj = pop() or unknown()
        push(Expr(kind="aiter", args=(obj,), origins=frozenset({off})))
        return

    if op == "GET_ANEXT":
        aiter_obj = stack[-1] if stack else unknown()
        push(Expr(kind="anext", args=(aiter_obj,), origins=frozenset({off})))
        return

    if op == "BEFORE_ASYNC_WITH":
        ctx = pop() or unknown()
        push(Expr(kind="async_with_exit", args=(ctx,), origins=frozenset({off})))
        push(Expr(kind="async_with_enter", args=(ctx,), origins=frozenset({off})))
        return

    if op == "MATCH_SEQUENCE":
        subject = stack[-1] if stack else unknown()
        push(Expr(kind="match_sequence", args=(subject,), origins=frozenset({off})))
        return

    if op == "MATCH_MAPPING":
        subject = stack[-1] if stack else unknown()
        push(Expr(kind="match_mapping", args=(subject,), origins=frozenset({off})))
        return

    if op == "MATCH_CLASS":
        n = instr.get("arg") or 0
        kw_attrs = pop() or unknown()
        cls = pop() or unknown()
        subject = pop() or unknown()
        push(Expr(kind="match_class", args=(cls, subject), value=n, origins=frozenset({off})))
        return

    if op == "MATCH_KEYS":
        keys = pop() or unknown()
        subject = stack[-1] if stack else unknown()
        push(Expr(kind="match_keys", args=(subject, keys), origins=frozenset({off})))
        return

    if op == "GET_LEN":
        obj = stack[-1] if stack else unknown()
        push(Expr(kind="get_len", args=(obj,), origins=frozenset({off})))
        return
    if op == "EXTENDED_ARG":
        return

    if op == "CALL_INTRINSIC_1":
        arg = pop() or unknown()
        intrinsic_id = instr.get("arg", 0)
        push(Expr(kind="intrinsic", value=intrinsic_id, args=(arg,), origins=frozenset({off})))
        return

    if op == "CALL_INTRINSIC_2":
        arg2 = pop() or unknown()
        arg1 = pop() or unknown()
        intrinsic_id = instr.get("arg", 0)
        push(Expr(kind="intrinsic", value=intrinsic_id, args=(arg1, arg2), origins=frozenset({off})))
        return

    if op == "LIST_EXTEND":
        it = pop()
        lst = stack[-1] if stack else None
        if isinstance(lst, Expr) and lst.kind == "list":
            if isinstance(it, Expr) and it.kind == "const" and isinstance(it.value, tuple):
                elems = tuple(Expr(kind="const", value=v, origins=frozenset({off})) for v in it.value)
                stack[-1] = Expr(kind="list", args=tuple(lst.args) + elems, origins=lst.origins | frozenset({off}))
            else:
                starred = Expr(kind="starred", args=(it or unknown(),), origins=frozenset({off}))
                stack[-1] = Expr(kind="list", args=tuple(lst.args) + (starred,), origins=lst.origins | frozenset({off}))
        else:
            stack[-1] = Expr(kind="list_extend", args=(lst or unknown(), it or unknown()), origins=frozenset({off}))
        return

    if op == "LIST_APPEND":
        n = instr.get("arg") or 0
        item = pop()
        idx = -n 
        if n > 0 and n <= len(stack):
            lst = stack[idx]
            if isinstance(lst, Expr) and lst.kind == "list":
                stack[idx] = Expr(
                    kind="list",
                    args=tuple(lst.args) + (item or unknown(),),
                    origins=lst.origins | frozenset({off}),
                )
            else:
                stack[idx] = Expr(kind="list_append", args=(lst, item or unknown()), origins=frozenset({off}))
        return

    if op == "COMPARE_OP":
        b = pop() or unknown()
        a = pop() or unknown()
        cmpop = instr.get("argrepr") or "?"
        push(Expr(kind="compare", value=cmpop, args=(a, b), origins=frozenset({off})))
        return

    if op == "BINARY_OP":
        b = pop() or unknown()
        a = pop() or unknown()
        sym = _binop_symbol(instr)
        push(Expr(kind="binop", value=sym, args=(a, b), origins=frozenset({off})))
        return

    if op == "KW_NAMES":
        push(Expr(kind="kw_names", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op == "PRECALL":
        return

    if op == "CALL":
        n = instr.get("arg") or 0
        kw = pop() if stack and isinstance(stack[-1], Expr) and stack[-1].kind == "kw_names" else None
        args = list(reversed(pop_n(n)))
        fn = pop() or unknown()
        if stack and isinstance(stack[-1], Expr) and stack[-1].kind == "null":
            pop() 
        elif stack and isinstance(stack[-1], Expr):
            real_callable = pop()
            args = [fn] + args
            fn = real_callable
        if kw is not None:
            push(Expr(kind="call_kw", args=(fn, *args, kw), origins=frozenset({off})))
        else:
            push(Expr(kind="call", args=(fn, *args), origins=frozenset({off})))
        return

    if op == "CALL_FUNCTION_EX":
        flags = instr.get("arg") or 0
        if flags & 0x01:
            kwargs = pop() or unknown()
        else:
            kwargs = None
        args_tuple = pop() or unknown()
        fn = pop() or unknown()
        if stack and isinstance(stack[-1], Expr) and stack[-1].kind == "null":
            pop()
        call_args = (fn, args_tuple)
        if kwargs:
            call_args += (kwargs,)
        push(Expr(kind="call_ex", args=call_args, value=flags, origins=frozenset({off})))
        return

    if op == "POP_TOP":
        v = pop()
        if v is None:
            return
        if isinstance(v, Expr) and v.kind in ("iter", "next", "exc", "exc_match", "null", "kw_names",
                                                "with_enter", "with_exit", "with_cleanup",
                                                "async_with_enter", "async_with_exit",
                                                "match_class", "match_sequence", "match_mapping",
                                                "match_keys"):
            return
        if isinstance(v, Expr) and v.kind == "call" and v.args:
            fn = v.args[0]
            if isinstance(fn, Expr) and fn.kind in ("with_exit", "with_cleanup", "async_with_exit"):
                return
        stmts.append(Stmt(kind="expr", expr=v, origins=frozenset({off})))
        return

    if op == "STORE_ATTR":
        obj = pop() or unknown()
        val = pop() or unknown()
        attr_name = str(instr.get("argval"))
        obj_repr = expr_repr(obj)
        if (isinstance(val, Expr) and val.kind == "binop"
                and isinstance(val.value, str) and val.value.endswith("=")
                and val.value != "==" and val.value != "!=" and val.value != "<="
                and val.value != ">="):
            a0 = val.args[0] if val.args else None
            if (isinstance(a0, Expr) and a0.kind == "attr"
                    and str(a0.value) == attr_name
                    and a0.args and expr_repr(a0.args[0]) == obj_repr):
                target_repr = f"{obj_repr}.{attr_name}"
                stmts.append(Stmt(kind="augassign", target=target_repr,
                                  expr=val.args[1], extra=val.value,
                                  origins=frozenset({off})))
                return
        stmts.append(Stmt(kind="store_attr", target=attr_name, expr=val, extra=obj_repr, origins=frozenset({off})))
        return

    if op == "DELETE_ATTR":
        obj = pop() or unknown()
        attr_name = str(instr.get("argval"))
        obj_repr = expr_repr(obj)
        stmts.append(Stmt(kind="del_attr", target=attr_name, extra=obj_repr, origins=frozenset({off})))
        return

    if op in ("DELETE_NAME", "DELETE_GLOBAL", "DELETE_DEREF"):
        target = str(instr.get("argval"))
        stmts.append(Stmt(kind="del", target=target, origins=frozenset({off})))
        return

    if op in ("STORE_FAST", "STORE_FAST_MAYBE_NULL", "STORE_NAME", "STORE_GLOBAL", "STORE_DEREF"):
        target = str(instr.get("argval"))
        rhs = pop() or unknown()
        if isinstance(rhs, Expr) and rhs.kind == "import":
            module_name = str(rhs.value)
            stmts.append(Stmt(kind="import", target=target, extra=module_name, origins=frozenset({off})))
            return

        if isinstance(rhs, Expr) and rhs.kind == "import_from":
            module_expr = rhs.args[0] if rhs.args else None
            module_name = module_expr.value if isinstance(module_expr, Expr) and module_expr.kind == "import" else "?"
            from_name = str(rhs.value)
            stmts.append(Stmt(kind="import_from", target=target,
                              extra={"module": str(module_name), "names": [(from_name, target if target != from_name else None)]},
                              origins=frozenset({off})))
            return

        if isinstance(rhs, Expr) and rhs.kind == "binop" and isinstance(rhs.value, str) and rhs.value.endswith("="):
            a0 = rhs.args[0] if rhs.args else None
            a1 = rhs.args[1] if len(rhs.args) > 1 else None
            if isinstance(a0, Expr) and a0.kind == "name" and str(a0.value) == target:
                stmts.append(Stmt(kind="augassign", target=target, expr=a1, extra=rhs.value, origins=frozenset({off})))
                return
        stmts.append(Stmt(kind="assign", target=target, expr=rhs, origins=frozenset({off})))
        return


    if op.startswith("STORE_"):
        rhs = pop() or unknown()
        stmts.append(Stmt(kind="assign", target="unknown_target", expr=rhs, origins=frozenset({off})))
        return

    if op in ("POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE"):
        cond = pop()
        if cond is not None:
            none_const = Expr(kind="const", value=None, origins=frozenset({off}))
            if op == "POP_JUMP_IF_NONE":
                expr = Expr(kind="is", value=1, args=(cond, none_const), origins=frozenset({off}))
            else:
                expr = Expr(kind="is", value=1, args=(cond, none_const), origins=frozenset({off}))
            block_conds.append(expr)
        return

    if op.startswith("POP_JUMP") and "IF_" in op:
        cond = pop()
        if cond is not None:
            block_conds.append(cond)
        return

    if op in ("JUMP_IF_FALSE_OR_POP", "JUMP_IF_TRUE_OR_POP"):
        cond = stack[-1] if stack else None
        if cond is not None:
            block_conds.append(cond)
        return

    if op == "RETURN_VALUE":
        val = pop()
        push(Expr(kind="return_value", args=(val,), origins=frozenset({off})))
        return

    if op == "RETURN_CONST":
        val = Expr(kind="const", value=instr.get("argval"), origins=frozenset({off}))
        push(Expr(kind="return_value", args=(val,), origins=frozenset({off})))
        return

    if op == "RAISE_VARARGS":
        n = instr.get("arg") or 0
        if n == 0:
            stmts.append(Stmt(kind="raise", expr=None, origins=frozenset({off})))
        elif n == 1:
            exc = pop() or unknown()
            stmts.append(Stmt(kind="raise", expr=exc, origins=frozenset({off})))
        elif n == 2:
            cause = pop() or unknown()
            exc = pop() or unknown()
            stmts.append(Stmt(kind="raise", expr=exc, extra=cause, origins=frozenset({off})))
        else:
            exc = pop() or unknown()
            stmts.append(Stmt(kind="raise", expr=exc, origins=frozenset({off})))
        stack.clear()
        return

    if op in ("JUMP", "JUMP_FORWARD", "JUMP_BACKWARD",
              "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_NO_INTERRUPT"):
        return

    if op in ("POP_BLOCK", "SETUP_FINALLY", "SETUP_WITH", "SETUP_CLEANUP",
              "SETUP_ANNOTATIONS", "INTERPRETER_EXIT"):
        return

    if op == "END_ASYNC_FOR":
        pop()
        pop()
        return

    if op == "CLEANUP_THROW":
        pop()  
        val = pop() or unknown()
        pop() 
        push(val)
        return

    if op == "GET_YIELD_FROM_ITER":
        iterable = pop() or unknown()
        push(Expr(kind="yield_from_iter", args=(iterable,), origins=frozenset({off})))
        return

    if op == "CHECK_EG_MATCH":
        exc_type = pop() or unknown()
        exc = pop() or unknown()
        push(Expr(kind="exc_group_remaining", args=(exc, exc_type), origins=frozenset({off})))
        push(Expr(kind="exc_group_match", args=(exc, exc_type), origins=frozenset({off})))
        return

    if debug:
        print(f"[DEBUG] Opcode não tratado: {op} @ offset {off}")
