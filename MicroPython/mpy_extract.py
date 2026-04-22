from MicroPython.mpy_loader import KIND_BYTECODE
from MicroPython.mpy_stack_sim import (
    build_mpy_basic_blocks,
    build_mpy_cfg,
    simulate_mpy_stack,
)
from MicroPython.mpy_patterns import detect_mpy_patterns
from utils.ast_recover import build_recovered_ast
from utils.ir import Expr, Stmt, expr_repr




def process_mpy_code_object(mpy_obj, depth: int = 0, debug: bool = False) -> dict:

    children = [
        process_mpy_code_object(child, depth=depth + 1, debug=debug)
        for child in mpy_obj._children
    ]

    if mpy_obj.kind != KIND_BYTECODE:
        return {
            "name":         mpy_obj.co_name,
            "recovered_ast": None,
            "stack_info":   {},
            "children":     children,
            "code_obj":     mpy_obj,
            "co_flags":     mpy_obj.co_flags,
            "native":       True,
            "arch_code":    mpy_obj.arch_code,
        }

    instrs = mpy_obj._instructions
    if not instrs:
        return {
            "name":         mpy_obj.co_name,
            "recovered_ast": None,
            "stack_info":   {},
            "children":     children,
            "code_obj":     mpy_obj,
            "co_flags":     mpy_obj.co_flags,
        }

    blocks     = build_mpy_basic_blocks(instrs, debug=debug)
    cfg        = build_mpy_cfg(blocks, instrs, debug=debug)
    stack_info = simulate_mpy_stack(blocks, cfg, instrs, mpy_obj, debug=debug)
    patterns   = detect_mpy_patterns(blocks, cfg, stack_info, mpy_obj, debug=debug)

    _fix_for_range_loops(blocks, stack_info, patterns=patterns, debug=debug)

    recovered_ast = build_recovered_ast(
        blocks=blocks,
        cfg=cfg,
        stack_info=stack_info,
        patterns=patterns,
        code_obj=mpy_obj,
        debug=debug,
    )

    node = {
        "name":         mpy_obj.co_name,
        "recovered_ast": recovered_ast,
        "stack_info":   stack_info,
        "children":     children,
        "code_obj":     mpy_obj,
        "co_flags":     mpy_obj.co_flags,
    }


    _attach_names_to_children(children, stack_info)
    _attach_defaults_to_children(children, stack_info)
    _rename_closure_locals_in_parent(children, stack_info)
    _fix_lambda_calls(children, stack_info)
    _fix_comp_calls(children, stack_info)
    _fix_genexpr_calls(children, stack_info)

    return node



def _attach_names_to_children(children: list, stack_info: dict):

    block_stmts = stack_info.get("block_statements") or {}
    for stmts in block_stmts.values():
        for st in stmts:
            if not (isinstance(st, Stmt) and isinstance(st.expr, Expr)):
                continue

            if (st.kind in ("assign", "expr")
                    and st.expr.kind == "make_function"):
                child_idx = st.expr.value
                if not isinstance(child_idx, int) or child_idx >= len(children):
                    continue
                ch = children[child_idx]
                co = ch.get("code_obj")
                if co is None:
                    continue
                inferred = st.target if st.kind == "assign" else None
                if inferred and (not co.co_name or co.co_name.startswith("<child_")):
                    co.co_name = inferred
                    ch["name"]  = inferred
                continue


            if (st.kind == "assign"
                    and st.expr.kind == "call"
                    and st.expr.args
                    and isinstance(st.expr.args[0], Expr)
                    and st.expr.args[0].kind == "name"
                    and st.expr.args[0].value == "__build_class__"):
                for arg in st.expr.args[1:]:
                    if isinstance(arg, Expr) and arg.kind == "make_function":
                        child_idx = arg.value
                        if isinstance(child_idx, int) and child_idx < len(children):
                            ch = children[child_idx]
                            co = ch.get("code_obj")
                            if co is not None and (not co.co_name or co.co_name.startswith("<child_")):
                                co.co_name = st.target
                                ch["name"] = st.target
                        break




def _rename_expr(expr, mapping: dict):
    if not isinstance(expr, Expr):
        return expr
    if expr.kind == "name" and isinstance(expr.value, str) and expr.value in mapping:
        return Expr(kind="name", value=mapping[expr.value],
                    args=expr.args, origins=expr.origins)
    new_args = tuple(_rename_expr(a, mapping) for a in (expr.args or ()))
    if new_args != (expr.args or ()):
        return Expr(kind=expr.kind, value=expr.value, args=new_args, origins=expr.origins)
    return expr


def _rename_stmt(st, mapping: dict):
    if not isinstance(st, Stmt):
        return st
    new_target = st.target
    if isinstance(st.target, str) and st.target in mapping and st.kind != "assign":
        new_target = mapping[st.target]
    new_expr = _rename_expr(st.expr, mapping) if st.expr is not None else None
    if new_expr is st.expr and new_target is st.target:
        return st
    return Stmt(kind=st.kind, target=new_target, expr=new_expr,
                extra=st.extra, origins=st.origins)


def _rename_closure_locals_in_parent(children: list, stack_info: dict):

    mapping = {}
    block_stmts = stack_info.get("block_statements") or {}
    for stmts in block_stmts.values():
        for st in stmts:
            if not (isinstance(st, Stmt) and st.kind == "assign"
                    and isinstance(st.expr, Expr) and st.expr.kind == "make_function"):
                continue
            target = st.target
            child_idx = st.expr.value
            if not (isinstance(target, str) and target.startswith("_local_")):
                continue
            if not (isinstance(child_idx, int) and 0 <= child_idx < len(children)):
                continue
            co = children[child_idx].get("code_obj")
            if co is None:
                continue
            cn = getattr(co, "co_name", None)
            if not cn or cn.startswith("<") or cn.startswith("_local_"):
                continue
            mapping[target] = cn

    if not mapping:
        return

    for bid, stmts in list(block_stmts.items()):
        new_stmts = []
        changed = False
        for st in stmts:
            new_st = _rename_stmt(st, mapping)
            if new_st is not st:
                changed = True
            new_stmts.append(new_st)
        if changed:
            block_stmts[bid] = new_stmts

    block_conditions = stack_info.get("block_conditions") or {}
    for bid, cond in list(block_conditions.items()):
        new_cond = _rename_expr(cond, mapping)
        if new_cond is not cond:
            block_conditions[bid] = new_cond



def _instr_to_expr(instr: dict):

    if instr is None:
        return None
    op = instr.get("opname", "")
    argval = instr.get("argval")
    argrepr = instr.get("argrepr")

    if op in ("LOAD_FAST_MULTI", "LOAD_FAST_N"):
        name = argrepr or (f"_local_{argval}" if argval is not None else "_local_?")
        return Expr(kind="name", value=name, origins=frozenset())

    if op in ("LOAD_CONST_SMALL_INT", "LOAD_CONST_SMALL_INT_MULTI"):
        return Expr(kind="const", value=argval, origins=frozenset())

    if op in ("LOAD_NAME", "LOAD_GLOBAL"):
        return Expr(kind="name", value=argval, origins=frozenset())

    return None


def _fix_for_range_loops(blocks: list, stack_info: dict, patterns: dict = None, debug: bool = False):

    if not blocks:
        return

    blocks_sorted = sorted(blocks, key=lambda b: b["start_offset"])
    block_by_id = {b["id"]: b for b in blocks_sorted}
    offset_to_bid = {}
    for b in blocks_sorted:
        for ins in b.get("instructions", []):
            offset_to_bid[ins["offset"]] = b["id"]

    all_bids_sorted = [b["id"] for b in blocks_sorted]

    block_statements  = stack_info.setdefault("block_statements", {})
    in_stack          = stack_info.setdefault("in_stack", {})
    block_conditions  = stack_info.setdefault("block_conditions", {})

    for b in blocks_sorted:
        bid    = b["id"]
        instrs = b.get("instructions", [])
        if len(instrs) < 4:
            continue

        opnames = [i["opname"] for i in instrs]
        if opnames != ["DUP_TOP_TWO", "ROT_TWO", "BINARY_OP_MULTI", "POP_JUMP_IF_TRUE"]:
            continue
        if instrs[2].get("argval") != "<":
            continue
        comparison_bid   = bid
        comparison_start = b["start_offset"]

        init_bid = None
        for ob in blocks_sorted:
            ob_instrs = ob.get("instructions", [])
            if not ob_instrs:
                continue
            last = ob_instrs[-1]
            if last.get("opname") == "JUMP" and last.get("jump_target") == comparison_start:
                if len(ob_instrs) < 2:
                    continue
                second_last = ob_instrs[-2]
                if second_last.get("opname") not in ("LOAD_CONST_SMALL_INT", "LOAD_CONST_SMALL_INT_MULTI"):
                    continue
                if second_last.get("argval") != 0:
                    continue
                init_bid = ob["id"]
                break

        if init_bid is None:
            continue

        init_block  = block_by_id[init_bid]
        init_instrs = init_block.get("instructions", [])

        if len(init_instrs) < 3:
            continue
        range_instr = init_instrs[-3]
        range_arg   = _instr_to_expr(range_instr)
        if range_arg is None:
            continue

        pop_jump_instr = instrs[3]
        body_start_off = pop_jump_instr.get("jump_target")
        if body_start_off is None:
            continue
        body_bid = offset_to_bid.get(body_start_off)
        if body_bid is None:
            continue
        body_block  = block_by_id.get(body_bid, {})
        body_instrs = body_block.get("instructions", [])
        if len(body_instrs) < 2:
            continue
        if body_instrs[0].get("opname") != "DUP_TOP":
            continue
        store_op = body_instrs[1].get("opname", "")
        if store_op not in ("STORE_FAST_MULTI", "STORE_FAST_N"):
            continue

        store_instr = body_instrs[1]
        loop_var = store_instr.get("argrepr") or (
            f"_local_{store_instr.get('argval')}" if store_instr.get("argval") is not None else "_loop_var"
        )

        comp_idx = all_bids_sorted.index(comparison_bid) if comparison_bid in all_bids_sorted else -1
        cleanup_bid = None
        if comp_idx >= 0 and comp_idx + 1 < len(all_bids_sorted):
            cand = all_bids_sorted[comp_idx + 1]
            if cand != body_bid:
                cleanup_bid = cand

        if debug:
            print(f"[DEBUG FOR-RANGE] init={init_bid} comparison={comparison_bid} "
                  f"body={body_bid} cleanup={cleanup_bid} "
                  f"loop_var={loop_var} range_arg={range_arg}")

        range_call = Expr(
            kind="call",
            args=(Expr(kind="name", value="range", origins=frozenset()), range_arg),
            origins=frozenset(),
        )
        iter_expr = Expr(
            kind="iter",
            args=(range_call,),
            origins=frozenset(),
        )


        for_iter_offset = init_instrs[-3]["offset"] 
        new_init_instrs = list(init_instrs[:-3]) + [{
            "opname":      "FOR_ITER",
            "offset":      for_iter_offset,
            "argval":      None,
            "argrepr":     None,
            "jump_target": None,
        }]
        init_block["instructions"] = new_init_instrs

        in_stack[init_bid]          = [iter_expr]
        block_conditions[init_bid]  = []

        b["instructions"]             = []
        block_statements[comparison_bid] = []
        block_conditions[comparison_bid] = []
        in_stack[comparison_bid]         = []


        body_stmts = list(block_statements.get(body_bid, []))
        if (body_stmts
                and isinstance(body_stmts[0], Stmt)
                and body_stmts[0].kind in ("assign", "augassign")
                and body_stmts[0].target == loop_var):
            body_stmts.pop(0)

        iter_ref  = Expr(kind="name", value="_for_iter_ref_", origins=frozenset())
        next_expr = Expr(kind="next", args=(iter_ref,), origins=frozenset())
        assign_stmt = Stmt(
            kind="assign",
            target=loop_var,
            expr=next_expr,
            extra=None,
            origins=frozenset(),
        )
        body_stmts.insert(0, assign_stmt)
        block_statements[body_bid] = body_stmts

        if cleanup_bid is not None:
            cleanup_stmts = list(block_statements.get(cleanup_bid, []))
            filtered = []
            for st in cleanup_stmts:
                if isinstance(st, Stmt) and st.kind == "expr" and isinstance(st.expr, Expr):
                    if st.expr.kind in ("binop", "unknown", "augassign"):
                        continue 
                filtered.append(st)
            block_statements[cleanup_bid] = filtered

        if patterns is not None:
            for lp in (patterns.get("loops") or []):

                if lp.get("header") == comparison_bid:
                    lp["header"]      = init_bid
                    lp["body_entry"]  = body_bid
                    lp["latch"]       = body_bid
                    lp["body_blocks"] = [init_bid, body_bid]
                    lp["is_for"]      = True
                    if debug:
                        print(f"[DEBUG FOR-RANGE] Loop atualizado: header={init_bid} "
                              f"body_entry={body_bid} latch={body_bid}")



def _attach_defaults_to_children(children: list, stack_info: dict):

    block_stmts = stack_info.get("block_statements") or {}
    for stmts in block_stmts.values():
        for st in stmts:
            expr = st.expr if isinstance(st, Stmt) else None
            if not isinstance(expr, Expr) or expr.kind != "make_function":
                continue
            child_idx = expr.value
            if not isinstance(child_idx, int) or child_idx >= len(children):
                continue

            ch = children[child_idx]
            args = expr.args or ()


            if "defaults" not in ch:
                ch["defaults"]     = args[0] if len(args) > 0 else None
                ch["kwdefaults"]   = args[1] if len(args) > 1 else None
                ch["annotations"]  = args[2] if len(args) > 2 else None
                ch["closure_vars"] = args[3] if len(args) > 3 else None




def _extract_lambda_info(child: dict):

    co = child.get("code_obj")
    if co is None:
        return None

    is_lambda = co.co_name == "<lambda>"
    if not is_lambda:
        return None

    argc = getattr(co, "co_argcount", 0) or 0
    posonly = getattr(co, "co_posonlyargcount", 0) or 0
    kwonly = getattr(co, "co_kwonlyargcount", 0) or 0
    flags = getattr(co, "co_flags", 0) or 0
    varnames = list(getattr(co, "co_varnames", ()) or ())
    has_varargs = bool(flags & 0x04)
    has_varkw = bool(flags & 0x08)

    parts = []
    for i, name in enumerate(varnames[:argc]):
        if name == ".0":
            continue
        parts.append(str(name))
        if posonly > 0 and i == posonly - 1:
            parts.append("/")
    if has_varargs:
        va_idx = argc + kwonly
        va_name = varnames[va_idx] if va_idx < len(varnames) else "args"
        parts.append(f"*{va_name}")
    elif kwonly > 0:
        parts.append("*")
    for i in range(kwonly):
        idx = argc + i
        if idx < len(varnames):
            parts.append(str(varnames[idx]))
    if has_varkw:
        kw_idx = argc + kwonly + (1 if has_varargs else 0)
        kw_name = varnames[kw_idx] if kw_idx < len(varnames) else "kwargs"
        parts.append(f"**{kw_name}")
    params_str = ", ".join(parts)

    stack_info  = child.get("stack_info") or {}
    block_stmts = stack_info.get("block_statements") or {}
    body_expr   = None
    for stmts in block_stmts.values():
        for st in stmts:
            if isinstance(st, Stmt) and st.kind == "return" and st.expr is not None:
                body_expr = st.expr
                break
        if body_expr is not None:
            break

    if body_expr is None:
        return None
    return (params_str, body_expr)


def _subst_lambda_in_expr(expr: Expr, lambda_map: dict) -> Expr:

    if not isinstance(expr, Expr):
        return expr

    if expr.kind == "make_function" and isinstance(expr.value, int):
        if expr.value in lambda_map:
            params_str, body_expr = lambda_map[expr.value]
            return Expr(
                kind="lambda",
                value=params_str,
                args=(body_expr,),
                origins=expr.origins,
            )

    new_args = tuple(_subst_lambda_in_expr(a, lambda_map) for a in (expr.args or ()))
    if new_args != expr.args:
        return Expr(kind=expr.kind, value=expr.value, args=new_args, origins=expr.origins)
    return expr


def _subst_lambda_in_stmt(st: Stmt, lambda_map: dict) -> Stmt:
    if not isinstance(st, Stmt) or st.expr is None:
        return st
    new_expr = _subst_lambda_in_expr(st.expr, lambda_map)
    if new_expr is st.expr:
        return st
    return Stmt(kind=st.kind, target=st.target, expr=new_expr, extra=st.extra, origins=st.origins)


def _fix_lambda_calls(children: list, stack_info: dict):
    lambda_map = {}
    for i, ch in enumerate(children):
        info = _extract_lambda_info(ch)
        if info is not None:
            co = ch.get("code_obj")
            if co is not None:
                lambda_map[i] = info  
    if not lambda_map:
        return

    block_stmts = stack_info.get("block_statements") or {}
    for bid in list(block_stmts.keys()):
        stmts     = block_stmts[bid]
        new_stmts = []
        changed   = False
        for st in stmts:
            new_st = _subst_lambda_in_stmt(st, lambda_map)
            if new_st is not st:
                changed = True
            new_stmts.append(new_st)
        if changed:
            block_stmts[bid] = new_stmts



def _extract_comp_info(child: dict, child_idx: int):
    co = child.get("code_obj")
    if co is None:
        return None
    instrs = getattr(co, "_instructions", None)
    if not instrs:
        return None
    first_op = instrs[0].get("opname", "")
    if first_op == "BUILD_LIST":
        kind = "listcomp"
    elif first_op == "BUILD_MAP":
        kind = "dictcomp"
    elif first_op == "BUILD_SET":
        kind = "setcomp"
    else:
        return None

    has_store_comp = any(i.get("opname") == "STORE_COMP" for i in instrs)
    if not has_store_comp:
        return None

    stack_info  = child.get("stack_info") or {}
    block_stmts = stack_info.get("block_statements") or {}
    block_conds = stack_info.get("block_conditions") or {}

    element_expr = None
    loop_vars    = []   
    cond         = None

    def _inner_next(e):
        if isinstance(e, Expr) and e.kind == "unpack" and e.args:
            inner = e.args[0]
            if isinstance(inner, Expr) and inner.kind == "next":
                return inner
        if isinstance(e, Expr) and e.kind == "next":
            return e
        return None

    def _iterable_of_next(next_expr):
        if not isinstance(next_expr, Expr) or next_expr.kind != "next" or not next_expr.args:
            return None
        iter_e = next_expr.args[0]
        if isinstance(iter_e, Expr) and iter_e.kind == "iter" and iter_e.args:
            return iter_e.args[0]
        return None

    sorted_bids = sorted(block_stmts.keys())

    _pending_unpack = None  

    def _flush_unpack():
        nonlocal _pending_unpack
        if _pending_unpack is None:
            return
        var_tuple = ", ".join(_pending_unpack["vars"])
        iterable = _iterable_of_next(_pending_unpack["next_expr"])
        if not loop_vars:
            loop_vars.append((var_tuple, None))
        else:
            loop_vars.append((var_tuple, iterable))
        _pending_unpack = None

    for bid in sorted_bids:
        stmts = block_stmts[bid]
        for st in stmts:
            if not isinstance(st, Stmt):
                continue
            if st.kind == "store_comp" and element_expr is None:
                element_expr = st.expr
                continue
            if st.kind != "assign":
                continue

            inner_next = _inner_next(st.expr) if isinstance(st.expr, Expr) else None
            if (isinstance(st.expr, Expr) and st.expr.kind == "unpack"
                    and inner_next is not None):
                idx = st.expr.value if isinstance(st.expr.value, int) else 0
                if _pending_unpack is not None:
                    same_next = expr_repr(_pending_unpack["next_expr"]) == expr_repr(inner_next)
                    if same_next and idx == _pending_unpack["expected_idx"]:
                        _pending_unpack["vars"].append(st.target)
                        _pending_unpack["expected_idx"] += 1
                        continue
                    _flush_unpack()
                if idx == 0:
                    _pending_unpack = {"vars": [st.target], "next_expr": inner_next, "expected_idx": 1}
                continue

            if isinstance(st.expr, Expr) and st.expr.kind == "next":
                _flush_unpack()
                iterable = _iterable_of_next(st.expr)
                if not loop_vars:
                    loop_vars.append((st.target, None))
                else:
                    loop_vars.append((st.target, iterable))
                continue


            _flush_unpack()

    _flush_unpack()

    for bid_conds in block_conds.values():
        for c in bid_conds:
            if cond is None and isinstance(c, Expr):
                cond = c
            break
        if cond is not None:
            break

    if element_expr is None or not loop_vars:
        return None
    return (kind, element_expr, loop_vars, cond)


def _subst_comp_in_expr(expr: Expr, comp_map: dict) -> Expr:

    if not isinstance(expr, Expr):
        return expr

    if expr.kind == "call" and len(expr.args) >= 2:
        fn_e     = expr.args[0]
        iter_arg = expr.args[1]
        if (isinstance(fn_e, Expr)
                and fn_e.kind == "make_function"
                and isinstance(fn_e.value, int)
                and fn_e.value in comp_map):
            kind, element_expr, loop_vars, cond = comp_map[fn_e.value]
            if isinstance(iter_arg, Expr) and iter_arg.kind == "iter" and iter_arg.args:
                actual_iterable = iter_arg.args[0]
            else:
                actual_iterable = iter_arg
            first_var = loop_vars[0][0] if loop_vars else "item"
            args = (
                element_expr,
                Expr(kind="name", value=first_var, origins=frozenset()),
                actual_iterable,
            )
            for var_name, iterable in loop_vars[1:]:
                args = args + (Expr(
                    kind="for_clause",
                    args=(
                        Expr(kind="name", value=var_name, origins=frozenset()),
                        iterable if iterable is not None else Expr(kind="unknown", origins=frozenset()),
                    ),
                    origins=frozenset(),
                ),)
            if cond is not None:
                args = args + (cond,)
            return Expr(kind=kind, args=args, origins=expr.origins)

    new_args = tuple(_subst_comp_in_expr(a, comp_map) for a in (expr.args or ()))
    if new_args != expr.args:
        return Expr(kind=expr.kind, value=expr.value, args=new_args, origins=expr.origins)
    return expr


def _subst_comp_in_stmt(st: Stmt, comp_map: dict) -> Stmt:
    if not isinstance(st, Stmt) or st.expr is None:
        return st
    new_expr = _subst_comp_in_expr(st.expr, comp_map)
    if new_expr is st.expr:
        return st
    return Stmt(kind=st.kind, target=st.target, expr=new_expr, extra=st.extra, origins=st.origins)


def _fix_comp_calls(children: list, stack_info: dict):
    comp_map = {}
    for i, ch in enumerate(children):
        info = _extract_comp_info(ch, i)
        if info is not None:
            comp_map[i] = info

    if not comp_map:
        return

    block_stmts = stack_info.get("block_statements") or {}
    for bid in list(block_stmts.keys()):
        stmts     = block_stmts[bid]
        new_stmts = []
        changed   = False
        for st in stmts:
            new_st = _subst_comp_in_stmt(st, comp_map)
            if new_st is not st:
                changed = True
            new_stmts.append(new_st)
        if changed:
            block_stmts[bid] = new_stmts



_MP_SCOPE_GENERATOR = 0x01


def _extract_genexpr_info(child: dict, child_idx: int):
    co = child.get("code_obj")
    if co is None:
        return None

    is_gen = (
        "<genexpr>" in (co.co_name or "")
        or bool(getattr(co, "scope_flags", 0) & _MP_SCOPE_GENERATOR)
    )
    if not is_gen:
        return None

    stack_info  = child.get("stack_info") or {}
    block_stmts = stack_info.get("block_statements") or {}

    element_expr = None
    loop_var     = None

    for stmts in block_stmts.values():
        for st in stmts:
            if not isinstance(st, Stmt):
                continue
            if (st.kind == "expr"
                    and isinstance(st.expr, Expr)
                    and st.expr.kind == "yield"
                    and st.expr.args):
                if element_expr is None:
                    element_expr = st.expr.args[0]
            if (st.kind == "assign"
                    and isinstance(st.expr, Expr)
                    and st.expr.kind == "next"):
                if loop_var is None:
                    loop_var = st.target

    if element_expr is None or loop_var is None:
        return None
    return (element_expr, loop_var)


def _subst_genexpr_in_expr(expr: Expr, genexpr_map: dict) -> Expr:
    if not isinstance(expr, Expr):
        return expr

    if expr.kind == "call" and len(expr.args) >= 2:
        fn_e    = expr.args[0]
        iter_arg = expr.args[1]
        if (isinstance(fn_e, Expr)
                and fn_e.kind == "make_function"
                and isinstance(fn_e.value, int)
                and fn_e.value in genexpr_map):
            element_expr, loop_var = genexpr_map[fn_e.value]
            if isinstance(iter_arg, Expr) and iter_arg.kind == "iter" and iter_arg.args:
                actual_iterable = iter_arg.args[0]
            else:
                actual_iterable = iter_arg
            return Expr(
                kind="genexpr",
                args=(
                    element_expr,
                    Expr(kind="name", value=loop_var, origins=frozenset()),
                    actual_iterable,
                ),
                origins=expr.origins,
            )

    new_args = tuple(_subst_genexpr_in_expr(a, genexpr_map) for a in (expr.args or ()))
    if new_args != expr.args:
        return Expr(kind=expr.kind, value=expr.value, args=new_args, origins=expr.origins)
    return expr


def _subst_genexpr_in_stmt(st: Stmt, genexpr_map: dict) -> Stmt:
    if not isinstance(st, Stmt) or st.expr is None:
        return st
    new_expr = _subst_genexpr_in_expr(st.expr, genexpr_map)
    if new_expr is st.expr:
        return st
    return Stmt(kind=st.kind, target=st.target, expr=new_expr, extra=st.extra, origins=st.origins)


def _fix_genexpr_calls(children: list, stack_info: dict):
    genexpr_map = {}
    for i, ch in enumerate(children):
        info = _extract_genexpr_info(ch, i)
        if info is not None:
            genexpr_map[i] = info

    if not genexpr_map:
        return

    block_stmts = stack_info.get("block_statements") or {}
    for bid in list(block_stmts.keys()):
        stmts     = block_stmts[bid]
        new_stmts = []
        changed   = False
        for st in stmts:
            new_st = _subst_genexpr_in_stmt(st, genexpr_map)
            if new_st is not st:
                changed = True
            new_stmts.append(new_st)
        if changed:
            block_stmts[bid] = new_stmts
