import types
from typing import Dict, Any, List

from disasm import parse_instructions
from utils.cfg import build_basic_blocks, build_cfg
from stack_sim import simulate_stack
from patterns import detect_high_level_patterns
from utils.ast_recover import build_recovered_ast
from utils.ir import Expr, Stmt

def extract_code_objects(code_obj, depth=0, debug=False):
    instructions = parse_instructions(code_obj, debug=False)


    blocks = build_basic_blocks(instructions, code_obj=code_obj, debug=False)

    cfg = build_cfg(blocks, instructions, code_obj, debug=False)
    stack_info = simulate_stack(blocks, cfg, instructions, code_obj, debug=False)

    patterns = detect_high_level_patterns(
        blocks=blocks, cfg=cfg, stack_info=stack_info, code_obj=code_obj, debug=False
    )

    recovered_ast = build_recovered_ast(
        blocks=blocks, cfg=cfg, stack_info=stack_info, patterns=patterns, code_obj=code_obj, debug=False
    )

    children = []
    for const in code_obj.co_consts:
        if isinstance(const, types.CodeType):
            children.append(extract_code_objects(const, depth=depth + 1, debug=False))


    _attach_defaults_to_children(children, stack_info)
    _fix_genexpr_calls(children, stack_info)
    _fix_lambda_calls(children, stack_info)

    return {
        "name": code_obj.co_name,
        "recovered_ast": recovered_ast,
        "stack_info": stack_info,
        "children": children,
        "code_obj": code_obj,
        "co_flags": code_obj.co_flags,
    }


def _attach_defaults_to_children(children, stack_info):
    """Percorre os statements do pai para encontrar MAKE_FUNCTION e associar defaults/kwdefaults."""
    if not children:
        return

    child_by_name = {}
    for ch in children:
        name = ch.get("name")
        if name:
            child_by_name.setdefault(name, []).append(ch)

    block_stmts = stack_info.get("block_statements") or {}
    for bid, stmts in block_stmts.items():
        for st in stmts:
            if not (isinstance(st, Stmt) and st.kind == "assign" and isinstance(st.expr, Expr)):
                continue
            if st.expr.kind != "make_function":
                continue

            target_name = st.target
            if target_name not in child_by_name:
                continue

            args = st.expr.args or ()
            # args = (code, defaults, kwdefaults, annotations) from stack_sim
            defaults_expr = args[1] if len(args) > 1 else None
            kwdefaults_expr = args[2] if len(args) > 2 else None
            annotations_expr = args[3] if len(args) > 3 else None

            # Associa ao primeiro filho com esse nome que ainda não tem defaults
            for ch in child_by_name[target_name]:
                if "defaults" not in ch:
                    ch["defaults"] = defaults_expr
                    ch["kwdefaults"] = kwdefaults_expr
                    ch["annotations"] = annotations_expr
                    break


def _extract_genexpr_info(child):

    code_obj = child.get("code_obj")
    if not (isinstance(code_obj, types.CodeType) and code_obj.co_name == "<genexpr>"):
        return None
    stack_info = child.get("stack_info") or {}
    block_stmts = stack_info.get("block_statements") or {}
    block_conds = stack_info.get("block_conditions") or {}

    element_expr = None
    loop_var = None
    tuple_unpack = {}

    yield_bids = set()
    for _bid, stmts in block_stmts.items():
        for st in stmts:
            if not isinstance(st, Stmt):
                continue
            if st.kind == "expr" and isinstance(st.expr, Expr) and st.expr.kind == "yield":
                yield_bids.add(_bid)
                if element_expr is None and st.expr.args:
                    element_expr = st.expr.args[0]
            if st.kind == "assign" and isinstance(st.expr, Expr) and st.expr.kind == "next":
                if loop_var is None:
                    loop_var = st.target
            if (st.kind == "assign" and isinstance(st.expr, Expr)
                    and st.expr.kind == "unpack" and st.expr.args
                    and isinstance(st.expr.value, int)):
                obj_e = st.expr.args[0]
                if isinstance(obj_e, Expr) and obj_e.kind == "next":
                    tuple_unpack.setdefault(st.expr.value, st.target)


    if tuple_unpack and all(i in tuple_unpack for i in range(len(tuple_unpack))):
        names = [tuple_unpack[i] for i in range(len(tuple_unpack))]
        loop_var = Expr(
            kind="tuple",
            args=tuple(Expr(kind="name", value=n, origins=frozenset()) for n in names),
            origins=frozenset(),
        )

    if element_expr is None or loop_var is None:
        return None

    filter_exprs = []
    for _bid in sorted(block_conds.keys()):
        if _bid in yield_bids:
            continue
        for _c in block_conds.get(_bid, ()):
            if isinstance(_c, Expr):
                filter_exprs.append(_c)

    return (element_expr, loop_var, filter_exprs)


def _subst_genexpr_in_expr(expr, genexpr_map):

    if not isinstance(expr, Expr):
        return expr

    if expr.kind == "call" and len(expr.args) >= 2:
        fn_e = expr.args[0]
        iter_arg = expr.args[1]
        if (isinstance(fn_e, Expr) and fn_e.kind == "make_function"
                and fn_e.args
                and isinstance(fn_e.args[0], Expr)
                and fn_e.args[0].kind == "const"):
            code_id = id(fn_e.args[0].value)
            if code_id in genexpr_map:
                element_expr, loop_var, filter_exprs = genexpr_map[code_id]
                if isinstance(iter_arg, Expr) and iter_arg.kind == "iter" and iter_arg.args:
                    actual_iterable = iter_arg.args[0]
                else:
                    actual_iterable = iter_arg
                if isinstance(loop_var, Expr):
                    var_expr = loop_var
                else:
                    var_expr = Expr(kind="name", value=loop_var, origins=frozenset())
                gx_args = [
                    element_expr,
                    var_expr,
                    actual_iterable,
                ]

                gx_args.extend(filter_exprs)
                return Expr(
                    kind="genexpr",
                    args=tuple(gx_args),
                    origins=expr.origins,
                )

    new_args = tuple(_subst_genexpr_in_expr(a, genexpr_map) for a in (expr.args or ()))
    if new_args != expr.args:
        return Expr(kind=expr.kind, value=expr.value, args=new_args, origins=expr.origins)
    return expr


def _subst_genexpr_in_stmt(st, genexpr_map):
    if not isinstance(st, Stmt) or st.expr is None:
        return st
    new_expr = _subst_genexpr_in_expr(st.expr, genexpr_map)
    if new_expr is st.expr:
        return st
    return Stmt(kind=st.kind, target=st.target, expr=new_expr, extra=st.extra, origins=st.origins)


def _extract_lambda_info(child):
    """Extrai (params_str, body_expr) de um child cujo co_name é '<lambda>'."""
    code_obj = child.get("code_obj")
    if not (isinstance(code_obj, types.CodeType) and code_obj.co_name == "<lambda>"):
        return None

    argc = code_obj.co_argcount or 0
    posonly = code_obj.co_posonlyargcount or 0
    kwonly = code_obj.co_kwonlyargcount or 0
    flags = code_obj.co_flags
    varnames = list(code_obj.co_varnames)
    has_varargs = bool(flags & 0x04)
    has_varkw = bool(flags & 0x08)

    parts = []
    for i, name in enumerate(varnames[:argc]):
        parts.append(name)
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
            parts.append(varnames[idx])
    if has_varkw:
        kw_idx = argc + kwonly + (1 if has_varargs else 0)
        kw_name = varnames[kw_idx] if kw_idx < len(varnames) else "kwargs"
        parts.append(f"**{kw_name}")
    params_str = ", ".join(parts)

    stack_info = child.get("stack_info") or {}
    block_stmts = stack_info.get("block_statements") or {}

    body_expr = None
    for _bid, stmts in block_stmts.items():
        for st in stmts:
            if isinstance(st, Stmt) and st.kind == "return" and st.expr is not None:
                body_expr = st.expr
                break
        if body_expr is not None:
            break

    if body_expr is None:
        return None
    return (params_str, body_expr)


def _subst_lambda_in_expr(expr, lambda_map):

    if not isinstance(expr, Expr):
        return expr

    if (expr.kind == "make_function"
            and expr.args
            and isinstance(expr.args[0], Expr)
            and expr.args[0].kind == "const"):
        code_id = id(expr.args[0].value)
        if code_id in lambda_map:
            params_str, body_expr = lambda_map[code_id]
            return Expr(kind="lambda", value=params_str, args=(body_expr,), origins=expr.origins)

    new_args = tuple(_subst_lambda_in_expr(a, lambda_map) for a in (expr.args or ()))
    if new_args != expr.args:
        return Expr(kind=expr.kind, value=expr.value, args=new_args, origins=expr.origins)
    return expr


def _subst_lambda_in_stmt(st, lambda_map):
    if not isinstance(st, Stmt) or st.expr is None:
        return st
    new_expr = _subst_lambda_in_expr(st.expr, lambda_map)
    if new_expr is st.expr:
        return st
    return Stmt(kind=st.kind, target=st.target, expr=new_expr, extra=st.extra, origins=st.origins)


def _fix_lambda_calls(children, stack_info):
    lambda_map = {}
    for ch in children:
        info = _extract_lambda_info(ch)
        if info is not None:
            code_obj = ch.get("code_obj")
            if code_obj is not None:
                lambda_map[id(code_obj)] = info

    if not lambda_map:
        return

    block_stmts = stack_info.get("block_statements") or {}
    for bid in list(block_stmts.keys()):
        stmts = block_stmts[bid]
        new_stmts = []
        changed = False
        for st in stmts:
            new_st = _subst_lambda_in_stmt(st, lambda_map)
            if new_st is not st:
                changed = True
            new_stmts.append(new_st)
        if changed:
            block_stmts[bid] = new_stmts


def _fix_genexpr_calls(children, stack_info):
    genexpr_map = {}
    for ch in children:
        info = _extract_genexpr_info(ch)
        if info is not None:
            code_obj = ch.get("code_obj")
            if code_obj is not None:
                genexpr_map[id(code_obj)] = info

    if not genexpr_map:
        return

    block_stmts = stack_info.get("block_statements") or {}
    for bid in list(block_stmts.keys()):
        stmts = block_stmts[bid]
        new_stmts = []
        changed = False
        for st in stmts:
            new_st = _subst_genexpr_in_stmt(st, genexpr_map)
            if new_st is not st:
                changed = True
            new_stmts.append(new_st)
        if changed:
            block_stmts[bid] = new_stmts
