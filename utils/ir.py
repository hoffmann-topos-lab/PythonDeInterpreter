from dataclasses import dataclass
from typing import Any, List, Dict, Optional, Tuple, Set

class StackValue:
    def __init__(self, origin):
        self.origin = origin 

    def __repr__(self):
        return f"V({self.origin})"


class PhiValue(StackValue):
    def __init__(self, sources):
        super().__init__("phi")
        self.sources = sources

    def __repr__(self):
        return f"PHI({self.sources})"


@dataclass(frozen=True)
class Expr:
    kind: str
    value: Any = None
    args: Tuple["Expr", ...] = ()
    origins: frozenset = frozenset()

@dataclass(frozen=True)
class Stmt:
    kind: str
    target: Optional[str] = None
    expr: Optional[Expr] = None
    extra: Any = None
    origins: frozenset = frozenset()


def _collect_compare_chain(e):
    def rec(x):
        if not isinstance(x, Expr):
            return None
        if x.kind == "compare" and len(x.args) == 2:
            return [(x.args[0], str(x.value) if x.value is not None else "?", x.args[1])]
        if x.kind == "binop" and x.value == "and" and len(x.args) == 2:
            L = rec(x.args[0])
            if L is None:
                return None
            R = rec(x.args[1])
            if R is None:
                return None
            return L + R
        return None

    chain = rec(e)
    if chain is None or len(chain) < 2:
        return None
    for i in range(len(chain) - 1):
        a_right = chain[i][2]
        b_left = chain[i + 1][0]
        if a_right is b_left:
            continue
        if isinstance(a_right, Expr) and isinstance(b_left, Expr):
            if expr_repr(a_right) == expr_repr(b_left):
                continue
        return None
    return chain


def expr_repr(e, _seen=None, _depth=0, _max_depth=50):
    if _seen is None:
        _seen = set()

    if e is None:
        return "<?>"
    if _depth > _max_depth:
        return "<...>"

    eid = id(e)
    if eid in _seen:
        return "<cycle>"
    _seen = _seen | {eid}

    if isinstance(e, (int, float, str, bool, type(None))):
        return repr(e)

    if isinstance(e, Expr):
        k = e.kind
        a = e.args or ()

        if k == "const":
            return repr(e.value)
        if k == "name":
            return str(e.value)
        if k == "unknown":
            return "<?>"

        if k == "phi":
            inner = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
            return f"phi({inner})"

        if k == "binop":
            sym = str(e.value) if e.value is not None else "?"
            if sym == "and" and len(a) == 2:
                chain = _collect_compare_chain(e)
                if chain is not None:
                    parts = [expr_repr(chain[0][0], _seen, _depth + 1, _max_depth)]
                    for (_L, op, R) in chain:
                        parts.append(op)
                        parts.append(expr_repr(R, _seen, _depth + 1, _max_depth))
                    return "(" + " ".join(parts) + ")"
            left = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            right = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            return f"({left} {sym} {right})"

        if k == "compare":
            op = str(e.value) if e.value is not None else "?"
            left = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            right = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            return f"({left} {op} {right})"

        if k == "call":
            fn = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            args = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a[1:])
            return f"{fn}({args})"

        if k == "iter":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"iter({inner})"

        if k == "next":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"next({inner})"

        if k == "list":
            elems = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
            return f"[{elems}]"

        if k == "tuple":
            elems = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
            if len(a) == 1:
                elems += ","
            return f"({elems})"

        if k == "attr":
            obj = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"{obj}.{e.value}"

        if k == "subscr":
            obj = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            key = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            return f"{obj}[{key}]"

        if k == "slice":
            def _sl(x):
                if isinstance(x, Expr) and x.kind == "const" and x.value is None:
                    return ""
                return expr_repr(x, _seen, _depth + 1, _max_depth)
            parts = [_sl(x) for x in a]
            return ":".join(parts)

        if k == "unary":
            op = str(e.value) if e.value else "?"
            operand_e = a[0] if len(a) > 0 else None
            if op == "not" and isinstance(operand_e, Expr) and operand_e.kind == "binop":
                inner_op = operand_e.value
                if inner_op in ("in", "is") and len(operand_e.args or ()) >= 2:
                    left = expr_repr(operand_e.args[0], _seen, _depth + 1, _max_depth)
                    right = expr_repr(operand_e.args[1], _seen, _depth + 1, _max_depth)
                    neg_op = "not in" if inner_op == "in" else "is not"
                    return f"({left} {neg_op} {right})"
            operand = expr_repr(operand_e, _seen, _depth + 1, _max_depth)
            if op == "not":
                return f"not {operand}"
            return f"({op}{operand})"

        if k == "is":
            left = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            right = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            op = "is not" if e.value else "is"
            return f"({left} {op} {right})"

        if k == "contains":
            left = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            right = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            op = "not in" if e.value else "in"
            return f"({left} {op} {right})"

        if k == "import":
            return f"__import__({e.value!r})"

        if k == "import_from":
            module = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"{module}.{e.value}"

        if k == "set":
            elems = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
            return f"{{{elems}}}"

        if k == "dict":
            pairs = []
            for idx in range(0, len(a), 2):
                key_e = a[idx] if idx < len(a) else None
                val_e = a[idx + 1] if idx + 1 < len(a) else None
                kk = expr_repr(key_e, _seen, _depth + 1, _max_depth)
                vv = expr_repr(val_e, _seen, _depth + 1, _max_depth)
                if isinstance(key_e, Expr) and key_e.kind == "const" and key_e.value is None and e.value == "unpack":
                    pairs.append(f"**{vv}")
                else:
                    pairs.append(f"{kk}: {vv}")
            return f"{{{', '.join(pairs)}}}"

        if k == "fstring":
            parts = []
            for x in a:
                if isinstance(x, Expr) and x.kind == "const" and isinstance(x.value, str):
                    parts.append(x.value.replace("{", "{{").replace("}", "}}"))
                elif isinstance(x, Expr) and x.kind == "format":
                    inner = expr_repr(x.args[0] if x.args else None, _seen, _depth + 1, _max_depth)
                    spec = x.value or ""
                    conv = ""
                    if x.args and len(x.args) > 1 and isinstance(x.args[1], Expr) and x.args[1].kind == "const":
                        cv = x.args[1].value
                        if cv == ord('s') or cv == 1: conv = "!s"
                        elif cv == ord('r') or cv == 2: conv = "!r"
                        elif cv == ord('a') or cv == 3: conv = "!a"
                    if spec:
                        parts.append(f"{{{inner}{conv}:{spec}}}")
                    else:
                        parts.append(f"{{{inner}{conv}}}")
                else:
                    parts.append(f"{{{expr_repr(x, _seen, _depth + 1, _max_depth)}}}")
            return 'f"' + "".join(parts) + '"'

        if k == "format":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            spec = e.value or ""
            conv = ""
            if a and len(a) > 1 and isinstance(a[1], Expr) and a[1].kind == "const":
                cv = a[1].value
                if cv == ord('s') or cv == 1: conv = "!s"
                elif cv == ord('r') or cv == 2: conv = "!r"
                elif cv == ord('a') or cv == 3: conv = "!a"
            if spec:
                return f'f"{{{inner}{conv}:{spec}}}"'
            return f'f"{{{inner}{conv}}}"'

        if k == "unpack":
            src = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"{src}[{e.value}]"

        if k == "starred":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"*{inner}"


        if k == "make_function":
            return f"<function>"

        if k == "closure_var":
            return str(e.value)

        if k in ("genexpr", "listcomp", "setcomp", "dictcomp"):
            elem_e = a[0] if len(a) > 0 else None
            var  = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            src  = expr_repr(a[2] if len(a) > 2 else None, _seen, _depth + 1, _max_depth)
            extra_fors = ""
            cond_str = ""
            for extra in a[3:]:
                if isinstance(extra, Expr) and extra.kind == "for_clause" and extra.args and len(extra.args) >= 2:
                    ev = expr_repr(extra.args[0], _seen, _depth + 1, _max_depth)
                    es = expr_repr(extra.args[1], _seen, _depth + 1, _max_depth)
                    extra_fors += f" for {ev} in {es}"
                elif extra is not None:
                    cond_str += f" if {expr_repr(extra, _seen, _depth + 1, _max_depth)}"

            clauses = f"for {var} in {src}{extra_fors}{cond_str}"

            if k == "genexpr":
                elem = expr_repr(elem_e, _seen, _depth + 1, _max_depth)
                return f"({elem} {clauses})"

            if k == "listcomp":
                elem = expr_repr(elem_e, _seen, _depth + 1, _max_depth)
                return f"[{elem} {clauses}]"

            if k == "setcomp":
                elem = expr_repr(elem_e, _seen, _depth + 1, _max_depth)
                return f"{{{elem} {clauses}}}"

            if k == "dictcomp":
                if isinstance(elem_e, Expr) and elem_e.kind == "pair" and len(elem_e.args) >= 2:
                    val = expr_repr(elem_e.args[0], _seen, _depth + 1, _max_depth)
                    key = expr_repr(elem_e.args[1], _seen, _depth + 1, _max_depth)
                    return f"{{{key}: {val} {clauses}}}"
                elem = expr_repr(elem_e, _seen, _depth + 1, _max_depth)
                return f"{{{elem} {clauses}}}"

        if k == "lambda":
            params = str(e.value) if e.value is not None else ""
            body = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            return f"lambda {params}: {body}"

        if k == "yield":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"(yield {inner})"

        if k == "yield_from":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"(yield from {inner})"

        if k == "await":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"(await {inner})"

        if k == "aiter":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"aiter({inner})"

        if k == "anext":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"anext({inner})"

        if k == "with_enter":
            return expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)

        if k in ("with_exit", "with_cleanup", "async_with_exit", "async_with_enter"):
            return expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)

        if k == "match_sequence":
            return f"isinstance({expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)}, Sequence)"

        if k == "match_mapping":
            return f"isinstance({expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)}, Mapping)"

        if k == "match_class":
            cls = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            return f"match_class({cls})"

        if k == "match_keys":
            return f"match_keys({', '.join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)})"

        if k == "get_len":
            return f"len({expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)})"

        if k == "intrinsic":

            iid = e.value
            if iid == 4 and len(a) == 1:  
                return expr_repr(a[0], _seen, _depth + 1, _max_depth)
            if iid == 5 and len(a) == 1: 
                return f"(+{expr_repr(a[0], _seen, _depth + 1, _max_depth)})"
            if iid == 6 and len(a) == 1:  
                inner = a[0]
                if isinstance(inner, Expr) and inner.kind == "list":
                    elems = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in inner.args)
                    if len(inner.args) == 1:
                        elems += ","
                    return f"({elems})"
                return f"tuple({expr_repr(inner, _seen, _depth + 1, _max_depth)})"
            inner = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
            return f"intrinsic_{e.value}({inner})"

        if k == "call_kw":
            fn = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            kw_expr = a[-1] if a else None
            pos_args = a[1:-1] if len(a) > 2 else ()
            parts = [expr_repr(x, _seen, _depth + 1, _max_depth) for x in pos_args]
            if isinstance(kw_expr, Expr) and kw_expr.kind == "kw_names" and isinstance(kw_expr.value, tuple):
                kw_names = kw_expr.value
                n_kw = len(kw_names)
                n_pos = len(parts) - n_kw
                positional = parts[:max(0, n_pos)]
                kw_vals = parts[max(0, n_pos):]
                kw_parts = [f"{kn}={kv}" for kn, kv in zip(kw_names, kw_vals)]
                all_parts = positional + kw_parts
            else:
                all_parts = parts
            return f"{fn}({', '.join(all_parts)})"

        if k == "call_ex":
            fn = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            args_t = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            if len(a) > 2:
                kw_arg = a[2]
                if (isinstance(kw_arg, Expr) and kw_arg.kind == "dict"
                        and getattr(kw_arg, "value", None) == "unpack"
                        and len(kw_arg.args or ()) == 2
                        and isinstance(kw_arg.args[0], Expr)
                        and kw_arg.args[0].kind == "const"
                        and kw_arg.args[0].value is None):
                    kwargs_t = expr_repr(kw_arg.args[1], _seen, _depth + 1, _max_depth)
                else:
                    kwargs_t = expr_repr(kw_arg, _seen, _depth + 1, _max_depth)
                return f"{fn}(*{args_t}, **{kwargs_t})"
            return f"{fn}(*{args_t})"

        if k == "ternary":
            cond = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            then_v = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            else_v = expr_repr(a[2] if len(a) > 2 else None, _seen, _depth + 1, _max_depth)
            return f"({then_v} if {cond} else {else_v})"

        if k == "walrus":
            inner = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            return f"({e.value} := {inner})"

        if k == "list_comp":
            elem = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            var = str(e.value) if e.value else "_item"
            for_kw = "for"
            if var.startswith("async "):
                for_kw = "async for"
                var = var[len("async "):]
            cond_str = ""
            if len(a) > 2 and a[2] is not None:
                cond_str = f" if {expr_repr(a[2], _seen, _depth + 1, _max_depth)}"
            return f"[{elem} {for_kw} {var} in {it}{cond_str}]"

        if k == "set_comp":
            elem = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            var = str(e.value) if e.value else "_item"
            for_kw = "for"
            if var.startswith("async "):
                for_kw = "async for"
                var = var[len("async "):]
            cond_str = ""
            if len(a) > 2 and a[2] is not None:
                cond_str = f" if {expr_repr(a[2], _seen, _depth + 1, _max_depth)}"
            return f"{{{elem} {for_kw} {var} in {it}{cond_str}}}"

        if k == "dict_comp":
            key = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            val = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[2] if len(a) > 2 else None, _seen, _depth + 1, _max_depth)
            var = str(e.value) if e.value else "_item"
            for_kw = "for"
            if var.startswith("async "):
                for_kw = "async for"
                var = var[len("async "):]
            cond_str = ""
            if len(a) > 3 and a[3] is not None:
                cond_str = f" if {expr_repr(a[3], _seen, _depth + 1, _max_depth)}"
            return f"{{{key}: {val} {for_kw} {var} in {it}{cond_str}}}"

        if k == "list_append":
            lst = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            item = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            return f"{lst}.append({item})"

        if k == "list_extend":
            lst = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            return f"[*{lst}, *{it}]"

        if k == "yield_from_iter":
            inner = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            return f"(yield from {inner})"

        if k == "exc_group_match":
            return "<exc_group_match>"

        if k == "exc_group_remaining":
            return "<exc_group_remaining>"

        if k == "return_value":
            inner = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            return f"return({inner})"

        if k == "null":
            return "<null>"

        if k == "exc":
            return f"<exc:{e.value}>"

        if k == "exc_match":
            return "<exc_match>"

        if k == "kw_names":
            return f"<kw_names:{e.value}>"

        if k == "kwarg":
            val = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            name = e.value if e.value else "?"
            return f"{name}={val}"

        if k == "double_starred":
            inner = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            return f"**{inner}"

        inner = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
        return f"{k}({inner})" if inner else f"{k}"

    if isinstance(e, dict):
        t = e.get("type")
        args = e.get("args", [])
        if not isinstance(args, (list, tuple)):
            args = [args]
        inner = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in args)
        return f"{t}({inner})" if t else f"Expr({inner})"

    t = getattr(e, "type", None) or getattr(e, "kind", None) or e.__class__.__name__
    args = getattr(e, "args", None)
    if args is None:
        val = getattr(e, "value", None)
        if val is not None and val is not e:
            return f"{t}({expr_repr(val, _seen, _depth + 1, _max_depth)})"
        return f"{t}"
    if not isinstance(args, (list, tuple)):
        args = [args]
    inner = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in args)
    return f"{t}({inner})"

def stmt_repr(s: Stmt) -> str:
    if s.kind == "assign":
        return f"{s.target} = {expr_repr(s.expr) if s.expr else 'None'}"

    if s.kind == "augassign":
        op = s.extra or "+="
        return f"{s.target} {op} {expr_repr(s.expr) if s.expr else '<?>'}"

    if s.kind == "expr":
        if isinstance(s.expr, Expr) and s.expr.kind == "yield":
            inner = expr_repr(s.expr.args[0] if s.expr.args else None)
            return f"yield {inner}" if s.expr.args else "yield"
        if isinstance(s.expr, Expr) and s.expr.kind == "yield_from":
            inner = expr_repr(s.expr.args[0] if s.expr.args else None)
            return f"yield from {inner}" if s.expr.args else "yield from <?>"
        return expr_repr(s.expr) if s.expr else "pass"

    if s.kind == "return":
        return f"return {expr_repr(s.expr)}" if s.expr else "return"

    if s.kind == "raise":
        if s.expr is None:
            return "raise"
        if s.extra is not None:
            cause = expr_repr(s.extra) if isinstance(s.extra, Expr) else str(s.extra)
            return f"raise {expr_repr(s.expr)} from {cause}"
        return f"raise {expr_repr(s.expr)}"

    if s.kind == "reraise":
        return "raise"

    if s.kind == "del":
        return f"del {s.target}"

    if s.kind == "store_attr":
        return f"{s.extra}.{s.target} = {expr_repr(s.expr) if s.expr else 'None'}"

    if s.kind == "del_attr":
        return f"del {s.extra}.{s.target}"

    if s.kind == "store_subscr":
        return f"{s.target} = {expr_repr(s.expr) if s.expr else 'None'}"

    if s.kind == "del_subscr":
        return f"del {s.target}"

    if s.kind == "import":
        module = s.extra if isinstance(s.extra, str) else str(s.extra)
        if module and module != s.target:
            return f"import {module} as {s.target}"
        return f"import {s.target}"

    if s.kind == "import_from":
        if isinstance(s.extra, dict):
            module = s.extra.get("module", "?")
            names = s.extra.get("names", [])
            parts = []
            for item in names:
                if isinstance(item, tuple) and len(item) == 2:
                    name, alias = item
                    parts.append(f"{name} as {alias}" if alias and alias != name else str(name))
                else:
                    parts.append(str(item))
            return f"from {module} import {', '.join(parts)}"
        return f"from ? import {s.target}"

    if s.kind == "import_star":
        return f"from {s.target} import *"

    if s.kind == "yield":
        return f"yield {expr_repr(s.expr)}" if s.expr else "yield"

    if s.kind == "yield_from":
        inner = f"yield from {expr_repr(s.expr)}" if s.expr else "yield from <?>"
        return f"{s.target} = {inner}" if s.target else inner

    if s.kind == "await":
        inner = f"await {expr_repr(s.expr)}" if s.expr else "await <?>"
        return f"{s.target} = {inner}" if s.target else inner

    if s.kind == "async_for_item":
        iterable = expr_repr(s.expr) if s.expr else "<?>"
        return f"{s.target} = await anext({iterable})" if s.target else f"await anext({iterable})"

    if s.kind == "with":
        ctx = expr_repr(s.expr) if s.expr else "<?>"
        if s.target:
            return f"with {ctx} as {s.target}:"
        return f"with {ctx}:"

    if s.kind == "async_with":
        ctx = expr_repr(s.expr) if s.expr else "<?>"
        if s.target:
            return f"async with {ctx} as {s.target}:"
        return f"async with {ctx}:"

    if s.kind == "assert":
        test = expr_repr(s.expr) if s.expr else "True"
        if s.extra:
            msg = expr_repr(s.extra) if isinstance(s.extra, Expr) else repr(s.extra)
            return f"assert {test}, {msg}"
        return f"assert {test}"

    if s.kind == "global":
        return f"global {s.target}"

    if s.kind == "nonlocal":
        return f"nonlocal {s.target}"

    if s.kind == "store_comp":
        return f"<store_comp>({expr_repr(s.expr) if s.expr else '?'})"

    return "pass"
