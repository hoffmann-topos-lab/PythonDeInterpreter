from dataclasses import dataclass
from typing import Any, List, Dict, Optional, Tuple, Set

class StackValue:
    def __init__(self, origin):
        self.origin = origin  # instr offset ou PHI

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
    # Cria novo set local (não muta o set do chamador) para que nós irmãos
    # possam referenciar o mesmo objeto sem falso "<cycle>" (compartilhamento DAG).
    # Ciclos verdadeiros (nó que aparece em seu próprio ancestral) ainda são detectados.
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

        # --- Fase 1: attr, subscr, slice, unary, is, contains ---

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
            operand = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            op = str(e.value) if e.value else "?"
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

        # --- Fase 2: import ---

        if k == "import":
            return f"__import__({e.value!r})"

        if k == "import_from":
            module = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"{module}.{e.value}"

        # --- Fase 3: set, dict, fstring, format ---

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
            if spec:
                return f"format({inner}, {spec!r})"
            return f"format({inner})"

        # --- Fase 4: unpack, starred ---

        if k == "unpack":
            src = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"{src}[{e.value}]"

        if k == "starred":
            inner = expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)
            return f"*{inner}"

        # --- Fase 5: make_function, closure_var, genexpr ---

        if k == "make_function":
            return f"<function>"

        if k == "closure_var":
            return str(e.value)

        if k in ("genexpr", "listcomp", "setcomp", "dictcomp"):
            # Renderiza comprehension/genexpr com suporte a múltiplos for-clauses
            # args: (element, var, iterable, *extras)
            # extras pode conter Expr(kind="for_clause") e/ou condição
            elem_e = a[0] if len(a) > 0 else None
            var  = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            src  = expr_repr(a[2] if len(a) > 2 else None, _seen, _depth + 1, _max_depth)

            # Processa extras: for_clause e condição
            extra_fors = ""
            cond_str = ""
            for extra in a[3:]:
                if isinstance(extra, Expr) and extra.kind == "for_clause" and extra.args and len(extra.args) >= 2:
                    ev = expr_repr(extra.args[0], _seen, _depth + 1, _max_depth)
                    es = expr_repr(extra.args[1], _seen, _depth + 1, _max_depth)
                    extra_fors += f" for {ev} in {es}"
                elif extra is not None:
                    cond_str = f" if {expr_repr(extra, _seen, _depth + 1, _max_depth)}"

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

        # --- Fase 7: yield, await, aiter, anext ---

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

        # --- Fase 6: with ---

        if k == "with_enter":
            return expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)

        if k in ("with_exit", "with_cleanup", "async_with_exit", "async_with_enter"):
            return expr_repr(a[0] if len(a) > 0 else None, _seen, _depth + 1, _max_depth)

        # --- Fase 8: match ---

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

        # --- Fase 9: intrinsic ---

        if k == "intrinsic":
            # Python 3.12 CALL_INTRINSIC_1 mappings
            iid = e.value
            if iid == 4 and len(a) == 1:  # INTRINSIC_ASYNC_GEN_ASEND (transparent wrapper)
                return expr_repr(a[0], _seen, _depth + 1, _max_depth)
            if iid == 5 and len(a) == 1:  # INTRINSIC_UNARY_POSITIVE
                return f"(+{expr_repr(a[0], _seen, _depth + 1, _max_depth)})"
            if iid == 6 and len(a) == 1:  # INTRINSIC_LIST_TO_TUPLE
                return f"tuple({expr_repr(a[0], _seen, _depth + 1, _max_depth)})"
            inner = ", ".join(expr_repr(x, _seen, _depth + 1, _max_depth) for x in a)
            return f"intrinsic_{e.value}({inner})"

        # --- Fase 10: call_kw, call_ex, list_append, list_extend ---

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
                # Simplifica {**x} → x: BUILD_MAP 0 + DICT_MERGE gera dict-unpack trivial
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

        if k == "list_comp":
            # args: (element, iterable) ou (element, iterable, cond)
            # value: nome da variável de loop
            elem = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            var = str(e.value) if e.value else "_item"
            cond_str = ""
            if len(a) > 2 and a[2] is not None:
                cond_str = f" if {expr_repr(a[2], _seen, _depth + 1, _max_depth)}"
            return f"[{elem} for {var} in {it}{cond_str}]"

        if k == "set_comp":
            elem = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            var = str(e.value) if e.value else "_item"
            cond_str = ""
            if len(a) > 2 and a[2] is not None:
                cond_str = f" if {expr_repr(a[2], _seen, _depth + 1, _max_depth)}"
            return f"{{{elem} for {var} in {it}{cond_str}}}"

        if k == "dict_comp":
            key = expr_repr(a[0] if a else None, _seen, _depth + 1, _max_depth)
            val = expr_repr(a[1] if len(a) > 1 else None, _seen, _depth + 1, _max_depth)
            it = expr_repr(a[2] if len(a) > 2 else None, _seen, _depth + 1, _max_depth)
            var = str(e.value) if e.value else "_item"
            cond_str = ""
            if len(a) > 3 and a[3] is not None:
                cond_str = f" if {expr_repr(a[3], _seen, _depth + 1, _max_depth)}"
            return f"{{{key}: {val} for {var} in {it}{cond_str}}}"

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
        # RERAISE do bytecode
        return "raise"

    if s.kind == "del":
        return f"del {s.target}"

    # --- Fase 1: store_attr, del_attr, store_subscr, del_subscr ---

    if s.kind == "store_attr":
        return f"{s.extra}.{s.target} = {expr_repr(s.expr) if s.expr else 'None'}"

    if s.kind == "del_attr":
        return f"del {s.extra}.{s.target}"

    if s.kind == "store_subscr":
        return f"{s.target} = {expr_repr(s.expr) if s.expr else 'None'}"

    if s.kind == "del_subscr":
        return f"del {s.target}"

    # --- Fase 2: import, import_from, import_star ---

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

    # --- Fase 7: yield, yield_from ---

    if s.kind == "yield":
        return f"yield {expr_repr(s.expr)}" if s.expr else "yield"

    if s.kind == "yield_from":
        inner = f"yield from {expr_repr(s.expr)}" if s.expr else "yield from <?>"
        return f"{s.target} = {inner}" if s.target else inner

    if s.kind == "await":
        inner = f"await {expr_repr(s.expr)}" if s.expr else "await <?>"
        return f"{s.target} = {inner}" if s.target else inner

    if s.kind == "async_for_item":
        # Usado internamente por render_loop para reconstruir `async for var in iterable:`
        # Nunca deve ser emitido diretamente; render_loop extrai target/expr daqui.
        iterable = expr_repr(s.expr) if s.expr else "<?>"
        return f"{s.target} = await anext({iterable})" if s.target else f"await anext({iterable})"

    # --- Fase 10: with, async_with, assert, global, nonlocal ---

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
