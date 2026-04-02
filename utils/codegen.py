import re
from typing import Dict, List, Any
from utils.ir import Expr, Stmt, expr_repr, stmt_repr
from utils.block_utils import (
    get_stack_info, get_block_statements, get_block_condition,
    get_in_stack, get_out_stack,
)


def _group_from_imports(import_lines):
    """Agrupa 'from X import Y' consecutivos do mesmo módulo."""
    grouped = []
    pending_module = None
    pending_names = []

    _from_re = re.compile(r"^from\s+(\S+)\s+import\s+(.+)$")

    def flush():
        nonlocal pending_module, pending_names
        if pending_module and pending_names:
            grouped.append(f"from {pending_module} import {', '.join(pending_names)}")
        pending_module = None
        pending_names = []

    for line in import_lines:
        m = _from_re.match(line)
        if m:
            mod = m.group(1)
            names_part = m.group(2)
            names = [n.strip() for n in names_part.split(",")]
            if mod == pending_module:
                pending_names.extend(names)
            else:
                flush()
                pending_module = mod
                pending_names = list(names)
        else:
            flush()
            grouped.append(line)

    flush()
    return grouped


def generate_python_code(tree, debug=True):
    IND = " " * 4

    def emit(lines, s, level=0):
        lines.append(f"{IND*level}{s}")

    def find_structs(ra, t):
        return [s for s in ra.get("structures", []) if s.get("type") == t]

    def basic_block_order(ra):
        bbs = ra.get("basic_blocks") or []
        pairs = []
        for bb in bbs:
            if isinstance(bb, dict) and bb.get("type") == "BasicBlock":
                pairs.append((bb.get("start", 10**18), bb.get("id")))
        pairs.sort()
        order = [bid for _, bid in pairs if bid is not None]
        start_by = {bid: off for off, bid in pairs}
        return order, start_by

    def block_opnames(ra, bid):
        for bb in (ra.get("basic_blocks") or []):
            if bb.get("type") == "BasicBlock" and bb.get("id") == bid:
                return bb.get("opnames") or []
        return []

    def _extract_defaults(node):
        """Extrai defaults e kwdefaults do nó (preenchidos pelo extract.py)."""
        pos_defaults = []
        kw_defaults = {}

        defaults_expr = node.get("defaults")
        if isinstance(defaults_expr, Expr):
            if defaults_expr.kind == "const" and isinstance(defaults_expr.value, tuple):
                pos_defaults = list(defaults_expr.value)
            elif defaults_expr.kind == "tuple":
                for a in (defaults_expr.args or ()):
                    if isinstance(a, Expr) and a.kind == "const":
                        pos_defaults.append(a.value)
                    else:
                        pos_defaults.append(expr_repr(a))

        kwdefaults_expr = node.get("kwdefaults")
        if isinstance(kwdefaults_expr, Expr):
            if kwdefaults_expr.kind == "const" and isinstance(kwdefaults_expr.value, dict):
                kw_defaults = dict(kwdefaults_expr.value)
            elif kwdefaults_expr.kind == "dict":
                args = kwdefaults_expr.args or ()
                for idx in range(0, len(args), 2):
                    key_e = args[idx] if idx < len(args) else None
                    val_e = args[idx + 1] if idx + 1 < len(args) else None
                    if isinstance(key_e, Expr) and key_e.kind == "const":
                        k = key_e.value
                    else:
                        continue
                    if isinstance(val_e, Expr) and val_e.kind == "const":
                        kw_defaults[k] = val_e.value
                    else:
                        kw_defaults[k] = expr_repr(val_e)

        return pos_defaults, kw_defaults

    def _extract_annotations(node):
        """Parseia a tuple de annotations em dict {param: 'type_str', 'return': 'type_str'}."""
        result = {}
        ann_expr = node.get("annotations")
        if not isinstance(ann_expr, Expr):
            return result
        items = None
        if ann_expr.kind == "tuple":
            items = ann_expr.args or ()
        elif ann_expr.kind == "const" and isinstance(ann_expr.value, tuple):
            # fallback: tuple de constantes (raro)
            flat = ann_expr.value
            i = 0
            while i + 1 < len(flat):
                k, v = flat[i], flat[i + 1]
                if isinstance(k, str):
                    result[k] = repr(v)
                i += 2
            return result
        if items is None:
            return result
        # Formato: ('param', type_expr, 'param', type_expr, ..., 'return', type_expr)
        i = 0
        while i + 1 < len(items):
            key_e = items[i]
            val_e = items[i + 1]
            if isinstance(key_e, Expr) and key_e.kind == "const" and isinstance(key_e.value, str):
                result[key_e.value] = expr_repr(val_e)
            i += 2
        return result

    def pick_arg_signature(node, ra, annotations=None):
        co = node.get("code_obj")
        if co is None:
            argc = ra.get("argcount", 0) or 0
            return ", ".join(f"arg{i}" for i in range(argc))

        argc = co.co_argcount or 0
        posonly = co.co_posonlyargcount or 0
        kwonly = co.co_kwonlyargcount or 0
        flags = co.co_flags
        varnames = list(co.co_varnames)

        has_varargs = bool(flags & 0x04)   # CO_VARARGS
        has_varkw = bool(flags & 0x08)     # CO_VARKEYWORDS

        pos_defaults, kw_defaults = _extract_defaults(node)
        ann = annotations or {}

        def _param(name, default=None):
            """Formata um parâmetro com anotação e/ou default opcionais."""
            ann_txt = f": {ann[name]}" if name in ann else ""
            if default is not None:
                sep = " = " if ann_txt else "="
                return f"{name}{ann_txt}{sep}{default!r}"
            return f"{name}{ann_txt}"

        parts = []

        # Argumentos posicionais (com defaults para os últimos N)
        pos_args = varnames[:argc]
        n_defaults = len(pos_defaults)
        first_default_idx = argc - n_defaults  # defaults aplicam-se aos últimos N args
        for i, name in enumerate(pos_args):
            if i >= first_default_idx and n_defaults > 0:
                default_val = pos_defaults[i - first_default_idx]
                parts.append(_param(name, default_val))
            else:
                parts.append(_param(name))
            if posonly > 0 and i == posonly - 1:
                parts.append("/")

        # *args ou separador *
        if has_varargs:
            va_idx = argc + kwonly
            va_name = varnames[va_idx] if va_idx < len(varnames) else "args"
            parts.append(f"*{va_name}")
        elif kwonly > 0:
            parts.append("*")

        # Keyword-only args (com kwdefaults)
        for i in range(kwonly):
            idx = argc + i
            if idx < len(varnames):
                kw_name = varnames[idx]
                if kw_name in kw_defaults:
                    parts.append(_param(kw_name, kw_defaults[kw_name]))
                else:
                    parts.append(_param(kw_name))

        # **kwargs
        if has_varkw:
            kw_idx = argc + kwonly + (1 if has_varargs else 0)
            kw_name = varnames[kw_idx] if kw_idx < len(varnames) else "kwargs"
            parts.append(f"**{kw_name}")

        return ", ".join(parts)

    def is_plumbing_stmt_text(s: str, in_except=False, exc_var=None, in_finally=False):
        t = s.replace(" ", "")
        if t in ("pass", ""):
            return True
        if exc_var:
            if t in (f"{exc_var}=None",):
                return True
            if t in (f"del{exc_var}", f"del({exc_var})"):
                return True
            if t in (f"{exc_var}=exc", f"{exc_var}=exc_info", f"{exc_var}=<exc:exc>"):
                return True
        if "(None,None,None)" in t:
            return True
        return False

    def _get_unpack_info(st):
        """Retorna (seq_repr, idx, is_starred, target) para assigns de unpack, ou None."""
        if not (isinstance(st, Stmt) and st.kind == "assign"):
            return None
        e = st.expr
        if isinstance(e, Expr) and e.kind == "unpack":
            seq = e.args[0] if e.args else None
            return (expr_repr(seq), e.value, False, st.target)
        if isinstance(e, Expr) and e.kind == "starred":
            inner = e.args[0] if e.args else None
            if isinstance(inner, Expr) and inner.kind == "unpack":
                seq = inner.args[0] if inner.args else None
                return (expr_repr(seq), inner.value, True, st.target)
        return None

    def emit_statements(lines, stmts, level, in_finally=False, in_except=False, exc_var=None,
                         suppress_with_as=None):
        wrote = False
        i = 0
        while i < len(stmts):
            st = stmts[i]

            if isinstance(st, Stmt) and st.kind == "reraise":
                i += 1
                continue

            if isinstance(st, Stmt) and st.kind == "expr" and isinstance(st.expr, Expr):
                if st.expr.kind in ("phi", "unknown", "yield_from_iter"):
                    i += 1
                    continue
                if st.expr.kind in ("name", "global_name"):
                    i += 1
                    continue
                # Suprime None espúrio de handler cleanup (LOAD_CONST_NONE → POP_TOP)
                if st.expr.kind == "const" and st.expr.value is None:
                    i += 1
                    continue
            if isinstance(st, Stmt) and st.kind == "async_for_item":
                i += 1
                continue

            if suppress_with_as and isinstance(st, Stmt) and st.kind == "assign":
                if st.target == suppress_with_as and isinstance(st.expr, Expr) and st.expr.kind == "with_enter":
                    i += 1
                    continue

            if isinstance(st, Stmt) and st.kind == "assign" and isinstance(st.expr, Expr):
                if st.expr.kind in ("const", "name", "global_name"):
                    rhs_repr = expr_repr(st.expr)
                    j = i + 1
                    chain = [st.target]
                    while j < len(stmts):
                        nxt = stmts[j]
                        if not (isinstance(nxt, Stmt) and nxt.kind == "assign" and isinstance(nxt.expr, Expr)):
                            break
                        if nxt.expr.kind not in ("const", "name", "global_name"):
                            break
                        if expr_repr(nxt.expr) != rhs_repr:
                            break
                        chain.append(nxt.target)
                        j += 1
                    if j > i + 1:
                        lhs = " = ".join(chain)
                        emit(lines, f"{lhs} = {rhs_repr}", level)
                        wrote = True
                        i = j
                        continue

            ui = _get_unpack_info(st)
            if ui is not None and ui[1] == 0:
                seq_repr_0, _, _, target_0 = ui
                targets = [None] * 1  # será expandido
                targets[0] = (target_0, ui[2])  # (nome, is_starred)
                j = i + 1
                next_idx = 1
                while j < len(stmts):
                    uj = _get_unpack_info(stmts[j])
                    if uj is None or uj[0] != seq_repr_0 or uj[1] != next_idx:
                        break
                    targets.append((uj[3], uj[2]))
                    next_idx += 1
                    j += 1
                if j > i + 1:
                    lhs_parts = []
                    for (tgt, starred) in targets:
                        lhs_parts.append(f"*{tgt}" if starred else tgt)
                    lhs = ", ".join(lhs_parts)
                    emit(lines, f"{lhs} = {seq_repr_0}", level)
                    wrote = True
                    i = j
                    continue

            s = stmt_repr(st).strip()
            if not s:
                i += 1
                continue

            if is_plumbing_stmt_text(s, in_except=in_except, exc_var=exc_var, in_finally=in_finally):
                i += 1
                continue

            if in_finally and getattr(st, "kind", None) == "return":
                if isinstance(st.expr, Expr) and st.expr.kind == "const" and st.expr.value is None:
                    i += 1
                    continue
                has_non_return = any(
                    getattr(s, "kind", None) not in ("return", "reraise")
                    for s in stmts
                )
                if has_non_return:
                    i += 1
                    continue

            emit(lines, s, level)
            wrote = True
            i += 1

        return wrote

    def render_code_object(node):
        ra = node.get("recovered_ast") or {}
        name = node.get("name", "<unknown>")

        if debug:
            structures = ra.get("structures", [])
            basic_blocks = ra.get("basic_blocks", [])
            print(f"[DEBUG] generate_python_code: render {name} | structures={len(structures)} basic_blocks={len(basic_blocks)}")

        if name == "<module>":
            out = ["# recovered from bytecode (heuristic)", ""]

            cls_defs = find_structs(ra, "ClassDef")
            cls_by_name = {c["name"]: c for c in cls_defs}

            child_names = {ch.get("name") for ch in node.get("children", [])}
            order_mod, start_by_mod = basic_block_order(ra)
            import_lines = []   # import / from X import Y
            global_lines = []   # COUNTER = 0, NAME = 'test', etc.
            entry_lines = []    # print(...), func calls, etc.

            # Detecta loops no módulo para renderizar for/while
            loops_mod = find_structs(ra, "Loop")
            loop_by_header_mod = {}
            for lp in loops_mod:
                h = lp.get("header")
                if h is not None:
                    loop_by_header_mod[h] = lp
            visited_mod = set()

            def _mod_stmt_skip(st):
                """True se o stmt deve ser ignorado no módulo."""
                if isinstance(st, Stmt) and st.kind == "assign":
                    if st.target in child_names:
                        return True
                    if isinstance(st.expr, Expr) and st.expr.kind == "make_function":
                        return True
                    if isinstance(st.expr, Expr) and st.expr.kind in ("call", "call_kw") and st.expr.args:
                        fn = st.expr.args[0]
                        if isinstance(fn, Expr) and fn.kind == "name" and fn.value == "__build_class__":
                            return True
                if isinstance(st, Stmt) and st.kind == "expr":
                    if isinstance(st.expr, Expr) and st.expr.kind in ("import", "import_from"):
                        return True
                return False

            def _mod_classify(st, s):
                """Classifica stmt para import_lines, global_lines ou entry_lines."""
                if isinstance(st, Stmt) and st.kind in ("import", "import_from", "import_star"):
                    import_lines.append(s)
                elif isinstance(st, Stmt) and st.kind == "assign":
                    if isinstance(st.expr, Expr) and st.expr.kind in ("call", "call_kw", "call_ex"):
                        entry_lines.append(s)
                    else:
                        global_lines.append(s)
                else:
                    entry_lines.append(s)

            for bid in order_mod:
                if bid in visited_mod:
                    continue

                # Renderiza loop (for/while) no módulo
                if bid in loop_by_header_mod:
                    lp = loop_by_header_mod[bid]
                    ops = block_opnames(ra, bid)
                    in_st = get_in_stack(node, bid)
                    header_iter = in_st[-1] if in_st else None
                    is_for = ("FOR_ITER" in ops) and isinstance(header_iter, Expr) and header_iter.kind == "iter"

                    body_bids = sorted(
                        [b for b in (lp.get("body_blocks") or []) if b != bid],
                        key=lambda b: start_by_mod.get(b, 10**18),
                    )

                    if is_for:
                        iter_txt = expr_repr(header_iter.args[0]) if header_iter and header_iter.args else "<?>"
                        loop_var = "item"
                        if body_bids:
                            stmts0 = get_block_statements(node, body_bids[0]) or []
                            for st in stmts0:
                                if (isinstance(st, Stmt) and st.kind == "assign"
                                        and isinstance(st.expr, Expr) and st.expr.kind == "next"):
                                    loop_var = st.target or loop_var
                                    break
                        entry_lines.append(f"for {loop_var} in {iter_txt}:")
                    else:
                        # while loop — emite condição se houver
                        cond = get_block_condition(node, bid, 0)
                        cond_txt = expr_repr(cond) if cond else "True"
                        entry_lines.append(f"while {cond_txt}:")

                    for body_bid in body_bids:
                        body_stmts = get_block_statements(node, body_bid) or []
                        for st in body_stmts:
                            if _mod_stmt_skip(st):
                                continue
                            # Suprime atribuição do loop var (já no header for)
                            if (is_for and isinstance(st, Stmt) and st.kind == "assign"
                                    and isinstance(st.expr, Expr) and st.expr.kind == "next"):
                                continue
                            s = stmt_repr(st).strip()
                            if s and s != "pass" and not s.startswith("return"):
                                entry_lines.append(f"{IND}{s}")
                        visited_mod.add(body_bid)

                    visited_mod.add(bid)
                    continue

                stmts = get_block_statements(node, bid)
                if not stmts:
                    continue
                for st in stmts:
                    if _mod_stmt_skip(st):
                        continue

                    s = stmt_repr(st).strip()
                    if not s or s == "pass" or s.startswith("return"):
                        continue

                    _mod_classify(st, s)

            grouped_imports = _group_from_imports(import_lines)
            for line in grouped_imports:
                out.append(line)

            if grouped_imports and global_lines:
                out.append("")
            for line in global_lines:
                out.append(line)

            if grouped_imports or global_lines:
                out.append("")

            mod_func_decos = {}
            for fd in find_structs(ra, "FuncDecorators"):
                for fname, deco_list in (fd.get("decorators") or {}).items():
                    mod_func_decos.setdefault(fname, []).extend(deco_list)
            mod_deco_idx = {}

            for ch in node.get("children", []):
                ch_name = ch.get("name", "")
                if ch_name in cls_by_name:
                    cls = cls_by_name[ch_name]
                    decorators = cls.get("decorators") or []
                    bases = cls.get("bases") or []

                    for d in decorators:
                        out.append(f"@{expr_repr(d)}")

                    if bases:
                        bases_txt = ", ".join(
                            expr_repr(b) if isinstance(b, Expr) else str(b) for b in bases
                        )
                        out.append(f"class {ch_name}({bases_txt}):")
                    else:
                        out.append(f"class {ch_name}:")

                    body = render_code_object(ch)
                    for ln in body:
                        out.append(f"{IND}{ln}")
                    out.append("")
                else:
                    # Emite decorators de função do módulo
                    idx = mod_deco_idx.get(ch_name, 0)
                    deco_list = mod_func_decos.get(ch_name) or []
                    if idx < len(deco_list):
                        for d in deco_list[idx]:
                            out.append(f"@{expr_repr(d)}")
                        mod_deco_idx[ch_name] = idx + 1
                    out.extend(render_code_object(ch))
                    out.append("")

            # Emite entry-point (chamadas de funções) após as definições
            if entry_lines:
                for line in entry_lines:
                    out.append(line)
                out.append("")

            if node.get("suppress_main_guard"):
                return out[:-1] if out and out[-1] == "" else out

            has_main = any(ch.get("name") == "main" for ch in node.get("children", []))
            out.append("if __name__ == '__main__':")
            out.append(f"{IND}{'main()' if has_main else 'pass'}")
            return out

        # ---------- CLASS BODY ----------
        # Detecta se este code object é um corpo de classe
        # (tem __module__ e __qualname__ como primeiras atribuições)
        is_class_body = False
        order_check, _ = basic_block_order(ra)
        if order_check:
            first_stmts = get_block_statements(node, order_check[0])
            assign_targets = [st.target for st in first_stmts if isinstance(st, Stmt) and st.kind == "assign"]
            if "__module__" in assign_targets and "__qualname__" in assign_targets:
                is_class_body = True

        if is_class_body:
            # Coleta decorators de métodos desta classe
            cls_func_decos = {}
            for fd in find_structs(ra, "FuncDecorators"):
                for fname, deco_list in (fd.get("decorators") or {}).items():
                    cls_func_decos.setdefault(fname, []).extend(deco_list)
            # Índice para consumir decorators por nome (para múltiplos methods com mesmo nome, e.g. property getter/setter)
            cls_deco_idx = {}

            # Renderiza métodos (children) e filtra body plumbing
            cls_out = []
            for ch in node.get("children", []):
                ch_name = ch.get("name", "")
                # Emite decorators do método
                idx = cls_deco_idx.get(ch_name, 0)
                deco_list = cls_func_decos.get(ch_name) or []
                if idx < len(deco_list):
                    for d in deco_list[idx]:
                        cls_out.append(f"@{expr_repr(d)}")
                    cls_deco_idx[ch_name] = idx + 1
                body = render_code_object(ch)
                cls_out.extend(body)
                cls_out.append("")

            # Emite statements do corpo da classe (atributos, class_var, etc.)
            child_names_cls = {ch.get("name") for ch in node.get("children", [])}
            for bid in order_check:
                stmts = get_block_statements(node, bid)
                for st in stmts:
                    if isinstance(st, Stmt) and st.kind == "assign":
                        if st.target in ("__module__", "__qualname__"):
                            continue
                        if st.target in child_names_cls:
                            continue
                        if isinstance(st.expr, Expr) and st.expr.kind == "make_function":
                            continue
                        if isinstance(st.expr, Expr) and st.expr.kind in ("call", "call_kw") and st.expr.args:
                            fn = st.expr.args[0]
                            if isinstance(fn, Expr) and fn.kind == "name" and fn.value == "__build_class__":
                                continue
                    s = stmt_repr(st).strip()
                    if s and s != "pass" and not s.startswith("return"):
                        cls_out.append(s)

            if not cls_out or not any(ln.strip() for ln in cls_out):
                cls_out = ["pass"]

            return cls_out

        # ---------- FUNCTION ----------

        # Função native/viper — sem bytecode decodificável
        if node.get("native"):
            kind_label = "native" if node.get("arch_code", 0) else "native"
            co = node.get("code_obj")
            if co and co.co_varnames:
                sig = ", ".join(co.co_varnames[:co.co_argcount])
            else:
                sig = "..."

            # Tenta disassembly do código de máquina
            asm_lines = []
            if co and hasattr(co, "_native_code") and co._native_code and co._prelude_offset > 0:
                try:
                    from NativeDisasm import disassemble_native
                    asm_text = disassemble_native(co._native_code, co.arch_code, co._prelude_offset)
                    asm_lines = [f"    {l}" for l in asm_text.splitlines()]
                except Exception:
                    pass

            out = [
                f"@micropython.{kind_label}",
                f"def {name}({sig}):",
            ]
            if asm_lines:
                out.extend(asm_lines)
            else:
                out.append(f"    ...")
            return out

        co = node.get("code_obj")
        co_flags = co.co_flags if co else (ra.get("co_flags") or 0)
        is_async = bool(co_flags & 0x80) or bool(co_flags & 0x200)  # CO_COROUTINE=0x80 | CO_ASYNC_GENERATOR=0x200 (Python 3.12)

        ann = _extract_annotations(node)
        sig = pick_arg_signature(node, ra, annotations=ann)
        ret_ann = ann.get("return", "")
        ret_str = f" -> {ret_ann}" if ret_ann else ""

        # Decorators de função
        func_decos_struct = find_structs(ra, "FuncDecorators")
        out = []
        # Nota: decorators são detectados no pai, não neste code object
        # O pai poderia passar os decorators, mas a arquitetura atual não faz isso.
        # Por agora, verificamos se há FuncDecorators no recovered_ast do pai.

        prefix = "async def" if is_async else "def"
        out = [f"{prefix} {name}({sig}){ret_str}:"]

        order, start_by_id = basic_block_order(ra)

        sc_blocks = set(ra.get("short_circuit_blocks") or [])
        yf_blocks = set(get_stack_info(node).get("yield_from_blocks") or [])

        ifs = find_structs(ra, "If")
        if_by_cond = {x.get("cond_block"): x for x in ifs if x.get("cond_block") is not None}

        loops = find_structs(ra, "Loop")
        loop_by_header = {}
        for x in loops:
            if x.get("header") is None:
                continue
            # Exclui loops espúrios cujos latches são todos blocos de infra yield from
            lp_latches = set(x.get("latches") or [])
            if lp_latches and lp_latches.issubset(yf_blocks):
                continue
            loop_by_header[x.get("header")] = x

        tefs = find_structs(ra, "TryExceptFinally")
        tef_by_entry = {}
        for t in tefs:
            tbs = t.get("try_blocks") or []
            if not tbs:
                continue
            entry_bid = min(tbs, key=lambda bid: start_by_id.get(bid, 10**18))
            tef_by_entry[entry_bid] = t

        # with/async with
        withs = find_structs(ra, "With") + find_structs(ra, "AsyncWith")
        with_by_block = {}
        with_body_blocks = set()   # todos os blocos que pertencem a algum with (body + handler)
        with_as_vars = {}          # block_id -> as_var (para suprimir atribuição no body)
        with_all_handler_blocks = set()  # handler + plumbing blocks de with
        with_normal_cleanup_blocks = set()  # blocos de cleanup normal (__exit__ no caminho normal)
        for w in withs:
            wb = w.get("block")
            if wb is not None:
                with_by_block[wb] = w
            body = w.get("body_blocks") or []
            hb = w.get("handler_block")
            as_var = w.get("as_var")
            for bb in body:
                with_body_blocks.add(bb)
                if as_var:
                    with_as_vars[bb] = as_var
            if hb is not None:
                with_all_handler_blocks.add(hb)
            # Expande com todos os handler blocks detectados pelo patterns
            for ahb in (w.get("all_handler_blocks") or []):
                with_all_handler_blocks.add(ahb)
            # Blocos de cleanup normal (SWAP + __exit__(None,None,None) + POP_TOP)
            for ncb in (w.get("normal_cleanup_blocks") or []):
                with_normal_cleanup_blocks.add(ncb)

        # assert
        assert_structs = find_structs(ra, "Assert")
        assert_by_cond = {a.get("cond_block"): a for a in assert_structs if a.get("cond_block") is not None}

        # match
        match_structs = find_structs(ra, "Match")
        match_by_block = {m.get("first_block"): m for m in match_structs if m.get("first_block") is not None}

        # global/nonlocal (emitir no início)
        global_decls = find_structs(ra, "GlobalDecl")
        nonlocal_decls = find_structs(ra, "NonlocalDecl")

        def sorted_region(region_ids):
            return sorted(set(region_ids), key=lambda bid: start_by_id.get(bid, 10**18))

        visited = set()
        # (bid -> set of target names) a suprimir por já terem sido atribuídos por comprehension
        _comp_skip_assign = {}

        def same_cond(a: Expr, b: Expr) -> bool:
            try:
                return expr_repr(a) == expr_repr(b)
            except Exception:
                return False

        def block_has_emittable_stmts(bid, in_finally=False, in_except=False, exc_var=None):
            stmts = get_block_statements(node, bid) or []
            for st in stmts:
                if isinstance(st, Stmt) and st.kind == "reraise":
                    continue
                # Suprime None espúrio (LOAD_CONST_NONE → POP_TOP)
                if (isinstance(st, Stmt) and st.kind == "expr"
                        and isinstance(st.expr, Expr) and st.expr.kind == "const"
                        and st.expr.value is None):
                    continue
                s = stmt_repr(st).strip()
                if not s:
                    continue
                if is_plumbing_stmt_text(s, in_except=in_except, exc_var=exc_var, in_finally=in_finally):
                    continue
                if in_finally and getattr(st, "kind", None) == "return":
                    if isinstance(st.expr, Expr) and st.expr.kind == "const" and st.expr.value is None:
                        continue
                return True
            return False

        def region_has_emittable_stmts(bids, in_finally=False, in_except=False, exc_var=None):
            for bid in bids or []:
                if block_has_emittable_stmts(bid, in_finally=in_finally, in_except=in_except, exc_var=exc_var):
                    return True
            return False

        def is_exception_plumbing_block(bid):
            # With handler blocks são sempre plumbing
            if bid in with_all_handler_blocks:
                return True
            # With normal cleanup blocks (SWAP + __exit__(None,None,None))
            if bid in with_normal_cleanup_blocks:
                return True
            ops = set(block_opnames(ra, bid))
            allowed = {
                "NOP", "COPY", "POP_EXCEPT", "RERAISE", "PUSH_EXC_INFO", "CHECK_EXC_MATCH",
                "WITH_EXCEPT_START", "BEFORE_WITH", "POP_TOP",
                "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_NO_INTERRUPT", "JUMP",
                "CALL_INTRINSIC_1", "CLEANUP_THROW", "END_ASYNC_FOR",
                # MicroPython-specific exception infrastructure
                "END_FINALLY", "POP_EXCEPT_JUMP", "WITH_CLEANUP",
            }
            if ops and not ops.issubset(allowed):
                # Verifica se é bloco de cleanup de variável de exceção
                # (LOAD_CONST None + STORE_FAST + DELETE_FAST + RERAISE)
                cleanup_allowed = allowed | {"LOAD_CONST", "STORE_FAST", "DELETE_FAST", "STORE_NAME", "DELETE_NAME"}
                if ops and ops.issubset(cleanup_allowed) and "RERAISE" in ops and "DELETE_FAST" in ops:
                    return True
                # Verifica se é handler de restauração de comprehension inlined (PEP 709)
                # Padrão: SWAP + POP_TOP + SWAP + STORE_FAST + RERAISE
                comp_restore_allowed = allowed | {"SWAP", "STORE_FAST", "STORE_NAME", "LOAD_FAST", "LOAD_CONST"}
                if (ops and ops.issubset(comp_restore_allowed) and "RERAISE" in ops
                        and ("STORE_FAST" in ops or "STORE_NAME" in ops)
                        and "SWAP" in ops
                        and "CHECK_EXC_MATCH" not in ops
                        and "POP_EXCEPT" not in ops
                        and "WITH_EXCEPT_START" not in ops):
                    return True
                return False
            stmts = get_block_statements(node, bid) or []
            for st in stmts:
                k = getattr(st, "kind", None)
                if k not in (None, "raise", "reraise"):
                    return False
            return True

        def render_region(
            lines,
            region_ids,
            level,
            loop_set=None,
            loop_meta=None,
            in_finally=False,
            in_except=False,
            exc_var=None,
            loop_cond_expr=None,
            loop_header_bid=None,
            suppress_with_as=None,
        ):
            wrote_any = False

            for bid in sorted_region(region_ids):
                if bid in visited:
                    continue

                if is_exception_plumbing_block(bid):
                    visited.add(bid)
                    continue

                # Blocos internos de yield from (SEND loop, CLEANUP_THROW, etc.)
                if bid in yf_blocks:
                    visited.add(bid)
                    continue

                # TRY/EXCEPT/FINALLY (com múltiplos handlers)
                if bid in tef_by_entry:
                    t = tef_by_entry[bid]
                    try_blocks = sorted_region(t.get("try_blocks") or [])
                    handlers = t.get("handlers") or []
                    finally_blocks = sorted_region(t.get("finally_blocks") or [])

                    # Fallback: se não tem handlers[], usa campos antigos
                    if not handlers and t.get("except_blocks"):
                        handlers = [{
                            "handler_blocks": sorted_region(t.get("except_blocks") or []),
                            "exc_type": t.get("except_type") or "Exception",
                            "exc_var": t.get("except_var"),
                            "handler_entry": t.get("except_entry"),
                        }]

                    saved = tef_by_entry.pop(bid, None)

                    emit(lines, "try:", level)
                    wrote_any = True

                    if try_blocks:
                        render_region(lines, try_blocks, level + 1, in_finally=False, in_except=False)
                    else:
                        emit(lines, "pass", level + 1)

                    # Renderiza cada except handler
                    all_handler_blocks = []
                    for h in handlers:
                        exc_type = h.get("exc_type")
                        exc_var0 = h.get("exc_var")
                        handler_blocks = sorted_region(h.get("handler_blocks") or [])
                        all_handler_blocks.extend(handler_blocks)

                        if exc_type and exc_var0:
                            emit(lines, f"except {exc_type} as {exc_var0}:", level)
                        elif exc_type:
                            emit(lines, f"except {exc_type}:", level)
                        else:
                            emit(lines, "except:", level)

                        handler_keep = [b for b in handler_blocks
                                       if block_has_emittable_stmts(b, in_except=True, exc_var=exc_var0)]
                        if handler_keep:
                            render_region(lines, handler_keep, level + 1,
                                         in_finally=False, in_except=True, exc_var=exc_var0)
                        else:
                            emit(lines, "pass", level + 1)

                        for x in handler_blocks:
                            visited.add(x)

                    # Se não tem handlers e não tem finally, emite except genérico
                    if not handlers and not finally_blocks:
                        emit(lines, "except:", level)
                        emit(lines, "pass", level + 1)

                    # Else (executa se nenhuma exceção foi levantada)
                    else_b = sorted_region(t.get("else_blocks") or [])
                    if else_b and region_has_emittable_stmts(else_b):
                        emit(lines, "else:", level)
                        render_region(lines, else_b, level + 1, in_finally=False, in_except=False)
                        for x in else_b:
                            visited.add(x)

                    # Pré-marca blocos de continuação como visitados antes de renderizar
                    # o finally, para que render_if não os inclua no else branch
                    fin_cont_bids = list(t.get("finally_continuation_bids") or [])
                    for x in fin_cont_bids:
                        visited.add(x)

                    # Finally
                    if finally_blocks:
                        emit(lines, "finally:", level)
                        # Usa render_region diretamente (blocos inline já são a cópia correta)
                        fin_render = [b for b in finally_blocks
                                      if not is_exception_plumbing_block(b)]
                        if fin_render:
                            render_region(lines, fin_render, level + 1,
                                          in_finally=True, in_except=False, exc_var=None)
                        else:
                            emit(lines, "pass", level + 1)

                    fin_exc_bids = list(t.get("finally_exc_handler_bids") or [])
                    for x in try_blocks + all_handler_blocks + finally_blocks + fin_cont_bids + fin_exc_bids:
                        visited.add(x)
                    visited.add(bid)

                    # Emite stmts de continuação pós-try (ex: return value após finally)
                    post_stmts = list(t.get("post_finally_stmts") or [])
                    if post_stmts:
                        emit_statements(lines, post_stmts, level,
                                        in_finally=False, in_except=False)
                        wrote_any = True

                    if saved is not None:
                        tef_by_entry[bid] = saved
                    continue

                # WITH / ASYNC WITH
                if bid in with_by_block:
                    w = with_by_block[bid]
                    ctx_expr = w.get("ctx_expr")
                    as_var = w.get("as_var")
                    body_blocks = sorted_region(w.get("body_blocks") or [])
                    is_async_with = w.get("type") == "AsyncWith"

                    ctx_txt = expr_repr(ctx_expr) if ctx_expr else "<?>"
                    kw = "async with" if is_async_with else "with"

                    if as_var:
                        emit(lines, f"{kw} {ctx_txt} as {as_var}:", level)
                    else:
                        emit(lines, f"{kw} {ctx_txt}:", level)

                    body_wrote = False
                    body_wrote_any = False  # qualquer linha escrita, inclusive pass
                    if body_blocks:
                        # Renderiza body filtrando a atribuição do as_var (já está no header)
                        lines_before = len(lines)
                        render_region(lines, body_blocks, level + 1)
                        body_wrote = any(ln.strip() and ln.strip() != "pass" for ln in lines[lines_before:])
                        body_wrote_any = any(ln.strip() for ln in lines[lines_before:])

                    # Detecta return computado dentro do body que foi movido para
                    # os blocos de cleanup pelo compilador (padrão com SWAP + __exit__ + return)
                    if not body_wrote and body_blocks:
                        # Verifica se o último bloco do body deixou valor na pilha
                        last_body = body_blocks[-1]
                        out_st = get_out_stack(node, last_body)
                        real_vals = [v for v in out_st if isinstance(v, Expr)
                                     and v.kind not in ("with_exit", "with_enter", "null", "unknown", "exc")]
                        if real_vals:
                            # Procura return nos blocos de cleanup normais após o body
                            cleanup_bids = sorted_region(w.get("normal_cleanup_blocks") or [])
                            # Também verifica blocos normais logo após o body
                            body_end_off = max(start_by_id.get(b, 0) for b in body_blocks) if body_blocks else 0
                            handler_off = start_by_id.get(w.get("handler_block"), 10**18) if w.get("handler_block") else 10**18
                            for other_bid in order:
                                other_off = start_by_id.get(other_bid, 0)
                                if other_off <= body_end_off or other_off >= handler_off:
                                    continue
                                if other_bid in with_all_handler_blocks:
                                    continue
                                if other_bid not in cleanup_bids:
                                    cleanup_bids.append(other_bid)
                            cleanup_bids = sorted(set(cleanup_bids), key=lambda x: start_by_id.get(x, 10**18))

                            for cb in cleanup_bids:
                                stmts = get_block_statements(node, cb)
                                for st in stmts:
                                    if isinstance(st, Stmt) and st.kind == "return" and st.expr is not None:
                                        # Verifica se NÃO é return None (seria implícito)
                                        is_none = (isinstance(st.expr, Expr) and st.expr.kind == "const"
                                                   and st.expr.value is None)
                                        if not is_none:
                                            # Remove pass anterior se existir
                                            while lines and lines[-1].strip() == "pass":
                                                lines.pop()
                                            ret_txt = expr_repr(st.expr) if st.expr else ""
                                            emit(lines, f"return {ret_txt}", level + 1)
                                            visited.add(cb)
                                            body_wrote = True
                                            break
                                if body_wrote:
                                    break

                    if not body_wrote_any and not body_wrote:
                        emit(lines, "pass", level + 1)

                    for x in body_blocks:
                        visited.add(x)
                    visited.add(bid)
                    handler_bid = w.get("handler_block")
                    if handler_bid is not None:
                        visited.add(handler_bid)
                    # Marca todos os blocos de plumbing de with (handlers, reraise) como visitados
                    for hb in with_all_handler_blocks:
                        visited.add(hb)
                    # Marca blocos de cleanup normal como visitados
                    for ncb in (w.get("normal_cleanup_blocks") or []):
                        visited.add(ncb)
                    wrote_any = True
                    continue

                # ASSERT
                if bid in assert_by_cond:
                    a = assert_by_cond[bid]
                    cond_expr_a = a.get("cond_expr")
                    msg_expr_a = a.get("msg_expr")
                    cond_txt_a = expr_repr(cond_expr_a) if cond_expr_a is not None else "True"

                    if msg_expr_a:
                        emit(lines, f"assert {cond_txt_a}, {expr_repr(msg_expr_a)}", level)
                    else:
                        emit(lines, f"assert {cond_txt_a}", level)

                    visited.add(bid)
                    fail_bid = a.get("fail_block")
                    if fail_bid is not None:
                        visited.add(fail_bid)
                    wrote_any = True
                    continue

                # MATCH/CASE
                if bid in match_by_block:
                    m = match_by_block[bid]
                    subject = m.get("subject_expr")
                    subject_txt = expr_repr(subject) if subject else "<?>"
                    is_chain = m.get("is_chain", False)
                    is_seq_chain = m.get("is_seq_chain", False)

                    emit(lines, f"match {subject_txt}:", level)

                    if is_seq_chain:
                        # seq_match_chain: padrões de sequência multi-bloco (ex: block_match_complex)
                        for case_info in (m.get("cases") or []):
                            pat_str = case_info.get("pattern_str", "_")
                            body_bid_sc = case_info.get("body_bid")
                            n_bindings_sc = case_info.get("n_bindings", 0)

                            emit(lines, f"case {pat_str}:", level + 1)
                            body_stmts_sc = get_block_statements(node, body_bid_sc) if body_bid_sc is not None else []
                            if n_bindings_sc > 0 and body_stmts_sc:
                                body_stmts_sc = list(body_stmts_sc)[n_bindings_sc:]
                            if not body_stmts_sc or not emit_statements(lines, body_stmts_sc, level + 2,
                                                                        in_finally=in_finally, in_except=in_except,
                                                                        exc_var=exc_var):
                                emit(lines, "pass", level + 2)

                            for all_bid_sc in (case_info.get("all_bids") or set()):
                                visited.add(all_bid_sc)
                            if case_info.get("fail_all_bid") is not None:
                                visited.add(case_info["fail_all_bid"])

                        # Default case: emite case _: apenas se houver código real
                        default_bid_sc = m.get("default_block")
                        if default_bid_sc is not None:
                            def_stmts_sc = get_block_statements(node, default_bid_sc)
                            temp_lines_sc = []
                            has_real_sc = emit_statements(temp_lines_sc, def_stmts_sc, level + 2,
                                                          in_finally=in_finally, in_except=in_except,
                                                          exc_var=exc_var)
                            if has_real_sc or temp_lines_sc:
                                emit(lines, "case _:", level + 1)
                                lines.extend(temp_lines_sc)
                            visited.add(default_bid_sc)

                        for all_bid_sc in (m.get("all_blocks") or set()):
                            visited.add(all_bid_sc)

                    elif is_chain:
                        # match_chain: cases com info de padrão completa
                        for case_info in (m.get("cases") or []):
                            ptype = case_info.get("pattern_type", "unknown")
                            body_bid = case_info.get("body_block")

                            if ptype == "literal":
                                lit = case_info.get("literal_value")
                                pat_txt = repr(lit) if lit is not None else "_"
                                emit(lines, f"case {pat_txt}:", level + 1)
                            elif ptype == "class":
                                cls_name = case_info.get("class_name", "?")
                                captures = case_info.get("captures", [])
                                cap_txt = ", ".join(captures)
                                emit(lines, f"case {cls_name}({cap_txt}):", level + 1)
                            elif ptype == "sequence":
                                emit(lines, "case [...]:", level + 1)
                            elif ptype == "mapping":
                                emit(lines, "case {**_}:", level + 1)
                            else:
                                emit(lines, "case _:", level + 1)

                            # Render body: skip os primeiros stmts que são artefatos de unpack/subject
                            body_stmts = get_block_statements(node, body_bid) if body_bid is not None else []
                            # Para class case: pula assigns de unpack (s = match_class[0])
                            n_skip = len(case_info.get("captures", []))
                            if n_skip > 0 and body_stmts:
                                body_stmts = list(body_stmts)[n_skip:]
                            if not body_stmts or not emit_statements(lines, body_stmts, level + 2):
                                emit(lines, "pass", level + 2)

                            if body_bid is not None:
                                visited.add(body_bid)
                            visited.add(case_info["cond_block"])

                        # Default case
                        default_bid = m.get("default_block")
                        if default_bid is not None:
                            emit(lines, "case _:", level + 1)
                            def_stmts = get_block_statements(node, default_bid)
                            if not def_stmts or not emit_statements(lines, def_stmts, level + 2):
                                emit(lines, "pass", level + 2)
                            visited.add(default_bid)

                        # Marca todos os blocos da cadeia como visitados
                        for all_bid in (m.get("all_blocks") or set()):
                            visited.add(all_bid)
                    else:
                        # Legacy match_regions (block_match_complex): renderização antiga
                        for case_info in (m.get("cases") or []):
                            case_bid = case_info["block"]
                            cond_c = get_block_condition(node, case_bid, 0)

                            if cond_c and isinstance(cond_c, Expr):
                                if cond_c.kind == "match_sequence":
                                    emit(lines, "case [...]:", level + 1)
                                elif cond_c.kind == "match_mapping":
                                    emit(lines, "case {**_}:", level + 1)
                                elif cond_c.kind == "match_class":
                                    emit(lines, f"case {expr_repr(cond_c)}:", level + 1)
                                else:
                                    emit(lines, f"case {expr_repr(cond_c)}:", level + 1)
                            else:
                                emit(lines, "case _:", level + 1)

                            case_stmts = get_block_statements(node, case_bid)
                            if not case_stmts or not emit_statements(lines, case_stmts, level + 2):
                                emit(lines, "pass", level + 2)

                            visited.add(case_bid)

                    visited.add(bid)
                    wrote_any = True
                    continue

                # LOOP
                if bid in loop_by_header:
                    visited.add(bid)
                    render_loop(lines, bid, loop_by_header[bid], level)
                    wrote_any = True
                    continue

                # IF (caso especial: latch do while no mesmo bloco do corpo)
                if bid in if_by_cond:
                    # Suprime blocos de short-circuit (COPY+POP_JUMP): já resolvidos em and/or
                    if bid in sc_blocks:
                        visited.add(bid)
                        # Emite statements pré-condição: resultado de short-circuit anterior
                        # (ex: x = (a and b) no bloco que também inicia a or b)
                        sc_stmts = get_block_statements(node, bid) or []
                        if sc_stmts:
                            emit_statements(lines, sc_stmts, level,
                                            in_finally=in_finally, in_except=in_except, exc_var=exc_var)
                        continue

                    iff = if_by_cond[bid]

                    if loop_set is not None and loop_cond_expr is not None:
                        c = get_block_condition(node, bid, 0)
                        if c is not None and same_cond(c, loop_cond_expr):
                            # se esse cond_block tem stmts reais, ele é "corpo do while + latch";
                            # emite stmts e suprime o IF.
                            if block_has_emittable_stmts(bid, in_finally=in_finally, in_except=in_except, exc_var=exc_var):
                                stmts_here = get_block_statements(node, bid) or []
                                if emit_statements(lines, stmts_here, level, in_finally=in_finally, in_except=in_except, exc_var=exc_var):
                                    wrote_any = True
                                visited.add(bid)
                                for bb in (iff.get("then_blocks") or []):
                                    visited.add(bb)
                                continue
                            # se não tem stmts reais, é guard redundante: só suprime
                            else:
                                visited.add(bid)
                                for bb in (iff.get("then_blocks") or []):
                                    visited.add(bb)
                                continue

                    visited.add(bid)
                    render_if(
                        lines, iff, level,
                        loop_set=loop_set, loop_meta=loop_meta,
                        in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                        loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid
                    )
                    # Marca sub-blocos do if como visitados para o loop externo não re-renderizá-los
                    for _b in list((iff.get("then_blocks") or []) + (iff.get("else_blocks") or [])):
                        visited.add(_b)
                    wrote_any = True
                    continue

                # Suprime bloco de plumbing do short-circuit (POP_TOP fall-through)
                if bid in sc_blocks:
                    visited.add(bid)
                    continue

                # BLOCO "normal"
                visited.add(bid)
                stmts = get_block_statements(node, bid)
                # Determina se estamos dentro de um with body e devemos suprimir a atribuição as_var
                _with_as = suppress_with_as or with_as_vars.get(bid)
                if stmts:
                    # Processa statements preservando ordem, renderizando defs aninhadas inline
                    _ch_by_name = {}
                    for _ch in node.get("children", []):
                        _cn = _ch.get("name")
                        if _cn:
                            _ch_by_name.setdefault(_cn, []).append(_ch)
                    _ch_emit_idx = {}
                    _pending = []  # statements normais acumulados antes de um def

                    def _flush_pending():
                        nonlocal wrote_any
                        if _pending:
                            if emit_statements(lines, list(_pending), level,
                                               in_finally=in_finally, in_except=in_except,
                                               exc_var=exc_var, suppress_with_as=_with_as):
                                wrote_any = True
                            _pending.clear()

                    for st in stmts:
                        if not (isinstance(st, Stmt) and st.kind == "assign"):
                            _pending.append(st)
                            continue
                        # Suprime assigns já tratados por comprehension rendering
                        if st.target and st.target in (_comp_skip_assign.get(bid) or set()):
                            continue
                        # Suprime identity assigns (x = x) gerados por LOAD_FAST_AND_CLEAR
                        if (st.target and isinstance(st.expr, Expr) and st.expr.kind == "name"
                                and st.expr.value == st.target):
                            continue
                        # Tenta extrair make_function (possivelmente envolto em decorators)
                        _expr = st.expr
                        _decos = []
                        while isinstance(_expr, Expr) and _expr.kind in ("call", "call_kw"):
                            _args = _expr.args or ()
                            if len(_args) >= 2:
                                _inner = _args[1]
                                if isinstance(_inner, Expr) and _inner.kind == "make_function":
                                    _decos.append(_args[0])
                                    _expr = _inner
                                    break
                                elif isinstance(_inner, Expr) and _inner.kind in ("call", "call_kw"):
                                    _decos.append(_args[0])
                                    _expr = _inner
                                else:
                                    break
                            else:
                                break
                        if not (isinstance(_expr, Expr) and _expr.kind == "make_function"):
                            _pending.append(st)
                            continue
                        _target = st.target
                        _ch_list = _ch_by_name.get(_target)
                        if not _ch_list:
                            _pending.append(st)
                            continue
                        _idx = _ch_emit_idx.get(_target, 0)
                        if _idx >= len(_ch_list):
                            _pending.append(st)
                            continue
                        _ch = _ch_list[_idx]
                        _ch_emit_idx[_target] = _idx + 1
                        # Flush statements pendentes antes de emitir o def
                        _flush_pending()
                        # Emite decorators (outermost first)
                        _decos.reverse()
                        for _d in _decos:
                            emit(lines, f"@{expr_repr(_d)}", level)
                        # Emite a função aninhada
                        for _ln in render_code_object(_ch):
                            emit(lines, _ln, level)
                        wrote_any = True
                    _flush_pending()
                else:
                    ops = set(block_opnames(ra, bid))
                    if ops.issubset({"NOP", "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"}):
                        continue

            # garante corpo não-vazio (evita "else:" sem nada, ou "if:" sem nada)
            if not wrote_any:
                emit(lines, "pass", level)

        def render_if(
            lines,
            iff,
            level,
            loop_set=None,
            loop_meta=None,
            in_finally=False,
            in_except=False,
            exc_var=None,
            loop_cond_expr=None,
            loop_header_bid=None,
        ):
            cblk = iff.get("cond_block")
            cond_expr = get_block_condition(node, cblk, 0)
            cond_txt = expr_repr(cond_expr) if cond_expr is not None else "True"

            # Walrus recovery: COPY 1 + STORE_FAST gera um stmt assign no cblk cuja
            # expr é o MESMO objeto Python (identidade) que aparece na condição.
            # Atribuições normais criam Exprs distintos (ex: LOAD_FAST cria novo Expr("name")).
            def _expr_contains_id(haystack, needle):
                """Busca recursiva por identidade de objeto (não igualdade de valor)."""
                if haystack is needle:
                    return True
                if isinstance(haystack, Expr) and haystack.args:
                    return any(_expr_contains_id(a, needle) for a in haystack.args)
                return False

            _cblk_stmts = list(get_block_statements(node, cblk) or [])
            # Suprime assigns de variável de loop (ex: i = next(iter(...))) já codificados no "for"
            _skip_in_cblk = _comp_skip_assign.get(cblk, set())
            if _skip_in_cblk:
                _cblk_stmts = [s for s in _cblk_stmts
                               if not (isinstance(s, Stmt) and s.kind == "assign"
                                       and s.target in _skip_in_cblk)]
            if _cblk_stmts and cond_expr is not None:
                last_st = _cblk_stmts[-1]
                if (isinstance(last_st, Stmt) and last_st.kind == "assign"
                        and last_st.target and last_st.expr is not None
                        and _expr_contains_id(cond_expr, last_st.expr)):
                    # Último stmt é walrus: embutir na condição como (var := expr)
                    st_txt = expr_repr(last_st.expr)
                    cond_txt = cond_txt.replace(st_txt, f"({last_st.target} := {st_txt})", 1)
                    _cblk_stmts = _cblk_stmts[:-1]

            if _cblk_stmts:
                emit_statements(lines, _cblk_stmts, level,
                                in_finally=in_finally, in_except=in_except, exc_var=exc_var)

            then_ids = sorted_region(iff.get("then_blocks") or [])
            else_ids = sorted_region(iff.get("else_blocks") or [])
            join_bid = iff.get("join_block")

            def _is_latch_region(bids):
                """Verifica se todos os blocos são latches do loop (= continue)."""
                if not bids or loop_meta is None:
                    return False
                latches = set(loop_meta.get("latches", []))
                return all(bid in latches for bid in bids)

            def _is_for_break_region(bids):
                """Verifica se a região é um break de for-loop (POP_TOP + exit)."""
                if not bids or loop_meta is None:
                    return False
                for bid in bids:
                    ops = set(block_opnames(ra, bid))
                    stmts = get_block_statements(node, bid) or []
                    # Break em for-loop: POP_TOP (pop iterador) + saída (RETURN_CONST/RETURN_VALUE)
                    if "POP_TOP" in ops and ops & {"RETURN_CONST", "RETURN_VALUE", "JUMP_FORWARD"}:
                        # Verifica que os statements são apenas return None (epílogo de break)
                        real = [s for s in stmts if not is_plumbing_stmt_text(
                            stmt_repr(s).strip(), in_except=in_except, exc_var=exc_var, in_finally=in_finally)]
                        if not real:
                            return True
                        if len(real) == 1 and real[0].kind == "return":
                            e = real[0].expr
                            if isinstance(e, Expr) and e.kind == "const" and e.value is None:
                                return True
                return False

            if loop_set is not None:
                then_has = region_has_emittable_stmts(then_ids, in_finally=in_finally, in_except=in_except, exc_var=exc_var)

                # SUPRIME checagem redundante do while cond: (CPython 3.12 duplica a condição no fim do corpo)
                # Quando a condição do IF é a mesma do while e then=latch → não emitir nada; o pai cuida do else
                if (loop_cond_expr is not None and cond_expr is not None
                        and expr_repr(cond_expr) == expr_repr(loop_cond_expr)
                        and not then_has and _is_latch_region(then_ids)):
                    return

                # CONTINUE: then-branch é latch sem statements reais
                if not then_has and _is_latch_region(then_ids):
                    emit(lines, f"if {cond_txt}:", level)
                    emit(lines, "continue", level + 1)
                    else_has = region_has_emittable_stmts(else_ids, in_finally=in_finally, in_except=in_except, exc_var=exc_var)
                    if else_ids and else_has:
                        # Sem else: — continue já sai do branch; restante fica no mesmo nível
                        render_region(
                            lines, else_ids, level,
                            loop_set=loop_set, loop_meta=loop_meta,
                            in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                            loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid
                        )
                    return

                # BREAK (for-loop): then-branch tem POP_TOP + saída do loop
                if _is_for_break_region(then_ids):
                    emit(lines, f"if {cond_txt}:", level)
                    emit(lines, "break", level + 1)
                    else_has = region_has_emittable_stmts(else_ids, in_finally=in_finally, in_except=in_except, exc_var=exc_var)
                    if else_ids and else_has:
                        # Sem else: — break já sai do branch; restante fica no mesmo nível
                        render_region(
                            lines, else_ids, level,
                            loop_set=loop_set, loop_meta=loop_meta,
                            in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                            loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid
                        )
                    return

                # BREAK (genérico): join fora do loop, then sem stmts reais
                if join_bid is not None and join_bid not in loop_set:
                    if not then_has:
                        emit(lines, f"if {cond_txt}:", level)
                        emit(lines, "break", level + 1)
                        else_has = region_has_emittable_stmts(else_ids, in_finally=in_finally, in_except=in_except, exc_var=exc_var)
                        if else_ids and else_has:
                            # Sem else: — break já sai do branch; restante fica no mesmo nível
                            render_region(
                                lines, else_ids, level,
                                loop_set=loop_set, loop_meta=loop_meta,
                                in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                                loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid
                            )
                        return

                # BREAK (while-True): else-branch é latch, then-branch está fora do loop
                # CPython 3.12: break compila como salto para o bloco pós-loop
                if (then_ids and _is_latch_region(else_ids)
                        and set(then_ids).isdisjoint(loop_set)):
                    emit(lines, f"if {cond_txt}:", level)
                    emit(lines, "break", level + 1)
                    # then_ids são pós-loop → não renderizar aqui; o pai os renderiza após o loop
                    return

            emit(lines, f"if {cond_txt}:", level)

            if then_ids:
                render_region(
                    lines, then_ids, level + 1,
                    loop_set=loop_set, loop_meta=loop_meta,
                    in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                    loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid
                )
            else:
                emit(lines, "pass", level + 1)

            # elif / else
            _render_else_or_elif(
                lines, else_ids, level,
                loop_set=loop_set, loop_meta=loop_meta,
                in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid,
            )

        def _render_else_or_elif(
            lines, else_ids, level,
            loop_set=None, loop_meta=None,
            in_finally=False, in_except=False, exc_var=None,
            loop_cond_expr=None, loop_header_bid=None,
        ):
            """Emite elif/else, achatando cadeias de elif."""
            if not else_ids:
                return
            # Filtra blocos já visitados (ex: continuation_bids pré-marcados do finally)
            else_ids = [b for b in else_ids if b not in visited]
            if not else_ids:
                return

            # Detecta elif: o primeiro bloco do else é cond_block de outro If,
            # e os demais blocos são parte dessa mesma estrutura if (then + else)
            first_else = else_ids[0] if else_ids else None
            can_elif = False
            if first_else is not None and first_else in if_by_cond and first_else not in assert_by_cond:
                next_if = if_by_cond[first_else]
                inner_blocks = set(next_if.get("then_blocks") or []) | set(next_if.get("else_blocks") or [])
                remaining = set(else_ids[1:])
                # elif é válido se todos os blocos restantes do else pertencem ao inner if
                can_elif = remaining.issubset(inner_blocks | {first_else})

            if can_elif:
                next_cblk = first_else
                visited.add(next_cblk)

                next_cond = get_block_condition(node, next_cblk, 0)
                next_cond_txt = expr_repr(next_cond) if next_cond is not None else "True"

                emit(lines, f"elif {next_cond_txt}:", level)

                next_then = sorted_region(next_if.get("then_blocks") or [])
                next_else = sorted_region(next_if.get("else_blocks") or [])

                if next_then:
                    render_region(
                        lines, next_then, level + 1,
                        loop_set=loop_set, loop_meta=loop_meta,
                        in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                        loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid,
                    )
                else:
                    emit(lines, "pass", level + 1)

                # Recursão para mais elif/else
                _render_else_or_elif(
                    lines, next_else, level,
                    loop_set=loop_set, loop_meta=loop_meta,
                    in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                    loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid,
                )
                return

            # else normal — só emite se tiver conteúdo real (evita "else: pass")
            else_has = region_has_emittable_stmts(else_ids, in_finally=in_finally, in_except=in_except, exc_var=exc_var)
            if not else_has:
                # Marca como visitados para não serem re-processados como blocos soltos
                visited.update(else_ids)
                return
            emit(lines, "else:", level)
            render_region(
                lines, else_ids, level + 1,
                loop_set=loop_set, loop_meta=loop_meta,
                in_finally=in_finally, in_except=in_except, exc_var=exc_var,
                loop_cond_expr=loop_cond_expr, loop_header_bid=loop_header_bid,
            )

        def render_loop(lines, header_bid, lp, level):
            body_all = sorted_region(lp.get("body_blocks") or [])
            body = [b for b in body_all if b != header_bid]
            loop_set = set([header_bid] + (lp.get("body_blocks") or []))
            loop_meta = {"header": header_bid, "latches": list(lp.get("latches") or [])}

            ops = block_opnames(ra, header_bid)
            in_st = get_in_stack(node, header_bid)
            header_iter = (in_st[-1] if in_st else None)

            # Verifica se é async for
            is_async_for = lp.get("is_async_for", False)

            # FOR / ASYNC FOR
            is_for = ("FOR_ITER" in ops) and isinstance(header_iter, Expr) and header_iter.kind == "iter"
            is_afor = is_async_for or (isinstance(header_iter, Expr) and header_iter.kind == "aiter")

            if is_for or is_afor:
                if is_afor and isinstance(header_iter, Expr) and header_iter.kind == "aiter":
                    iter_txt = expr_repr(header_iter.args[0] if header_iter.args else None)
                else:
                    iter_txt = expr_repr(header_iter.args[0] if header_iter and header_iter.args else None)

                loop_var = "item"
                # Para async for: loop_var vem de Stmt(kind="async_for_item") no header
                if is_afor:
                    hdr_stmts = get_block_statements(node, header_bid) or []
                    for st in hdr_stmts:
                        if isinstance(st, Stmt) and st.kind == "async_for_item" and st.target:
                            loop_var = st.target
                            break
                if loop_var == "item" and body:
                    stmts0 = get_block_statements(node, body[0]) or []
                    for st in stmts0:
                        if isinstance(st, Stmt) and st.kind == "assign" and isinstance(st.expr, Expr) and st.expr.kind in ("next", "anext"):
                            loop_var = st.target or loop_var
                            # Suprime "loop_var = next(iter(...))" do corpo — já codificado no header for
                            _comp_skip_assign.setdefault(body[0], set()).add(loop_var)
                            break

                # Verifica se é comprehension inlined (PEP 709)
                comp_type = None
                comp_element = None
                comp_cond = None   # condição de filtro (ex: for x in items if x > 0)
                _cond_bid = None   # bloco onde comp_cond foi extraído

                def _find_comp_element(v, append_kind, _seen=None):
                    """Extrai elemento de list_append/set_add/map_add, inclusive dentro de phi cycles."""
                    if _seen is None:
                        _seen = set()
                    if not isinstance(v, Expr):
                        return None
                    vid = id(v)
                    if vid in _seen:
                        return None
                    _seen.add(vid)
                    if v.kind == append_kind:
                        return v.args[-1] if v.args else None
                    if v.kind in ("list", "set", "dict") and v.args:
                        return v.args[-1]
                    if v.kind == "phi":
                        for arg in (v.args or ()):
                            r = _find_comp_element(arg, append_kind, _seen)
                            if r is not None:
                                return r
                    return None

                for _cbid in body:
                    _cops = set(block_opnames(ra, _cbid))
                    if "LIST_APPEND" in _cops:
                        comp_type = "list"
                    elif "SET_ADD" in _cops:
                        comp_type = "set"
                    elif "MAP_ADD" in _cops:
                        comp_type = "dict"
                    if comp_type:
                        _append_kind = {"list": "list_append", "set": "set_add", "dict": "map_add"}.get(comp_type, "list_append")
                        _bout = get_out_stack(node, _cbid)
                        for _v in reversed(_bout):
                            if not isinstance(_v, Expr):
                                continue
                            r = _find_comp_element(_v, _append_kind)
                            if r is not None:
                                comp_element = r
                                break
                        break

                # Extrai condição do filtro: bloco de corpo com COND mas sem LIST_APPEND
                if comp_type and comp_element is not None:
                    for _fbid in body:
                        _fcops = set(block_opnames(ra, _fbid))
                        if ("LIST_APPEND" not in _fcops and "SET_ADD" not in _fcops and "MAP_ADD" not in _fcops):
                            _fcond = get_block_condition(node, _fbid, 0)
                            if _fcond is not None:
                                comp_cond = _fcond
                                _cond_bid = _fbid
                                break

                if comp_type and comp_element is not None and not is_afor:
                    # Verifica se _fix_comprehensions já tratou esta compreensão
                    # (substituiu phi por list_comp/set_comp no bloco pós-loop)
                    body_all_set = set(body_all)
                    max_body_start = max((start_by_id.get(b, 0) for b in body_all), default=0)
                    already_handled = False
                    for _pbid in order:
                        if _pbid in body_all_set:
                            continue
                        if start_by_id.get(_pbid, 0) <= max_body_start:
                            continue
                        _pstmts = get_block_statements(node, _pbid) or []
                        for _ps in _pstmts:
                            if isinstance(_ps, Stmt) and _ps.kind == "assign" and isinstance(_ps.expr, Expr):
                                if _ps.expr.kind in ("list_comp", "set_comp", "dict_comp"):
                                    already_handled = True
                                    break
                        if already_handled:
                            break

                    if not already_handled:
                        # phi → ternário inline: phi(a,b) com cond ativa é `then if cond else else`
                        if (isinstance(comp_element, Expr) and comp_element.kind == "phi"
                                and comp_cond is not None and _cond_bid is not None
                                and _cond_bid in if_by_cond
                                and len(comp_element.args or ()) == 2):
                            _tif = if_by_cond[_cond_bid]
                            _then_bids = _tif.get("then_blocks") or []
                            _phi_args = comp_element.args
                            # fallback: phi(a,b) → b=then, a=else (ordem comum do set)
                            _then_val, _else_val = _phi_args[1], _phi_args[0]
                            # usa out_stack do último bloco do then-branch para identificar o then-value
                            if _then_bids:
                                _then_stk = get_out_stack(node, _then_bids[-1])
                                _then_top = _then_stk[-1] if _then_stk else None
                                if _then_top is not None:
                                    _top_repr = expr_repr(_then_top)
                                    if expr_repr(_phi_args[0]) == _top_repr:
                                        _then_val, _else_val = _phi_args[0], _phi_args[1]
                                    elif expr_repr(_phi_args[1]) == _top_repr:
                                        _then_val, _else_val = _phi_args[1], _phi_args[0]
                            elem_txt = f"{expr_repr(_then_val)} if {expr_repr(comp_cond)} else {expr_repr(_else_val)}"
                            comp_cond = None
                        else:
                            elem_txt = expr_repr(comp_element)
                        cond_part = f" if {expr_repr(comp_cond)}" if comp_cond is not None else ""

                        # Detecta nested comprehension: corpo do loop externo contém inner FOR_ITER
                        # ex: [x for row in outer for x in row]
                        inner_for_clauses = []
                        for _nbid in body:
                            _nops = set(block_opnames(ra, _nbid))
                            if "FOR_ITER" not in _nops:
                                continue
                            # Extrai iterável do inner FOR_ITER via in_stack
                            _inner_in = get_in_stack(node, _nbid)
                            _inner_iter_expr = _inner_in[-1] if _inner_in else None
                            if not isinstance(_inner_iter_expr, Expr) or _inner_iter_expr.kind != "iter":
                                break
                            _inner_iterable = _inner_iter_expr.args[0] if _inner_iter_expr.args else None
                            _inner_iter_txt = expr_repr(_inner_iterable)
                            # Extrai inner loop var: STORE_FAST→next stmt no corpo do inner loop
                            _inner_var = None
                            if _nbid in loop_by_header:
                                _ilp = loop_by_header[_nbid]
                                _ibody = sorted_region(_ilp.get("body_blocks") or [])
                                for _ibbid in _ibody:
                                    if _ibbid == _nbid:
                                        continue
                                    _istmts = get_block_statements(node, _ibbid) or []
                                    for _ist in _istmts:
                                        if (isinstance(_ist, Stmt) and _ist.kind == "assign"
                                                and isinstance(_ist.expr, Expr)
                                                and _ist.expr.kind in ("next", "anext")):
                                            _inner_var = _ist.target
                                            break
                                    if _inner_var:
                                        break
                            if _inner_var:
                                inner_for_clauses.append((_inner_var, _inner_iter_txt))
                            break  # um nível de aninhamento

                        for_part = f"for {loop_var} in {iter_txt}"
                        for (_iv, _it) in inner_for_clauses:
                            for_part += f" for {_iv} in {_it}"

                        if comp_type == "list":
                            comp_expr = f"[{elem_txt} {for_part}{cond_part}]"
                        elif comp_type == "set":
                            comp_expr = f"{{{elem_txt} {for_part}{cond_part}}}"
                        else:
                            comp_expr = f"{{? {for_part}{cond_part}}}"

                        # Encontra variável de destino no bloco pós-loop
                        comp_target = None
                        for _pbid in order:
                            if _pbid in body_all_set:
                                continue
                            if start_by_id.get(_pbid, 0) <= max_body_start:
                                continue
                            _pstmts = get_block_statements(node, _pbid) or []
                            for _ps in _pstmts:
                                if isinstance(_ps, Stmt) and _ps.kind == "assign" and _ps.target:
                                    _repr = expr_repr(_ps.expr) if _ps.expr is not None else ""
                                    if "phi" in _repr or "<cycle>" in _repr:
                                        comp_target = _ps.target
                                        _comp_skip_assign.setdefault(_pbid, set()).add(_ps.target)
                                        break
                            if comp_target:
                                break

                        if comp_target:
                            emit(lines, f"{comp_target} = {comp_expr}", level)
                        else:
                            emit(lines, comp_expr, level)

                    # Marca blocos do body como visitados (independente de already_handled)
                    for _vbid in body_all:
                        visited.add(_vbid)
                    return

                # Emite stmts do header antes do for (ex: setup de lista no padrão range() MicroPython)
                hdr_stmts_for = get_block_statements(node, header_bid) or []
                # Filtra stmts que são plumbing do for-iter (next/iter refs) — não devem aparecer
                hdr_user_stmts = [
                    st for st in hdr_stmts_for
                    if not (isinstance(st, Stmt) and st.kind == "assign"
                            and isinstance(st.expr, Expr)
                            and st.expr.kind in ("next", "anext", "iter"))
                ]
                if hdr_user_stmts:
                    emit_statements(lines, hdr_user_stmts, level)

                kw = "async for" if is_afor else "for"
                emit(lines, f"{kw} {loop_var} in {iter_txt}:", level)
                if body:
                    render_region(lines, body, level + 1, loop_set=loop_set, loop_meta=loop_meta, in_finally=False, in_except=False)
                else:
                    emit(lines, "pass", level + 1)
                return

            # WHILE: verifica se é while True (latch é uncondicional JUMP_BACKWARD)
            cond_expr = get_block_condition(node, header_bid, 0)

            # Detecta while True: o latch é um JUMP_BACKWARD puro (sem condição)
            # e a condição do header controla a saída (break)
            latches = list(lp.get("latches") or [])
            is_while_true = False
            if cond_expr is not None and latches:
                # Verifica se todos os latches são apenas JUMP_BACKWARD
                all_latch_unconditional = True
                for latch_bid in latches:
                    latch_ops = set(block_opnames(ra, latch_bid))
                    if not latch_ops.issubset({"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "NOP"}):
                        all_latch_unconditional = False
                        break
                if all_latch_unconditional:
                    # Se body_entry != header, o header foi promovido (while cond:, não while True:)
                    body_entry = lp.get("body_entry", header_bid)
                    if body_entry == header_bid and header_bid in if_by_cond:
                        h_if = if_by_cond[header_bid]
                        then_bids = set(h_if.get("then_blocks") or [])
                        else_bids = set(h_if.get("else_blocks") or [])
                        # Se then ou else contém blocos fora do loop -> break pattern
                        if then_bids - loop_set or else_bids - loop_set:
                            is_while_true = True

            if is_while_true:
                # while True: render_if emite os stmts do header e o if/break
                emit(lines, "while True:", level)
                h_if = if_by_cond[header_bid]
                render_if(
                    lines, h_if, level + 1,
                    loop_set=loop_set, loop_meta=loop_meta,
                    in_finally=False, in_except=False,
                    loop_cond_expr=None, loop_header_bid=header_bid
                )
                # Renderiza resto do body (excluindo header, latches puros e já visitados)
                _latch_only = {"JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT", "NOP"}
                rest = [b for b in body if b not in visited
                        and not set(block_opnames(ra, b)).issubset(_latch_only)]
                if rest:
                    render_region(
                        lines, rest, level + 1,
                        loop_set=loop_set, loop_meta=loop_meta,
                        in_finally=False, in_except=False,
                        loop_cond_expr=None, loop_header_bid=header_bid
                    )
            else:
                # while normal com condição
                hdr_stmts = get_block_statements(node, header_bid) or []
                cond_txt = expr_repr(cond_expr) if cond_expr is not None else "True"

                if not body:
                    # Self-loop: o header É o corpo do loop
                    emit(lines, f"while {cond_txt}:", level)
                    if hdr_stmts:
                        emit_statements(lines, hdr_stmts, level + 1, in_finally=False, in_except=False)
                    else:
                        emit(lines, "pass", level + 1)
                else:
                    # While normal: stmts do header antes do while (setup)
                    if hdr_stmts:
                        emit_statements(lines, hdr_stmts, level, in_finally=False, in_except=False)
                    emit(lines, f"while {cond_txt}:", level)
                    render_region(
                        lines, body, level + 1,
                        loop_set=loop_set, loop_meta=loop_meta,
                        in_finally=False, in_except=False,
                        loop_cond_expr=cond_expr, loop_header_bid=header_bid
                    )

        # Emite global/nonlocal no início do corpo
        for g in global_decls:
            for gname in (g.get("names") or []):
                emit(out, f"global {gname}", 1)
        for nl in nonlocal_decls:
            for nlname in (nl.get("names") or []):
                emit(out, f"nonlocal {nlname}", 1)

        render_region(out, order, 1)
        cleaned = []
        for ln in out:
            cleaned.append(ln)
        out = cleaned

        i = 0
        while i < len(out) - 1:
            a = out[i].strip()
            b = out[i + 1].strip()
            # Só remove pass se o próximo statement está no MESMO nível de indentação
            a_indent = len(out[i]) - len(out[i].lstrip())
            b_indent = len(out[i + 1]) - len(out[i + 1].lstrip())
            if a == "pass" and a_indent == b_indent and (b.startswith("return") or b in ("break", "continue") or b.startswith("raise")):
                del out[i]
                continue
            i += 1
            
        if not any(ln.strip() for ln in out[1:]):
            emit(out, "pass", 1)

        # Suprime 'return None' espúrio no final de generators.
        # Em generators, o return None implícito no fim do bytecode nunca deve ser
        # exibido — basta o gerador "sair" (raises StopIteration automaticamente).
        is_generator_func = any(
            ("yield " in ln or ln.strip() == "yield"
             or "yield from " in ln)
            for ln in out[1:]
        )
        if is_generator_func:
            for i in range(len(out) - 1, 0, -1):
                stripped = out[i].strip()
                if stripped:
                    if stripped == "return None":
                        del out[i]
                    break

        return out

    return "\n".join(render_code_object(tree))

