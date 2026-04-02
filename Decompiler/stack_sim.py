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

            # --- materialização controlada de return ---
            ret_expr = None
            for v in cur_stack[::-1]:
                if isinstance(v, Expr) and v.kind == "return_value":
                    ret_expr = v
                    break

            if ret_expr is not None:
                is_loop_cleanup = block.get("loop_after") is not None
                val = ret_expr.args[0] if ret_expr.args else None

                # Normaliza detecção de None (Expr(const None) ou None)
                is_none = (
                    val is None
                    or (isinstance(val, Expr) and val.kind == "const" and val.value is None)
                )

                # Heurística: se o bloco já tem statements "reais" (ex.: print),
                # então esse RETURN_CONST None é muito provavelmente epílogo/cleanup (ex.: finally),
                # e NÃO deve virar "return None" no pseudo-código.
                has_real_stmt = any(s.kind not in ("del",) for s in stmts)

                # Regras:
                # - return com valor: materializa sempre (fora de cleanup de loop)
                # - return None: materializa apenas se NÃO houver statements reais no bloco
                #   (evita colar return None em finally)
                if not is_loop_cleanup:
                    if not is_none:
                        stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))
                    else:
                        if not has_real_stmt:
                            stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))

                # remove todos os marcadores
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

    # ---- Pós-processamento: short-circuit and/or ----
    _fix_short_circuit(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=debug)

    # ---- Pós-processamento: comprehensions inlined (PEP 709) ----
    _fix_comprehensions(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=debug)

    # ---- Pós-processamento: yield from (GET_YIELD_FROM_ITER + SEND loop) ----
    yield_from_blocks = _fix_yield_from(blocks, cfg, block_statements, in_stack, out_stack, debug=debug)

    return {
        "in_stack": in_stack,
        "out_stack": out_stack,
        "in_fp": in_fp,
        "out_fp": out_fp,
        "block_statements": block_statements,
        "block_conditions": block_conditions,
        "yield_from_blocks": yield_from_blocks,
    }

def _fix_short_circuit(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=False):
    """Substitui phi(a,b) por binop(and/or) quando vem de short-circuit."""
    block_by_id = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)

    for b in blocks:
        bid = b["id"]
        instrs = b.get("instructions", []) or []
        if len(instrs) < 2:
            continue
        last = instrs[-1]
        prev = instrs[-2]
        op_last = last.get("opname", "")
        op_prev = prev.get("opname", "")

        # Precisa terminar com COPY(1) + POP_JUMP_IF_*
        if not (op_last.startswith("POP_JUMP") and "IF_" in op_last):
            continue
        if op_prev != "COPY" or prev.get("arg") != 1:
            continue

        is_and = "IF_FALSE" in op_last  # salta quando false → and
        is_or = "IF_TRUE" in op_last    # salta quando true  → or
        if not (is_and or is_or):
            continue

        op = "and" if is_and else "or"

        # Identifica bloco jump-target e fall-through
        jump_off = last.get("jump_target")
        jump_bid = offset_to_block.get(jump_off) if jump_off is not None else None

        succs = list(cfg.get(bid, set()))
        fall_bid = next((s for s in succs if s != jump_bid), None)
        if fall_bid is None:
            continue

        # Fall-through deve começar com POP_TOP
        fall_b = block_by_id.get(fall_bid, {})
        fall_instrs = fall_b.get("instructions", []) or []
        if not fall_instrs or fall_instrs[0].get("opname") != "POP_TOP":
            continue

        # Valor 'a' = topo do out_stack do bloco sc (o original que ficou na pilha)
        a_stack = out_stack.get(bid, [])
        b_stack = out_stack.get(fall_bid, [])
        if not a_stack or not b_stack:
            continue
        a_val = a_stack[-1]
        b_val = b_stack[-1]
        if a_val is None or b_val is None:
            continue

        # Constrói expressão and/or
        sc_expr = Expr(kind="binop", value=op, args=(a_val, b_val), origins=frozenset())

        # Blocos de merge = interseção dos sucessores de fall_bid e jump_bid
        fall_succs = set(cfg.get(fall_bid, set()))
        sc_succs = set(cfg.get(bid, set()))
        # O bloco de merge pode ser jump_bid (se o resultado fica em jump_bid)
        # ou pode ser um bloco posterior. Verifica onde o phi aparece.
        candidates = fall_succs | (sc_succs - {fall_bid})

        def _replace_phi_in_stack(stk, old_a, old_b, new_expr):
            """Substitui o primeiro phi que contenha old_a ou old_b pelo new_expr."""
            changed = False
            new_stk = list(stk)
            for i, v in enumerate(new_stk):
                if not (isinstance(v, Expr) and v.kind == "phi"):
                    continue
                phi_args = v.args or ()
                # Compara por repr para evitar problemas de identidade de objetos
                a_repr = expr_repr(old_a)
                b_repr = expr_repr(old_b)
                phi_reprs = {expr_repr(x) for x in phi_args}
                if a_repr in phi_reprs or b_repr in phi_reprs:
                    new_stk[i] = new_expr
                    changed = True
                    break
            return new_stk, changed

        for merge_bid in candidates:
            merge_in = in_stack.get(merge_bid, [])
            new_merge, patched = _replace_phi_in_stack(merge_in, a_val, b_val, sc_expr)
            if not patched:
                continue
            in_stack[merge_bid] = new_merge
            # Re-simula o bloco de merge para atualizar block_statements e out_stack
            merge_b = block_by_id.get(merge_bid, {})
            new_stmts = []
            new_conds = []
            cur_stk = list(new_merge)
            for instr in merge_b.get("instructions", []) or []:
                simulate_instruction(instr, cur_stk, new_stmts, new_conds, debug=False)
            # Materializa return_value (como faz o loop principal de fixpoint)
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
            # Atualiza out_stack para que blocos subsequentes vejam o valor corrigido
            out_stack[merge_bid] = [v for v in cur_stk if not (isinstance(v, Expr) and v.kind == "return_value")]
            if debug:
                print(f"[DEBUG] short-circuit {op}: patched phi em bloco {merge_bid}")


def _fix_comprehensions(blocks, cfg, block_statements, block_conditions, in_stack, out_stack, debug=False):
    """Detecta comprehensions inlined (PEP 709) e substitui phi do acumulador por list_comp/set_comp."""
    block_by_id = build_block_by_id(blocks)
    offset_to_block = build_offset_to_block(blocks)
    succs = {bid: set(cfg.get(bid, set())) for bid in block_by_id}
    preds = build_predecessor_map(blocks, cfg)

    def block_opnames(bid):
        return get_block_opnames(block_by_id.get(bid, {}))

    # Busca blocos com LOAD_FAST_AND_CLEAR (início de comprehension inlined)
    for b in blocks:
        bid = b["id"]
        ops = block_opnames(bid)
        if "LOAD_FAST_AND_CLEAR" not in ops:
            continue

        instrs = b.get("instructions", []) or []
        # Extrai a(s) variável(is) salvas (LOAD_FAST_AND_CLEAR args)
        lfc_vars = []
        for ins in instrs:
            if ins["opname"] == "LOAD_FAST_AND_CLEAR":
                v = ins.get("argval") or ins.get("argrepr")
                if v:
                    lfc_vars.append(v)
        lfc_var = lfc_vars[0] if lfc_vars else None
        if lfc_var is None:
            continue

        # Encontra o bloco com BUILD_LIST/BUILD_SET/BUILD_MAP e o loop header (FOR_ITER)
        # Percorre o CFG a partir do bloco atual
        def find_comp_structure(start_bid, visited_bids=None):
            """Retorna (build_bid, header_bid, body_bid, comp_kind) ou None."""
            if visited_bids is None:
                visited_bids = set()
            if start_bid in visited_bids or len(visited_bids) > 10:
                return None
            visited_bids.add(start_bid)
            ops_here = set(block_opnames(start_bid))
            if "FOR_ITER" in ops_here:
                return None  # já passou do ponto de busca
            # Verifica se tem BUILD_LIST/SET/MAP
            build_kind = None
            if "BUILD_LIST" in ops_here:
                build_kind = "list"
            elif "BUILD_SET" in ops_here:
                build_kind = "set"
            elif "BUILD_MAP" in ops_here:
                build_kind = "dict"
            for succ in succs.get(start_bid, set()):
                succ_ops = set(block_opnames(succ))
                if "FOR_ITER" in succ_ops:
                    # Encontrou o loop header
                    # Procura o corpo (body block com LIST_APPEND/SET_ADD/MAP_ADD)
                    for body_bid in succs.get(succ, set()):
                        body_ops = set(block_opnames(body_bid))
                        if "LIST_APPEND" in body_ops:
                            return (start_bid, succ, body_bid, "list")
                        if "SET_ADD" in body_ops:
                            return (start_bid, succ, body_bid, "set")
                        if "MAP_ADD" in body_ops:
                            return (start_bid, succ, body_bid, "dict")
                else:
                    result = find_comp_structure(succ, visited_bids)
                    if result:
                        return result
            return None

        comp_struct = find_comp_structure(bid)
        if comp_struct is None:
            continue

        build_bid, header_bid, body_bid, comp_kind = comp_struct

        if debug:
            print(f"[DEBUG] comprehension: lfc_var={lfc_var} build={build_bid} header={header_bid} body={body_bid} kind={comp_kind}")

        # Extrai o elemento sendo acumulado do body block
        body_instrs = block_by_id.get(body_bid, {}).get("instructions", []) or []
        append_ops = {"list": "LIST_APPEND", "set": "SET_ADD", "dict": "MAP_ADD"}
        append_op = append_ops[comp_kind]

        # Re-simula o body block para obter o elemento antes do LIST_APPEND
        body_in = in_stack.get(body_bid, [])
        cur_stk = list(body_in)
        stmts_tmp = []
        conds_tmp = []
        comp_element = None
        comp_cond = None
        comp_key = None   # dict_comp: chave
        comp_val = None   # dict_comp: valor

        for ins in body_instrs:
            op = ins["opname"]
            if op == append_op:
                if comp_kind == "dict":
                    # MAP_ADD: cur_stk[-2]=key, cur_stk[-1]=value
                    if len(cur_stk) >= 2:
                        k_e = cur_stk[-2]
                        v_e = cur_stk[-1]
                        if isinstance(k_e, Expr) and isinstance(v_e, Expr):
                            comp_key = k_e
                            comp_val = v_e
                            comp_element = comp_key  # sentinel para o check abaixo
                else:
                    # Elemento é o topo da pilha
                    if cur_stk:
                        comp_element = cur_stk[-1]
                        if not isinstance(comp_element, Expr):
                            comp_element = None
                break
            simulate_instruction(ins, cur_stk, stmts_tmp, conds_tmp, debug=False)

        if comp_element is None:
            continue

        # Extrai a condição de filtro (ex: for x in items if x > 0)
        # Blocos de corpo SEM LIST_APPEND mas com COND (POP_JUMP_IF_*)
        for filter_bid in succs.get(header_bid, set()):
            if filter_bid == body_bid:
                continue
            filter_ops = set(block_opnames(filter_bid))
            if any(op.startswith("POP_JUMP") for op in filter_ops):
                filter_conds = block_conditions.get(filter_bid, [])
                if filter_conds:
                    comp_cond = filter_conds[0]
                    break

        # Extrai o iterável: in_stack do header_bid deve ter iter(iterable) no topo
        header_in = in_stack.get(header_bid, [])
        iterable_expr = None
        for v in reversed(header_in):
            if isinstance(v, Expr) and v.kind == "iter":
                iterable_expr = v.args[0] if v.args else v
                break
        if iterable_expr is None:
            continue

        # Cria o Expr de comprehension
        if comp_kind == "list":
            comp_args = (comp_element, iterable_expr) if comp_cond is None else (comp_element, iterable_expr, comp_cond)
            comp_expr = Expr(kind="list_comp", value=lfc_var, args=comp_args, origins=frozenset())
        elif comp_kind == "set":
            comp_args = (comp_element, iterable_expr) if comp_cond is None else (comp_element, iterable_expr, comp_cond)
            comp_expr = Expr(kind="set_comp", value=lfc_var, args=comp_args, origins=frozenset())
        else:  # dict_comp
            if comp_key is None or comp_val is None:
                continue
            # Loop var: "k, v" para tuple unpacking (múltiplos LOAD_FAST_AND_CLEAR)
            lv = ", ".join(lfc_vars) if len(lfc_vars) >= 2 else lfc_var
            comp_args = (comp_key, comp_val, iterable_expr) if comp_cond is None else (comp_key, comp_val, iterable_expr, comp_cond)
            comp_expr = Expr(kind="dict_comp", value=lv, args=comp_args, origins=frozenset())

        # Encontra o bloco APÓS o loop (exit do FOR_ITER)
        # Exit = successor do header que não é o body
        exit_bid = None
        for s in succs.get(header_bid, set()):
            body_ops_set = set(block_opnames(s))
            if "JUMP_BACKWARD" not in body_ops_set and "JUMP_BACKWARD_NO_INTERRUPT" not in body_ops_set:
                # Verifica se não é o loop body
                if s != body_bid:
                    exit_bid = s
                    break
        # Se não encontrou, tenta o successor do header que não é body
        if exit_bid is None:
            for s in succs.get(header_bid, set()):
                if s != body_bid:
                    exit_bid = s
                    break

        if debug:
            print(f"[DEBUG] comprehension exit_bid={exit_bid}")

        # Procura o bloco onde result = phi(accumulator) é armazenado
        # É o bloco após exit_bid ou o próprio exit_bid
        result_bid = exit_bid
        result_target = None
        search_bids = [exit_bid] if exit_bid is not None else []
        # Também verifica o successor do exit_bid
        if exit_bid is not None:
            for s in succs.get(exit_bid, set()):
                search_bids.append(s)

        for sb in search_bids:
            if sb is None:
                continue
            stmts_here = block_statements.get(sb, [])
            for st in stmts_here:
                if not (isinstance(st, Stmt) and st.kind == "assign"):
                    continue
                if not isinstance(st.expr, Expr):
                    continue
                if st.expr.kind != "phi":
                    continue
                # Verifica se este phi representa o acumulador (contém list/list_append/set etc.)
                phi_args = st.expr.args or ()
                has_accum = False
                for pa in phi_args:
                    if isinstance(pa, Expr) and pa.kind in ("list", "list_append", "set", "set_add", "dict", "map_add"):
                        has_accum = True
                        break
                    # Também verifica phi aninhado com <cycle>
                    if isinstance(pa, Expr) and pa.kind == "phi":
                        has_accum = True
                        break
                if has_accum or len(phi_args) >= 2:
                    result_target = st.target
                    result_bid = sb
                    break
            if result_target:
                break

        if result_target is None:
            if debug:
                print(f"[DEBUG] comprehension: não encontrou result_target")
            continue

        # Substitui o stmt "result = phi(...)" por "result = list_comp_expr" no result_bid
        old_stmts = block_statements.get(result_bid, [])
        new_stmts = []
        patched = False
        for st in old_stmts:
            if (not patched and isinstance(st, Stmt) and st.kind == "assign"
                    and st.target == result_target
                    and isinstance(st.expr, Expr) and st.expr.kind == "phi"):
                new_stmts.append(Stmt(kind="assign", target=result_target, expr=comp_expr,
                                      origins=st.origins))
                patched = True
            else:
                new_stmts.append(st)

        if patched:
            block_statements[result_bid] = new_stmts
            if debug:
                print(f"[DEBUG] comprehension: {result_target} = {comp_kind}_comp em bloco {result_bid}")

            # Suprime stmts "x = x" (restauração de LOAD_FAST_AND_CLEAR) para todos os lfc_vars
            lfc_vars_set = set(lfc_vars)
            for cleanup_bid in list(block_by_id.keys()):
                c_stmts = block_statements.get(cleanup_bid, [])
                c_new = []
                changed = False
                for st in c_stmts:
                    # Suprime "x = x" (self-assignment de restauração)
                    if (isinstance(st, Stmt) and st.kind == "assign"
                            and st.target in lfc_vars_set
                            and isinstance(st.expr, Expr) and st.expr.kind == "name"
                            and st.expr.value == st.target):
                        changed = True
                        continue
                    c_new.append(st)
                if changed:
                    block_statements[cleanup_bid] = c_new


def _fix_yield_from(blocks, cfg, block_statements, in_stack, out_stack, debug=False):
    """Detecta padrões yield from (GET_YIELD_FROM_ITER + SEND loop) e simplifica.
    Adiciona Stmt(kind='yield_from') ao bloco setup e marca blocos internos."""
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

        # Extrai iterável do out_stack (yield_from_iter, await ou anext expr)
        out = out_stack.get(bid, [])
        iterable_expr = None
        if is_anext:
            # GET_ANEXT: extrai o iterável original (unwrap anext→aiter→iterable)
            for v in reversed(out):
                if isinstance(v, Expr) and v.kind == "anext" and v.args:
                    aiter_obj = v.args[0]
                    # Unwrap aiter para obter o iterável original
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

        # Encontra o SEND block (successor direto com SEND)
        send_bid = None
        for succ in cfg.get(bid, set()):
            s_ops = block_opnames(succ)
            if "SEND" in s_ops:
                send_bid = succ
                break
        if send_bid is None:
            continue

        # Encontra o END_SEND block: alvo do SEND quando StopIteration/coroutine done
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

        # BFS de send_bid, mas não ultrapassa o bloco END_SEND nem blocos END_ASYNC_FOR
        # (blocos normais após END_SEND são código do usuário, não infraestrutura)
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

        # Marca END_SEND como interno apenas se não há código do usuário após END_SEND
        # Infra pura: END_SEND + POP_TOP + NOP + RESUME + RETURN_CONST None (implícito)
        # NÃO é infra: STORE_FAST, RETURN_CONST 'done', LOAD_FAST, RETURN_VALUE, etc.
        if end_send_bid is not None:
            end_instrs = block_by_id.get(end_send_bid, {}).get("instructions", []) or []
            pure_infra = True
            for ins in end_instrs:
                op_i = ins["opname"]
                if op_i in ("END_SEND", "POP_TOP", "NOP", "RESUME"):
                    continue
                if op_i == "RETURN_CONST" and ins.get("argval") is None:
                    continue  # return None implícito
                pure_infra = False
                break
            if pure_infra:
                internal.add(end_send_bid)

        # Detecta se END_SEND captura o resultado (STORE_FAST/STORE_NAME logo após END_SEND)
        # → `target = await expr` / `target = yield from iterable`
        # Quando end_send_bid é pure_infra (só END_SEND), verifica o bloco successor
        # (acontece quando o exception table cria um novo líder imediatamente após END_SEND)
        yf_target = None
        store_bid = None  # bloco onde está o STORE_FAST (pode ser end_send_bid ou seu successor)
        if end_send_bid is not None and end_send_bid not in internal:
            # END_SEND não é pure_infra: STORE pode estar no mesmo bloco
            store_bid = end_send_bid
        elif end_send_bid is not None and end_send_bid in internal:
            # END_SEND é pure_infra: STORE está no bloco successor (se existir)
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
                break  # primeira instrução não-END_SEND determina o padrão

            if yf_target is not None:
                # Remove o phi-assign `var = phi(...)` do store_bid
                old_stmts = list(block_statements.get(store_bid, []))
                new_stmts = [s for s in old_stmts
                             if not (isinstance(s, Stmt) and s.kind == "assign"
                                     and s.target == yf_target)]
                block_statements[store_bid] = new_stmts

        # GET_AWAITABLE 2 = await __aexit__(...) — infraestrutura do async with.
        # Não gera stmt; marca o bloco setup e os blocos de cleanup como internos.
        if is_await:
            is_aexit_await = any(
                ins["opname"] == "GET_AWAITABLE" and ins.get("arg", 0) == 2
                for ins in (block_by_id.get(bid, {}).get("instructions", []) or [])
            )
            if is_aexit_await:
                yield_from_internal.update(internal)
                yield_from_internal.add(bid)
                # Marca end_send_bid e seus sucessores de cleanup como internos
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
                continue  # Não adiciona stmt

        # Adiciona Stmt ao bloco setup:
        # GET_ANEXT (async for) → Stmt(kind="async_for_item")
        # GET_AWAITABLE → Stmt(kind="await")
        # GET_YIELD_FROM_ITER → Stmt(kind="yield_from")
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
            # se esse predecessor não tem esse slot, ignore (não injete unknown)
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
            # ninguém tinha esse slot -> não inventa pilha
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

    # -------------------------
    # Exception machinery 3.11+
    # -------------------------
    if op == "PUSH_EXC_INFO":
        # Python 3.12: PUSH_EXC_INFO empurra (prev_exc, new_exc) na pilha de valores.
        # Stack effect: (-- prev_exc, new_exc). prev_exc é a exceção ativa anterior (salva
        # internamente); new_exc é a exceção sendo capturada agora (fica no TOS).
        # Isso é necessário para que SWAP 2 antes de POP_EXCEPT possa colocar o valor
        # de retorno abaixo de prev_exc, e POP_EXCEPT remova prev_exc corretamente.
        prev_exc = Expr(kind="exc", value="prev_exc", origins=frozenset({off}))
        new_exc  = Expr(kind="exc", value="exc",      origins=frozenset({off}))
        push(prev_exc)   # prev_exc fica na posição 2 (abaixo)
        push(new_exc)    # new_exc fica no TOS
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
        # COPY(n) duplica o n-ésimo item do topo (1-indexed, TOS=1)
        idx = -n
        if n > 0 and (-idx) <= len(stack):
            push(stack[idx])
        else:
            push(unknown())
        return

    if op == "SWAP":
        n = instr.get("arg") or 0
        # SWAP(n) troca TOS com o n-ésimo item do topo (1-indexed)
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

    # -------------------------
    # Restante
    # -------------------------
    if op == "PUSH_NULL":
        push(Expr(kind="null", origins=frozenset({off})))
        return

    if op == "LOAD_CONST":
        push(Expr(kind="const", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op in ("LOAD_FAST", "LOAD_NAME", "LOAD_GLOBAL", "LOAD_DEREF"):
        # Em 3.12, LOAD_GLOBAL com arg & 1 == 1 empurra NULL antes do valor
        # (usado para function calls: NULL + callable)
        if op == "LOAD_GLOBAL":
            raw_arg = instr.get("arg") or 0
            if raw_arg & 1:
                push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    # --- Fase 1: LOAD_ATTR ---
    if op == "LOAD_ATTR":
        obj = pop() or unknown()
        attr_name = instr.get("argval")
        # Em 3.12, LOAD_ATTR com arg & 1 == 1 funciona como method lookup
        # e empurra [NULL, attr] (como LOAD_METHOD)
        raw_arg = instr.get("arg") or 0
        is_method = bool(raw_arg & 1)
        if is_method:
            push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr_name, args=(obj,), origins=frozenset({off})))
        return

    # --- Fase 5: LOAD_CLOSURE ---
    if op == "LOAD_CLOSURE":
        push(Expr(kind="closure_var", value=instr.get("argval"), origins=frozenset({off})))
        return

    # --- Fase 5: LOAD_FAST_CHECK / LOAD_FAST_AND_CLEAR ---
    if op in ("LOAD_FAST_CHECK", "LOAD_FAST_AND_CLEAR"):
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    # --- Fase 5: LOAD_SUPER_ATTR ---
    if op == "LOAD_SUPER_ATTR":
        self_val = pop() or unknown()
        self_type = pop() or unknown()
        super_fn = pop() or unknown()
        attr_name = instr.get("argval")
        super_call = Expr(kind="call", args=(Expr(kind="name", value="super", origins=frozenset({off})),), origins=frozenset({off}))
        push(Expr(kind="attr", value=attr_name, args=(super_call,), origins=frozenset({off})))
        return

    # --- Fase 9: LOAD_ASSERTION_ERROR ---
    if op == "LOAD_ASSERTION_ERROR":
        push(Expr(kind="name", value="AssertionError", origins=frozenset({off})))
        return

    # --- LOAD_BUILD_CLASS ---
    if op == "LOAD_BUILD_CLASS":
        push(Expr(kind="name", value="__build_class__", origins=frozenset({off})))
        return

    # --- LOAD_LOCALS ---
    if op == "LOAD_LOCALS":
        push(Expr(kind="call", args=(Expr(kind="name", value="locals", origins=frozenset({off})),), origins=frozenset({off})))
        return

    # --- LOAD_METHOD (3.12 otimização de LOAD_ATTR para métodos) ---
    if op == "LOAD_METHOD":
        obj = pop() or unknown()
        attr_name = instr.get("argval")
        push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr_name, args=(obj,), origins=frozenset({off})))
        return

    # --- LOAD_SUPER_METHOD / LOAD_ZERO_SUPER_METHOD ---
    if op in ("LOAD_SUPER_METHOD", "LOAD_ZERO_SUPER_METHOD"):
        self_val = pop() or unknown()
        self_type = pop() or unknown()
        super_fn = pop() or unknown()
        attr_name = instr.get("argval")
        super_call = Expr(kind="call", args=(Expr(kind="name", value="super", origins=frozenset({off})),), origins=frozenset({off}))
        push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr_name, args=(super_call,), origins=frozenset({off})))
        return

    # --- LOAD_ZERO_SUPER_ATTR ---
    if op == "LOAD_ZERO_SUPER_ATTR":
        self_val = pop() or unknown()
        self_type = pop() or unknown()
        super_fn = pop() or unknown()
        attr_name = instr.get("argval")
        super_call = Expr(kind="call", args=(Expr(kind="name", value="super", origins=frozenset({off})),), origins=frozenset({off}))
        push(Expr(kind="attr", value=attr_name, args=(super_call,), origins=frozenset({off})))
        return

    # --- LOAD_FROM_DICT_OR_DEREF / LOAD_FROM_DICT_OR_GLOBALS ---
    if op in ("LOAD_FROM_DICT_OR_DEREF", "LOAD_FROM_DICT_OR_GLOBALS"):
        pop()  # mapping (locals dict)
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    # --- Generic LOAD_ fallback ---
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

    # --- Fase 1: BINARY_SUBSCR, STORE_SUBSCR, DELETE_SUBSCR ---
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
        stmts.append(Stmt(kind="store_subscr", target=target_repr, expr=val, origins=frozenset({off})))
        return

    if op == "DELETE_SUBSCR":
        key = pop() or unknown()
        obj = pop() or unknown()
        target_repr = f"{expr_repr(obj)}[{expr_repr(key)}]"
        stmts.append(Stmt(kind="del_subscr", target=target_repr, origins=frozenset({off})))
        return

    # --- Fase 1: BINARY_SLICE, STORE_SLICE, BUILD_SLICE ---
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

    # --- Fase 1: UNARY_NEGATIVE, UNARY_NOT, UNARY_INVERT ---
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

    # --- Fase 1: IS_OP, CONTAINS_OP ---
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

    # --- Fase 1: END_FOR ---
    if op == "END_FOR":
        pop()
        pop()
        return

    # --- Fase 3: BUILD_SET, BUILD_MAP, BUILD_CONST_KEY_MAP ---
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

    # --- Fase 3: MAP_ADD, SET_ADD ---
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

    # --- Fase 3: DICT_MERGE, DICT_UPDATE, SET_UPDATE ---
    if op in ("DICT_MERGE", "DICT_UPDATE"):
        n = instr.get("arg") or 0
        update = pop() or unknown()
        idx = -(n)
        if -idx <= len(stack):
            d = stack[idx]
            stack[idx] = Expr(kind="dict", args=tuple(getattr(d, 'args', ())) + (
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
            # Se update é um frozenset constante, expande seus elementos
            if isinstance(update, Expr) and update.kind == "const" and isinstance(update.value, frozenset):
                new_elems = tuple(
                    Expr(kind="const", value=v, origins=frozenset({off}))
                    for v in sorted(update.value, key=repr)
                )
                stack[idx] = Expr(kind="set", args=tuple(getattr(s, 'args', ())) + new_elems, origins=frozenset({off}))
            else:
                stack[idx] = Expr(kind="set", args=tuple(getattr(s, 'args', ())) + (update,), origins=frozenset({off}))
        return

    # --- Fase 3: BUILD_STRING, FORMAT_*, CONVERT_VALUE ---
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

    # --- Fase 4: UNPACK_SEQUENCE, UNPACK_EX ---
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

    # --- Fase 2: IMPORT_NAME, IMPORT_FROM, IMPORT_STAR ---
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

    # --- Fase 5: MAKE_FUNCTION ---
    if op == "MAKE_FUNCTION":
        flags = instr.get("arg") or 0
        code = pop() or unknown()
        closure = None
        annotations = None
        kwdefaults = None
        defaults = None
        if flags & 0x08:
            closure = pop()  # closure tuple
        if flags & 0x04:
            annotations = pop()  # annotations
        if flags & 0x02:
            kwdefaults = pop()  # kwdefaults dict
        if flags & 0x01:
            defaults = pop()  # defaults tuple
        push(Expr(kind="make_function", value=flags, args=(code, defaults, kwdefaults, annotations), origins=frozenset({off})))
        return

    # --- Fase 5: MAKE_CELL, COPY_FREE_VARS ---
    if op in ("MAKE_CELL", "COPY_FREE_VARS"):
        return

    # --- Fase 6: BEFORE_WITH, WITH_EXCEPT_START ---
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

    # --- Fase 7: RETURN_GENERATOR, YIELD_VALUE ---
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

    # --- Fase 8: MATCH_* opcodes ---
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

    # --- Fase 9: EXTENDED_ARG, CALL_INTRINSIC_1/2 ---
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
                stack[-1] = Expr(kind="list_extend", args=(lst, it or unknown()), origins=frozenset({off}))
        else:
            stack[-1] = Expr(kind="list_extend", args=(lst or unknown(), it or unknown()), origins=frozenset({off}))
        return

    if op == "LIST_APPEND":
        n = instr.get("arg") or 0
        item = pop()
        idx = -n  # PEEK(n) após pop: stack[-n] é o acumulador (mesmo índice do CPython PEEK)
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
            pop()  # function call com NULL
        elif stack and isinstance(stack[-1], Expr):
            # Sem NULL: o item abaixo do callable é o callable real (method call em 3.12)
            # LOAD_NAME(decorator) + MAKE_FUNCTION + CALL 0 → swap: decorator(make_function)
            # LOAD_ASSERTION_ERROR + LOAD_CONST(msg) + CALL 0 → swap: AssertionError(msg)
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
        # Suprime chamada __exit__(None, None, None) gerada pelo with-statement
        if isinstance(v, Expr) and v.kind == "call" and v.args:
            fn = v.args[0]
            if isinstance(fn, Expr) and fn.kind in ("with_exit", "with_cleanup", "async_with_exit"):
                return
        stmts.append(Stmt(kind="expr", expr=v, origins=frozenset({off})))
        return

    # --- Fase 1: STORE_ATTR, DELETE_ATTR ---
    if op == "STORE_ATTR":
        obj = pop() or unknown()
        val = pop() or unknown()
        attr_name = str(instr.get("argval"))
        obj_repr = expr_repr(obj)
        stmts.append(Stmt(kind="store_attr", target=attr_name, expr=val, extra=obj_repr, origins=frozenset({off})))
        return

    if op == "DELETE_ATTR":
        obj = pop() or unknown()
        attr_name = str(instr.get("argval"))
        obj_repr = expr_repr(obj)
        stmts.append(Stmt(kind="del_attr", target=attr_name, extra=obj_repr, origins=frozenset({off})))
        return

    # --- Fase 4: DELETE_NAME, DELETE_GLOBAL, DELETE_DEREF ---
    if op in ("DELETE_NAME", "DELETE_GLOBAL", "DELETE_DEREF"):
        target = str(instr.get("argval"))
        stmts.append(Stmt(kind="del", target=target, origins=frozenset({off})))
        return

    if op in ("STORE_FAST", "STORE_FAST_MAYBE_NULL", "STORE_NAME", "STORE_GLOBAL", "STORE_DEREF"):
        target = str(instr.get("argval"))
        rhs = pop() or unknown()

        # --- Fase 2: Import detection ---
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

    # --- Fase 1: STORE_ATTR for generic STORE_ fallback (catches STORE_SUBSCR already handled above) ---
    if op.startswith("STORE_"):
        rhs = pop() or unknown()
        stmts.append(Stmt(kind="assign", target="unknown_target", expr=rhs, origins=frozenset({off})))
        return

    # --- Fase 1: POP_JUMP_IF_NONE / POP_JUMP_IF_NOT_NONE ---
    if op in ("POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE"):
        cond = pop()
        if cond is not None:
            none_const = Expr(kind="const", value=None, origins=frozenset({off}))
            if op == "POP_JUMP_IF_NONE":
                # jump_on_true("POP_JUMP_IF_NONE") = False → true_succ = fall_block (NOT None)
                # Condição deve ser "is not None" para que "if cond: [fall]" faça sentido
                expr = Expr(kind="is", value=1, args=(cond, none_const), origins=frozenset({off}))
            else:
                # POP_JUMP_IF_NOT_NONE: jump_on_true = True → true_succ = jump_block (NOT None)
                # Condição "is not None" para que "if cond: [jump]" faça sentido
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

    # -------------------------
    # RETURN: apenas marca (decisão é no nível do bloco)
    # -------------------------
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

    # --- Opcodes de salto puro (sem efeito na pilha, CFG trata) ---
    if op in ("JUMP", "JUMP_FORWARD", "JUMP_BACKWARD",
              "JUMP_BACKWARD_NO_INTERRUPT", "JUMP_NO_INTERRUPT"):
        return

    # --- Pre-3.11 / sem efeito de pilha em 3.12 ---
    if op in ("POP_BLOCK", "SETUP_FINALLY", "SETUP_WITH", "SETUP_CLEANUP",
              "SETUP_ANNOTATIONS", "INTERPRETER_EXIT"):
        return

    # --- END_ASYNC_FOR ---
    if op == "END_ASYNC_FOR":
        pop()
        pop()
        return

    # --- CLEANUP_THROW ---
    if op == "CLEANUP_THROW":
        pop()  # exc
        val = pop() or unknown()
        pop()  # sub
        push(val)
        return

    # --- GET_YIELD_FROM_ITER ---
    if op == "GET_YIELD_FROM_ITER":
        iterable = pop() or unknown()
        push(Expr(kind="yield_from_iter", args=(iterable,), origins=frozenset({off})))
        return

    # --- CHECK_EG_MATCH (except*, PEP 654) ---
    if op == "CHECK_EG_MATCH":
        exc_type = pop() or unknown()
        exc = pop() or unknown()
        push(Expr(kind="exc_group_remaining", args=(exc, exc_type), origins=frozenset({off})))
        push(Expr(kind="exc_group_match", args=(exc, exc_type), origins=frozenset({off})))
        return

    # --- Fallback: opcode não reconhecido ---
    if debug:
        print(f"[DEBUG] Opcode não tratado: {op} @ offset {off}")
