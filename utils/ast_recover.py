from typing import Dict, List, Set, Any, Optional
from utils.ir import Expr, Stmt
import dis
from utils.block_utils import (
    build_block_by_id, build_offset_to_block,
    si_block_statements, si_block_conditions, si_in_stack, si_out_stack,
    si_all_block_statements, si_all_block_conditions,
)
from utils.handler_classify import (
    classify_handler_block, is_pure_cleanup_block, is_finally_exc_handler,
)

_TERMINAL_OPS = {"RETURN_VALUE", "RETURN_CONST", "RERAISE", "RAISE_VARARGS"}


def block_has_terminal(bid: int, blocks_by_id: dict) -> bool:
    b = blocks_by_id.get(bid)
    if not b:
        return False
    opnames = [ins["opname"] for ins in (b.get("instructions") or [])]
    return any(op in opnames for op in _TERMINAL_OPS)


def walk_region(start_bid, all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                stop_set=None, max_nodes=256, use_norm=True, min_start_off=None):
    if start_bid is None or start_bid not in all_nodes:
        return []
    stop_set = set(stop_set or [])
    succ = succ_norm if use_norm else succ_all

    out = []
    seen = set()
    st = [start_bid]
    while st and len(out) < max_nodes:
        n = st.pop()
        if n in seen:
            continue
        seen.add(n)
        if n in stop_set:
            continue
        if min_start_off is not None and start_by_id.get(n, 10**18) < min_start_off:
            continue
        out.append(n)
        if block_has_terminal(n, blocks_by_id):
            continue
        for s in succ.get(n, set()):
            if s in stop_set:
                continue
            st.append(s)

    out.sort(key=lambda x: start_by_id.get(x, 10**18))
    return out


def build_recovered_ast(blocks, cfg, stack_info, patterns, code_obj, debug=True):

    def node(ntype, **kw):
        d = {"type": ntype}
        d.update(kw)
        return d

    if debug:
        print(f"[DEBUG] build_recovered_ast: {code_obj.co_name}")

    # ---- indexação básica ----
    blocks_sorted = sorted(blocks, key=lambda b: b["start_offset"])
    blocks_by_id = build_block_by_id(blocks_sorted)
    start_by_id = {b["id"]: b["start_offset"] for b in blocks_sorted}
    all_nodes = set(blocks_by_id.keys())
    entry = blocks_sorted[0]["id"] if blocks_sorted else None

    # cfg pode trazer dsts como set/list. Normalize.
    succ_all = {bid: set(cfg.get(bid, set())) for bid in all_nodes}
    pred_all = {bid: set() for bid in all_nodes}
    for s, dsts in succ_all.items():
        for d in dsts:
            if d in pred_all:
                pred_all[d].add(s)

    # ---- map offset -> block id ----
    offset_to_block = build_offset_to_block(blocks_sorted)

    # ---- exception table real (3.11+) ----
    exc_entries = []
    try:
        exc_entries = list(dis.Bytecode(code_obj).exception_entries)
    except Exception:
        exc_entries = []

    def blocks_overlapping_range(start, end):
        out = []
        for b in blocks_sorted:
            offs = [ins["offset"] for ins in (b.get("instructions") or [])]
            if any((o >= start) and (o < end) for o in offs):
                out.append(b["id"])
        return out

    try_regions = []
    for e in exc_entries:
        prot = blocks_overlapping_range(e.start, e.end)
        hb = offset_to_block.get(e.target)
        if hb is not None:
            hcls = classify_handler_block(blocks_by_id.get(hb, {}))
            # Filtra generator/coroutine cleanup handlers
            if hcls["is_gen_cleanup"]:
                continue
            # Filtra exception variable cleanup handlers (e=None; del e; reraise)
            if hcls["is_exc_var_cleanup"]:
                continue
            # Filtra with handler entries (WITH_EXCEPT_START ou with reraise)
            if hcls["is_with_handler"] or hcls["is_with_reraise"]:
                continue
            # Filtra comprehension restore handlers (PEP 709 inlined comprehensions)
            if hcls["is_comp_restore"]:
                continue
            # Filtra CLEANUP_THROW handlers (await/yield from coroutine cleanup)
            if hcls["is_cleanup_throw"]:
                continue
            # Filtra END_ASYNC_FOR handlers (async for StopAsyncIteration plumbing)
            if hcls["is_async_for_exit"]:
                continue
            # Filtra finally exception handlers (PUSH_EXC_INFO + código + RERAISE sem POP_EXCEPT)
            # Esses handlers protegem o else/except/plumbing e são associados ao try principal
            if is_finally_exc_handler(hb, blocks_by_id, succ_all):
                continue
        try_regions.append(
            {
                "range": (e.start, e.end),
                "depth": getattr(e, "depth", 0),
                "lasti": getattr(e, "lasti", False),
                "protected_blocks": prot,
                "handler_blocks": [hb] if hb is not None else [],
                "handler_entry": hb,
                "target_offset": e.target,
            }
        )

    # ---- Expande try_regions cujos protected_blocks são todos pure-cleanup ----
    # Quando o bloco protegido é COPY+POP_EXCEPT+RERAISE, é infraestrutura de re-raise
    # de um try/except interno. Expandimos para incluir todos os blocos que re-fazem
    # raise através desse cleanup block, obtendo o corpo real do try externo.
    for tr in try_regions:
        prot = tr.get("protected_blocks", [])
        if not prot or not all(is_pure_cleanup_block(blocks_by_id.get(bid, {})) for bid in prot):
            continue
        # Expande via cadeia reversa de exc_entries:
        # blocos que lançam exceção que chega ao cleanup block (prot[i]) via entries.
        expanded = set(prot)
        worklist = list(prot)
        while worklist:
            bid = worklist.pop()
            bid_off = start_by_id.get(bid, -1)
            for raw_e in exc_entries:
                if raw_e.target != bid_off:
                    continue
                for nb in blocks_overlapping_range(raw_e.start, raw_e.end):
                    if nb not in expanded:
                        expanded.add(nb)
                        worklist.append(nb)
        # Inclui o bloco de entrada da função (RESUME/NOP) se for predecessor normal
        # de algum bloco expandido — garante entry_bid diferente do try interno.
        if blocks_sorted:
            entry_blk = blocks_sorted[0]
            entry_id = entry_blk["id"]
            if entry_id not in expanded:
                entry_ops = set(i["opname"] for i in (entry_blk.get("instructions") or []))
                if entry_ops.issubset({"RESUME", "NOP"}):
                    if any(s in expanded for s in succ_all.get(entry_id, set())):
                        expanded.add(entry_id)
        tr["protected_blocks"] = sorted(expanded, key=lambda x: start_by_id.get(x, 10**18))

    # ---- arestas de exceção (para excluir do CFG normal) ----
    exc_edges = set()
    for tr in try_regions:
        for p in tr.get("protected_blocks") or []:
            for h in tr.get("handler_blocks") or []:
                exc_edges.add((p, h))

    # CFG "normal" = sem arestas de exceção
    succ_norm = {}
    for s in all_nodes:
        nd = set()
        for d in succ_all.get(s, set()):
            if (s, d) in exc_edges:
                continue
            nd.add(d)
        succ_norm[s] = nd

    pred_norm = {bid: set() for bid in all_nodes}
    for s, dsts in succ_norm.items():
        for d in dsts:
            pred_norm[d].add(s)

    # ---- dominadores / pós-dominadores no CFG normal ----
    def compute_dominators():
        if entry is None:
            return {}
        dom = {n: set(all_nodes) for n in all_nodes}
        dom[entry] = {entry}
        changed = True
        while changed:
            changed = False
            for n in all_nodes:
                if n == entry:
                    continue
                ps = pred_norm.get(n, set())
                if not ps:
                    new = {n}
                else:
                    inter = None
                    for p in ps:
                        inter = set(dom[p]) if inter is None else (inter & dom[p])
                    new = (inter if inter is not None else set()) | {n}
                if new != dom[n]:
                    dom[n] = new
                    changed = True
        return dom

    def compute_postdominators():
        exits = [n for n in all_nodes if not succ_norm.get(n)]
        if not exits:
            exits = list(all_nodes)

        pdom = {n: set(all_nodes) for n in all_nodes}
        for e in exits:
            pdom[e] = {e}

        changed = True
        while changed:
            changed = False
            for n in all_nodes:
                if n in exits:
                    continue
                ss = succ_norm.get(n, set())
                if not ss:
                    new = {n}
                else:
                    inter = None
                    for s in ss:
                        inter = set(pdom[s]) if inter is None else (inter & pdom[s])
                    new = (inter if inter is not None else set()) | {n}
                if new != pdom[n]:
                    pdom[n] = new
                    changed = True
        return pdom

    dom = compute_dominators() if entry is not None else {}
    pdom = compute_postdominators() if entry is not None else {}

    def immediate_postdom(n):
        if n not in pdom:
            return None
        strict = pdom[n] - {n}
        if not strict:
            return None
        cands = sorted(strict, key=lambda x: start_by_id.get(x, 10**18))
        for c in cands:
            ok = True
            for d in strict:
                if d != c and c in pdom.get(d, set()):
                    ok = False
                    break
            if ok:
                return c
        return cands[0] if cands else None

    # ---- detecta "print('Finalizado')" via stack_info ----
    def is_print_finalizado(bid: int) -> bool:
        bstmts = si_block_statements(stack_info, bid)
        for st in bstmts:
            if getattr(st, "kind", None) != "expr":
                continue
            e = getattr(st, "expr", None)
            if not isinstance(e, Expr):
                continue
            if e.kind not in ("call", "call_kw"):
                continue
            args = list(e.args or ())
            if not args:
                continue
            fn = args[0]
            if not (isinstance(fn, Expr) and fn.kind == "name" and str(fn.value) == "print"):
                continue
            for a in args[1:]:
                if isinstance(a, Expr) and a.kind == "const" and a.value == "Finalizado":
                    return True
        return False

    def detect_class_defs(blocks_sorted, stack_info):
        class_defs = []
        block_stmts = si_all_block_statements(stack_info)

        for b in blocks_sorted:
            instrs = b.get("instructions") or []
            stmts = block_stmts.get(b["id"], [])

            # Procura nos statements por chamadas a __build_class__
            for st in stmts:
                if not (isinstance(st, Stmt) and st.kind == "assign"
                        and isinstance(st.expr, Expr)
                        and st.expr.kind in ("call", "call_kw", "call_ex")):
                    continue

                call_expr = st.expr
                if not call_expr.args:
                    continue

                fn = call_expr.args[0]
                if not (isinstance(fn, Expr) and fn.kind == "name" and fn.value == "__build_class__"):
                    continue

                class_name = st.target
                if not isinstance(class_name, str):
                    continue

                # Extrai bases: args[0]=__build_class__, args[1]=make_function, args[2]=name, args[3:]=bases
                bases = []
                if len(call_expr.args) > 3:
                    bases = list(call_expr.args[3:])

                class_defs.append({
                    "type": "ClassDef",
                    "name": class_name,
                    "block": b["id"],
                    "bases": bases,
                    "decorators": [],
                })

            # Detecta decoradores de classe (calls aninhados que envolvem o nome da classe)
            class_names = {cd["name"] for cd in class_defs if cd["block"] == b["id"]}
            for st in stmts:
                if not (isinstance(st, Stmt) and st.kind == "assign"
                        and isinstance(st.expr, Expr)
                        and st.expr.kind in ("call", "call_kw")):
                    continue
                if st.target not in class_names:
                    continue
                call_expr = st.expr
                if len(call_expr.args) >= 2:
                    decorated = call_expr.args[1]
                    if (isinstance(decorated, Expr) and decorated.kind == "name"
                            and decorated.value == st.target):
                        fn = call_expr.args[0]
                        if isinstance(fn, Expr):
                            for cd in class_defs:
                                if cd["name"] == st.target and cd["block"] == b["id"]:
                                    cd["decorators"].append(fn)

        return class_defs

    # ---- basic blocks nodes ----
    basic = [
        node(
            "BasicBlock",
            id=b["id"],
            start=b["start_offset"],
            end=b["end_offset"],
            opnames=[ins["opname"] for ins in (b.get("instructions") or [])],
        )
        for b in blocks_sorted
    ]

    structures = []
    class_defs = detect_class_defs(blocks_sorted, stack_info)
    structures.extend(class_defs)


    # ---- TRY/EXCEPT/FINALLY (recuperação real) ----
    # Identifica blocos que pertencem a handlers de with (para excluí-los do try/except)
    with_handler_blocks = set(patterns.get("with_handler_blocks") or set())
    for wr in (patterns.get("with_regions") or []):
        hb = wr.get("handler_block")
        if hb is not None:
            with_handler_blocks.add(hb)

    # Agrupa exception entries por range protegido
    range_groups = {}
    for r in try_regions:
        rng = r.get("range")
        if rng:
            range_groups.setdefault(rng, []).append(r)

    processed_try_ranges = set()
    for rng, regions in sorted(range_groups.items()):
        if rng in processed_try_ranges:
            continue

        try_blocks_set = set()
        for r in regions:
            try_blocks_set.update(r.get("protected_blocks", []))
        try_blocks = sorted(try_blocks_set, key=lambda x: start_by_id.get(x, 10**18))

        if not try_blocks:
            continue

        handlers = []
        finally_handler_entry = None

        for r in regions:
            handler_entry = r.get("handler_entry")
            if handler_entry is None:
                continue
            if handler_entry in with_handler_blocks:
                continue  # handler de with, não de try/except

            h_block = blocks_by_id.get(handler_entry, {})
            h_instrs = h_block.get("instructions", []) or []
            h_opnames = [ins["opname"] for ins in h_instrs]

            has_check_exc = "CHECK_EXC_MATCH" in h_opnames
            has_push_exc = "PUSH_EXC_INFO" in h_opnames
            has_with_exc_start = "WITH_EXCEPT_START" in h_opnames

            if has_with_exc_start:
                continue  # handler de with

            if has_push_exc or has_check_exc:
                # Segue cadeia de CHECK_EXC_MATCH para detectar multi-handler
                check_chain = []  # [(check_block_id, exc_type, exc_var, jump_target_block)]

                def _extract_check_info(bid):
                    """Extrai exc_type, exc_var e jump_target de um bloco com CHECK_EXC_MATCH."""
                    blk = blocks_by_id.get(bid, {})
                    ins = blk.get("instructions", []) or []
                    et = None
                    jt_block = None
                    for idx, i in enumerate(ins):
                        if i["opname"] == "CHECK_EXC_MATCH":
                            if idx > 0:
                                prev = ins[idx - 1]
                                if prev["opname"] in ("LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR"):
                                    et = prev.get("argval")
                        if i["opname"].startswith("POP_JUMP_IF_"):
                            jt_off = i.get("jump_target")
                            if jt_off is not None:
                                jt_block = offset_to_block.get(jt_off)
                    # exc_var está no bloco fall-through (sucessor que não é o jump target)
                    ev = None
                    fall_bid = None
                    for s in succ_all.get(bid, set()):
                        if s != jt_block and s not in (succ_all.get(bid, set()) & set(try_blocks)):
                            sb = blocks_by_id.get(s, {})
                            si = sb.get("instructions", []) or []
                            if si and si[0]["opname"] in ("STORE_FAST", "STORE_NAME"):
                                ev = si[0].get("argval")
                                fall_bid = s
                                break
                    return et, ev, jt_block, fall_bid

                # Começa no handler_entry (que tem PUSH_EXC_INFO + CHECK_EXC_MATCH)
                current_check = handler_entry
                while current_check is not None:
                    cb = blocks_by_id.get(current_check, {})
                    ci = cb.get("instructions", []) or []
                    cops = [i["opname"] for i in ci]
                    if "CHECK_EXC_MATCH" not in cops:
                        break
                    et, ev, jt_block, fall_bid = _extract_check_info(current_check)
                    check_chain.append((current_check, et, ev, jt_block, fall_bid))
                    # Próximo na cadeia: o jump target do POP_JUMP_IF_FALSE
                    if jt_block is not None:
                        nb = blocks_by_id.get(jt_block, {})
                        ni = nb.get("instructions", []) or []
                        nops = [i["opname"] for i in ni]
                        if "CHECK_EXC_MATCH" in nops:
                            current_check = jt_block
                        else:
                            break
                    else:
                        break

                if check_chain:
                    # Cria um handler para cada CHECK_EXC_MATCH na cadeia
                    all_check_blocks = {c[0] for c in check_chain}
                    all_jump_targets = {c[3] for c in check_chain if c[3] is not None}
                    stop = set(try_blocks) | all_check_blocks | all_jump_targets

                    for i, (chk_bid, et, ev, jt_bid, fall_bid) in enumerate(check_chain):
                        # Walk do handler body a partir do fall-through
                        body_start = fall_bid if fall_bid else chk_bid
                        # Stop set: try blocks + outros check blocks + próximo jump target
                        h_stop = set(try_blocks)
                        for j, (other_chk, _, _, other_jt, _) in enumerate(check_chain):
                            if j != i:
                                h_stop.add(other_chk)
                                if other_jt is not None:
                                    h_stop.add(other_jt)
                        if jt_bid is not None:
                            h_stop.add(jt_bid)

                        handler_blocks = walk_region(
                            body_start,
                            all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                            stop_set=h_stop,
                            use_norm=False,
                            min_start_off=start_by_id.get(body_start),
                        )
                        # Remove blocos do finally-exception-handler que entraram via exc edges
                        # (ex: POP_EXCEPT+JUMP_BACKWARD → finally handler via exception table depth-0)
                        _fin_exc_excl = set()
                        for _fb in list(handler_blocks):
                            if is_finally_exc_handler(_fb, blocks_by_id, succ_all):
                                for _rb in walk_region(_fb,
                                                       all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                                                       use_norm=False,
                                                       min_start_off=start_by_id.get(_fb)):
                                    _fin_exc_excl.add(_rb)
                        if _fin_exc_excl:
                            handler_blocks = [b for b in handler_blocks if b not in _fin_exc_excl]
                        # Inclui o check block no handler
                        handler_blocks = sorted(
                            set(handler_blocks) | {chk_bid},
                            key=lambda x: start_by_id.get(x, 10**18)
                        )

                        handlers.append({
                            "handler_entry": chk_bid,
                            "handler_blocks": handler_blocks,
                            "exc_type": str(et) if et else None,
                            "exc_var": ev,
                        })
                else:
                    # Fallback: handler sem CHECK_EXC_MATCH chain (bare except)
                    min_off = start_by_id.get(handler_entry, None)
                    stop = set(try_blocks)
                    handler_blocks = walk_region(
                        handler_entry,
                        all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                        stop_set=stop,
                        use_norm=False,
                        min_start_off=min_off,
                    )
                    handler_blocks = sorted(set(handler_blocks), key=lambda x: start_by_id.get(x, 10**18))

                    handlers.append({
                        "handler_entry": handler_entry,
                        "handler_blocks": handler_blocks,
                        "exc_type": None,
                        "exc_var": None,
                    })
            else:
                # Handler de finally/cleanup (sem CHECK_EXC_MATCH)
                if finally_handler_entry is None:
                    finally_handler_entry = handler_entry

        # Se não há handlers de except, pode ser apenas um with - pular
        if not handlers and finally_handler_entry is None:
            continue

        processed_try_ranges.add(rng)

        # --- Detecta finally via JUMP_BACKWARD de POP_EXCEPT para offset pós-try ---
        # Em 3.12, o finally é duplicado: cópia inline (caminho normal) e handler de exceção.
        # O sinal é: algum handler block tem POP_EXCEPT + JUMP_BACKWARD para um offset
        # >= try_end. Esse offset é o início do código inline do finally.
        try_end_off = rng[1]
        finally_inline_start_bid = None
        finally_exc_handler_entry2 = None
        if handlers:
            outer_done = False
            for h in handlers:
                if outer_done:
                    break
                for hbid in h.get("handler_blocks", []):
                    if outer_done:
                        break
                    hb_data = blocks_by_id.get(hbid, {})
                    hins = hb_data.get("instructions", []) or []
                    for ins in hins:
                        op = ins["opname"]
                        if op not in ("JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"):
                            continue
                        jmp_off = ins.get("jump_target") or ins.get("argval")
                        if jmp_off is None or jmp_off < try_end_off:
                            continue
                        # JUMP_BACKWARD para offset pós-try → início do inline finally
                        finally_inline_start_bid = offset_to_block.get(jmp_off)
                        # Encontra handler da exceção que protege este bloco (POP_EXCEPT+JMP)
                        hb_start_off = start_by_id.get(hbid, -1)
                        for exc_e in exc_entries:
                            if not (exc_e.start <= hb_start_off < exc_e.end):
                                continue
                            exc_hb = offset_to_block.get(exc_e.target)
                            if exc_hb is None:
                                continue
                            _hcls = classify_handler_block(blocks_by_id.get(exc_hb, {}))
                            if (_hcls["is_gen_cleanup"]
                                    or _hcls["is_exc_var_cleanup"]
                                    or _hcls["is_comp_restore"]
                                    or _hcls["is_with_handler"] or _hcls["is_with_reraise"]):
                                continue
                            finally_exc_handler_entry2 = exc_hb
                            break
                        outer_done = True
                        break

        # Determina blocos de finally
        _infra_fin = {"PUSH_EXC_INFO", "RERAISE", "COPY", "POP_EXCEPT", "NOP",
                      "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"}

        def _has_user_code_block(bid2):
            b2 = blocks_by_id.get(bid2, {})
            ops2 = {ins["opname"] for ins in (b2.get("instructions", []) or [])}
            return bool(ops2 - _infra_fin)

        finally_blocks = []
        finally_continuation_bids = []
        post_finally_stmts = []

        if finally_inline_start_bid is not None:
            # Reúne todos os handler blocks para o stop_set
            all_h_bids_fin = set()
            for h in handlers:
                all_h_bids_fin.update(h.get("handler_blocks", []))

            stop_fin = set(try_blocks) | all_h_bids_fin

            # Walk do inline finally (caminho normal)
            finally_inline_all = walk_region(
                finally_inline_start_bid,
                all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                stop_set=stop_fin,
                use_norm=True,
                min_start_off=start_by_id.get(finally_inline_start_bid),
            )
            finally_inline_all = sorted(
                set(finally_inline_all),
                key=lambda x: start_by_id.get(x, 10**18)
            )

            # Determina split finally_blocks / continuation pelo conteúdo dos blocos inline.
            # Blocos "de continuação" são os que só contêm return (e aparecem DEPOIS de
            # blocos com código real do finally). Blocos mistos (ex: print+return) ficam
            # em finally_blocks e o return é extraído via post_finally_stmts abaixo.
            block_stmts_map = si_all_block_statements(stack_info)
            if finally_exc_handler_entry2 is not None:
                finally_blocks = []
                finally_continuation_bids = []
                found_finally = False
                for _bid in finally_inline_all:
                    _b_stmts = list(block_stmts_map.get(_bid, []))
                    _has_only_return = (
                        bool(_b_stmts)
                        and all(getattr(s, "kind", None) == "return" for s in _b_stmts)
                    )
                    if _has_only_return and found_finally:
                        # Bloco puro de return após código real do finally → continuação
                        finally_continuation_bids.append(_bid)
                    else:
                        finally_blocks.append(_bid)
                        if _b_stmts:
                            found_finally = True
            else:
                finally_blocks = finally_inline_all
                finally_continuation_bids = []

            # Extrai stmts de continuação dos blocos puro-return separados
            for cbid in finally_continuation_bids:
                post_finally_stmts.extend(block_stmts_map.get(cbid, []))

            # Para blocos mistos (finally_blocks que contêm RETURN_VALUE no bytecode):
            # o caminho de exceção termina com RERAISE, não RETURN_VALUE.
            # Qualquer return não-None no finally é continuação pós-try.
            _fin_exc_entry = finally_exc_handler_entry2
            exc_has_return = False
            if _fin_exc_entry is not None:
                _exc_walk = walk_region(
                    _fin_exc_entry,
                    all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                    stop_set=set(try_blocks),
                    use_norm=False,
                    min_start_off=start_by_id.get(_fin_exc_entry),
                )
                exc_has_return = any(
                    any(ins["opname"] in ("RETURN_VALUE", "RETURN_CONST")
                        for ins in (blocks_by_id.get(b, {}).get("instructions", []) or []))
                    for b in _exc_walk
                )
            if not exc_has_return:
                for fbid in finally_blocks:
                    b_stmts = list(block_stmts_map.get(fbid, []))
                    if not b_stmts:
                        continue
                    last_st = b_stmts[-1]
                    if (isinstance(last_st, Stmt) and last_st.kind == "return"
                            and not (isinstance(last_st.expr, Expr)
                                     and last_st.expr.kind == "const"
                                     and last_st.expr.value is None)):
                        post_finally_stmts.append(last_st)

            if debug:
                print(f"[DEBUG] Finally inline: start={finally_inline_start_bid} "
                      f"blocks={finally_blocks} cont={finally_continuation_bids} "
                      f"post_stmts={len(post_finally_stmts)}")

        elif finally_handler_entry:
            # Fallback: finally detectado pelo handler sem CHECK_EXC_MATCH (caminho antigo)
            stop_set = set(try_blocks) | {h["handler_entry"] for h in handlers}
            finally_blocks = walk_region(
                finally_handler_entry,
                all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                stop_set=stop_set,
                use_norm=False,
                min_start_off=start_by_id.get(finally_handler_entry),
            )
            finally_blocks = sorted(set(finally_blocks), key=lambda x: start_by_id.get(x, 10**18))

        # Detecta else_blocks: blocos entre o fim do try e o início do primeiro handler
        # (executados apenas quando nenhuma exceção foi levantada).
        # Discriminação de inline-finally: o bloco de inline-finally tem um predecessor
        # NORMAL que é o handler do except (JUMP_BACKWARD), enquanto o else block só é
        # alcançável pelo fall-through do último bloco do try.
        all_handler_block_ids = set()
        for h in handlers:
            all_handler_block_ids.update(h.get("handler_blocks", []))
        all_handler_block_ids.update(finally_blocks)

        else_range_start = rng[1]  # entry.end (exclusivo), = primeiro offset depois do try
        else_range_end = min(
            (r.get("target_offset") for r in regions if r.get("target_offset") is not None),
            default=10**18
        )
        # Identifica blocos inline-finally na faixa candidata:
        # são os que um handler alcança diretamente (ex: JUMP_BACKWARD do except para o
        # início do finally inline), e os alcançados a partir deles na mesma faixa.
        inline_finally_set = set()
        for h_bid in all_handler_block_ids:
            for s_bid in succ_norm.get(h_bid, set()):
                s_off = start_by_id.get(s_bid, 10**18)
                if else_range_start <= s_off < else_range_end:
                    inline_finally_set.add(s_bid)
        # Propaga para blocos alcançados pelos inline-finally (dentro da faixa)
        worklist = list(inline_finally_set)
        while worklist:
            curr = worklist.pop()
            for s_bid in succ_norm.get(curr, set()):
                if s_bid not in inline_finally_set:
                    s_off = start_by_id.get(s_bid, 10**18)
                    if else_range_start <= s_off < else_range_end:
                        inline_finally_set.add(s_bid)
                        worklist.append(s_bid)

        else_blocks = []
        if else_range_start < else_range_end:
            for b in blocks_sorted:
                b_off = b.get("start_offset", 0)
                if else_range_start <= b_off < else_range_end:
                    bid2 = b["id"]
                    if (bid2 not in try_blocks_set
                            and bid2 not in all_handler_block_ids
                            and bid2 not in inline_finally_set):
                        else_blocks.append(bid2)
        else_blocks.sort(key=lambda x: start_by_id.get(x, 10**18))

        # Exclui else sem código real: se TODOS os blocos candidatos são compostos apenas de
        # LOAD_* + RETURN_*, é a continuação natural do try (não um else explícito).
        # Casos: "return x", "return None", "return result" logo após o try body.
        # Preserva: blocos com STORE_*, BINARY_OP, CALL, etc. (código real do usuário).
        def _else_has_real_code(bids):
            pure_ops = {"RETURN_CONST", "RETURN_VALUE", "RESUME", "NOP", "COPY",
                        "FORMAT_VALUE", "BUILD_STRING"}
            for bid2 in bids:
                b2 = blocks_by_id.get(bid2, {})
                for instr in (b2.get("instructions", []) or []):
                    op = instr["opname"]
                    if op in pure_ops or op.startswith("LOAD_"):
                        continue
                    return True  # tem opcode real (STORE, BINARY_OP, CALL, etc.)
            return False

        if not _else_has_real_code(else_blocks):
            else_blocks = []

        join_after_try = immediate_postdom(try_blocks[-1]) if try_blocks else None

        # Blocos do finally exception handler (precisam de visited em codegen para suprimir)
        finally_exc_handler_bids = []
        if finally_inline_start_bid is not None and finally_exc_handler_entry2 is not None:
            finally_exc_handler_bids = sorted(
                set(walk_region(
                    finally_exc_handler_entry2,
                    all_nodes, start_by_id, succ_norm, succ_all, blocks_by_id,
                    stop_set=set(),
                    use_norm=False,
                    min_start_off=start_by_id.get(finally_exc_handler_entry2),
                )),
                key=lambda x: start_by_id.get(x, 10**18),
            )

        structures.append(
            node(
                "TryExceptFinally",
                try_blocks=try_blocks,
                handlers=handlers,
                finally_blocks=finally_blocks,
                finally_continuation_bids=finally_continuation_bids,
                finally_exc_handler_bids=finally_exc_handler_bids,
                post_finally_stmts=post_finally_stmts,
                else_blocks=else_blocks,
                join_block=join_after_try,
                # Compatibilidade: primeiro handler
                except_type=handlers[0]["exc_type"] if handlers else None,
                except_var=handlers[0].get("exc_var") if handlers else None,
                except_blocks=handlers[0]["handler_blocks"] if handlers else [],
                except_entry=handlers[0]["handler_entry"] if handlers else None,
            )
        )

        if debug:
            ht = ", ".join(f"{h.get('exc_type', '?')} as {h.get('exc_var', '?')}" for h in handlers)
            print(f"[DEBUG] TryExceptFinally: try={try_blocks} handlers=[{ht}] finally={finally_blocks}")

    # ---- MicroPython fallback: usa patterns["try_regions"] quando exc_entries está vazio ----
    if not try_regions and patterns.get("try_regions"):

        def _mpy_walk_handlers(handler_bid):
            """
            Percorre a cadeia de handlers except MicroPython a partir de handler_bid.
            Retorna lista de {"exc_type": str|None, "handler_blocks": [bid], "handler_entry": bid}.
            """
            handlers_out = []
            current_bid = handler_bid
            while current_bid is not None:
                hblock = blocks_by_id.get(current_bid, {})
                h_instrs_local = hblock.get("instructions", []) or []

                has_exc_match = any(
                    i.get("opname") == "BINARY_OP_MULTI" and i.get("argval") == "exc_match"
                    for i in h_instrs_local
                )
                if not has_exc_match:
                    break

                # Extrai exc_type: LOAD_GLOBAL/LOAD_NAME antes de BINARY_OP_MULTI exc_match
                exc_type = None
                for idx_i, instr_i in enumerate(h_instrs_local):
                    if instr_i.get("opname") == "BINARY_OP_MULTI" and instr_i.get("argval") == "exc_match":
                        j = idx_i - 1
                        if j >= 0 and h_instrs_local[j].get("opname") == "BUILD_TUPLE":
                            n_types = h_instrs_local[j].get("argval", 0)
                            exc_tuple = []
                            for k in range(j - n_types, j):
                                if 0 <= k < len(h_instrs_local):
                                    v = h_instrs_local[k].get("argval")
                                    if v:
                                        exc_tuple.append(str(v))
                            exc_type = f"({', '.join(exc_tuple)})" if exc_tuple else None
                        elif j >= 0 and h_instrs_local[j].get("opname") in ("LOAD_GLOBAL", "LOAD_NAME"):
                            exc_type = str(h_instrs_local[j].get("argval", "Exception"))
                        break

                # Encontra POP_JUMP_IF_FALSE → próximo check ou end
                pop_jump_target = None
                for instr_i in h_instrs_local:
                    if instr_i.get("opname") == "POP_JUMP_IF_FALSE":
                        pop_jump_target = instr_i.get("jump_target")
                        break

                next_bid = offset_to_block.get(pop_jump_target) if pop_jump_target is not None else None

                # Body: bloco em ordem de offset logo após o check block (não é next_bid)
                all_bids_sorted_local = sorted(all_nodes, key=lambda x: start_by_id.get(x, 10**18))
                check_idx = all_bids_sorted_local.index(current_bid) if current_bid in all_bids_sorted_local else -1
                body_bid = None
                if check_idx >= 0 and check_idx + 1 < len(all_bids_sorted_local):
                    cand = all_bids_sorted_local[check_idx + 1]
                    if cand != next_bid:
                        body_bid = cand

                # Coleta body blocks desde body_bid até encontrar next_bid ou terminal
                body_blocks = []
                if body_bid is not None:
                    stop = set()
                    if next_bid is not None:
                        stop.add(next_bid)
                    stop.add(current_bid)
                    seen_walk = set()
                    work = [body_bid]
                    while work:
                        wb = work.pop()
                        if wb in seen_walk or wb in stop:
                            continue
                        seen_walk.add(wb)
                        body_blocks.append(wb)
                        # POP_EXCEPT_JUMP sai do handler — não seguir seu target
                        wb_block_local = blocks_by_id.get(wb, {})
                        wb_instrs_local = wb_block_local.get("instructions", []) or []
                        wb_last_op = wb_instrs_local[-1].get("opname") if wb_instrs_local else None
                        if wb_last_op == "POP_EXCEPT_JUMP":
                            continue
                        for s in succ_all.get(wb, set()):
                            if s not in stop and s not in seen_walk:
                                if start_by_id.get(s, 10**18) >= start_by_id.get(body_bid, 0):
                                    work.append(s)
                    body_blocks.sort(key=lambda x: start_by_id.get(x, 10**18))

                handlers_out.append({
                    "exc_type":      exc_type,
                    "handler_blocks": [current_bid] + body_blocks,
                    "handler_entry": current_bid,
                })

                # Continua na cadeia se next_bid também tem exc_match
                if next_bid is not None:
                    nb = blocks_by_id.get(next_bid, {})
                    nb_instrs = nb.get("instructions", []) or []
                    nb_has_exc_match = any(
                        i.get("opname") == "BINARY_OP_MULTI" and i.get("argval") == "exc_match"
                        for i in nb_instrs
                    )
                    if nb_has_exc_match:
                        current_bid = next_bid
                    else:
                        break
                else:
                    break

            return handlers_out

        # Blocos que pertencem a alguma try region (como protected ou handler entry)
        _all_mpy_try_protected = set()
        _all_mpy_try_handler_entries = set()
        for _mpy_tr in patterns.get("try_regions", []):
            _all_mpy_try_protected.update(_mpy_tr.get("protected_blocks", []))
            for _mpy_h in _mpy_tr.get("handlers", []):
                hb_ = _mpy_h.get("handler_block")
                if hb_ is not None:
                    _all_mpy_try_handler_entries.add(hb_)

        def _mpy_collect_plumbing_tail(handler_bid):
            """
            A partir do handler_bid, coleta blocos de infra de exceção MicroPython
            (END_FINALLY, POP_EXCEPT_JUMP, etc.) alcançáveis via CFG que devem ser
            marcados como visitados mas não renderizados.

            Para evitar que blocos de try-except subsequentes sejam engolidos,
            a caminhada para quando encontra um bloco com SETUP_EXCEPT/FINALLY/WITH
            (início de nova região try) — esse bloco pode ser incluído como infra
            (pelo seu END_FINALLY), mas seus sucessores não são visitados.
            """
            plumbing = []
            visited_walk = set()
            work = [handler_bid]
            while work:
                wb = work.pop()
                if wb in visited_walk:
                    continue
                visited_walk.add(wb)
                wb_block = blocks_by_id.get(wb, {})
                wb_instrs = wb_block.get("instructions", []) or []
                wb_ops = {i.get("opname") for i in wb_instrs}
                # Inclui se o bloco tem infra de exceção MicroPython
                if "END_FINALLY" in wb_ops or "POP_EXCEPT_JUMP" in wb_ops:
                    plumbing.append(wb)
                # Não caminha além de blocos que iniciam uma nova região try-except
                # (SETUP_EXCEPT/SETUP_FINALLY/SETUP_WITH) — esses blocos podem ser
                # incluídos como infra (pelo END_FINALLY), mas seus sucessores
                # pertencem à próxima região.
                has_setup = wb_ops & {"SETUP_EXCEPT", "SETUP_FINALLY", "SETUP_WITH"}
                if has_setup:
                    continue
                # Também não caminha para blocos protegidos ou handler entries de
                # OUTRAS regiões try (evita engolir try-except subsequentes)
                for s in succ_all.get(wb, set()):
                    if s in visited_walk:
                        continue
                    work.append(s)
            return plumbing

        # ---- Colapsa SETUP_FINALLY + SETUP_EXCEPT aninhados → try/except/finally ----
        # Mpy-cross compila try/except/finally como dois blocos: SETUP_FINALLY externo +
        # SETUP_EXCEPT interno. Detecta pares onde o except está dentro do finally e cria
        # um único TryExceptFinally com handlers + finally_blocks.
        _cleanup_list = []  # (protected_set, hb, mpy_region) de regiões is_cleanup
        _except_list  = []  # (protected_set, hb, mpy_region, h_info) de regiões is_except
        for mpy_region_pre in patterns["try_regions"]:
            for h_info_pre in mpy_region_pre.get("handlers", []):
                hb_pre = h_info_pre.get("handler_block")
                if hb_pre is None:
                    continue
                p_pre = frozenset(mpy_region_pre.get("protected_blocks", []))
                if h_info_pre.get("is_cleanup"):
                    _cleanup_list.append((p_pre, hb_pre, mpy_region_pre))
                elif h_info_pre.get("is_except"):
                    _except_list.append((p_pre, hb_pre, mpy_region_pre, h_info_pre))

        # Encontra pares onde o except está completamente dentro do cleanup
        _merged_cleanup_ids = set()  # índices em _cleanup_list que foram merged
        _merged_except_ids  = set()  # índices em _except_list que foram merged
        for ci, (c_prot, c_hb, c_region) in enumerate(_cleanup_list):
            for ei, (e_prot, e_hb, e_region, e_h_info) in enumerate(_except_list):
                if ei in _merged_except_ids:
                    continue
                if e_prot and e_prot.issubset(c_prot):
                    # Except está dentro do cleanup → merge
                    handlers_list_m = _mpy_walk_handlers(e_hb)
                    if not handlers_list_m:
                        handlers_list_m = [{"exc_type": None, "handler_blocks": [e_hb], "handler_entry": e_hb}]

                    all_handler_bids_m = set()
                    for hl in handlers_list_m:
                        all_handler_bids_m.update(hl.get("handler_blocks", []))

                    exc_infra_m = _mpy_collect_plumbing_tail(e_hb)
                    exc_infra_m = [b for b in exc_infra_m if b not in all_handler_bids_m]

                    # Blocos de infraestrutura do cleanup (SETUP_EXCEPT, END_FINALLY, etc.)
                    # são todos os blocos do cleanup_protected exceto a body (e_prot) e os handlers
                    infra_cleanup = list(c_prot - e_prot - all_handler_bids_m)

                    structures.append(node(
                        "TryExceptFinally",
                        try_blocks=list(e_prot),
                        handlers=handlers_list_m,
                        finally_blocks=[c_hb],
                        finally_continuation_bids=[],
                        finally_exc_handler_bids=exc_infra_m + infra_cleanup,
                        post_finally_stmts=[],
                        else_blocks=[],
                        join_block=None,
                        except_type=handlers_list_m[0].get("exc_type") if handlers_list_m else None,
                        except_var=None,
                        except_blocks=handlers_list_m[0]["handler_blocks"] if handlers_list_m else [],
                        except_entry=handlers_list_m[0]["handler_entry"] if handlers_list_m else None,
                    ))

                    _merged_cleanup_ids.add(ci)
                    _merged_except_ids.add(ei)

                    if debug:
                        ht = ", ".join(h.get("exc_type", "?") or "?" for h in handlers_list_m)
                        print(f"[DEBUG] MPY TryExceptFinally MERGED: try={list(e_prot)} "
                              f"handlers=[{ht}] finally=[{c_hb}]")
                    break  # cada cleanup só se merge com um except

        for mpy_region in patterns["try_regions"]:
            protected = mpy_region.get("protected_blocks", [])
            if not protected:
                continue

            for h_info in mpy_region.get("handlers", []):
                hb = h_info.get("handler_block")
                if hb is None:
                    continue

                is_except  = h_info.get("is_except", False)
                is_cleanup = h_info.get("is_cleanup", False)

                # Pula regiões que já foram merged
                p_set = frozenset(protected)
                if is_cleanup and any(
                    c_prot == p_set and c_hb == hb
                    for ci2, (c_prot, c_hb, _) in enumerate(_cleanup_list)
                    if ci2 in _merged_cleanup_ids
                ):
                    continue
                if is_except and any(
                    e_prot == p_set and e_hb == hb
                    for ei2, (e_prot, e_hb, _, _) in enumerate(_except_list)
                    if ei2 in _merged_except_ids
                ):
                    continue

                if is_except:
                    handlers_list = _mpy_walk_handlers(hb)
                    if not handlers_list:
                        # Bare except sem exc_match
                        handlers_list = [{"exc_type": None, "handler_blocks": [hb], "handler_entry": hb}]

                    # Coleta blocos de infra de exceção (END_FINALLY, POP_EXCEPT_JUMP) para suprimir
                    all_handler_bids = set()
                    for hl in handlers_list:
                        all_handler_bids.update(hl.get("handler_blocks", []))
                    # O next_bid final (END_FINALLY / rethrow) precisa ser suprimido
                    exc_infra_bids = _mpy_collect_plumbing_tail(hb)
                    exc_infra_bids = [b for b in exc_infra_bids if b not in all_handler_bids]

                    # Extrai stmts de continuação de blocos de infra que também têm código de usuário
                    # (ex: END_FINALLY + LOAD_FAST _local_2 + RETURN_VALUE → return _local_2 pós-try)
                    post_stmts = []
                    for infra_bid in exc_infra_bids:
                        infra_stmts = si_block_statements(stack_info, infra_bid) or []
                        for st in infra_stmts:
                            if isinstance(st, Stmt) and st.kind == "return":
                                # Só inclui return não-None (return None é implícito)
                                if not (isinstance(st.expr, Expr)
                                        and st.expr.kind == "const"
                                        and st.expr.value is None):
                                    post_stmts.append(st)

                    structures.append(node(
                        "TryExceptFinally",
                        try_blocks=protected,
                        handlers=handlers_list,
                        finally_blocks=[],
                        finally_continuation_bids=[],
                        finally_exc_handler_bids=exc_infra_bids,
                        post_finally_stmts=post_stmts,
                        else_blocks=[],
                        join_block=None,
                        except_type=handlers_list[0].get("exc_type") if handlers_list else None,
                        except_var=None,
                        except_blocks=handlers_list[0]["handler_blocks"] if handlers_list else [],
                        except_entry=handlers_list[0]["handler_entry"] if handlers_list else None,
                    ))

                    if debug:
                        ht = ", ".join(h.get("exc_type", "?") or "?" for h in handlers_list)
                        print(f"[DEBUG] MPY TryExceptFinally: try={protected} handlers=[{ht}] "
                              f"infra={exc_infra_bids} post_stmts={len(post_stmts)}")

                elif is_cleanup:
                    structures.append(node(
                        "TryExceptFinally",
                        try_blocks=protected,
                        handlers=[],
                        finally_blocks=[hb],
                        finally_continuation_bids=[],
                        finally_exc_handler_bids=[],
                        post_finally_stmts=[],
                        else_blocks=[],
                        join_block=None,
                        except_type=None,
                        except_var=None,
                        except_blocks=[],
                        except_entry=None,
                    ))

                    if debug:
                        print(f"[DEBUG] MPY TryFinally: try={protected} finally=[{hb}]")

    # ---- Mantém metadados brutos ----
    for r in try_regions:
        structures.append(
            node(
                "TryRegion",
                range=r.get("range"),
                depth=r.get("depth"),
                protected_blocks=r.get("protected_blocks"),
                handler_blocks=r.get("handler_blocks"),
                handler_entry=r.get("handler_entry"),
                target_offset=r.get("target_offset"),
            )
        )

    # ---- LOOPS (do patterns) ----
    loops_by_header = {}
    for lp in (patterns.get("loops") or []):
        loops_by_header.setdefault(lp["header"], []).append(lp)

    def natural_loop(header, latch):
        loop = {header, latch}
        work = [latch]
        while work:
            n = work.pop()
            for p in pred_norm.get(n, set()):
                if p in loop:
                    continue
                if header in dom.get(p, set()):
                    loop.add(p)
                    work.append(p)
        return loop

    for header, lps in loops_by_header.items():
        latches = sorted({x["latch"] for x in lps})
        # body_entry: alvo real do back-edge (pode diferir do header se promovido por promote_loop_header)
        body_entry = lps[0].get("body_entry", header) if lps else header
        body = {header}
        for lt in latches:
            body |= natural_loop(header, lt)
        body_blocks = sorted(body, key=lambda x: start_by_id.get(x, 10**18))
        structures.append(
            node(
                "Loop",
                header=header,
                latches=latches,
                body_blocks=body_blocks,
                header_start=start_by_id.get(header),
                body_entry=body_entry,
            )
        )
        if debug:
            print(f"[DEBUG] Loop: header={header} latches={latches} body_blocks={body_blocks} body_entry={body_entry}")

    # ---- IFs (do patterns) ----
    def is_terminal_block(bid: int) -> bool:
        if bid is None:
            return False
        if not succ_norm.get(bid):
            return True
        bstmts = si_block_statements(stack_info, bid)
        return any(getattr(st, "kind", None) in ("return", "raise", "reraise") for st in bstmts) or block_has_terminal(bid, blocks_by_id)

    def collect_branch(start, join, cond_off):
        if start is None:
            return []
        seen = set()
        out = set()
        st = [start]
        while st:
            n = st.pop()
            if n in seen:
                continue
            seen.add(n)
            if join is not None and n == join:
                continue
            out.add(n)
            for s in succ_norm.get(n, ()):
                if join is not None and s == join:
                    continue
                if start_by_id.get(s, 10**18) <= cond_off:
                    continue
                st.append(s)
        return sorted(out, key=lambda x: start_by_id.get(x, 10**18))

    for iff in (patterns.get("ifs") or []):
        cond = iff.get("cond_block")
        if cond is None or cond not in all_nodes:
            continue

        cond_off = start_by_id.get(cond, -1)

        t_succ = iff.get("true_succ")
        f_succ = iff.get("false_succ")
        if t_succ is None or f_succ is None:
            t_succ, f_succ = iff.get("fall_block"), iff.get("jump_block")

        join = immediate_postdom(cond)

        then_blocks = collect_branch(t_succ, join, cond_off)
        else_blocks = collect_branch(f_succ, join, cond_off)

        if join is not None and is_terminal_block(join):
            if t_succ == join and not then_blocks:
                then_blocks = [join]
            if f_succ == join and not else_blocks:
                else_blocks = [join]

        then_set = set(then_blocks) - {cond}
        else_set = (set(else_blocks) - {cond}) - then_set

        then_blocks = sorted(then_set, key=lambda x: start_by_id.get(x, 10**18))
        else_blocks = sorted(else_set, key=lambda x: start_by_id.get(x, 10**18))

        structures.append(
            node(
                "If",
                cond_block=cond,
                opcode=iff.get("opcode"),
                jump_block=iff.get("jump_block"),
                fall_block=iff.get("fall_block"),
                true_succ=t_succ,
                false_succ=f_succ,
                jump_target_offset=iff.get("jump_target_offset"),
                join_block=join,
                then_blocks=then_blocks,
                else_blocks=else_blocks,
            )
        )

        if debug:
            print(f"[DEBUG] If: cond={cond} then={then_blocks} else={else_blocks} join={join}")

    # ---- WITH / ASYNC WITH RECOVERY ----
    all_with_handler_blocks = set(patterns.get("with_handler_blocks") or set())
    for wr in (patterns.get("with_regions") or []):
        bid = wr["block"]
        as_var = wr.get("as_var")
        protected = wr.get("protected_blocks", [])
        wtype = "AsyncWith" if wr.get("type") == "async_with" else "With"
        # Para async with: o STORE_FAST do "as var" está distante (após o SEND loop do __aenter__)
        # Recupera via Stmt(kind="await", target=yf_target) adicionado por _fix_yield_from no bloco
        if as_var is None and wtype == "AsyncWith":
            bstmts = si_block_statements(stack_info, bid)
            for st in bstmts:
                if isinstance(st, Stmt) and st.kind == "await" and st.target:
                    as_var = st.target
                    break

        # Encontra ctx_expr via with_enter/async_with_enter no out_stack
        ctx_expr = None
        bout = si_out_stack(stack_info, bid)
        for v in bout:
            if isinstance(v, Expr) and v.kind in ("with_enter", "async_with_enter"):
                ctx_expr = v.args[0] if v.args else None
                break
        # Fallback: procura com with_exit / async_with_exit
        if ctx_expr is None:
            for v in bout:
                if isinstance(v, Expr) and v.kind in ("with_exit", "async_with_exit"):
                    ctx_expr = v.args[0] if v.args else None
                    break
        # Fallback: procura nos statements do bloco
        if ctx_expr is None:
            bstmts = si_block_statements(stack_info, bid)
            for st in bstmts:
                if isinstance(st, Stmt) and st.kind == "assign" and as_var and st.target == as_var:
                    if isinstance(st.expr, Expr) and st.expr.kind in ("with_enter", "async_with_enter"):
                        ctx_expr = st.expr.args[0] if st.expr.args else None
                        break
        # Fallback extra para async with: extrai ctx do Stmt(kind="await") adicionado por _fix_yield_from
        if ctx_expr is None and wtype == "AsyncWith":
            bstmts = si_block_statements(stack_info, bid)
            for st in bstmts:
                if isinstance(st, Stmt) and st.kind == "await":
                    e = st.expr
                    if isinstance(e, Expr) and e.kind in ("async_with_enter",):
                        ctx_expr = e.args[0] if e.args else None
                    elif isinstance(e, Expr):
                        ctx_expr = e
                    break

        # Identifica blocos de cleanup normal (chamam __exit__(None,None,None) no caminho normal)
        # Esses blocos ficam entre o fim do body e o próximo código real
        normal_cleanup_blocks = []
        if protected:
            last_prot_off = max(start_by_id.get(p, 0) for p in protected)
            handler_off = start_by_id.get(wr.get("handler_block"), 10**18)
            for b in blocks_sorted:
                b_off = b.get("start_offset", 0)
                if b_off <= last_prot_off or b_off >= handler_off:
                    continue
                if b["id"] in all_with_handler_blocks:
                    continue
                ins = b.get("instructions", []) or []
                ops = {i["opname"] for i in ins}
                # Blocos de cleanup: SWAP + LOAD_CONST + CALL + POP_TOP
                # NÃO inclui RETURN_VALUE (retorno de valor real) — esses blocos
                # podem ter returns que devem ser renderizados
                # RETURN_CONST None é OK (retorno implícito), mas RETURN_CONST
                # com valor real (ex: 'done') NÃO é cleanup
                cleanup_allowed = {"SWAP", "LOAD_CONST", "CALL", "POP_TOP", "NOP",
                                   "RETURN_CONST"}
                if ops and ops.issubset(cleanup_allowed):
                    # Verifica se tem RETURN_CONST com valor não-None (return real)
                    has_real_return = any(
                        i["opname"] == "RETURN_CONST" and i.get("argval") is not None
                        for i in ins
                    )
                    if not has_real_return:
                        normal_cleanup_blocks.append(b["id"])

        structures.append(
            node(
                wtype,
                block=bid,
                ctx_expr=ctx_expr,
                as_var=as_var,
                body_blocks=protected,
                handler_block=wr.get("handler_block"),
                all_handler_blocks=sorted(all_with_handler_blocks),
                normal_cleanup_blocks=normal_cleanup_blocks,
            )
        )
        if debug:
            print(f"[DEBUG] {wtype}: block={bid} as_var={as_var} body={protected} cleanup={normal_cleanup_blocks}")

    # ---- ASSERT RECOVERY ----
    for ap in (patterns.get("assert_patterns") or []):
        cond_bid = ap["cond_block"]
        fail_bid = ap["fail_block"]

        conds = si_block_conditions(stack_info, cond_bid)
        cond_expr = conds[0] if conds else None

        # Mensagem: procura no bloco de falha (CALL AssertionError com argumento)
        msg_expr = None
        fail_stmts = si_block_statements(stack_info, fail_bid)
        for st in fail_stmts:
            if isinstance(st, Stmt) and st.kind == "raise" and isinstance(st.expr, Expr):
                if st.expr.kind in ("call", "call_kw") and st.expr.args:
                    fn = st.expr.args[0]
                    if isinstance(fn, Expr) and fn.kind == "name" and fn.value == "AssertionError":
                        if len(st.expr.args) > 1:
                            msg_expr = st.expr.args[1]

        structures.append(
            node(
                "Assert",
                cond_block=cond_bid,
                fail_block=fail_bid,
                cond_expr=cond_expr,
                msg_expr=msg_expr,
            )
        )
        if debug:
            print(f"[DEBUG] Assert: cond_block={cond_bid} fail_block={fail_bid}")

    # ---- MATCH/CASE RECOVERY ----
    # Caso 1: match_chains — padrões simples (literal, class) detectados por cadeia de MCBs
    match_chains = patterns.get("match_chains", [])
    for mc in match_chains:
        start_bid = mc["first_block"]
        chain_cases = mc["cases"]
        default_bid = mc.get("default_block")

        # Subject: no IN stack do primeiro bloco, ou carregado no próprio bloco antes do COPY 1
        in_stk = si_in_stack(stack_info, start_bid)
        subject_expr = None
        if in_stk:
            subject_expr = in_stk[-1]
        else:
            first_b = blocks_by_id.get(start_bid)
            if first_b:
                for ins in (first_b.get("instructions") or []):
                    if ins["opname"] == "COPY" and ins.get("arg") == 1:
                        break
                    if ins["opname"] == "LOAD_FAST":
                        subject_expr = Expr(kind="name", value=ins.get("argval", "?"),
                                           origins=frozenset())
                    elif ins["opname"] in ("LOAD_GLOBAL", "LOAD_NAME"):
                        subject_expr = Expr(kind="global_name", value=ins.get("argval", "?"),
                                           origins=frozenset())

        all_bids = set()
        for case in chain_cases:
            all_bids.add(case["cond_block"])
            if case.get("body_block") is not None:
                all_bids.add(case["body_block"])
        if default_bid is not None:
            all_bids.add(default_bid)

        structures.append(node(
            "Match",
            subject_expr=subject_expr,
            cases=chain_cases,
            first_block=start_bid,
            default_block=default_bid,
            all_blocks=all_bids,
            is_chain=True,
        ))
        if debug:
            print(f"[DEBUG] Match chain: start={start_bid}, {len(chain_cases)} cases, default={default_bid}")

    # Caso 2: match_regions — padrões complexos (multi-bloco por case, ex: block_match_complex)
    match_arms = patterns.get("match_regions", [])
    if match_arms:
        first_arm = match_arms[0]
        first_bid = first_arm["block"]

        # Subject: está no stack do predecessor
        subject_expr = None
        for pred_bid in pred_norm.get(first_bid, set()):
            bout = si_out_stack(stack_info, pred_bid)
            if bout:
                subject_expr = bout[-1]
                break

        cases = []
        for arm in match_arms:
            cases.append({
                "block": arm["block"],
                "match_type": arm.get("match_type", ""),
            })

        structures.append(
            node(
                "Match",
                subject_expr=subject_expr,
                cases=cases,
                first_block=first_bid,
                is_chain=False,
            )
        )
        if debug:
            print(f"[DEBUG] Match regions: first={first_bid}, {len(cases)} cases")

    # Caso 3: seq_match_chains — padrões de sequência multi-bloco (ex: block_match_complex)
    seq_match_chains = patterns.get("seq_match_chains", [])
    for smc in seq_match_chains:
        smc_start_bid = smc["first_block"]
        smc_cases = smc["cases"]
        smc_default_bid = smc.get("default_block")
        smc_all_bids = smc.get("all_blocks", set())

        # Subject: verifica in_stack do primeiro bloco, ou escaneia LOAD_FAST antes de COPY/MATCH_SEQ
        smc_in_stk = si_in_stack(stack_info, smc_start_bid)
        smc_subject = None
        if smc_in_stk:
            smc_subject = smc_in_stk[-1]
        else:
            first_b_smc = blocks_by_id.get(smc_start_bid)
            if first_b_smc:
                for ins_smc in (first_b_smc.get("instructions") or []):
                    if ins_smc["opname"] in ("COPY", "MATCH_SEQUENCE"):
                        break
                    if ins_smc["opname"] == "LOAD_FAST":
                        smc_subject = Expr(kind="name", value=ins_smc.get("argval", "?"),
                                          origins=frozenset())
                    elif ins_smc["opname"] in ("LOAD_GLOBAL", "LOAD_NAME"):
                        smc_subject = Expr(kind="global_name", value=ins_smc.get("argval", "?"),
                                          origins=frozenset())

        smc_block_conds = si_all_block_conditions(stack_info)
        smc_block_stmts = si_all_block_statements(stack_info)

        cases_with_pats = []
        for c_smc in smc_cases:
            c_start = c_smc["start_bid"]
            c_body = c_smc["body_bid"]
            c_all = c_smc["all_bids"]
            c_n = c_smc.get("n") or 0

            # Padrões dos elementos: constantes de condições, bindings de stmts do corpo
            elem_pats = {}  # índice → ("const", valor) ou ("bind", nome)

            # Percorre blocos intermediários (não start, não length-check) para condições de elementos
            for bid_smc in sorted(c_all):
                if bid_smc == c_start:
                    continue
                b_smc = blocks_by_id.get(bid_smc)
                if b_smc is None:
                    continue
                ops_smc = [i["opname"] for i in (b_smc.get("instructions") or [])]
                if "GET_LEN" in ops_smc:
                    continue  # Pula bloco de verificação de comprimento
                conds_smc = smc_block_conds.get(bid_smc, [])
                for cond_smc in conds_smc:
                    if not (isinstance(cond_smc, Expr) and cond_smc.kind == "compare"
                            and cond_smc.value == "=="):
                        continue
                    a_smc = cond_smc.args[0] if cond_smc.args else None
                    b_smc_val = cond_smc.args[1] if len(cond_smc.args) > 1 else None
                    if (isinstance(a_smc, Expr) and a_smc.kind == "unpack"
                            and isinstance(b_smc_val, Expr) and b_smc_val.kind == "const"):
                        elem_pats[a_smc.value] = ("const", b_smc_val.value)
                    elif (isinstance(b_smc_val, Expr) and b_smc_val.kind == "unpack"
                            and isinstance(a_smc, Expr) and a_smc.kind == "const"):
                        elem_pats[b_smc_val.value] = ("const", a_smc.value)

            # Bindings do bloco corpo (STORE_FAST no início)
            n_bindings_smc = 0
            body_stmts_smc = list(smc_block_stmts.get(c_body, []))
            for st_smc in body_stmts_smc:
                if (isinstance(st_smc, Stmt) and st_smc.kind == "assign"
                        and isinstance(st_smc.expr, Expr) and st_smc.expr.kind == "unpack"):
                    idx_smc = st_smc.expr.value
                    if idx_smc not in elem_pats:
                        elem_pats[idx_smc] = ("bind", st_smc.target)
                    n_bindings_smc += 1
                else:
                    break  # Para no primeiro stmt não-binding

            # Constrói string do padrão
            elems_smc = []
            for i_smc in range(c_n):
                p_smc = elem_pats.get(i_smc, ("_", None))
                if p_smc[0] == "const":
                    elems_smc.append(repr(p_smc[1]))
                elif p_smc[0] == "bind":
                    elems_smc.append(p_smc[1])
                else:
                    elems_smc.append("_")

            if c_n > 0:
                pat_str_smc = "(" + ", ".join(elems_smc) + ")"
            else:
                pat_str_smc = "_"

            cases_with_pats.append({
                "start_bid": c_start,
                "body_bid": c_body,
                "all_bids": c_all,
                "fail_all_bid": c_smc.get("fail_all_bid"),
                "pattern_str": pat_str_smc,
                "n_bindings": n_bindings_smc,
            })

        structures.append(node(
            "Match",
            subject_expr=smc_subject,
            cases=cases_with_pats,
            first_block=smc_start_bid,
            default_block=smc_default_bid,
            all_blocks=smc_all_bids,
            is_seq_chain=True,
        ))
        if debug:
            print(f"[DEBUG] Seq match chain: start={smc_start_bid}, {len(cases_with_pats)} cases, default={smc_default_bid}")

    # ---- GLOBAL / NONLOCAL INFERENCE ----
    if code_obj.co_name != "<module>":
        global_names = set()
        nonlocal_names = set()
        freevars = set(getattr(code_obj, "co_freevars", ()) or ())

        for b in blocks_sorted:
            for ins in (b.get("instructions") or []):
                if ins["opname"] == "STORE_GLOBAL":
                    global_names.add(ins.get("argval"))
                if ins["opname"] == "STORE_DEREF":
                    name = ins.get("argval")
                    if name in freevars:
                        nonlocal_names.add(name)

        if global_names:
            structures.append(node("GlobalDecl", names=sorted(global_names)))
            if debug:
                print(f"[DEBUG] GlobalDecl: {sorted(global_names)}")
        if nonlocal_names:
            structures.append(node("NonlocalDecl", names=sorted(nonlocal_names)))
            if debug:
                print(f"[DEBUG] NonlocalDecl: {sorted(nonlocal_names)}")

    # ---- FUNCTION DECORATOR DETECTION ----
    # Decorators são detectados no code object PAI, não no da função em si.
    # Aqui marcamos para que o codegen possa usar.
    def extract_func_decorators():
        """Procura patterns de decorator nos statements do módulo/classe."""
        block_stmts = si_all_block_statements(stack_info)
        func_decorators = {}  # name -> list of [decorator_exprs] (uma por ocorrência)

        for b in blocks_sorted:
            stmts = block_stmts.get(b["id"], [])
            for st in stmts:
                if not (isinstance(st, Stmt) and st.kind == "assign"
                        and isinstance(st.expr, Expr)
                        and st.expr.kind in ("call", "call_kw")):
                    continue

                # Desempacota calls aninhados: decor(make_function(...)) ou decor1(decor2(make_function(...)))
                decos = []
                expr = st.expr
                while isinstance(expr, Expr) and expr.kind in ("call", "call_kw"):
                    args = expr.args or ()
                    if len(args) >= 2:
                        fn = args[0]
                        inner = args[1]
                        if isinstance(inner, Expr) and inner.kind == "make_function":
                            decos.append(fn)
                            break
                        elif isinstance(inner, Expr) and inner.kind in ("call", "call_kw"):
                            decos.append(fn)
                            expr = inner
                            continue
                    break

                if decos and st.target:
                    decos.reverse()  # outermost first
                    func_decorators.setdefault(st.target, []).append(decos)

        return func_decorators

    func_decorators = extract_func_decorators()
    if func_decorators:
        structures.append(node("FuncDecorators", decorators=func_decorators))
        if debug:
            print(f"[DEBUG] FuncDecorators: {list(func_decorators.keys())}")

    recovered = node(
        "CodeObject",
        name=code_obj.co_name,
        filename=getattr(code_obj, "co_filename", None),
        firstlineno=getattr(code_obj, "co_firstlineno", None),
        argcount=getattr(code_obj, "co_argcount", None),
        posonlyargcount=getattr(code_obj, "co_posonlyargcount", None),
        kwonlyargcount=getattr(code_obj, "co_kwonlyargcount", None),
        co_flags=getattr(code_obj, "co_flags", 0),
        co_varnames=tuple(getattr(code_obj, "co_varnames", ())),
        co_cellvars=tuple(getattr(code_obj, "co_cellvars", ())),
        co_freevars=tuple(getattr(code_obj, "co_freevars", ())),
        structures=structures,
        basic_blocks=basic,
        short_circuit_blocks=list(patterns.get("short_circuit_blocks") or set()),
    )

    if debug:
        print(f"[DEBUG] build_recovered_ast: {code_obj.co_name} | structures={len(structures)} basic_blocks={len(basic)}")

    return recovered
