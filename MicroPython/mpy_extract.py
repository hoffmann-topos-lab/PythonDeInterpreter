"""
Orquestração recursiva do pipeline MicroPython.

Equivalente ao Decompiler/extract.py, mas para MpyCodeObject.

Pipeline por code object (pós-ordem: filhos processados antes do pai):
    mpy_stack_sim → mpy_patterns → ast_recover → codegen

IR fixup passes (após recursão nos filhos):
    _attach_names_to_children      — infere nomes de funções a partir de assigns
    _attach_defaults_to_children   — associa defaults/closures (MAKE_*_DEFARGS)
    _fix_lambda_calls              — reescreve make_function(<lambda>) → Expr(lambda)
    _fix_genexpr_calls             — reescreve call(make_function(<genexpr>),...) → Expr(genexpr)
    _fix_for_range_loops           — reescreve padrão range() do MicroPython

Diferenças em relação ao pipeline CPython:
  - Filhos estão em mpy_obj._children (não em co_consts)
  - child_idx (Expr.value) identifica o filho, não o id() do code object
  - Nomes dos filhos são inferidos dos assign-stmts do pai (STORE_NAME/STORE_FAST)
  - try/except recuperado via _build_mpy_try_structures em ast_recover.py
"""

from MicroPython.mpy_loader import KIND_BYTECODE
from MicroPython.mpy_stack_sim import (
    build_mpy_basic_blocks,
    build_mpy_cfg,
    simulate_mpy_stack,
)
from MicroPython.mpy_patterns import detect_mpy_patterns
from utils.ast_recover import build_recovered_ast
from utils.ir import Expr, Stmt, expr_repr


# ---------------------------------------------------------------------------
# Pipeline principal (recursivo)
# ---------------------------------------------------------------------------

def process_mpy_code_object(mpy_obj, depth: int = 0, debug: bool = False) -> dict:
    """
    Processa um MpyCodeObject recursivamente.

    Retorna um nó de árvore compatível com o formato de Decompiler/extract.py:
        {
            "name":          str,
            "recovered_ast": dict | None,
            "stack_info":    dict,
            "children":      list[dict],
            "code_obj":      MpyCodeObject,
            "co_flags":      int,
        }
    """
    # Processa filhos primeiro (pós-ordem)
    children = [
        process_mpy_code_object(child, depth=depth + 1, debug=debug)
        for child in mpy_obj._children
    ]

    # Código native/viper: sem decompilação de bytecode
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

    # --- Pipeline de decompilação ---
    blocks     = build_mpy_basic_blocks(instrs, debug=debug)
    cfg        = build_mpy_cfg(blocks, instrs, debug=debug)
    stack_info = simulate_mpy_stack(blocks, cfg, instrs, mpy_obj, debug=debug)
    patterns   = detect_mpy_patterns(blocks, cfg, stack_info, mpy_obj, debug=debug)

    # --- IR fixup: for-range loops (antes de ast_recover) ---
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

    # --- IR fixup passes ---
    _attach_names_to_children(children, stack_info)
    _attach_defaults_to_children(children, stack_info)
    _fix_lambda_calls(children, stack_info)
    _fix_comp_calls(children, stack_info)
    _fix_genexpr_calls(children, stack_info)

    return node


# ---------------------------------------------------------------------------
# Fixup 1: nomeação de filhos
# ---------------------------------------------------------------------------

def _attach_names_to_children(children: list, stack_info: dict):
    """
    Infere o nome de cada filho a partir dos assign-stmts do pai.

    Quando o pai executa MAKE_FUNCTION child_idx + STORE_NAME name,
    o stack_sim produz Stmt(kind="assign", target=name, expr=make_function(value=child_idx)).
    Este fixup usa essa informação para atualizar co_name do filho.

    Também lida com corpos de classe:
    Stmt(kind="assign", target=ClassName, expr=call(__build_class__, make_function(idx), "ClassName"))
    """
    block_stmts = stack_info.get("block_statements") or {}
    for stmts in block_stmts.values():
        for st in stmts:
            if not (isinstance(st, Stmt) and isinstance(st.expr, Expr)):
                continue

            # Padrão simples: assign/expr com make_function diretamente
            if (st.kind in ("assign", "expr")
                    and st.expr.kind == "make_function"):
                child_idx = st.expr.value
                if not isinstance(child_idx, int) or child_idx >= len(children):
                    continue
                # Só nomeia se o filho ainda tem nome gerado automaticamente
                ch = children[child_idx]
                co = ch.get("code_obj")
                if co is None:
                    continue
                inferred = st.target if st.kind == "assign" else None
                if inferred and (not co.co_name or co.co_name.startswith("<child_")):
                    co.co_name = inferred
                    ch["name"]  = inferred
                continue

            # Padrão de corpo de classe:
            # ClassName = call(__build_class__, make_function(idx), "ClassName")
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


# ---------------------------------------------------------------------------
# Fixup: for-range loops (MicroPython counter+limit pattern)
# ---------------------------------------------------------------------------

def _instr_to_expr(instr: dict):
    """
    Converte uma instrução LOAD simples num Expr, ou retorna None.

    Suporta:
      LOAD_FAST_MULTI / LOAD_FAST_N       → Expr(kind="name", value=argrepr or "_local_N")
      LOAD_CONST_SMALL_INT / _MULTI       → Expr(kind="const", value=argval)
      LOAD_NAME / LOAD_GLOBAL             → Expr(kind="name", value=argval)
    """
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
    """
    Detecta e corrige o padrão de for-range loop do MicroPython.

    O mpy-cross compila `for i in range(n):` como um contador+limite na pilha:
      init_block:        LOAD limit, LOAD 0, JUMP → comparison_block
      comparison_block:  DUP_TOP_TWO, ROT_TWO, BINARY_OP_MULTI <, POP_JUMP_IF_TRUE → body_block
      body_block:        DUP_TOP, STORE_FAST_MULTI loop_var, ...body..., LOAD 1, BINARY_OP_MULTI +=
      cleanup_block:     POP_TOP, POP_TOP, ...rest...

    Estratégia: transforma o init_block numa cabeça de loop FOR_ITER de modo que
    init_block (offset menor) seja o header, e body_block (offset intermediário)
    seja o corpo — assim o codegen (que itera em ordem de offset) processa o
    header antes do corpo, produzindo `for var in range(n):`.

    Também atualiza patterns["loops"] se fornecido.
    """
    if not blocks:
        return

    # Indexação
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

    # Detecta blocos de comparação: [DUP_TOP_TWO, ROT_TWO, BINARY_OP_MULTI <, POP_JUMP_IF_TRUE]
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

        # Encontra init_block: bloco cujo último opcode é JUMP com jump_target == comparison_start
        init_bid = None
        for ob in blocks_sorted:
            ob_instrs = ob.get("instructions", [])
            if not ob_instrs:
                continue
            last = ob_instrs[-1]
            if last.get("opname") == "JUMP" and last.get("jump_target") == comparison_start:
                # Confirma: penúltima instrução é LOAD_CONST_SMALL_INT[_MULTI] com argval==0
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

        # range_arg: terceira instrução a contar do fim (antes do LOAD 0 e JUMP)
        if len(init_instrs) < 3:
            continue
        range_instr = init_instrs[-3]
        range_arg   = _instr_to_expr(range_instr)
        if range_arg is None:
            continue

        # Encontra body_block: alvo do POP_JUMP_IF_TRUE no comparison_block
        pop_jump_instr = instrs[3]
        body_start_off = pop_jump_instr.get("jump_target")
        if body_start_off is None:
            continue
        body_bid = offset_to_bid.get(body_start_off)
        if body_bid is None:
            continue

        # Verifica body: começa com DUP_TOP + STORE_FAST_MULTI/STORE_FAST_N
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

        # Encontra cleanup_block: próximo bloco após comparison_block em ordem de offset
        # (NÃO é o body_bid)
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

        # --- Patches ---

        # Constrói o iterador iter(range(range_arg))
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

        # 1. Transforma o init_block no cabeçalho FOR_ITER:
        #    remove as 3 últimas instruções (LOAD limit, LOAD 0, JUMP) e substitui por FOR_ITER.
        #    O init_block tem offset < body_block, então o codegen o processa primeiro ✓
        for_iter_offset = init_instrs[-3]["offset"]  # offset do LOAD limit (substituído por FOR_ITER)
        new_init_instrs = list(init_instrs[:-3]) + [{
            "opname":      "FOR_ITER",
            "offset":      for_iter_offset,
            "argval":      None,
            "argrepr":     None,
            "jump_target": None,
        }]
        init_block["instructions"] = new_init_instrs

        # 2. Corrige in_stack do init_block: [iter(range(range_arg))]
        in_stack[init_bid]          = [iter_expr]
        block_conditions[init_bid]  = []

        # 3. Suprime o comparison_block (já não é mais necessário):
        #    esvazia suas instruções e stmts/conds
        b["instructions"]             = []
        block_statements[comparison_bid] = []
        block_conditions[comparison_bid] = []
        in_stack[comparison_bid]         = []

        # 4. Corrige stmts do body_block: insere loop-var assignment no início
        body_stmts = list(block_statements.get(body_bid, []))
        # Remove o primeiro stmt se for assign/augassign para loop_var (artefato DUP_TOP+STORE)
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

        # 5. Limpa stmts do cleanup_block: remove artefatos de POP_TOP
        if cleanup_bid is not None:
            cleanup_stmts = list(block_statements.get(cleanup_bid, []))
            filtered = []
            for st in cleanup_stmts:
                if isinstance(st, Stmt) and st.kind == "expr" and isinstance(st.expr, Expr):
                    if st.expr.kind in ("binop", "unknown", "augassign"):
                        continue  # remove artefato de POP_TOP
                filtered.append(st)
            block_statements[cleanup_bid] = filtered

        # 6. Atualiza patterns["loops"]: reaponta header para init_bid
        if patterns is not None:
            for lp in (patterns.get("loops") or []):
                # Loop original: header=comparison_bid, body_entry=body_bid, latch=comparison_bid
                if lp.get("header") == comparison_bid:
                    lp["header"]      = init_bid
                    lp["body_entry"]  = body_bid
                    # latch = last block do corpo que salta de volta → body_bid
                    # No padrão range(), o body_bid (BB1) é o próprio latch (cai em comparison)
                    lp["latch"]       = body_bid
                    # body_blocks: apenas body_bid (comparison e cleanup são infra)
                    lp["body_blocks"] = [init_bid, body_bid]
                    lp["is_for"]      = True
                    if debug:
                        print(f"[DEBUG FOR-RANGE] Loop atualizado: header={init_bid} "
                              f"body_entry={body_bid} latch={body_bid}")


# ---------------------------------------------------------------------------
# Fixup 2: defaults e closures
# ---------------------------------------------------------------------------

def _attach_defaults_to_children(children: list, stack_info: dict):
    """
    Associa defaults posicionais e closure vars aos filhos.

    MAKE_FUNCTION_DEFARGS child_idx pops defaults → args[0] = defaults_expr
    MAKE_CLOSURE child_idx n_closed pops closed vars → args[3] = closure_tuple
    """
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

            # args layout (de mpy_stack_sim):
            #   args[0] = defaults_expr  (None se MAKE_FUNCTION sem defaults)
            #   args[1] = kwdefaults     (sempre None — MicroPython não tem kwdefaults no bytecode)
            #   args[2] = annotations    (sempre None)
            #   args[3] = closure_tuple  (None se não é closure)
            if "defaults" not in ch:
                ch["defaults"]     = args[0] if len(args) > 0 else None
                ch["kwdefaults"]   = args[1] if len(args) > 1 else None
                ch["annotations"]  = args[2] if len(args) > 2 else None
                ch["closure_vars"] = args[3] if len(args) > 3 else None


# ---------------------------------------------------------------------------
# Fixup 3: lambda
# ---------------------------------------------------------------------------

def _extract_lambda_info(child: dict):
    """
    Extrai (params_str, body_expr) de um filho que seja uma lambda.

    Um filho é lambda se:
    - co_name == "<lambda>", OU
    - tem exatamente um return em todos os blocos e nenhum outro stmt relevante
    """
    co = child.get("code_obj")
    if co is None:
        return None

    is_lambda = co.co_name == "<lambda>"
    if not is_lambda:
        return None

    params_str = ", ".join(str(v) for v in (getattr(co, "co_varnames", ()) or ()))

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
    """Substitui make_function(child_idx) por Expr(kind='lambda') se child_idx ∈ lambda_map."""
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
    """Substitui, no stack_info do pai, make_function(<lambda_idx>) → Expr(lambda)."""
    lambda_map = {}
    for i, ch in enumerate(children):
        info = _extract_lambda_info(ch)
        if info is not None:
            co = ch.get("code_obj")
            if co is not None:
                lambda_map[i] = info   # chave = índice do filho

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


# ---------------------------------------------------------------------------
# Fixup 4a: list/dict/set comprehensions (STORE_COMP pattern)
# ---------------------------------------------------------------------------

def _extract_comp_info(child: dict, child_idx: int):
    """
    Detecta se um filho é um listcomp/dictcomp/setcomp e extrai suas partes.

    Retorna (kind, element_expr, loop_vars, cond) ou None.
      kind        : "listcomp" | "dictcomp" | "setcomp"
      element_expr: Expr — expressão do elemento acumulado
      loop_vars   : list[(str, Expr|None)] — variáveis de loop e iteráveis
                    O primeiro par tem iterable=None (vem do call do pai)
      cond        : Expr | None — condição de filtro (if ...)
    """
    co = child.get("code_obj")
    if co is None:
        return None
    instrs = getattr(co, "_instructions", None)
    if not instrs:
        return None

    # Detecta tipo pela primeira instrução
    first_op = instrs[0].get("opname", "")
    if first_op == "BUILD_LIST":
        kind = "listcomp"
    elif first_op == "BUILD_MAP":
        kind = "dictcomp"
    elif first_op == "BUILD_SET":
        kind = "setcomp"
    else:
        return None

    # Verifica que há STORE_COMP nas instruções (confirma que é comp e não genexpr)
    has_store_comp = any(i.get("opname") == "STORE_COMP" for i in instrs)
    if not has_store_comp:
        return None

    stack_info  = child.get("stack_info") or {}
    block_stmts = stack_info.get("block_statements") or {}
    block_conds = stack_info.get("block_conditions") or {}

    element_expr = None
    loop_vars    = []   # list of (var_name, iterable_expr_or_None)
    cond         = None

    # Coleta todos os blocos ordenados por id para processar na ordem do bytecode
    sorted_bids = sorted(block_stmts.keys())
    for bid in sorted_bids:
        stmts = block_stmts[bid]
        for st in stmts:
            if not isinstance(st, Stmt):
                continue
            if st.kind == "store_comp" and element_expr is None:
                element_expr = st.expr
            if (st.kind == "assign"
                    and isinstance(st.expr, Expr)
                    and st.expr.kind == "next"):
                # Extrai iterável do next(iter(X)) → X
                iter_e = st.expr.args[0] if st.expr.args else None
                iterable = None
                if isinstance(iter_e, Expr) and iter_e.kind == "iter" and iter_e.args:
                    iterable = iter_e.args[0]
                # Primeiro loop var: iterable vem do pai (None), os demais são internos
                if not loop_vars:
                    loop_vars.append((st.target, None))
                else:
                    loop_vars.append((st.target, iterable))

    # Condição de filtro: primeiro valor em block_conditions
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
    """
    Substitui call(make_function(child_idx), iter_arg)
    por Expr(kind='listcomp'/'dictcomp'/'setcomp', args=(element, var, iterable, ...)).

    Para comps com múltiplos for-clauses (nested), adiciona Expr(kind="for_clause")
    após o primeiro (var, iterable).
    """
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
            # Desfaz iter() para obter o iterável original (primeiro for-clause)
            if isinstance(iter_arg, Expr) and iter_arg.kind == "iter" and iter_arg.args:
                actual_iterable = iter_arg.args[0]
            else:
                actual_iterable = iter_arg
            # Primeiro for-clause
            first_var = loop_vars[0][0] if loop_vars else "item"
            args = (
                element_expr,
                Expr(kind="name", value=first_var, origins=frozenset()),
                actual_iterable,
            )
            # For-clauses adicionais (nested comps)
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
    """Substitui, no stack_info do pai, call(make_function(<comp_idx>), iter) → Expr(comp)."""
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


# ---------------------------------------------------------------------------
# Fixup 4b: genexpr
# ---------------------------------------------------------------------------

_MP_SCOPE_GENERATOR = 0x01


def _extract_genexpr_info(child: dict, child_idx: int):
    """
    Extrai (element_expr, loop_var) de um filho que seja um generator expression.

    Um filho é genexpr se co_name contém "<genexpr>" ou tem scope_flags & GENERATOR.
    """
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
            # YIELD_VALUE → elemento da genexpr
            if (st.kind == "expr"
                    and isinstance(st.expr, Expr)
                    and st.expr.kind == "yield"
                    and st.expr.args):
                if element_expr is None:
                    element_expr = st.expr.args[0]
            # x = next(iter) → variável de loop
            if (st.kind == "assign"
                    and isinstance(st.expr, Expr)
                    and st.expr.kind == "next"):
                if loop_var is None:
                    loop_var = st.target

    if element_expr is None or loop_var is None:
        return None
    return (element_expr, loop_var)


def _subst_genexpr_in_expr(expr: Expr, genexpr_map: dict) -> Expr:
    """
    Substitui call(make_function(child_idx), iter_arg)
    por Expr(kind='genexpr', args=(element, var_name, iterable)).
    """
    if not isinstance(expr, Expr):
        return expr

    # Padrão: call(make_function(child_idx), iter_arg, ...)
    if expr.kind == "call" and len(expr.args) >= 2:
        fn_e    = expr.args[0]
        iter_arg = expr.args[1]
        if (isinstance(fn_e, Expr)
                and fn_e.kind == "make_function"
                and isinstance(fn_e.value, int)
                and fn_e.value in genexpr_map):
            element_expr, loop_var = genexpr_map[fn_e.value]
            # Desfaz iter() para obter o iterável original
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
    """Substitui, no stack_info do pai, call(make_function(<genexpr_idx>), iter) → Expr(genexpr)."""
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
