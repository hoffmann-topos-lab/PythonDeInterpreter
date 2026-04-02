"""
Simulação de pilha para bytecode MicroPython (versão 6.x).

Reutiliza utils/ir.py (Expr, Stmt) e utils/block_utils.py.
Constrói blocos básicos via utils/cfg.build_basic_blocks (sem code_obj).
CFG: versão própria (terminadores MicroPython + arestas de exceção via SETUP_*).
"""

from typing import Optional

from utils.ir import Expr, Stmt, expr_repr
from utils.cfg import build_basic_blocks
from utils.block_utils import (
    build_block_by_id,
    build_offset_to_block,
    build_predecessor_map,
)


# ---------------------------------------------------------------------------
# Terminadores MicroPython
# ---------------------------------------------------------------------------

_MPY_TERMINATORS = frozenset({
    "JUMP",
    "RETURN_VALUE",
    "RAISE_LAST",
    "RAISE_OBJ",
    "RAISE_FROM",
    "POP_EXCEPT_JUMP",   # salto forward incondicional (ULABEL) — sem fall-through
})


# ---------------------------------------------------------------------------
# Blocos básicos
# ---------------------------------------------------------------------------

def build_mpy_basic_blocks(instructions: list, debug: bool = False) -> list:
    """
    Constrói blocos básicos para bytecode MicroPython.
    Delega a utils/cfg.build_basic_blocks sem code_obj
    (omite a exception_entries CPython).
    """
    return build_basic_blocks(instructions, code_obj=None, debug=debug)


# ---------------------------------------------------------------------------
# CFG MicroPython
# ---------------------------------------------------------------------------

def build_mpy_cfg(blocks: list, instructions: list, debug: bool = False) -> dict:
    """
    Constrói o CFG para bytecode MicroPython.

    Arestas normais:
      - salto explícito (jump_target não-None)
      - fall-through (bloco seguinte, se não for terminador)

    Arestas de exceção:
      - SETUP_EXCEPT / SETUP_FINALLY / SETUP_WITH: jump_target → handler block
        Adiciona aresta do bloco que contém o SETUP_* para o handler.

    Ao contrário do CFG CPython, não usa dis.Bytecode().exception_entries.
    """
    if not blocks:
        return {}

    offset_to_block: dict = {}
    for b in blocks:
        for ins in b["instructions"]:
            offset_to_block[ins["offset"]] = b["id"]

    cfg = {b["id"]: set() for b in blocks}

    _SETUP_OPS = {"SETUP_EXCEPT", "SETUP_FINALLY", "SETUP_WITH"}

    for i, b in enumerate(blocks):
        src = b["id"]
        last = b["instructions"][-1]
        op = last["opname"]

        # --- aresta de salto explícito ---
        jt = last.get("jump_target")
        if jt is not None and jt in offset_to_block:
            dst = offset_to_block[jt]
            cfg[src].add(dst)
            if debug:
                print(f"[DEBUG MPY CFG] bloco {src} -> salto -> bloco {dst}")

        # --- terminadores: sem fall-through ---
        if op in _MPY_TERMINATORS:
            if debug:
                print(f"[DEBUG MPY CFG] bloco {src} termina em {op}")
            continue

        # --- fall-through ---
        if i + 1 < len(blocks):
            dst = blocks[i + 1]["id"]
            cfg[src].add(dst)
            if debug:
                print(f"[DEBUG MPY CFG] bloco {src} -> fall-through -> bloco {dst}")

    # --- arestas de exceção via SETUP_* ---
    for b in blocks:
        src = b["id"]
        for instr in b["instructions"]:
            if instr["opname"] in _SETUP_OPS:
                handler_off = instr.get("jump_target")
                if handler_off is None:
                    continue
                handler_bid = offset_to_block.get(handler_off)
                if handler_bid is None or handler_bid == src:
                    continue
                cfg[src].add(handler_bid)
                if debug:
                    print(f"[DEBUG MPY CFG] bloco {src} -> exc_handler -> bloco {handler_bid}")

    return cfg


# ---------------------------------------------------------------------------
# Merge de pilhas (idêntico ao CPython stack_sim)
# ---------------------------------------------------------------------------

def merge_stacks(stacks: list, debug: bool = False) -> list:
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

        merged_val = (
            vals[0]
            if len(vals) == 1
            else Expr(kind="phi", args=tuple(vals), origins=frozenset())
        )
        merged.append(merged_val)

    return merged


# ---------------------------------------------------------------------------
# Emissão de assigns (com detecção de import e augassign)
# ---------------------------------------------------------------------------

def _emit_assign(stmts: list, target: str, rhs: Expr, off: int):
    if isinstance(rhs, Expr) and rhs.kind == "import":
        stmts.append(Stmt(kind="import", target=target, extra=str(rhs.value), origins=frozenset({off})))
        return

    if isinstance(rhs, Expr) and rhs.kind == "import_from":
        module_expr = rhs.args[0] if rhs.args else None
        module_name = (
            module_expr.value
            if isinstance(module_expr, Expr) and module_expr.kind == "import"
            else "?"
        )
        from_name = str(rhs.value)
        stmts.append(Stmt(
            kind="import_from", target=target,
            extra={"module": str(module_name),
                   "names": [(from_name, target if target != from_name else None)]},
            origins=frozenset({off}),
        ))
        return

    if (isinstance(rhs, Expr) and rhs.kind == "binop"
            and isinstance(rhs.value, str) and rhs.value.endswith("=")):
        a0 = rhs.args[0] if rhs.args else None
        a1 = rhs.args[1] if len(rhs.args) > 1 else None
        if isinstance(a0, Expr) and a0.kind == "name" and str(a0.value) == target:
            stmts.append(Stmt(kind="augassign", target=target, expr=a1, extra=rhs.value, origins=frozenset({off})))
            return

    stmts.append(Stmt(kind="assign", target=target, expr=rhs, origins=frozenset({off})))


# ---------------------------------------------------------------------------
# Simulação de instrução individual
# ---------------------------------------------------------------------------

def simulate_mpy_instruction(
    instr: dict,
    stack: list,
    stmts: list,
    block_conds: list,
    debug: bool = False,
):
    """
    Simula o efeito de uma instrução MicroPython na pilha e nos statements.

    Convenções:
      push(e) — empurra Expr na pilha
      pop()   — remove e retorna Expr do topo (ou None se vazia)
      pop_n(n)— remove n itens (TOS primeiro)
    """
    op  = instr["opname"]
    off = instr["offset"]

    def push(e: Expr):
        stack.append(e)
        if debug:
            print(f"[DEBUG MPY INSTR] {op}@{off}: PUSH {expr_repr(e)}")

    def pop() -> Optional[Expr]:
        if stack:
            return stack.pop()
        if debug:
            print(f"[DEBUG MPY INSTR] {op}@{off}: POP em pilha vazia")
        return None

    def pop_n(n: int) -> list:
        out = []
        for _ in range(n):
            v = pop()
            out.append(v if v is not None else Expr(kind="unknown", origins=frozenset({off})))
        return out

    def unknown() -> Expr:
        return Expr(kind="unknown", origins=frozenset({off}))

    # ------------------------------------------------------------------
    # Loads — constantes simples
    # ------------------------------------------------------------------
    if op == "LOAD_CONST_FALSE":
        push(Expr(kind="const", value=False, origins=frozenset({off})))
        return

    if op == "LOAD_CONST_NONE":
        push(Expr(kind="const", value=None, origins=frozenset({off})))
        return

    if op == "LOAD_CONST_TRUE":
        push(Expr(kind="const", value=True, origins=frozenset({off})))
        return

    if op in ("LOAD_CONST_SMALL_INT", "LOAD_CONST_SMALL_INT_MULTI"):
        push(Expr(kind="const", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op == "LOAD_CONST_STRING":
        push(Expr(kind="const", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op == "LOAD_CONST_OBJ":
        push(Expr(kind="const", value=instr.get("argval"), origins=frozenset({off})))
        return

    if op == "LOAD_NULL":
        push(Expr(kind="null", origins=frozenset({off})))
        return

    if op == "LOAD_BUILD_CLASS":
        push(Expr(kind="name", value="__build_class__", origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Loads — variáveis locais / closure / globais
    # ------------------------------------------------------------------
    if op in ("LOAD_FAST_N", "LOAD_FAST_MULTI"):
        name = instr.get("argrepr") or f"_local_{instr.get('argval', '?')}"
        push(Expr(kind="name", value=name, origins=frozenset({off})))
        return

    if op == "LOAD_DEREF":
        name = instr.get("argrepr") or f"_cell_{instr.get('argval', '?')}"
        push(Expr(kind="name", value=name, origins=frozenset({off})))
        return

    if op in ("LOAD_NAME", "LOAD_GLOBAL"):
        push(Expr(kind="name", value=instr.get("argval"), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Loads — atributos e subscripts
    # ------------------------------------------------------------------
    if op == "LOAD_ATTR":
        obj = pop() or unknown()
        push(Expr(kind="attr", value=instr.get("argval"), args=(obj,), origins=frozenset({off})))
        return

    if op in ("LOAD_METHOD", "LOAD_SUPER_METHOD"):
        obj = pop() or unknown()
        attr = instr.get("argval")
        # LOAD_METHOD empurra: null + método (como CPython)
        push(Expr(kind="null", origins=frozenset({off})))
        push(Expr(kind="attr", value=attr, args=(obj,), origins=frozenset({off})))
        return

    if op == "LOAD_SUBSCR":
        key = pop() or unknown()
        obj = pop() or unknown()
        push(Expr(kind="subscr", args=(obj, key), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Stores — variáveis
    # ------------------------------------------------------------------
    if op in ("STORE_FAST_N", "STORE_FAST_MULTI"):
        target = instr.get("argrepr") or f"_local_{instr.get('argval', '?')}"
        rhs = pop() or unknown()
        _emit_assign(stmts, target, rhs, off)
        return

    if op == "STORE_DEREF":
        target = instr.get("argrepr") or f"_cell_{instr.get('argval', '?')}"
        rhs = pop() or unknown()
        _emit_assign(stmts, target, rhs, off)
        return

    if op in ("STORE_NAME", "STORE_GLOBAL"):
        target = str(instr.get("argval"))
        rhs = pop() or unknown()
        _emit_assign(stmts, target, rhs, off)
        return

    if op == "STORE_ATTR":
        obj = pop() or unknown()
        val = pop() or unknown()
        attr_name = str(instr.get("argval"))
        stmts.append(Stmt(
            kind="store_attr", target=attr_name,
            expr=val, extra=expr_repr(obj),
            origins=frozenset({off}),
        ))
        return

    if op == "STORE_SUBSCR":
        obj  = pop() or unknown()
        key  = pop() or unknown()
        val  = pop() or unknown()
        target_repr = f"{expr_repr(obj)}[{expr_repr(key)}]"
        stmts.append(Stmt(kind="store_subscr", target=target_repr, expr=val, origins=frozenset({off})))
        return

    if op == "STORE_MAP":
        # Stack antes: [..., dict, key, val]  — TOS = val, TOS1 = key, TOS2 = dict
        val = pop() or unknown()
        key = pop() or unknown()
        if stack and isinstance(stack[-1], Expr) and stack[-1].kind == "dict":
            d = stack[-1]
            stack[-1] = Expr(kind="dict", args=tuple(d.args) + (key, val),
                             origins=d.origins | frozenset({off}))
        return

    if op == "STORE_COMP":
        # Emite elemento como Stmt "store_comp" para ser capturado pelo fixup de
        # comprehension em mpy_extract.py.
        # O tipo de acumulador (list/dict/set) é determinado por stack[0].kind.
        acc_kind = stack[0].kind if stack else "list"
        if acc_kind == "dict":
            # dictcomp: TOS = key, TOS-1 = value
            key   = pop() or unknown()
            value = pop() or unknown()
            pair  = Expr(kind="pair", args=(value, key), origins=frozenset({off}))
            stmts.append(Stmt(kind="store_comp", expr=pair, origins=frozenset({off})))
        else:
            # listcomp ou setcomp: TOS = element
            item = pop() or unknown()
            stmts.append(Stmt(kind="store_comp", expr=item, origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Deletes
    # ------------------------------------------------------------------
    if op in ("DELETE_FAST", "DELETE_DEREF"):
        target = instr.get("argrepr") or str(instr.get("argval", "?"))
        stmts.append(Stmt(kind="del", target=target, origins=frozenset({off})))
        return

    if op in ("DELETE_NAME", "DELETE_GLOBAL"):
        target = str(instr.get("argval"))
        stmts.append(Stmt(kind="del", target=target, origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Manipulação de pilha
    # ------------------------------------------------------------------
    if op == "DUP_TOP":
        push(stack[-1] if stack else unknown())
        return

    if op == "DUP_TOP_TWO":
        if len(stack) >= 2:
            push(stack[-2])
            push(stack[-1])
        else:
            push(unknown())
            push(unknown())
        return

    if op == "POP_TOP":
        v = pop()
        if v is None:
            return
        # Suprime valores internos (iteradores, sentinelas, etc.)
        if isinstance(v, Expr) and v.kind in (
            "iter", "next", "null", "exc", "exc_match",
            "with_enter", "with_exit", "with_cleanup",
        ):
            return
        stmts.append(Stmt(kind="expr", expr=v, origins=frozenset({off})))
        return

    if op == "ROT_TWO":
        if len(stack) >= 2:
            stack[-1], stack[-2] = stack[-2], stack[-1]
        return

    if op == "ROT_THREE":
        if len(stack) >= 3:
            tos = stack[-1]
            stack[-1] = stack[-2]
            stack[-2] = stack[-3]
            stack[-3] = tos
        return

    # ------------------------------------------------------------------
    # Operadores binários e unários (multi-opcode ranges)
    # ------------------------------------------------------------------
    if op == "BINARY_OP_MULTI":
        b_val = pop() or unknown()
        a_val = pop() or unknown()
        sym = instr.get("argval") or "?"
        push(Expr(kind="binop", value=sym, args=(a_val, b_val), origins=frozenset({off})))
        return

    if op == "UNARY_OP_MULTI":
        val = pop() or unknown()
        sym = instr.get("argval") or "?"
        push(Expr(kind="unary", value=sym, args=(val,), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Saltos condicionais (registra condição; CFG cuida do fluxo)
    # ------------------------------------------------------------------
    if op == "JUMP":
        return  # incondicional, sem efeito na pilha

    if op in ("POP_JUMP_IF_TRUE", "POP_JUMP_IF_FALSE"):
        cond = pop()
        if cond is not None:
            block_conds.append(cond)
        return

    if op in ("JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP"):
        # Peek: mantém TOS se o salto for tomado
        cond = stack[-1] if stack else None
        if cond is not None:
            block_conds.append(cond)
        return

    if op == "UNWIND_JUMP":
        return

    # ------------------------------------------------------------------
    # Iteração
    # ------------------------------------------------------------------
    if op == "GET_ITER":
        src = pop() or unknown()
        push(Expr(kind="iter", args=(src,), origins=frozenset({off})))
        return

    if op == "GET_ITER_STACK":
        # Converte TOS (já na pilha) em iterador
        src = pop() or unknown()
        push(Expr(kind="iter", args=(src,), origins=frozenset({off})))
        return

    if op == "FOR_ITER":
        # Peek no iterador; empurra próximo valor
        it = stack[-1] if stack else unknown()
        push(Expr(kind="next", args=(it,), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Coleções
    # ------------------------------------------------------------------
    if op == "BUILD_TUPLE":
        n = instr.get("argval") or 0
        elems = list(reversed(pop_n(n)))
        push(Expr(kind="tuple", args=tuple(elems), origins=frozenset({off})))
        return

    if op == "BUILD_LIST":
        n = instr.get("argval") or 0
        elems = list(reversed(pop_n(n)))
        push(Expr(kind="list", args=tuple(elems), origins=frozenset({off})))
        return

    if op == "BUILD_MAP":
        # MicroPython: BUILD_MAP 0 cria dict vazio; pares adicionados por STORE_MAP
        # (diferente do CPython BUILD_MAP n que pop 2n itens)
        push(Expr(kind="dict", args=(), origins=frozenset({off})))
        return

    if op == "BUILD_SET":
        n = instr.get("argval") or 0
        elems = list(reversed(pop_n(n)))
        push(Expr(kind="set", args=tuple(elems), origins=frozenset({off})))
        return

    if op == "BUILD_SLICE":
        n = instr.get("argval") or 2
        if n == 3:
            step  = pop() or unknown()
            stop  = pop() or unknown()
            start = pop() or unknown()
            push(Expr(kind="slice", args=(start, stop, step), origins=frozenset({off})))
        else:
            stop  = pop() or unknown()
            start = pop() or unknown()
            push(Expr(kind="slice", args=(start, stop), origins=frozenset({off})))
        return

    if op == "UNPACK_SEQUENCE":
        n = instr.get("argval") or 0
        seq = pop() or unknown()
        for i in range(n - 1, -1, -1):
            push(Expr(kind="unpack", value=i, args=(seq,), origins=frozenset({off})))
        return

    if op == "UNPACK_EX":
        argval = instr.get("argval") or (0, 0)
        n_before, n_after = argval if isinstance(argval, tuple) else (argval, 0)
        seq   = pop() or unknown()
        total = n_before + 1 + n_after
        for i in range(total - 1, -1, -1):
            if i == n_before:
                push(Expr(kind="starred",
                          args=(Expr(kind="unpack", value=i, args=(seq,), origins=frozenset({off})),),
                          origins=frozenset({off})))
            else:
                push(Expr(kind="unpack", value=i, args=(seq,), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Funções e closures
    # ------------------------------------------------------------------
    if op == "MAKE_FUNCTION":
        child_idx = instr.get("argval") or 0
        push(Expr(kind="make_function", value=child_idx,
                  args=(None, None, None, None), origins=frozenset({off})))
        return

    if op == "MAKE_FUNCTION_DEFARGS":
        child_idx = instr.get("argval") or 0
        defaults  = pop() or unknown()
        push(Expr(kind="make_function", value=child_idx,
                  args=(defaults, None, None, None), origins=frozenset({off})))
        return

    if op == "MAKE_CLOSURE":
        argval = instr.get("argval") or (0, 0)
        child_idx, n_closed = argval if isinstance(argval, tuple) else (argval, 0)
        closed_vars = list(reversed(pop_n(n_closed)))
        closure_tup = Expr(kind="tuple", args=tuple(closed_vars), origins=frozenset({off}))
        push(Expr(kind="make_function", value=child_idx,
                  args=(None, None, None, closure_tup), origins=frozenset({off})))
        return

    if op == "MAKE_CLOSURE_DEFARGS":
        argval = instr.get("argval") or (0, 0)
        child_idx, n_closed = argval if isinstance(argval, tuple) else (argval, 0)
        closed_vars = list(reversed(pop_n(n_closed)))
        defaults    = pop() or unknown()
        closure_tup = Expr(kind="tuple", args=tuple(closed_vars), origins=frozenset({off}))
        push(Expr(kind="make_function", value=child_idx,
                  args=(defaults, None, None, closure_tup), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Chamadas de função / método
    # ------------------------------------------------------------------
    if op in ("CALL_FUNCTION", "CALL_FUNCTION_VAR_KW",
              "CALL_METHOD",   "CALL_METHOD_VAR_KW"):

        argval = instr.get("argval") or (0, 0)
        n_pos, n_kw = argval if isinstance(argval, tuple) else (argval, 0)

        has_var_kw = op in ("CALL_FUNCTION_VAR_KW", "CALL_METHOD_VAR_KW")
        is_method  = op in ("CALL_METHOD",          "CALL_METHOD_VAR_KW")

        # **kwargs dict no topo (se variante VAR_KW)
        kwargs_dict = pop() if has_var_kw else None

        # Pares de keyword args (n_kw pares key/val; key é constante string)
        kw_args = []
        for _ in range(n_kw):
            val = pop() or unknown()
            key = pop() or unknown()
            kw_args.insert(0, (key, val))

        # Args posicionais
        pos_args = list(reversed(pop_n(n_pos)))

        # Callable (TOS após args)
        fn = pop() or unknown()

        # CALL_METHOD: receiver ou NULL abaixo do callable
        if is_method:
            pop()  # descarta null/receiver (já embutido no attr expr)

        # Monta lista de args para Expr call
        all_args = [fn] + pos_args
        for k, v in kw_args:
            kw_name = (
                k.value
                if isinstance(k, Expr) and k.kind == "const" and isinstance(k.value, str)
                else expr_repr(k)
            )
            all_args.append(Expr(kind="kwarg", value=kw_name, args=(v,), origins=frozenset({off})))

        if kwargs_dict is not None:
            all_args.append(Expr(kind="double_starred", args=(kwargs_dict,), origins=frozenset({off})))

        push(Expr(kind="call", args=tuple(all_args), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Return / Yield
    # ------------------------------------------------------------------
    if op == "RETURN_VALUE":
        val = pop()
        push(Expr(kind="return_value", args=(val,), origins=frozenset({off})))
        return

    if op == "YIELD_VALUE":
        val = pop() or unknown()
        push(Expr(kind="yield", args=(val,), origins=frozenset({off})))
        return

    if op == "YIELD_FROM":
        # MicroPython: protocolo "yield from" como single opcode
        # TOS = send_val (valor a enviar ao sub-gerador), TOS1 = sub-gerador / iterável
        pop()  # descarta send_val (TOS)
        subgen = pop() or unknown()  # sub-gerador (TOS1)
        # Desfaz iter() wrapping: GET_ITER antes de YIELD_FROM é artefato do bytecode
        if isinstance(subgen, Expr) and subgen.kind == "iter" and subgen.args:
            subgen = subgen.args[0]
        stmts.append(Stmt(kind="yield_from", expr=subgen, origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Exceções
    # ------------------------------------------------------------------
    if op in ("SETUP_EXCEPT", "SETUP_FINALLY"):
        # Configura handler; sem efeito imediato na pilha
        return

    if op == "SETUP_WITH":
        # TOS = context manager; empurra __exit__ + resultado de __enter__()
        ctx = pop() or unknown()
        push(Expr(kind="with_exit",  args=(ctx,), origins=frozenset({off})))
        push(Expr(kind="with_enter", args=(ctx,), origins=frozenset({off})))
        return

    if op == "POP_EXCEPT_JUMP":
        pop()  # remove exceção do topo
        return

    if op == "WITH_CLEANUP":
        if stack:
            exc = pop() or unknown()
            push(Expr(kind="with_cleanup", args=(exc,), origins=frozenset({off})))
        return

    if op == "END_FINALLY":
        if stack:
            pop()
        return

    if op == "RAISE_LAST":
        stmts.append(Stmt(kind="raise", expr=None, origins=frozenset({off})))
        stack.clear()
        return

    if op == "RAISE_OBJ":
        exc = pop() or unknown()
        stmts.append(Stmt(kind="raise", expr=exc, origins=frozenset({off})))
        stack.clear()
        return

    if op == "RAISE_FROM":
        cause = pop() or unknown()
        exc   = pop() or unknown()
        stmts.append(Stmt(kind="raise", expr=exc, extra=cause, origins=frozenset({off})))
        stack.clear()
        return

    # ------------------------------------------------------------------
    # Import
    # ------------------------------------------------------------------
    if op == "IMPORT_NAME":
        fromlist    = pop() or unknown()
        level       = pop() or unknown()
        module_name = instr.get("argval")
        push(Expr(kind="import", value=module_name, args=(level, fromlist), origins=frozenset({off})))
        return

    if op == "IMPORT_FROM":
        module    = stack[-1] if stack else unknown()
        attr_name = instr.get("argval")
        push(Expr(kind="import_from", value=attr_name, args=(module,), origins=frozenset({off})))
        return

    if op == "IMPORT_STAR":
        module      = pop() or unknown()
        module_name = module.value if isinstance(module, Expr) and module.kind == "import" else "?"
        stmts.append(Stmt(kind="import_star", target=str(module_name), origins=frozenset({off})))
        return

    # ------------------------------------------------------------------
    # Fallback: opcode não reconhecido
    # ------------------------------------------------------------------
    if debug:
        print(f"[DEBUG MPY INSTR] Opcode não tratado: {op} @ offset {off}")


# ---------------------------------------------------------------------------
# Simulação principal (algoritmo de ponto-fixo)
# ---------------------------------------------------------------------------

def simulate_mpy_stack(
    blocks: list,
    cfg: dict,
    instructions: list,
    code_obj,
    debug: bool = False,
    max_iters: int = 2000,
) -> dict:
    """
    Simulação de pilha com fixpoint para bytecode MicroPython.

    Parâmetros:
        blocks       — lista de blocos básicos (de build_mpy_basic_blocks)
        cfg          — dicionário de arestas (de build_mpy_cfg)
        instructions — lista de instruções (de parse_mpy_instructions)
        code_obj     — MpyCodeObject (usado só para logs)
        debug        — ativa saída [DEBUG]
        max_iters    — limite de iterações do fixpoint

    Retorna dict com:
        "in_stack"         — {bid: list[Expr]}
        "out_stack"        — {bid: list[Expr]}
        "block_statements" — {bid: list[Stmt]}
        "block_conditions" — {bid: list[Expr]}
    """
    if debug:
        name = getattr(code_obj, "co_name", "<?>")
        print(f"[DEBUG MPY] Simulando pilha de '{name}' ({len(blocks)} blocos)")

    # --- fingerprint de pilha (para detecção de convergência) ---
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
        elif (isinstance(v, tuple)
              and all(isinstance(x, (int, float, str, bool, type(None))) for x in v)):
            vkey = ("valtuple", v)
        else:
            vkey = ("valtype", type(v).__name__)
        args_key = tuple(expr_key(a, depth - 1) for a in (e.args or ()))
        okey = tuple(sorted(e.origins)) if getattr(e, "origins", None) else ()
        return ("expr", e.kind, vkey, args_key, okey)

    def fp(stack):
        return tuple(
            expr_key(v) if isinstance(v, Expr) else ("obj", type(v).__name__)
            for v in stack
        )

    in_stack  = {b["id"]: [] for b in blocks}
    out_stack = {b["id"]: [] for b in blocks}
    in_fp     = {b["id"]: None for b in blocks}
    out_fp    = {b["id"]: None for b in blocks}

    block_statements = {b["id"]: [] for b in blocks}
    block_conditions = {b["id"]: [] for b in blocks}

    preds_map = build_predecessor_map(blocks, cfg)

    if blocks:
        entry = blocks[0]["id"]
        in_stack[entry] = []
        in_fp[entry]    = fp([])

    blocks_sorted = sorted(blocks, key=lambda b: b["start_offset"])

    changed = True
    it = 0

    while changed:
        it += 1
        if it > max_iters:
            if debug:
                print(f"[DEBUG MPY] Max iters ({max_iters}) atingido; parando fixpoint")
            break

        changed = False

        for block in blocks_sorted:
            bid   = block["id"]
            preds = list(preds_map.get(bid, ()))

            if preds:
                stacks = [out_stack[p] for p in preds if out_fp.get(p) is not None]
                merged_in = merge_stacks(stacks) if stacks else []
            else:
                merged_in = in_stack[bid] if in_fp[bid] is not None else []

            merged_fp = fp(merged_in)
            if in_fp[bid] != merged_fp:
                in_stack[bid] = list(merged_in)
                in_fp[bid]    = merged_fp
                changed = True

            cur_stack = list(in_stack[bid])
            stmts = []
            conds = []

            for instr in block["instructions"]:
                simulate_mpy_instruction(instr, cur_stack, stmts, conds, debug=False)

            ops_in_block = {ins["opname"] for ins in block.get("instructions", [])}

            # --- materialização de RETURN_VALUE ---
            ret_expr = None
            for v in reversed(cur_stack):
                if isinstance(v, Expr) and v.kind == "return_value":
                    ret_expr = v
                    break

            if ret_expr is not None:
                is_loop_cleanup = block.get("loop_after") is not None
                val     = ret_expr.args[0] if ret_expr.args else None
                is_none = (
                    val is None
                    or (isinstance(val, Expr) and val.kind == "const" and val.value is None)
                )
                has_real_stmt = any(s.kind not in ("del",) for s in stmts)

                # Detecta epílogo implícito: bloco cujas únicas instruções
                # são LOAD_CONST_NONE + RETURN_VALUE (return None implícito
                # adicionado pelo compilador MicroPython a toda função)
                block_ops = [ins["opname"] for ins in block["instructions"]]
                is_epilogue = is_none and block_ops == ["LOAD_CONST_NONE", "RETURN_VALUE"]

                if not is_loop_cleanup:
                    if not is_none:
                        stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))
                    elif not has_real_stmt and not is_epilogue:
                        stmts.append(Stmt(kind="return", expr=val, origins=ret_expr.origins))

                cur_stack = [
                    v for v in cur_stack
                    if not (isinstance(v, Expr) and v.kind == "return_value")
                ]

            block_statements[bid] = stmts
            block_conditions[bid] = conds

            # --- terminação ---
            terminated = (
                bool(ops_in_block & _MPY_TERMINATORS)
                or any(s.kind in ("return", "raise") for s in stmts)
            )

            if terminated:
                if out_fp[bid] is not None:
                    out_stack[bid] = []
                    out_fp[bid]    = None
                    changed = True
            else:
                cur_fp = fp(cur_stack)
                if out_fp[bid] != cur_fp:
                    out_stack[bid] = cur_stack
                    out_fp[bid]    = cur_fp
                    changed = True

    if debug:
        print(f"[DEBUG MPY] Fixpoint convergiu em {it} iterações")

    return {
        "in_stack":         in_stack,
        "out_stack":        out_stack,
        "block_statements": block_statements,
        "block_conditions": block_conditions,
    }
