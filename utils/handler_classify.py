from utils.block_utils import get_block_instrs, get_block_opnames


def classify_handler_block(block: dict) -> dict:
    """Classifica um bloco handler de exceção.

    Aceita um block dict diretamente.

    Retorna dict com flags booleanas:
        opnames, is_except, is_cleanup, is_gen_cleanup, is_exc_var_cleanup,
        is_with_handler, is_with_reraise, is_comp_restore,
        is_cleanup_throw, is_async_for_exit.
    """
    ins_list = get_block_instrs(block)
    opnames = get_block_opnames(block)

    is_except = ("CHECK_EXC_MATCH" in opnames) or ("PUSH_EXC_INFO" in opnames)
    is_cleanup = ("RERAISE" in opnames) or ("POP_EXCEPT" in opnames)

    # Generator/coroutine plumbing: CALL_INTRINSIC_1(3) = STOPITERATION_ERROR + RERAISE
    is_gen_cleanup = ("CALL_INTRINSIC_1" in opnames and "RERAISE" in opnames
                      and any(ins.get("opname") == "CALL_INTRINSIC_1" and ins.get("arg") == 3
                              for ins in ins_list))

    # CLEANUP_THROW: single opcode generated for await/yield from coroutine cleanup
    is_cleanup_throw = (set(opnames).issubset({"CLEANUP_THROW", "NOP"})
                        and "CLEANUP_THROW" in opnames)

    # END_ASYNC_FOR: plumbing de async for para tratar StopAsyncIteration
    is_async_for_exit = "END_ASYNC_FOR" in opnames

    # Exception variable cleanup: LOAD_CONST None + STORE_FAST + DELETE_FAST + RERAISE
    exc_var_cleanup_allowed = {"LOAD_CONST", "STORE_FAST", "DELETE_FAST", "RERAISE", "NOP"}
    is_exc_var_cleanup = (set(opnames).issubset(exc_var_cleanup_allowed)
                          and "RERAISE" in opnames and "DELETE_FAST" in opnames)

    # With handler: PUSH_EXC_INFO + WITH_EXCEPT_START
    is_with_handler = "WITH_EXCEPT_START" in opnames

    # With outer reraise: COPY + POP_EXCEPT + RERAISE (handler-of-handler for with)
    with_reraise_allowed = {"COPY", "POP_EXCEPT", "RERAISE", "NOP"}
    is_with_reraise = (set(opnames).issubset(with_reraise_allowed)
                       and "RERAISE" in opnames and "COPY" in opnames)

    # Comprehension restore handler (PEP 709): STORE_FAST + RERAISE sem CHECK_EXC_MATCH/POP_EXCEPT
    # Restaura variável salva por LOAD_FAST_AND_CLEAR no corpo da comprehension
    # Inclui SWAP e POP_TOP que aparecem no padrão real de 3.12
    comp_restore_allowed = {"PUSH_EXC_INFO", "NOP", "STORE_FAST", "STORE_NAME",
                            "LOAD_FAST", "LOAD_CONST", "RERAISE", "SWAP", "POP_TOP"}
    is_comp_restore = (set(opnames).issubset(comp_restore_allowed)
                       and "RERAISE" in opnames
                       and ("STORE_FAST" in opnames or "STORE_NAME" in opnames)
                       and "CHECK_EXC_MATCH" not in opnames
                       and "POP_EXCEPT" not in opnames
                       and "WITH_EXCEPT_START" not in opnames)

    return {
        "opnames": opnames,
        "is_except": is_except,
        "is_cleanup": is_cleanup,
        "is_gen_cleanup": is_gen_cleanup,
        "is_exc_var_cleanup": is_exc_var_cleanup,
        "is_with_handler": is_with_handler,
        "is_with_reraise": is_with_reraise,
        "is_comp_restore": is_comp_restore,
        "is_cleanup_throw": is_cleanup_throw,
        "is_async_for_exit": is_async_for_exit,
    }


def is_pure_cleanup_block(block: dict) -> bool:
    """True se o bloco é puro cleanup de exceção (COPY+POP_EXCEPT+RERAISE)."""
    ops = set(get_block_opnames(block))
    return bool(ops) and ops.issubset({"COPY", "POP_EXCEPT", "RERAISE", "NOP"}) and "RERAISE" in ops


def is_finally_exc_handler(bid: int, blocks_by_id: dict, succ_all: dict) -> bool:
    """Handler de finally-exception: PUSH_EXC_INFO + código do usuário + RERAISE,
    sem CHECK_EXC_MATCH nem POP_EXCEPT. Distingue 'finally' de 'except' bare."""
    b = blocks_by_id.get(bid, {})
    ins_list = get_block_instrs(b)
    opnames = get_block_opnames(b)

    if "PUSH_EXC_INFO" not in opnames:
        return False
    if "CHECK_EXC_MATCH" in opnames:
        return False
    if "POP_EXCEPT" in opnames:
        return False

    _infra = {"PUSH_EXC_INFO", "RERAISE", "COPY", "NOP",
              "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT"}
    # Verifica RERAISE e código do usuário (pode estar em sucessores)
    has_reraise = "RERAISE" in opnames
    has_user = any(op not in _infra for op in opnames)

    if not has_reraise:
        visited_c = {bid}
        queue = list(succ_all.get(bid, set()))
        while queue:
            nb = queue.pop()
            if nb in visited_c:
                continue
            visited_c.add(nb)
            nb_b = blocks_by_id.get(nb, {})
            nb_ops = get_block_opnames(nb_b)
            if "POP_EXCEPT" in nb_ops:
                # Bloco de cleanup puro (COPY+POP_EXCEPT+RERAISE): infraestrutura depth-1,
                # não é um handler real de except. Pula sem retornar False.
                pure_cleanup = set(nb_ops).issubset({"COPY", "NOP", "POP_EXCEPT", "RERAISE"})
                if not pure_cleanup:
                    return False
                continue
            if "RERAISE" in nb_ops or "RETURN_VALUE" in nb_ops or "RETURN_CONST" in nb_ops:
                has_reraise = True
            if any(op not in _infra for op in nb_ops):
                has_user = True
            queue.extend(succ_all.get(nb, set()))
        if not has_reraise:
            return False

    return has_user
