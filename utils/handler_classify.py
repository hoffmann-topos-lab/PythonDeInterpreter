from utils.block_utils import get_block_instrs, get_block_opnames


def classify_handler_block(block: dict) -> dict:

    ins_list = get_block_instrs(block)
    opnames = get_block_opnames(block)

    is_except = ("CHECK_EXC_MATCH" in opnames) or ("PUSH_EXC_INFO" in opnames)
    is_cleanup = ("RERAISE" in opnames) or ("POP_EXCEPT" in opnames)

    is_gen_cleanup = ("CALL_INTRINSIC_1" in opnames and "RERAISE" in opnames
                      and any(ins.get("opname") == "CALL_INTRINSIC_1" and ins.get("arg") == 3
                              for ins in ins_list))

    is_cleanup_throw = (set(opnames).issubset({"CLEANUP_THROW", "NOP"})
                        and "CLEANUP_THROW" in opnames)

    is_async_for_exit = "END_ASYNC_FOR" in opnames

    exc_var_cleanup_allowed = {"LOAD_CONST", "STORE_FAST", "DELETE_FAST", "RERAISE", "NOP"}
    is_exc_var_cleanup = (set(opnames).issubset(exc_var_cleanup_allowed)
                          and "RERAISE" in opnames and "DELETE_FAST" in opnames)

    is_with_handler = "WITH_EXCEPT_START" in opnames

    with_reraise_allowed = {"COPY", "POP_EXCEPT", "RERAISE", "NOP"}
    is_with_reraise = (set(opnames).issubset(with_reraise_allowed)
                       and "RERAISE" in opnames and "COPY" in opnames)

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
    ops = set(get_block_opnames(block))
    return bool(ops) and ops.issubset({"COPY", "POP_EXCEPT", "RERAISE", "NOP"}) and "RERAISE" in ops


def is_finally_exc_handler(bid: int, blocks_by_id: dict, succ_all: dict) -> bool:
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
