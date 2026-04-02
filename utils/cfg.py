import dis
from typing import List, Dict, Set, Any

def build_basic_blocks(instructions, code_obj=None, debug=True):

    if not instructions:
        return []

    if debug:
        print("[DEBUG] Iniciando construção de blocos básicos (3.11/3.12)")

    # ---------------------------
    # 1) identificar líderes
    # ---------------------------
    leaders = {instructions[0]["offset"]}

    for i, instr in enumerate(instructions):
        if instr.get("jump_target") is not None:
            leaders.add(instr["jump_target"])
            if i + 1 < len(instructions):
                leaders.add(instructions[i + 1]["offset"])

    if code_obj is not None:
        try:
            entries = list(dis.Bytecode(code_obj).exception_entries)
        except Exception:
            entries = []
        if entries:
            inst_offsets = {ins["offset"] for ins in instructions}
            for e in entries:
                if e.target in inst_offsets:
                    leaders.add(e.target)
                if e.start in inst_offsets:
                    leaders.add(e.start)
                if e.end in inst_offsets:
                    leaders.add(e.end)

    leaders = set(sorted(leaders))
    if debug:
        print(f"[DEBUG] Líderes identificados: {sorted(leaders)}")

    # ---------------------------
    # 2) construir blocos + contexto de loop
    # ---------------------------
    blocks = []
    current = None
    bid = 0

    # pilha de after-loop offsets (target do FOR_ITER)
    loop_stack = []

    for ins in instructions:
        off = ins["offset"]

        # PATCH CRÍTICO:
        # se chegamos exatamente no after-loop, saímos do loop ANTES de iniciar o bloco
        while loop_stack and off == loop_stack[-1]:
            exited = loop_stack.pop()
            if debug:
                print(f"[DEBUG] Saída de loop detectada em offset {off} (after-loop={exited})")

        # inicia novo bloco se for leader
        if off in leaders:
            if current is not None:
                blocks.append(current)
                if debug:
                    print(
                        f"[DEBUG] Bloco {current['id']} finalizado em offset {current['end_offset']} "
                        f"(loop_after={current.get('loop_after')})"
                    )

            current = {
                "id": bid,
                "start_offset": off,
                "instructions": [],
                "loop_after": loop_stack[-1] if loop_stack else None,
            }
            bid += 1

            if debug:
                print(
                    f"[DEBUG] Novo bloco {current['id']} iniciado em offset {off} "
                    f"(loop_after={current['loop_after']})"
                )

        current["instructions"].append(ins)
        current["end_offset"] = off

        # entrada em loop FOR
        if ins["opname"] == "FOR_ITER" and ins.get("jump_target") is not None:
            loop_after = ins["jump_target"]
            loop_stack.append(loop_after)
            if debug:
                print(f"[DEBUG] FOR_ITER detectado em {off}, loop_after={loop_after}")

    if current is not None:
        blocks.append(current)
        if debug:
            print(
                f"[DEBUG] Bloco {current['id']} finalizado em offset {current['end_offset']} "
                f"(loop_after={current.get('loop_after')})"
            )

    if debug:
        print(f"[DEBUG] Total de blocos básicos construídos: {len(blocks)}")

    return blocks

def build_cfg(blocks, instructions, code_obj, debug=True):
    import dis

    if debug:
        print("[DEBUG] Iniciando construção do CFG")
        print(f"[DEBUG] CFG para code object: {getattr(code_obj, 'co_name', '<none>')}")

    # map offset -> block id
    offset_to_block = {}
    for b in blocks:
        for ins in b["instructions"]:
            offset_to_block[ins["offset"]] = b["id"]

    cfg = {b["id"]: set() for b in blocks}

    TERMINATORS = {
        "RAISE_VARARGS",
        "RERAISE",
        "JUMP_FORWARD",
        "JUMP_BACKWARD",
        "JUMP_BACKWARD_NO_INTERRUPT",
        "JUMP_NO_INTERRUPT",
        "JUMP",
        "POP_EXCEPT_JUMP",       # MicroPython: salto forward incondicional (ULABEL)
    }

    RETURN_OPS = {"RETURN_VALUE", "RETURN_CONST"}

    # ----------------------------
    # Arestas normais
    # ----------------------------
    for i, b in enumerate(blocks):
        src = b["id"]
        last = b["instructions"][-1]
        op = last["opname"]

        # salto explícito
        jt = last.get("jump_target")
        if jt is not None and jt in offset_to_block:
            dst = offset_to_block[jt]
            cfg[src].add(dst)
            if debug:
                print(f"[DEBUG] CFG: bloco {src} -> salto para bloco {dst}")

        # RETURN real (fora de loop): encerra
        if op in RETURN_OPS and b.get("loop_after") is None:
            if debug:
                print(f"[DEBUG] CFG: bloco {src} RETURN real (exit)")
            continue

        # RETURN estrutural (break em for 3.11+): vai para after-loop
        if op in RETURN_OPS and b.get("loop_after") is not None:
            after = b["loop_after"]
            dst = offset_to_block.get(after)
            if dst is not None:
                cfg[src].add(dst)
                if debug:
                    print(f"[DEBUG] CFG: bloco {src} break -> after-loop bloco {dst}")
            continue

        # terminadores sem fall-through
        if op in TERMINATORS:
            continue

        # fall-through normal
        if i + 1 < len(blocks):
            dst = blocks[i + 1]["id"]
            cfg[src].add(dst)
            if debug:
                print(f"[DEBUG] CFG: bloco {src} -> fall-through para bloco {dst}")

    if code_obj is None:
        return cfg

    # ----------------------------
    # Arestas de exceção (3.11+)
    # ----------------------------
    try:
        entries = list(dis.Bytecode(code_obj).exception_entries)
    except Exception:
        entries = []

    if not entries:
        if debug:
            print("[DEBUG] Nenhuma exception table encontrada")
        return cfg

    for e in entries:
        handler_bid = offset_to_block.get(e.target)
        if handler_bid is None:
            continue

        if debug:
            print(f"[DEBUG] Exception entry: range [{e.start}, {e.end}) -> handler {handler_bid}")

        # adiciona arestas de exceção: blocos protegidos -> handler
        for b in blocks:
            bid = b["id"]

            # PATCH CRÍTICO: não criar self-loop do handler
            if bid == handler_bid:
                continue

            for ins in b["instructions"]:
                off = ins["offset"]
                if e.start <= off < e.end:
                    cfg[bid].add(handler_bid)
                    if debug:
                        print(f"[DEBUG] CFG(EXC): bloco {bid} -> handler {handler_bid}")
                    break

    if debug:
        print("[DEBUG] Construção do CFG finalizada")

    return cfg
