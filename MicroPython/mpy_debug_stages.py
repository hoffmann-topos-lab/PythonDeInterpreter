

import sys
import os
import argparse
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from MicroPython.mpy_loader import load_mpy, ARCH_NAMES, KIND_BYTECODE
from MicroPython.mpy_disasm import parse_mpy_instructions, format_instructions
from MicroPython.mpy_ir_adapter import adapt_raw_code, MpyCodeObject
from MicroPython.mpy_stack_sim import (
    build_mpy_basic_blocks,
    build_mpy_cfg,
    simulate_mpy_stack,
)
from MicroPython.mpy_patterns import detect_mpy_patterns
from MicroPython.mpy_extract import process_mpy_code_object
from utils.codegen import generate_python_code
from utils.ir import stmt_repr, expr_repr



def collect_code_objects(mpy_obj: MpyCodeObject) -> list:
    """Retorna lista de MpyCodeObjects em pré-ordem (raiz primeiro)."""
    result = [mpy_obj]
    for child in mpy_obj._children:
        result.extend(collect_code_objects(child))
    return result



def print_header(mpy_obj: MpyCodeObject):
    print("\n" + "=" * 80)
    label = f"[CO] {mpy_obj.co_name}  (firstlineno={mpy_obj.co_firstlineno})"
    if mpy_obj.kind != KIND_BYTECODE:
        from MicroPython.mpy_loader import KIND_NATIVE, KIND_VIPER
        kind_name = {KIND_BYTECODE: "bytecode", 1: "native", 2: "viper"}.get(mpy_obj.kind, "?")
        label += f"  [{kind_name.upper()}]"
    print(label)
    print("=" * 80)


def print_hex(mpy_obj: MpyCodeObject):
    instrs = mpy_obj._instructions
    if not instrs:
        print("  (sem instruções decodificadas)")
        return
    print(format_instructions(instrs, mpy_obj._line_map))


def print_parsed(mpy_obj: MpyCodeObject):
    instrs = mpy_obj._instructions
    for instr in instrs:
        off  = instr["offset"]
        op   = instr["opname"]
        ar   = instr.get("argrepr") or ""
        jt   = instr.get("jump_target")
        mark = " [TARGET]" if instr.get("is_jump_target") else ""
        tgt  = f" -> {jt}" if jt is not None else ""
        if ar:
            print(f"{off:4d}  {op:32s} {ar}{tgt}{mark}")
        else:
            print(f"{off:4d}  {op:32s}{tgt}{mark}")


def print_blocks(blocks: list):
    for b in sorted(blocks, key=lambda bb: bb["start_offset"]):
        print(f"\n[BB {b['id']}] start={b['start_offset']} end={b['end_offset']}")
        for ins in b["instructions"]:
            off = ins["offset"]
            op  = ins["opname"]
            ar  = ins.get("argrepr") or ""
            jt  = ins.get("jump_target")
            if jt is not None:
                print(f"  {off:5d}  {op:32s} {ar:20s} -> {jt}")
            else:
                print(f"  {off:5d}  {op:32s} {ar}")


def print_cfg(cfg: dict):
    for src in sorted(cfg.keys()):
        print(f"  {src} -> {sorted(cfg[src])}")


def print_patterns_summary(patterns: dict):
    ifs      = patterns.get("ifs", [])
    loops    = patterns.get("loops", [])
    tries    = patterns.get("try_regions", [])
    withs    = patterns.get("with_regions", [])
    sc_bids  = patterns.get("short_circuit_blocks", set())
    sc_cands = patterns.get("short_circuit_candidates", [])
    comps    = patterns.get("comprehensions", [])

    print(f"\n  IFs ({len(ifs)}):")
    for p in ifs:
        print(f"    cond={p['cond_block']} ({p['opcode']}) jump={p['jump_block']} fall={p['fall_block']}")

    print(f"\n  LOOPs ({len(loops)}):")
    for p in loops:
        kind = "FOR" if p.get("is_for") else "WHILE"
        print(f"    [{kind}] header={p['header']} latch={p['latch']} body_entry={p['body_entry']}")

    print(f"\n  TRY-REGIONs ({len(tries)}):")
    for r in tries:
        hs = [h['handler_block'] for h in r.get('handlers', [])]
        kind = "EXCEPT" if r['handlers'][0]['is_except'] else "FINALLY" if r['handlers'][0]['is_cleanup'] else "?"
        print(f"    [{kind}] range={r['range']} prot={r['protected_blocks']} handlers={hs}")

    print(f"\n  WITHs ({len(withs)}):")
    for w in withs:
        print(f"    bloco={w['block']} as_var={w['as_var']} handler={w['handler_block']} prot={w['protected_blocks']}")

    print(f"\n  SHORT-CIRCUIT ({len(sc_cands)}) — blocks={sorted(sc_bids)}:")
    for sc in sc_cands:
        kind = "AND" if sc['is_and'] else "OR"
        print(f"    [{kind}] bloco={sc['block']} jump={sc['jump_block']} fall={sc['fall_block']}")

    print(f"\n  COMPREHENSIONs ({len(comps)}):")
    for c in comps:
        print(f"    header={c['header']}")

    wh = patterns.get("with_handler_blocks", set())
    if wh:
        print(f"\n  with_handler_blocks: {sorted(wh)}")


def print_stack_summary(blocks: list, stack_info: dict):
    bs   = stack_info.get("block_statements") or {}
    bc   = stack_info.get("block_conditions")  or {}
    ins_ = stack_info.get("in_stack")          or {}
    out_ = stack_info.get("out_stack")         or {}

    for b in sorted(blocks, key=lambda bb: bb["start_offset"]):
        bid = b["id"]
        print(f"\n  [BB {bid}]")
        print(f"    IN : {[expr_repr(x) for x in (ins_.get(bid) or [])]}")
        print(f"    OUT: {[expr_repr(x) for x in (out_.get(bid) or [])]}")
        if bs.get(bid):
            print("    STMTS:")
            for st in bs[bid]:
                print(f"      - {stmt_repr(st)}")
        if bc.get(bid):
            print("    CONDS:")
            for cnd in bc[bid]:
                print(f"      - {expr_repr(cnd)}")



def run_stage(mpy_obj: MpyCodeObject, stage: str, debug: bool):
    print_header(mpy_obj)

    if mpy_obj.kind != KIND_BYTECODE:
        from MicroPython.mpy_loader import KIND_NATIVE, KIND_VIPER
        kind_name = {1: "native", 2: "viper"}.get(mpy_obj.kind, "?")

        if stage == "native_asm":
            print(f"\n[STAGE native_asm] disassembly de código {kind_name}")
            if hasattr(mpy_obj, "_native_code") and mpy_obj._native_code and mpy_obj._prelude_offset > 0:
                from NativeDisasm import disassemble_native
                asm = disassemble_native(mpy_obj._native_code, mpy_obj.arch_code, mpy_obj._prelude_offset)
                print(asm)
            else:
                print("  (sem bytes de código nativo disponíveis)")
        else:
            print(f"  (código {kind_name} — sem decompilação de bytecode)")
        return

    instrs = mpy_obj._instructions
    if not instrs:
        print("  (sem instruções)")
        return

    if stage == "dis":
        print("\n[STAGE dis] hex dump / instruções decodificadas")
        print_hex(mpy_obj)
        return

    if stage == "parse":
        print("\n[STAGE parse] instruções decodificadas")
        print_parsed(mpy_obj)
        return

    blocks = build_mpy_basic_blocks(instrs, debug=debug)

    if stage == "blocks":
        print("\n[STAGE blocks] blocos básicos")
        print_blocks(blocks)
        return

    cfg = build_mpy_cfg(blocks, instrs, debug=debug)

    if stage == "cfg":
        print("\n[STAGE cfg] CFG")
        print_cfg(cfg)
        return

    stack_info = simulate_mpy_stack(blocks, cfg, instrs, mpy_obj, debug=debug)

    if stage == "stack":
        print("\n[STAGE stack] IN/OUT + stmts + conds (resumo por bloco)")
        print_stack_summary(blocks, stack_info)
        return

    patterns = detect_mpy_patterns(blocks, cfg, stack_info, mpy_obj, debug=debug)

    if stage == "patterns":
        print("\n[STAGE patterns] padrões de alto nível detectados")
        print_patterns_summary(patterns)
        return

    if stage == "gen_code":

        return



def main():
    STAGES = {"dis", "parse", "blocks", "cfg", "stack", "patterns", "native_asm", "gen_code"}

    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        description="Debug do pipeline MicroPython por stage.",
    )
    parser.add_argument("mpy_path", help="caminho para o arquivo .mpy")
    parser.add_argument(
        "--stage",
        required=True,
        choices=sorted(STAGES),
        help="etapa de debug a executar",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="habilita saída [DEBUG] interna",
    )
    args = parser.parse_args()

    mpy_path = args.mpy_path
    stage    = args.stage
    debug    = args.debug


    try:
        header, qstrs, consts, raw_root = load_mpy(mpy_path)
    except (ValueError, EOFError) as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        sys.exit(1)

    arch_code = header["arch_code"]
    arch_name = header.get("arch_name", ARCH_NAMES.get(arch_code, f"arch_{arch_code}"))
    sub_ver   = header["sub_version"]

    print(f"MicroPython .mpy v6.{sub_ver} · {arch_name} · {mpy_path}")
    print(f"  qstrs: {len(qstrs)}  constantes: {len(consts)}")

    root = adapt_raw_code(raw_root, qstrs, consts, filename=mpy_path, arch_code=arch_code)
    all_objs = collect_code_objects(root)

    if not all_objs:
        print("[ERRO] Nenhum code object encontrado no .mpy")
        sys.exit(1)

    if stage == "gen_code":
        print("\n[STAGE gen_code] pipeline completo — código recuperado\n")
        tree = process_mpy_code_object(root, debug=debug)
        print(generate_python_code(tree, debug=False))
        return

    for mpy_obj in all_objs:
        run_stage(mpy_obj, stage, debug)


if __name__ == "__main__":
    main()
)
from MicroPython.mpy_patterns import detect_mpy_patterns
from MicroPython.mpy_extract import process_mpy_code_object
from utils.codegen import generate_python_code
from utils.ir import stmt_repr, expr_repr


# ---------------------------------------------------------------------------
# Coleta recursiva de todos os MpyCodeObject (bytecode apenas)
# ---------------------------------------------------------------------------

def collect_code_objects(mpy_obj: MpyCodeObject) -> list:
    """Retorna lista de MpyCodeObjects em pré-ordem (raiz primeiro)."""
    result = [mpy_obj]
    for child in mpy_obj._children:
        result.extend(collect_code_objects(child))
    return result


# ---------------------------------------------------------------------------
# Helpers de impressão
# ---------------------------------------------------------------------------

def print_header(mpy_obj: MpyCodeObject):
    print("\n" + "=" * 80)
    label = f"[CO] {mpy_obj.co_name}  (firstlineno={mpy_obj.co_firstlineno})"
    if mpy_obj.kind != KIND_BYTECODE:
        from MicroPython.mpy_loader import KIND_NATIVE, KIND_VIPER
        kind_name = {KIND_BYTECODE: "bytecode", 1: "native", 2: "viper"}.get(mpy_obj.kind, "?")
        label += f"  [{kind_name.upper()}]"
    print(label)
    print("=" * 80)


def print_hex(mpy_obj: MpyCodeObject):
    """Dump hexadecimal do bytecode bruto."""
    # Os bytes brutos não estão diretamente em MpyCodeObject após o adapter.
    # Mostramos as instruções já decodificadas como fallback.
    instrs = mpy_obj._instructions
    if not instrs:
        print("  (sem instruções decodificadas)")
        return
    print(format_instructions(instrs, mpy_obj._line_map))


def print_parsed(mpy_obj: MpyCodeObject):
    instrs = mpy_obj._instructions
    for instr in instrs:
        off  = instr["offset"]
        op   = instr["opname"]
        ar   = instr.get("argrepr") or ""
        jt   = instr.get("jump_target")
        mark = " [TARGET]" if instr.get("is_jump_target") else ""
        tgt  = f" -> {jt}" if jt is not None else ""
        if ar:
            print(f"{off:4d}  {op:32s} {ar}{tgt}{mark}")
        else:
            print(f"{off:4d}  {op:32s}{tgt}{mark}")


def print_blocks(blocks: list):
    for b in sorted(blocks, key=lambda bb: bb["start_offset"]):
        print(f"\n[BB {b['id']}] start={b['start_offset']} end={b['end_offset']}")
        for ins in b["instructions"]:
            off = ins["offset"]
            op  = ins["opname"]
            ar  = ins.get("argrepr") or ""
            jt  = ins.get("jump_target")
            if jt is not None:
                print(f"  {off:5d}  {op:32s} {ar:20s} -> {jt}")
            else:
                print(f"  {off:5d}  {op:32s} {ar}")


def print_cfg(cfg: dict):
    for src in sorted(cfg.keys()):
        print(f"  {src} -> {sorted(cfg[src])}")


def print_patterns_summary(patterns: dict):
    """Imprime resumo dos padrões detectados."""
    ifs      = patterns.get("ifs", [])
    loops    = patterns.get("loops", [])
    tries    = patterns.get("try_regions", [])
    withs    = patterns.get("with_regions", [])
    sc_bids  = patterns.get("short_circuit_blocks", set())
    sc_cands = patterns.get("short_circuit_candidates", [])
    comps    = patterns.get("comprehensions", [])

    print(f"\n  IFs ({len(ifs)}):")
    for p in ifs:
        print(f"    cond={p['cond_block']} ({p['opcode']}) jump={p['jump_block']} fall={p['fall_block']}")

    print(f"\n  LOOPs ({len(loops)}):")
    for p in loops:
        kind = "FOR" if p.get("is_for") else "WHILE"
        print(f"    [{kind}] header={p['header']} latch={p['latch']} body_entry={p['body_entry']}")

    print(f"\n  TRY-REGIONs ({len(tries)}):")
    for r in tries:
        hs = [h['handler_block'] for h in r.get('handlers', [])]
        kind = "EXCEPT" if r['handlers'][0]['is_except'] else "FINALLY" if r['handlers'][0]['is_cleanup'] else "?"
        print(f"    [{kind}] range={r['range']} prot={r['protected_blocks']} handlers={hs}")

    print(f"\n  WITHs ({len(withs)}):")
    for w in withs:
        print(f"    bloco={w['block']} as_var={w['as_var']} handler={w['handler_block']} prot={w['protected_blocks']}")

    print(f"\n  SHORT-CIRCUIT ({len(sc_cands)}) — blocks={sorted(sc_bids)}:")
    for sc in sc_cands:
        kind = "AND" if sc['is_and'] else "OR"
        print(f"    [{kind}] bloco={sc['block']} jump={sc['jump_block']} fall={sc['fall_block']}")

    print(f"\n  COMPREHENSIONs ({len(comps)}):")
    for c in comps:
        print(f"    header={c['header']}")

    wh = patterns.get("with_handler_blocks", set())
    if wh:
        print(f"\n  with_handler_blocks: {sorted(wh)}")


def print_stack_summary(blocks: list, stack_info: dict):
    bs   = stack_info.get("block_statements") or {}
    bc   = stack_info.get("block_conditions")  or {}
    ins_ = stack_info.get("in_stack")          or {}
    out_ = stack_info.get("out_stack")         or {}

    for b in sorted(blocks, key=lambda bb: bb["start_offset"]):
        bid = b["id"]
        print(f"\n  [BB {bid}]")
        print(f"    IN : {[expr_repr(x) for x in (ins_.get(bid) or [])]}")
        print(f"    OUT: {[expr_repr(x) for x in (out_.get(bid) or [])]}")
        if bs.get(bid):
            print("    STMTS:")
            for st in bs[bid]:
                print(f"      - {stmt_repr(st)}")
        if bc.get(bid):
            print("    CONDS:")
            for cnd in bc[bid]:
                print(f"      - {expr_repr(cnd)}")


# ---------------------------------------------------------------------------
# Pipeline por code object
# ---------------------------------------------------------------------------

def run_stage(mpy_obj: MpyCodeObject, stage: str, debug: bool):
    print_header(mpy_obj)

    if mpy_obj.kind != KIND_BYTECODE:
        from MicroPython.mpy_loader import KIND_NATIVE, KIND_VIPER
        kind_name = {1: "native", 2: "viper"}.get(mpy_obj.kind, "?")

        if stage == "native_asm":
            print(f"\n[STAGE native_asm] disassembly de código {kind_name}")
            if hasattr(mpy_obj, "_native_code") and mpy_obj._native_code and mpy_obj._prelude_offset > 0:
                from NativeDisasm import disassemble_native
                asm = disassemble_native(mpy_obj._native_code, mpy_obj.arch_code, mpy_obj._prelude_offset)
                print(asm)
            else:
                print("  (sem bytes de código nativo disponíveis)")
        else:
            print(f"  (código {kind_name} — sem decompilação de bytecode)")
        return

    instrs = mpy_obj._instructions
    if not instrs:
        print("  (sem instruções)")
        return

    if stage == "dis":
        print("\n[STAGE dis] hex dump / instruções decodificadas")
        print_hex(mpy_obj)
        return

    if stage == "parse":
        print("\n[STAGE parse] instruções decodificadas")
        print_parsed(mpy_obj)
        return

    # Blocos básicos
    blocks = build_mpy_basic_blocks(instrs, debug=debug)

    if stage == "blocks":
        print("\n[STAGE blocks] blocos básicos")
        print_blocks(blocks)
        return

    # CFG
    cfg = build_mpy_cfg(blocks, instrs, debug=debug)

    if stage == "cfg":
        print("\n[STAGE cfg] CFG")
        print_cfg(cfg)
        return

    # Simulação de pilha
    stack_info = simulate_mpy_stack(blocks, cfg, instrs, mpy_obj, debug=debug)

    if stage == "stack":
        print("\n[STAGE stack] IN/OUT + stmts + conds (resumo por bloco)")
        print_stack_summary(blocks, stack_info)
        return

    # Detecção de padrões
    patterns = detect_mpy_patterns(blocks, cfg, stack_info, mpy_obj, debug=debug)

    if stage == "patterns":
        print("\n[STAGE patterns] padrões de alto nível detectados")
        print_patterns_summary(patterns)
        return

    if stage == "gen_code":
        # gen_code processa a partir da raiz, não por CO individual
        # (é tratado no main() diretamente)
        return


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    STAGES = {"dis", "parse", "blocks", "cfg", "stack", "patterns", "native_asm", "gen_code"}

    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        description="Debug do pipeline MicroPython por stage.",
    )
    parser.add_argument("mpy_path", help="caminho para o arquivo .mpy")
    parser.add_argument(
        "--stage",
        required=True,
        choices=sorted(STAGES),
        help="etapa de debug a executar",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="habilita saída [DEBUG] interna",
    )
    args = parser.parse_args()

    mpy_path = args.mpy_path
    stage    = args.stage
    debug    = args.debug

    # Carrega e adapta
    try:
        header, qstrs, consts, raw_root = load_mpy(mpy_path)
    except (ValueError, EOFError) as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        sys.exit(1)

    arch_code = header["arch_code"]
    arch_name = header.get("arch_name", ARCH_NAMES.get(arch_code, f"arch_{arch_code}"))
    sub_ver   = header["sub_version"]

    print(f"MicroPython .mpy v6.{sub_ver} · {arch_name} · {mpy_path}")
    print(f"  qstrs: {len(qstrs)}  constantes: {len(consts)}")

    root = adapt_raw_code(raw_root, qstrs, consts, filename=mpy_path, arch_code=arch_code)

    # Coleta todos os code objects
    all_objs = collect_code_objects(root)

    if not all_objs:
        print("[ERRO] Nenhum code object encontrado no .mpy")
        sys.exit(1)

    if stage == "gen_code":
        print("\n[STAGE gen_code] pipeline completo — código recuperado\n")
        tree = process_mpy_code_object(root, debug=debug)
        print(generate_python_code(tree, debug=False))
        return

    # Os outros stages iteram por CO individualmente
    for mpy_obj in all_objs:
        run_stage(mpy_obj, stage, debug)


if __name__ == "__main__":
    main()
