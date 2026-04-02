import sys
import os
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                    # Decompiler/ — loader, disasm, etc.
sys.path.insert(0, os.path.dirname(_HERE))   # v0.5/ — utils.*
import dis
import types
import argparse

# ---------------------------------------------------------------------------
# Detecção de formato: delega para mpy_debug_stages se o arquivo for .mpy
# ---------------------------------------------------------------------------

def _is_mpy(path: str) -> bool:
    if not path.lower().endswith(".mpy"):
        return False
    try:
        with open(path, "rb") as f:
            b = f.read(2)
        return len(b) >= 2 and b[0] == 0x4D and b[1] == 6
    except OSError:
        return False

from utils.ir import stmt_repr, expr_repr
from loader import load_code_object, _find_code_by_name
from extract import extract_code_objects
from utils.codegen import generate_python_code
from disasm import parse_instructions
from utils.cfg import build_basic_blocks, build_cfg
from stack_sim import simulate_stack
from patterns import detect_high_level_patterns
from utils.ast_recover import build_recovered_ast

def main():

    STAGES = {
        "dis",
        "parse",
        "blocks",
        "cfg",
        "stack",
        "patterns",
        "recovered_ast",
        "gen_code",
    }

    parser = argparse.ArgumentParser(prog=sys.argv[0])
    parser.add_argument("path", help="caminho para o arquivo .pyc ou .mpy")
    parser.add_argument(
        "--stage",
        required=True,
        choices=sorted(STAGES),
        help="etapa de debug a executar",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="habilita debug interno nas funções do pipeline quando aplicável",
    )
    args = parser.parse_args()

    pyc_path = args.path
    stage = args.stage
    debug = bool(args.debug)

    # Delega para o pipeline MicroPython se for arquivo .mpy
    if _is_mpy(pyc_path):
        from MicroPython import mpy_debug_stages
        mpy_debug_stages.main()
        return

    root = load_code_object(pyc_path)

    # -------- coletar TODOS os code objects do .pyc (recursivo) --------
    seen = set()
    all_cos = []

    def collect(co):
        if not isinstance(co, types.CodeType):
            return
        cid = id(co)
        if cid in seen:
            return
        seen.add(cid)
        all_cos.append(co)
        for c in (co.co_consts or ()):
            if isinstance(c, types.CodeType):
                collect(c)

    collect(root)

    if not all_cos:
        print("[ERRO] Nenhum code object encontrado no .pyc")
        sys.exit(1)

    # ordena por (arquivo/linha/nome) para ficar estável; <module> primeiro
    def _sort_key(co):
        name_rank = 0 if co.co_name == "<module>" else 1
        return (name_rank, getattr(co, "co_firstlineno", 0), co.co_name)

    all_cos.sort(key=_sort_key)

    # -------- helpers de impressão --------
    def print_parsed_instructions(ins):
        for x in ins:
            off = x["offset"]
            op = x["opname"]
            ar = x.get("argrepr") or ""
            jt = x.get("jump_target")
            tgt = f" -> {jt}" if jt is not None else ""
            mark = " [TARGET]" if x.get("is_target") else ""
            if ar:
                print(f"{off:4d}  {op:28s} {ar}{tgt}{mark}")
            else:
                print(f"{off:4d}  {op:28s}{tgt}{mark}")

    def print_blocks(blocks):
        for b in sorted(blocks, key=lambda bb: bb["start_offset"]):
            print(f"\n[BB {b['id']}] start={b['start_offset']} end={b['end_offset']}")
            for insn in b["instructions"]:
                off = insn["offset"]
                op = insn["opname"]
                ar = insn.get("argrepr") or ""
                jt = insn.get("jump_target")
                if jt is not None:
                    print(f"{off:6d}  {op:28s} {ar:20s} to {jt}")
                else:
                    print(f"{off:6d}  {op:28s} {ar}")

    def print_cfg(cfg):
        for src in sorted(cfg.keys()):
            print(f"  {src} -> {sorted(cfg[src])}")

    def print_stack_summary(blocks, stack_info):
        bs = stack_info.get("block_statements") or {}
        bc = stack_info.get("block_conditions") or {}
        ins_ = stack_info.get("in_stack") or {}
        outs_ = stack_info.get("out_stack") or {}

        for b in sorted(blocks, key=lambda bb: bb["start_offset"]):
            bid = b["id"]
            print(f"\n  [BB {bid}]")
            print(f"    IN : {[expr_repr(x) for x in (ins_.get(bid) or [])]}")
            print(f"    OUT: {[expr_repr(x) for x in (outs_.get(bid) or [])]}")
            if bs.get(bid):
                print("    STMTS:")
                for st in bs[bid]:
                    print(f"      - {stmt_repr(st)}")
            if bc.get(bid):
                print("    CONDS:")
                for cnd in bc[bid]:
                    print(f"      - {expr_repr(cnd)}")

    def print_ast_summary(recovered_ast):
        for s in (recovered_ast.get("structures") or []):
            t = s.get("type")
            if t == "TryExceptFinally":
                print(
                    f"  TryExceptFinally: try={s.get('try_blocks')} "
                    f"except={s.get('except_blocks')} finally={s.get('finally_blocks')}"
                )
            elif t == "Loop":
                print(f"  Loop: header={s.get('header')} body={s.get('body_blocks')}")
            elif t == "If":
                print(
                    f"  If: cond={s.get('cond_block')} then={s.get('then_blocks')} "
                    f"else={s.get('else_blocks')} join={s.get('join_block')}"
                )
            elif t == "TryRegion":
                print(
                    f"  TryRegion: range={s.get('range')} depth={s.get('depth')} "
                    f"protected={s.get('protected_blocks')} handler={s.get('handler_blocks')}"
                )

    def print_exception_table(co):
        try:
            print("ExceptionTable:")
            for e in dis.Bytecode(co).exception_entries:
                lasti = " lasti" if getattr(e, "lasti", False) else ""
                print(f"  {e.start} to {e.end} -> {e.target} [depth={e.depth}]{lasti}")
        except Exception:
            print("ExceptionTable: <indisponível>")

    # -------- pipeline por code object (cache por co) --------
    cache = {}  # id(co) -> dict(stage_artifacts)

    def get_artifacts(co):
        cid = id(co)
        if cid in cache:
            return cache[cid]

        art = {
            "co": co,
            "ins": None,
            "blocks": None,
            "cfg": None,
            "stack_info": None,
            "patterns": None,
            "recovered_ast": None,
        }

        # dis não precisa de artefatos

        # parse
        art["ins"] = parse_instructions(co, debug=debug)

        # blocks
        art["blocks"] = build_basic_blocks(art["ins"], code_obj=co, debug=debug)

        # cfg
        art["cfg"] = build_cfg(art["blocks"], art["ins"], co, debug=debug)

        # stack
        art["stack_info"] = simulate_stack(
            art["blocks"], art["cfg"], art["ins"], co, debug=debug
        )

        # patterns
        art["patterns"] = detect_high_level_patterns(
            blocks=art["blocks"],
            cfg=art["cfg"],
            stack_info=art["stack_info"],
            code_obj=co,
            debug=debug,
        )

        # recovered_ast
        art["recovered_ast"] = build_recovered_ast(
            blocks=art["blocks"],
            cfg=art["cfg"],
            stack_info=art["stack_info"],
            patterns=art["patterns"],
            code_obj=co,
            debug=debug,
        )

        cache[cid] = art
        return art

    # -------- execução por stage --------
    if stage == "gen_code":
        # gera para o bytecode inteiro (tree completo)
        print("[STAGE gen_code] gerando código para TODO o .pyc (todos os code objects)")
        tree = extract_code_objects(root, depth=0, debug=debug)
        print(generate_python_code(tree, debug=debug))
        return

    # demais stages: imprime por code object
    for co in all_cos:
        print("\n" + "=" * 80)
        print(f"[CO] {co.co_name}  (firstlineno={getattr(co, 'co_firstlineno', None)})")
        print("=" * 80)

        if stage == "dis":
            print(f"\n[STAGE dis] dis.dis({co.co_name})")
            dis.dis(co)
            print_exception_table(co)
            continue

        art = get_artifacts(co)

        if stage == "parse":
            print("\n[STAGE parse] instruções parseadas")
            print_parsed_instructions(art["ins"])
            continue

        if stage == "blocks":
            print("\n[STAGE blocks] blocos básicos")
            print_blocks(art["blocks"])
            continue

        if stage == "cfg":
            print("\n[STAGE cfg] CFG")
            print_cfg(art["cfg"])
            continue

        if stage == "stack":
            print("\n[STAGE stack] IN/OUT + stmts + conds (resumo por bloco)")
            print_stack_summary(art["blocks"], art["stack_info"])
            continue

        if stage == "patterns":
            p = art["patterns"] or {}
            print("\n[STAGE patterns]")
            print(f"  ifs: {len(p.get('ifs') or [])}")
            print(f"  loops: {len(p.get('loops') or [])}")
            print(f"  try_regions: {len(p.get('try_regions') or [])}")
            print(f"  short_circuit_candidates: {len(p.get('short_circuit_candidates') or [])}")
            continue

        if stage == "recovered_ast":
            ra = art["recovered_ast"] or {}
            print("\n[STAGE recovered_ast] structures (resumo)")
            print_ast_summary(ra)
            continue

if __name__ == "__main__":
    main()

#python seu_script.py alvo.pyc --stage dis
#... --stage parse
#... --stage blocks
#... --stage cfg
#... --stage stack
#... --stage patterns
#... --stage recovered_ast
#... --stage gen_main_only