import sys
import os
import json


_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from MicroPython.mpy_loader import load_mpy, ARCH_NAMES, KIND_BYTECODE
from MicroPython.mpy_ir_adapter import adapt_raw_code, MpyCodeObject
from MicroPython.mpy_disasm import format_instructions
from MicroPython.mpy_extract import process_mpy_code_object
from utils.codegen import generate_python_code


def _build_hierarchy(tree):

    name = tree.get("name", "?")
    ra = tree.get("recovered_ast") or {}
    children = tree.get("children", [])

    cls_names = set()
    for s in ra.get("structures", []):
        if s.get("type") == "ClassDef":
            cls_names.add(s.get("name"))

    def _child_type(ch_name):
        if ch_name == "<module>":
            return "module"
        if ch_name == "<lambda>":
            return "lambda"
        if ch_name in ("<genexpr>", "<listcomp>", "<setcomp>", "<dictcomp>"):
            return ch_name[1:-1]
        if ch_name in cls_names:
            return "class"
        return "function"

    result_children = []
    for ch in children:
        ch_node = _build_hierarchy(ch)
        ch_node["type"] = _child_type(ch.get("name", "?"))
        result_children.append(ch_node)

    return {
        "name": name,
        "type": "module" if name == "<module>" else "function",
        "children": result_children,
    }



def _collect_all(mpy_obj: MpyCodeObject) -> list:
    result = [mpy_obj]
    for child in mpy_obj._children:
        result.extend(_collect_all(child))
    return result


def _format_disassembly(root: MpyCodeObject, filename: str) -> tuple[str, list]:

    lines      = []
    meta_entries = []
    line_cursor  = 0  

    all_objs = _collect_all(root)

    for idx, obj in enumerate(all_objs):
        name    = obj.co_name or f"<code_{idx}>"
        addr    = f"0x{idx:08x}"
        firstln = obj.co_firstlineno

        header = (
            f'Disassembly of <code object {name} at {addr}, '
            f'file "{filename}", line {firstln}>:'
        )
        lines.append(header)
        line_cursor += 1
        meta_entries.append((name, addr, line_cursor))

        if obj.kind != KIND_BYTECODE or not obj._instructions:
            kind_str = {1: "native", 2: "viper"}.get(obj.kind, "?")
            if obj.kind != KIND_BYTECODE:
                # Tenta disassembly nativo
                if hasattr(obj, "_native_code") and obj._native_code and obj._prelude_offset > 0:
                    try:
                        from NativeDisasm import disassemble_native
                        asm = disassemble_native(obj._native_code, obj.arch_code, obj._prelude_offset)
                        for asm_line in asm.splitlines():
                            lines.append("  " + asm_line)
                            line_cursor += 1
                    except Exception:
                        lines.append(f"  (código {kind_str} — sem disassembly de bytecode)")
                        line_cursor += 1
                else:
                    lines.append(f"  (código {kind_str} — sem disassembly de bytecode)")
                    line_cursor += 1
            else:
                lines.append("  (sem instruções)")
                line_cursor += 1
            lines.append("")
            line_cursor += 1
            continue

        instr_text = format_instructions(obj._instructions, obj._line_map)
        for l in instr_text.splitlines():
            lines.append("  " + l)
            line_cursor += 1

        lines.append("")
        line_cursor += 1

    return "\n".join(lines), meta_entries



def main():
    if len(sys.argv) < 2:
        print("Uso: python3.12 MicroPython/mpy_engine.py <arquivo.mpy>", file=sys.stderr)
        sys.exit(1)

    mpy_path = sys.argv[1]

    try:
        header, qstrs, consts, raw_root = load_mpy(mpy_path)
    except (ValueError, EOFError, FileNotFoundError) as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        sys.exit(1)

    arch_code = header["arch_code"]
    arch_name = ARCH_NAMES.get(arch_code, f"arch_{arch_code}")
    sub_ver   = header["sub_version"]

    root = adapt_raw_code(
        raw_root, qstrs, consts,
        filename=mpy_path,
        arch_code=arch_code,
    )


    try:
        tree = process_mpy_code_object(root, debug=False)
        recovered = generate_python_code(tree, debug=False)
    except Exception as exc:
        tree      = None
        recovered = f"# [ERRO na recuperação de código: {exc}]"


    bytecode_text, meta_entries = _format_disassembly(root, mpy_path)

    print("===== BYTECODE =====")
    print(bytecode_text.rstrip())

    print("\n===== BYTECODE_META =====")


    print(f"__mpy__|v6.{sub_ver}|{arch_name}")

    for name, addr, line_no in meta_entries:
        print(f"{name}|{addr}|{line_no}")
    if tree:
        print(f"__hierarchy__|{json.dumps(_build_hierarchy(tree))}")


    print("\n===== RECOVERED =====")
    print(recovered)


if __name__ == "__main__":
    main()
