import sys
import os
import json
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)                    
sys.path.insert(0, os.path.dirname(_HERE))   
import dis
import io
from loader import load_code_object
from extract import extract_code_objects
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


def main():
    pyc = sys.argv[1]
    root = load_code_object(pyc)

    buf = io.StringIO()
    dis.dis(root, file=buf)
    bytecode_text = buf.getvalue()
    lines = bytecode_text.splitlines()

    meta = []

    for idx, line in enumerate(lines, start=1):
      
        if line.startswith("Disassembly of <code object"):
            try:
                head = line.split("<code object", 1)[1]
                name_part, rest = head.split(" at ", 1)
                name = name_part.strip()
                addr = rest.split(",", 1)[0].strip()
                meta.append((name, addr, idx))
            except Exception:
              
                pass
                
    tree = extract_code_objects(root, depth=0, debug=False)


    print("===== BYTECODE =====")
    print(bytecode_text.rstrip())

    print("\n===== BYTECODE_META =====")
    for name, addr, line_no in meta:
        print(f"{name}|{addr}|{line_no}")
    print(f"__hierarchy__|{json.dumps(_build_hierarchy(tree))}")

    print("\n===== RECOVERED =====")
    print(generate_python_code(tree, debug=False))


if __name__ == "__main__":
    main()
    for ch in children:
        ch_node = _build_hierarchy(ch)
        ch_node["type"] = _child_type(ch.get("name", "?"))
        result_children.append(ch_node)

    return {
        "name": name,
        "type": "module" if name == "<module>" else "function",
        "children": result_children,
    }


def main():
    pyc = sys.argv[1]
    root = load_code_object(pyc)
    buf = io.StringIO()
    dis.dis(root, file=buf)
    bytecode_text = buf.getvalue()
    lines = bytecode_text.splitlines()

    meta = []

    for idx, line in enumerate(lines, start=1):

        if line.startswith("Disassembly of <code object"):
            try:
                head = line.split("<code object", 1)[1]
                name_part, rest = head.split(" at ", 1)
                name = name_part.strip()
                addr = rest.split(",", 1)[0].strip()
                meta.append((name, addr, idx))
            except Exception:

                pass
    tree = extract_code_objects(root, depth=0, debug=False)

    print("===== BYTECODE =====")
    print(bytecode_text.rstrip())

    print("\n===== BYTECODE_META =====")
    for name, addr, line_no in meta:
        print(f"{name}|{addr}|{line_no}")
    print(f"__hierarchy__|{json.dumps(_build_hierarchy(tree))}")

    print("\n===== RECOVERED =====")
    print(generate_python_code(tree, debug=False))


if __name__ == "__main__":
    main()
