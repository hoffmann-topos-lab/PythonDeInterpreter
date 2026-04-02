import dis
from typing import List, Dict, Any


def bytecode_recovery(code_obj):
    print("[INFO] Disassembly do bytecode:")
    dis.dis(code_obj)

def parse_instructions(code_obj, debug=True):
    instructions = []

    if debug:
        print("[DEBUG] Iniciando parsing de instruções")
        print(f"[DEBUG] Nome do código: {code_obj.co_name}")
        print(f"[DEBUG] Número de constantes: {len(code_obj.co_consts)}")
        print(f"[DEBUG] Número de nomes: {len(code_obj.co_names)}")

    for instr in dis.get_instructions(code_obj):
        instr_dict = {
            "offset": instr.offset,
            "opcode": instr.opcode,
            "opname": instr.opname,
            "arg": instr.arg,
            "argval": instr.argval,
            "argrepr": instr.argrepr,
            "is_jump_target": instr.is_jump_target,
            "jump_target": None
        }

        if instr.opcode in dis.hasjrel or instr.opcode in dis.hasjabs:
            instr_dict["jump_target"] = instr.argval
            if debug:
                print(
                    f"[DEBUG] Salto detectado: {instr.opname} "
                    f"@ offset {instr.offset} -> target {instr.argval}"
                )

        if instr.is_jump_target and debug:
            print(f"[DEBUG] Início de bloco detectado no offset {instr.offset}")

        instructions.append(instr_dict)

    if debug:
        print(f"[DEBUG] Total de instruções parseadas: {len(instructions)}")
        print("[DEBUG] Parsing de instruções finalizado")

    return instructions