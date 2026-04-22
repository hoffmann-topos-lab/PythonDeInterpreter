import marshal
import types
from typing import Optional


def load_code_object(pyc_path):
    with open(pyc_path, "rb") as f:
        f.read(16)  
        return marshal.load(f)

def _find_code_by_name(co: types.CodeType, name: str) -> Optional[types.CodeType]:
    if co.co_name == name:
        return co
    for c in co.co_consts:
        if isinstance(c, types.CodeType):
            r = _find_code_by_name(c, name)
            if r is not None:
                return r
    return None
