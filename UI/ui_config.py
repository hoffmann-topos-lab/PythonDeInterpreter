from pathlib import Path

ENGINE_PYTHON = "python3.12"

BYTECODE_MARKER      = "===== BYTECODE ====="
RECOVERED_MARKER     = "===== RECOVERED ====="
BYTECODE_META_MARKER = "===== BYTECODE_META ====="

APP_TITLE = "Python Decompiler"

SUPPORTED_VERSIONS = ["3.12"]
SUPPORTED_HINT = "Compatível apenas com: " + ", ".join(SUPPORTED_VERSIONS)


SUPPORTED_EXTENSIONS = [".pyc", ".mpy"]
FILE_FILTER          = "Bytecode Files (*.pyc *.mpy)"

_UI_DIR        = Path(__file__).parent
_PROJECT_ROOT  = _UI_DIR.parent
MPY_ENGINE_PATH = _PROJECT_ROOT / "MicroPython" / "mpy_engine.py"

GUTTER     = 10
LEFT_WIDTH = 320
