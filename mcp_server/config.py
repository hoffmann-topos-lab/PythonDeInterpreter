from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SAMPLES_DIR = PROJECT_ROOT / "tests"

MAX_TEXT_CHARS = 200_000
MAX_LIST_ITEMS = 500
SUBPROCESS_TIMEOUT = 120

MPY_MAGIC = b"M\x06"
PYC_MAGIC_3_12 = 0xCB0D0D0A
