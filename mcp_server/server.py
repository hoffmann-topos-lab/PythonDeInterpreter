import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from mcp.server.fastmcp import FastMCP  # noqa: E402

mcp = FastMCP("python-decompiler")

from mcp_server.tools import (  # noqa: E402
    file_info,
    pipeline,
    stages,
    code_objects,
    analysis,
    search,
    native,
    annotations,
    diff,
    samples,
)

for module in (
    file_info,
    pipeline,
    stages,
    code_objects,
    analysis,
    search,
    native,
    annotations,
    diff,
    samples,
):
    module.register(mcp)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
