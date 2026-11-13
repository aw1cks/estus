"""Launch the packaged Rust application without proxying its stdio or lifecycle."""

import json
import os
from pathlib import Path
import sys


def main() -> None:
    executable = Path(__file__).parent / "_bin" / "ssh-mcp"
    # Preserve the interpreter pathname: resolving its symlink would lose a venv.
    os.environ["SSH_MCP_PYTHON_RUNTIME"] = json.dumps(
        {
            "schema": 1,
            "interpreter": os.path.abspath(sys.executable),
            "prefix": os.path.abspath(sys.prefix),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    )
    os.execv(executable, sys.argv)
