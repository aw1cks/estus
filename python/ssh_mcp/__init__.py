"""Launch the packaged Rust application without proxying its stdio or lifecycle."""

import os
from pathlib import Path
import sys


def main() -> None:
    executable = Path(__file__).parent / "_bin" / "ssh-mcp"
    os.execv(executable, sys.argv)
