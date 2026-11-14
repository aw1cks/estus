"""Launch the packaged Rust application without proxying its stdio or lifecycle."""

import json
import os
from pathlib import Path
import sys


def main() -> None:
    package_root = Path(__file__).resolve(strict=True).parent
    executable = package_root / "_bin" / "estus"
    # Installed inert data is selected by this launcher, never the caller's cwd.
    os.environ["ESTUS_CATALOG_ROOT"] = str(package_root / "_catalog")
    # Preserve the interpreter pathname: resolving its symlink would lose a venv.
    os.environ["ESTUS_PYTHON_RUNTIME"] = json.dumps(
        {
            "schema": 2,
            "interpreter": os.path.abspath(sys.executable),
            "prefix": os.path.abspath(sys.prefix),
            # uv run may install the package outside the interpreter's prefix.
            # Capture only this installation, never ambient sys.path/PYTHONPATH.
            "package_root": str(package_root),
            "scripts": str(Path(sys.argv[0]).resolve(strict=True).parent),
        },
        separators=(",", ":"),
        ensure_ascii=True,
    )
    os.execv(executable, sys.argv)
