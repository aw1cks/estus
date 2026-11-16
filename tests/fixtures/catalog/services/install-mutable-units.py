"""Install the immutable guest unit fixture without overwriting mutable state."""

import os
from pathlib import Path
import shutil
import sys


def install_directory(source, target, depth=0):
    if depth > 8:
        raise RuntimeError('fixture unit directory exceeds bound')
    target.mkdir(mode=0o755, parents=True, exist_ok=True)
    for entry in source.iterdir():
        destination = target / entry.name
        if entry.is_dir():
            install_directory(entry, destination, depth + 1)
        elif not destination.exists() and not destination.is_symlink():
            if entry.is_symlink():
                destination.symlink_to(os.readlink(entry))
            else:
                shutil.copy2(entry, destination)


install_directory(Path(sys.argv[1]), Path(sys.argv[2]))
