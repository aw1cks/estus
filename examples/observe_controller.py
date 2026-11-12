#!/usr/bin/env python3
"""Read controller identity and scratch-filesystem capacity from private JSON input."""
import json
import os
import platform
import shutil
import sys

if len(sys.argv) != 2:
    raise SystemExit("Expected one private JSON input path")
with open(sys.argv[1], encoding="utf-8") as source:
    request = json.load(source)
usage = shutil.disk_usage(os.getcwd())
print(json.dumps({
    "label": request["label"],
    "execution_location": "controller",
    "system": platform.system(),
    "machine": platform.machine(),
    "uid": os.getuid(),
    "scratch_bytes": {
        "total": usage.total,
        "used": usage.used,
        "free": usage.free,
    },
}, ensure_ascii=False))
