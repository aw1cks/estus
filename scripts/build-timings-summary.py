#!/usr/bin/env python3
"""Summarise a `cargo build --timings` report as Markdown, for a CI job summary.

    build-timings-summary.py cargo-timing.html [TOP]

Reads the unit data cargo embeds in the HTML report and prints the total wall
time, the number of compilation units and the TOP (default 15) slowest ones.
The full report, with the timeline and concurrency graph, is the HTML itself.
"""

import json
import re
import sys
from pathlib import Path


def unit_data(html):
    match = re.search(r"const UNIT_DATA = (\[.*?\]);\s*$", html, re.MULTILINE | re.DOTALL)
    if not match:
        sys.exit("no UNIT_DATA in the timings report; has cargo's format changed?")
    return json.loads(match.group(1))


def codegen_time(unit):
    """Seconds spent in codegen: from `sections` (current cargo), else `rmeta_time`."""
    sections = unit.get("sections")
    if sections:
        spans = [span for name, span in sections if name == "codegen"]
        return sum(span["end"] - span["start"] for span in spans) if spans else None
    rmeta = unit.get("rmeta_time")
    return unit["duration"] - rmeta if rmeta is not None else None


def main():
    path = Path(sys.argv[1])
    top = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    units = unit_data(path.read_text(encoding="utf-8"))
    if not units:
        sys.exit("the timings report lists no units")
    total = max(u["start"] + u["duration"] for u in units)
    print("## Build timings\n")
    print(f"`cargo build --release --locked`, dependencies included: **{total:.1f}s** wall time, "
          f"{len(units)} units. The full timeline is in the `build-timings` artifact.\n")
    print("| Crate | Version | Target | Time (s) | Codegen (s) |")
    print("| --- | --- | --- | ---: | ---: |")
    for unit in sorted(units, key=lambda u: u["duration"], reverse=True)[:top]:
        codegen = codegen_time(unit)
        codegen = f"{codegen:.1f}" if codegen is not None else "-"
        target = unit.get("target", "").strip() or "lib"
        print(f"| {unit['name']} | {unit['version']} | {target} | {unit['duration']:.1f} | {codegen} |")


if __name__ == "__main__":
    main()
