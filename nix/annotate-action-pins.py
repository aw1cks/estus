"""Append each pinned action's version to its `uses:` line, as `# <version>`.

nix/ci.nix pins every action as `"owner/repo@<sha>"; # <version>`. The workflows
are generated through JSON, which has no comments, so the versions are restored
here: Renovate reads them to update the pins, in the YAML and in nix/ci.nix
alike, and zizmor's online audits check them against the tags. Every action
pinned by SHA must have a version, or generation fails.

    annotate-action-pins.py nix/ci.nix WORKFLOW.yml...
"""

import re
import sys
from pathlib import Path

PIN = re.compile(r'"([\w.-]+/[\w./-]+@[0-9a-f]{40})"; # (\S+)$')
USES = re.compile(r"^\s*(?:- )?uses: ([\w.-]+/[\w./-]+@[0-9a-f]{40})$")


def main():
    source, *workflows = sys.argv[1:]
    versions = {}
    for line in Path(source).read_text(encoding="utf-8").splitlines():
        match = PIN.search(line)
        if match:
            versions[match[1]] = match[2]
    missing = set()
    for path in map(Path, workflows):
        lines = path.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            match = USES.match(line)
            if not match:
                continue
            version = versions.get(match[1])
            if version is None:
                missing.add(match[1])
            else:
                lines[index] = f"{line} # {version}"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if missing:
        sys.exit(f"{source} has no `# <version>` comment for: {', '.join(sorted(missing))}")


if __name__ == "__main__":
    main()
