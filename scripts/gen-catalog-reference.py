#!/usr/bin/env python3
"""Render the repository's catalog reference with Python 3.8 or newer."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "catalog"
OUTPUT = ROOT / "docs/tools/catalog-reference.md"
TIERS = ("observe", "inspect", "preview", "change", "exec")
DOMAINS = (
    ("Host and hardware", ("host", "cpu", "memory", "pressure", "hardware", "pci", "device_attributes")),
    ("Systemd", ("systemd", "time_sync")),
    ("Network", ("network",)),
    ("NIC", ("nic",)),
    ("Storage", ("storage", "filesystem")),
    ("Kernel", ("kernel",)),
    ("Boot", ("boot",)),
    ("Packages", ("package", "packages", "apt", "dnf")),
    ("Journal and processes", ("journal", "kernel_log", "process", "processes", "sockets")),
    ("Cgroups", ("cgroup",)),
    ("Sysctl", ("sysctl",)),
)

# Pairing is runtime policy, not catalog metadata. Keep this in sync with
# PreviewSpec in src/server/preview.rs; names alone cannot establish a pairing.
PREVIEW_PAIRS = (
    ("preview_apt", "change_apt", ""),
    ("preview_dnf", "change_dnf", ""),
    ("preview_package", "change_package", ""),
    ("preview_kernel_module_load", "change_kernel_module_load", "no module parameters"),
    ("preview_sysctl", "change_sysctl_config", '`mode = "config"`'),
    ("preview_sysctl", "change_sysctl_runtime", '`mode = "runtime"`'),
    ("preview_systemd_service", "change_systemd_unit", "start, stop, restart or reload"),
    ("preview_systemd_service", "change_systemd_unit_file", ""),
)


def read_json(path):
    return json.loads(path.read_bytes())


def code(text):
    return "`{}`".format(text)


def code_list(values):
    return ", ".join(map(code, values))


def row(*cells):
    return "| " + " | ".join(cell.replace("|", r"\|") for cell in cells) + " |"


def domain(name):
    subject = name.split("_", 1)[1]
    if subject.endswith("_probe") or subject == "dns_lookup":
        return "Probes"
    if subject == "host_reboot":
        return "Boot"
    if subject == "kernel_log":
        return "Journal and processes"
    for label, prefixes in DOMAINS:
        if any(subject == prefix or subject.startswith(prefix + "_") for prefix in prefixes):
            return label
    return "Other"


def definition_fields(path, name):
    # The CLI parses and validates the whole TOML. It does not include these
    # two fields in its JSON output. The shipped definitions write them as
    # JSON-compatible values in the main tool table, so Python 3.8 needs no
    # TOML dependency. Report an error if that format changes.
    _, separator, body = path.read_text(encoding="utf-8").partition("[tools.{}]".format(name))
    if not separator:
        raise ValueError("{}: missing tool table".format(path.name))
    body = re.split(r"^[ \t]*\[tools\.", body, maxsplit=1, flags=re.MULTILINE)[0]
    values = {}
    decoder = json.JSONDecoder()
    for key, expected in (("authority", str), ("effects", list)):
        match = re.search(r"^\s*" + key + r"\s*=\s*", body, re.MULTILINE)
        if not match:
            raise ValueError("{}: missing {}".format(path.name, key))
        raw = body[match.end():]
        value, end = decoder.raw_decode(raw)
        tail = raw[end:].split("\n", 1)[0].strip()
        if not isinstance(value, expected) or (tail and not tail.startswith("#")):
            raise ValueError("{}: unsupported {} syntax".format(path.name, key))
        values[key] = value
    return values["authority"], values["effects"]


def requirements(template):
    executor = template["executor"]
    labels = set(template["requires"]) - {"python3"}
    if executor["kind"] == "native_payload":
        spec = read_json(CATALOG / executor["path"] / "manifest.json")["requirements"]
        python = "Python ≥ " + ".".join(map(str, spec["python_min"]))
        labels.update(spec.get("executables", ()))
        labels.update(spec.get("executable_candidates", ()))
    elif executor["kind"] == "ansible_module":
        python = "Python (bundle minimum); Ansible bundle: " + code(executor["module"])
    else:
        raise ValueError("unknown catalog executor: {}".format(executor["kind"]))
    return "; ".join([python, *map(code, sorted(labels))])


def render(inventory, manifest):
    entries = inventory["tools"]
    tools = {entry["name"]: entry for entry in entries}
    templates = manifest["tools"]
    definitions = {template["definition"] for template in templates.values()}
    files = {path.name for path in CATALOG.glob("*.toml")}
    if (len(tools) != len(entries) or set(tools) != set(templates)
            or len(definitions) != len(templates) or definitions != files):
        raise ValueError("catalog list, catalog.json and TOML definitions disagree")

    pairs = defaultdict(list)
    for preview, change, condition in PREVIEW_PAIRS:
        if preview not in tools or change not in tools:
            raise ValueError("update preview pairing: {} / {}".format(preview, change))
        for tool, partner in ((preview, change), (change, preview)):
            pairs[tool].append(code(partner) + (" (" + condition + ")" if condition else ""))

    lines = [
        "# Catalog reference",
        "",
        "> Generated. Do not edit. Regenerate with `python3 scripts/gen-catalog-reference.py`.",
        "",
        "Use this reference to choose catalog tools and check what they need on the",
        "target. See [the catalog guide](../catalog.md) for selection and site policy.",
        "",
        "## Presets",
        "",
        "| Preset | Tools |",
        "| --- | --- |",
    ]
    for name, members in sorted(inventory["presets"].items()):
        lines.append(row(code(name), code_list(members)))
    lines.extend([
        "",
        "Authorities and tiers are defined in [Concepts](../concepts.md). A qualification",
        "marked **policy required** needs a site overlay. A preview pairing still requires",
        "matching intent; see [Policy](../policy.md). The bundle sets the Python minimum",
        "for [Ansible-backed tools](../ansible-bundles.md).",
    ])

    grouped = defaultdict(list)
    for name in sorted(tools, key=lambda name: (TIERS.index(name.split("_", 1)[0]), name)):
        tool = tools[name]
        template = templates[name]
        authority, effects = definition_fields(CATALOG / template["definition"], name)
        description = re.split(r"(?<=[.!?])\s+", " ".join(tool["description"].split()), maxsplit=1)[0]
        qualification = code(tool["qualification"])
        if tool["policy_required"]:
            qualification += "; **policy required**"
        grouped[domain(name)].append(row(
            code(name), code(name.split("_", 1)[0]), description, code_list(effects),
            code(authority), qualification, requirements(template), ", ".join(pairs[name]) or "—",
        ))

    for label in [label for label, _ in DOMAINS] + ["Probes", "Other"]:
        if label in grouped:
            lines += [
                "", "## " + label, "",
                "| Tool | Tier | Description | Effects | Authority | Qualification | Requirements | Preview pairing |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
                *grouped[label],
            ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--estus", default="estus", help="Estus executable (default: estus on PATH)")
    parser.add_argument("--check", action="store_true", help="fail if the reference needs regeneration")
    args = parser.parse_args()
    try:
        inventory = json.loads(subprocess.check_output([
            args.estus, "catalog", "list", "--json", "--root", str(CATALOG),
        ]))
        content = render(inventory, read_json(CATALOG / "catalog.json")).encode("utf-8")
        if not args.check:
            OUTPUT.write_bytes(content)
        elif not OUTPUT.is_file() or OUTPUT.read_bytes() != content:
            print("{} is out of date; run without --check".format(OUTPUT.relative_to(ROOT)), file=sys.stderr)
            return 1
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print("catalog reference: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
