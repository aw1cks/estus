"""Offline AnsiballZ module bundle compiler for Estus.

Runs outside the MCP server lifecycle inside an operator-selected Python/Ansible
environment. Produces reproducible ZIP_STORED module archives, wrapper.py, and
bundle.json containing SHA-256 digests and ansible-doc specifications.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import zipfile

DEFAULT_MODULES = [
    "ansible.builtin.apt",
    "ansible.builtin.dnf",
    "ansible.builtin.dnf5",
    "ansible.builtin.package_facts",
    "ansible.builtin.stat",
    "community.general.apk",
    "community.general.zypper",
    "community.general.pacman",
]


def normalize_zip(raw_zip: bytes) -> tuple[bytes, list[str], list[str]]:
    src = zipfile.ZipFile(io.BytesIO(raw_zip), "r")
    buf = io.BytesIO()
    dst = zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED)
    names = sorted(src.namelist())
    internal_pkgs = {name.split("/", 1)[0] for name in names if "/" in name}
    external_imports: set[str] = set()
    stdlib_names = getattr(sys, "stdlib_module_names", frozenset())

    for name in names:
        data = src.read(name)
        if name.endswith(".py"):
            try:
                tree = ast.parse(data.decode("utf-8", errors="replace"), filename=name)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            top = alias.name.split(".", 1)[0]
                            if top and top not in stdlib_names and top not in internal_pkgs:
                                external_imports.add(top)
                    elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                        top = node.module.split(".", 1)[0]
                        if top and top not in stdlib_names and top not in internal_pkgs:
                            external_imports.add(top)
            except SyntaxError:
                pass
        out_info = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
        out_info.compress_type = zipfile.ZIP_STORED
        out_info.external_attr = 0o644 << 16
        dst.writestr(out_info, data)
    dst.close()
    return buf.getvalue(), names, sorted(external_imports)


def extract_zip_bytes(rendered: str) -> bytes:
    for quote in ("'", '"'):
        marker = f"zip_data={quote}"
        idx = rendered.find(marker)
        if idx != -1:
            start = idx + len(marker)
            end = rendered.index(quote, start)
            return base64.b64decode(rendered[start:end])
    raise ValueError("compiled AnsiballZ payload did not contain zip_data")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an offline Estus Ansible bundle pack.")
    parser.add_argument("--output", required=True, help="Output directory to populate")
    parser.add_argument(
        "--collections-path",
        action="append",
        default=[],
        help="Optional Ansible collections root directory (repeatable)",
    )
    parser.add_argument(
        "--runtime-root",
        default=None,
        help="Optional Estus automationRuntime root directory",
    )
    parser.add_argument(
        "--module",
        dest="modules",
        action="append",
        default=[],
        help="Module FQCN to bundle (repeatable; defaults to stock SRE set)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    out_dir = pathlib.Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    modules_dir = out_dir / "modules"
    modules_dir.mkdir(parents=True, exist_ok=True)

    collections_paths: list[str] = []
    if args.runtime_root:
        rt = pathlib.Path(os.path.abspath(args.runtime_root))
        rt_manifest = json.loads((rt / "runtime.json").read_text(encoding="utf-8"))
        site_packages = rt / rt_manifest["site_packages"]
        sys.path.insert(0, str(site_packages))
        col = rt / "collections"
        if col.is_dir():
            collections_paths.append(str(col))

    for raw_col in args.collections_path:
        collections_paths.append(str(pathlib.Path(raw_col).resolve(strict=True)))

    env_col = os.environ.get("ANSIBLE_COLLECTIONS_PATH") or os.environ.get("ANSIBLE_COLLECTIONS_PATHS")
    if env_col:
        for entry in env_col.split(os.pathsep):
            if entry and entry not in collections_paths:
                collections_paths.append(entry)

    import ansible
    from ansible.executor.module_common import modify_module
    from ansible.module_utils import basic as module_basic
    from ansible.parsing.dataloader import DataLoader
    from ansible.plugins.loader import init_plugin_loader, module_loader
    from ansible.release import __version__ as ansible_version
    from ansible.template import Templar

    init_plugin_loader(collections_paths)
    templar = Templar(loader=DataLoader())

    ansible_pkg_root = pathlib.Path(os.path.abspath(ansible.__file__)).parent
    wrapper_src = (ansible_pkg_root / "_internal" / "_ansiballz" / "_wrapper.py").read_bytes()
    (out_dir / "wrapper.py").write_bytes(wrapper_src)
    wrapper_sha256 = hashlib.sha256(wrapper_src).hexdigest()

    requested = list(dict.fromkeys(args.modules or DEFAULT_MODULES))
    # Never attempt to compile virtual action-only stubs as zip archives; routers handle them.
    concrete_fqcns = [m for m in requested if m != "ansible.builtin.package"]

    doc_env = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8", ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False")
    if collections_paths:
        doc_env["ANSIBLE_COLLECTIONS_PATH"] = os.pathsep.join(collections_paths)
    with tempfile.TemporaryDirectory() as doc_tmp:
        cfg_path = pathlib.Path(doc_tmp) / "ansible.cfg"
        col_line = f"collections_path = {os.pathsep.join(collections_paths)}\n" if collections_paths else ""
        cfg_path.write_text(
            f"[defaults]\n{col_line}collections_scan_sys_path = False\n",
            encoding="utf-8",
        )
        doc_env["ANSIBLE_CONFIG"] = str(cfg_path)
        doc_env["HOME"] = doc_tmp
        doc_cmd = [
            sys.executable,
            "-I",
            "-X",
            "utf8",
            "-m",
            "ansible.cli.doc",
            "-t",
            "module",
            "--json",
            *concrete_fqcns,
        ]
        raw_docs = json.loads(subprocess.check_output(doc_cmd, env=doc_env, timeout=60))

    modules_meta: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory() as td:
        os.environ["ANSIBLE_LOCAL_TEMP"] = td
        for fqcn in concrete_fqcns:
            ctx = module_loader.find_plugin_with_context(fqcn)
            if not ctx or not ctx.plugin_resolved_path:
                raise SystemExit(f"Could not resolve Ansible module plugin: {fqcn}")
            mod_path = pathlib.Path(os.path.abspath(ctx.plugin_resolved_path))
            built = modify_module(
                module_name=fqcn,
                module_path=str(mod_path),
                module_args={},
                templar=templar,
                task_vars={"ansible_python_interpreter": "/usr/bin/python3"},
            )
            rendered = built.b_module_data.decode("utf-8")
            raw_zip = extract_zip_bytes(rendered)
            norm_zip, import_closure, external_imports = normalize_zip(raw_zip)
            zip_sha256 = hashlib.sha256(norm_zip).hexdigest()
            (modules_dir / f"{fqcn}.zip").write_bytes(norm_zip)

            parts = fqcn.split(".")
            if fqcn.startswith(("ansible.builtin.", "ansible.legacy.")):
                module_fqn = f"ansible.modules.{parts[2]}"
            else:
                module_fqn = f"ansible_collections.{parts[0]}.{parts[1]}.plugins.modules.{parts[2]}"

            doc_entry = raw_docs.get(fqcn)
            if not isinstance(doc_entry, dict) or "doc" not in doc_entry:
                raise SystemExit(f"Missing ansible-doc specification for {fqcn}")
            attrs = doc_entry["doc"].get("attributes") or {}
            check_support = str((attrs.get("check_mode") or {}).get("support", "unknown"))
            diff_support = str((attrs.get("diff_mode") or {}).get("support", "unknown"))

            modules_meta[fqcn] = {
                "ansible_module": parts[-1],
                "module_fqn": module_fqn,
                "module_style": built.module_style,
                "serialization_profile": built.serialization_profile,
                "check_mode_support": check_support,
                "diff_mode_support": diff_support,
                "zip_sha256": zip_sha256,
                "zip_bytes": len(norm_zip),
                "import_closure_count": len(import_closure),
                "external_imports": external_imports,
                "document": {"doc": doc_entry["doc"]},
            }

    pkg_routes: dict[str, str] = {}
    for mgr, candidate in (
        ("apt", "ansible.builtin.apt"),
        ("dnf", "ansible.builtin.dnf"),
        ("dnf5", "ansible.builtin.dnf5"),
        ("apk", "community.general.apk"),
        ("zypper", "community.general.zypper"),
        ("pacman", "community.general.pacman"),
    ):
        if candidate in modules_meta:
            pkg_routes[mgr] = candidate

    dnf_routes: dict[str, str] = {}
    if "ansible.builtin.dnf" in modules_meta:
        dnf_routes["dnf"] = "ansible.builtin.dnf"
        dnf_routes["yum"] = "ansible.builtin.dnf"
        dnf_routes["yum4"] = "ansible.builtin.dnf"
        dnf_routes["dnf4"] = "ansible.builtin.dnf"
    if "ansible.builtin.dnf5" in modules_meta:
        dnf_routes["dnf5"] = "ansible.builtin.dnf5"

    routers: dict[str, dict[str, object]] = {}
    if pkg_routes:
        routers["ansible.builtin.package"] = {
            "kind": "pkg_mgr",
            "routes": pkg_routes,
            "check_mode_support": "full",
            "diff_mode_support": "partial",
        }
    if dnf_routes:
        routers["ansible.builtin.dnf"] = {
            "kind": "dnf_backend",
            "routes": dnf_routes,
            "check_mode_support": "full",
            "diff_mode_support": "full",
        }

    py_min = [int(x) for x in getattr(module_basic, "_PY_MIN", (3, 8))[:2]]
    body = {
        "schema": 1,
        "ansible_core_version": str(ansible_version),
        "target_python_floor": py_min,
        "wrapper_sha256": wrapper_sha256,
        "modules": modules_meta,
        "routers": routers,
    }
    canonical = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body["bundle_sha256"] = hashlib.sha256(canonical).hexdigest()
    (out_dir / "bundle.json").write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
