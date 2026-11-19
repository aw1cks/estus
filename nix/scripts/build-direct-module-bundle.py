"""Build reproducible AnsiballZ direct-module bundles from pinned automationRuntime."""

import ast
import base64
import hashlib
import io
import json
import os
import pathlib
import sys
import tempfile
import zipfile


def normalize_zip(raw_zip: bytes) -> tuple[bytes, list[str], dict[str, list[str]]]:
    src = zipfile.ZipFile(io.BytesIO(raw_zip), "r")
    buf = io.BytesIO()
    dst = zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED)
    names = sorted(src.namelist())
    internal_pkgs = {name.split("/", 1)[0] for name in names if "/" in name}
    external_imports: set[str] = set()
    stdlib_names = getattr(sys, "stdlib_module_names", frozenset())

    for name in names:
        info = src.getinfo(name)
        data = src.read(name)
        new_info = zipfile.ZipInfo(filename=name, date_time=(2026, 1, 1, 0, 0, 0))
        new_info.external_attr = info.external_attr
        dst.writestr(new_info, data)
        if name.endswith(".py"):
            try:
                tree = ast.parse(data.decode("utf-8"), filename=name)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".", 1)[0]
                        if top not in internal_pkgs and top not in stdlib_names:
                            external_imports.add(top)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    top = node.module.split(".", 1)[0]
                    if top not in internal_pkgs and top not in stdlib_names:
                        external_imports.add(top)
    dst.close()
    return buf.getvalue(), names, {"external": sorted(external_imports)}


def main() -> None:
    runtime_root = pathlib.Path(sys.argv[1]).resolve(strict=True)
    out_dir = pathlib.Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    bundles_dir = out_dir / "bundles"
    bundles_dir.mkdir(parents=True, exist_ok=True)

    runtime_manifest = json.loads((runtime_root / "runtime.json").read_text(encoding="utf-8"))
    site_packages = runtime_root / runtime_manifest["site_packages"]
    sys.path.insert(0, str(site_packages))

    from ansible.executor.module_common import modify_module
    from ansible.module_utils import basic as module_basic
    from ansible.parsing.dataloader import DataLoader
    from ansible.plugins.loader import init_plugin_loader
    from ansible.release import __version__ as ansible_version
    from ansible.template import Templar

    collections_root = runtime_root / "collections"
    init_plugin_loader([str(collections_root)])
    templar = Templar(loader=DataLoader())

    wrapper_src = (
        site_packages / "ansible" / "_internal" / "_ansiballz" / "_wrapper.py"
    ).read_text(encoding="utf-8")
    (out_dir / "wrapper.py").write_text(wrapper_src, encoding="utf-8")
    wrapper_sha256 = hashlib.sha256(wrapper_src.encode("utf-8")).hexdigest()

    targets = [
        (
            "ansible.builtin.systemd_service",
            site_packages / "ansible" / "modules" / "systemd_service.py",
            (site_packages / "ansible" / "plugins" / "action" / "systemd_service.py").exists(),
            [],
        ),
        (
            "ansible.posix.sysctl",
            collections_root
            / "ansible_collections"
            / "ansible"
            / "posix"
            / "plugins"
            / "modules"
            / "sysctl.py",
            (
                collections_root
                / "ansible_collections"
                / "ansible"
                / "posix"
                / "plugins"
                / "action"
                / "sysctl.py"
            ).exists(),
            [],
        ),
        (
            "ansible.builtin.package_facts",
            site_packages / "ansible" / "modules" / "package_facts.py",
            (site_packages / "ansible" / "plugins" / "action" / "package_facts.py").exists(),
            [],
        ),
        (
            "ansible.builtin.apt",
            site_packages / "ansible" / "modules" / "apt.py",
            (site_packages / "ansible" / "plugins" / "action" / "apt.py").exists(),
            [],
        ),
        (
            "ansible.builtin.dnf",
            site_packages / "ansible" / "modules" / "dnf.py",
            (site_packages / "ansible" / "plugins" / "action" / "dnf.py").exists(),
            ["ansible.legacy.setup (if use_backend=auto)", "ansible.legacy.dnf / dnf5"],
        ),
        (
            "ansible.builtin.stat",
            site_packages / "ansible" / "modules" / "stat.py",
            (site_packages / "ansible" / "plugins" / "action" / "stat.py").exists(),
            [],
        ),
    ]

    bundles_meta = {}
    with tempfile.TemporaryDirectory() as td:
        os.environ["ANSIBLE_LOCAL_TEMP"] = td
        for fqn, mod_path, has_action, action_notes in targets:
            if not mod_path.is_file():
                raise SystemExit(f"Missing module source: {mod_path}")
            built = modify_module(
                module_name=fqn,
                module_path=str(mod_path),
                module_args={},
                templar=templar,
                task_vars={"ansible_python_interpreter": "/usr/bin/python3"},
            )
            rendered = built.b_module_data.decode("utf-8")
            marker = "zip_data='"
            start = rendered.index(marker) + len(marker)
            end = rendered.index("'", start)
            raw_zip = base64.b64decode(rendered[start:end])
            norm_zip, import_closure, imports_info = normalize_zip(raw_zip)
            zip_b64 = base64.b64encode(norm_zip).decode("ascii")
            zip_sha256 = hashlib.sha256(norm_zip).hexdigest()

            module_fqn = (
                "ansible.modules." + fqn.split(".", 2)[2]
                if fqn.startswith("ansible.builtin.")
                else f"ansible_collections.{fqn.split('.')[0]}.{fqn.split('.')[1]}.plugins.modules.{fqn.split('.')[2]}"
            )
            bundle_doc = {
                "schema": 1,
                "module_fqcn": fqn,
                "ansible_module": fqn.rsplit(".", 1)[-1],
                "module_fqn": module_fqn,
                "module_style": built.module_style,
                "serialization_profile": built.serialization_profile,
                "rlimit_nofile": 0,
                "extensions": {},
                "action_plugin": has_action,
                "action_plugin_notes": action_notes,
                "zip_sha256": zip_sha256,
                "zip_bytes": len(norm_zip),
                "import_closure_count": len(import_closure),
                "import_closure": import_closure,
                "external_imports": imports_info["external"],
                "zip_data": zip_b64,
            }
            (bundles_dir / f"{fqn}.json").write_text(
                json.dumps(bundle_doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            bundles_meta[fqn] = {
                "zip_sha256": zip_sha256,
                "zip_bytes": len(norm_zip),
                "module_style": built.module_style,
                "serialization_profile": built.serialization_profile,
                "action_plugin": has_action,
                "action_plugin_notes": action_notes,
                "import_closure_count": len(import_closure),
                "external_imports": imports_info["external"],
            }

    manifest = {
        "schema": 1,
        "ansible_core_version": ansible_version,
        "runtime_id": runtime_manifest["identity"]["runtime_id"],
        "target_python_floor": list(module_basic._PY_MIN),
        "controller_python_requires": ">=3.12",
        "wrapper_sha256": wrapper_sha256,
        "modules": bundles_meta,
    }
    (out_dir / "bundle.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
