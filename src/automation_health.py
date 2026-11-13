"""Private, import-only runtime identity probe; never execute automation."""

import contextlib
import hashlib
import importlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import sys
import sysconfig


# Installer-managed environments are tested against these releases only.
ENVIRONMENT_VERSIONS = {
    "collection_bundle": ("ansible", "14.4.0"),
    "ansible_core": ("ansible-core", "2.21.5"),
    "ansible_runner": ("ansible-runner", "2.4.3"),
}
BASELINE_COLLECTIONS = ("ansible.posix", "community.general")


class HealthFailure(Exception):
    def __init__(self, code):
        self.code = code


def require(condition, code="runtime_check_failed"):
    if not condition:
        raise HealthFailure(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_json(path, maximum):
    require(path.is_file())
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    require(len(raw) <= maximum)
    return json.loads(raw, object_pairs_hook=unique_object), raw


def exact_keys(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def public_string(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.+\-]{1,128}", value) is not None


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def load_manifest(root):
    manifest, _ = read_json(root / "runtime.json", 16384)
    exact_keys(manifest, ("schema", "health_sha256", "site_packages", "identity"))
    require(type(manifest["schema"]) is int and manifest["schema"] == 1)
    require(digest(manifest["health_sha256"]))
    require(hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == manifest["health_sha256"])
    site = manifest["site_packages"]
    require(isinstance(site, str) and 0 < len(site) <= 4096 and "\x00" not in site)
    relative = PurePosixPath(site)
    require(not relative.is_absolute() and all(part not in ("", ".", "..") for part in site.split("/")))
    identity = manifest["identity"]
    exact_keys(identity, ("runtime_id", "platform", "python", "ansible_core", "ansible_runner", "collection_bundle", "collections"))
    require(digest(identity["runtime_id"]))
    for key in ("platform", "python", "ansible_core", "ansible_runner", "collection_bundle"):
        require(public_string(identity[key]))
    collections = identity["collections"]
    require(type(collections) is list and len(collections) == 2)
    for entry in collections:
        exact_keys(entry, ("name", "version", "manifest_sha256"))
        require(public_string(entry["version"]) and digest(entry["manifest_sha256"]))
    require([entry["name"] for entry in collections] == ["ansible.posix", "community.general"])
    return manifest


def absolute_path(value):
    require(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 4096
            and "\x00" not in value)
    path = Path(value)
    require(path.is_absolute())
    return path


def environment_paths(payload):
    interpreter = absolute_path(payload["interpreter"])
    prefix = absolute_path(payload["prefix"])
    # Lexical executable equality deliberately does not resolve a venv symlink.
    require(os.path.abspath(sys.executable) == os.path.abspath(interpreter))
    require(Path(sys.prefix).resolve(strict=True) == prefix.resolve(strict=True))
    require(interpreter.is_file() and os.access(interpreter, os.X_OK))
    paths = sysconfig.get_paths()
    sites = list(dict.fromkeys(absolute_path(paths[key]) for key in ("purelib", "platlib")))
    scripts = absolute_path(paths["scripts"])
    require(all(path.resolve().is_relative_to(prefix.resolve()) for path in (*sites, scripts)))
    # Do not retain system-site-packages or paths contributed by ambient .pth files.
    stdlib = list(dict.fromkeys(absolute_path(paths[key]) for key in ("stdlib", "platstdlib")))
    dynamic = absolute_path(sysconfig.get_config_var("DESTSHARED"))
    sys.path[:] = list(dict.fromkeys(str(path) for path in (*stdlib, dynamic, *sites)))
    return sites, scripts


def check_collections(roots, expected):
    spec = importlib.machinery.PathFinder.find_spec("ansible_collections", [str(root) for root in roots])
    require(spec is not None and spec.loader is None, "runtime_collection_mismatch")
    # Namespace discovery is limited to selected installation roots, not sys.path.
    namespace = importlib.util.module_from_spec(spec)
    sys.modules["ansible_collections"] = namespace
    observed = []
    for index, name in enumerate(BASELINE_COLLECTIONS):
        namespace_name, collection_name = name.split(".")
        directories = [
            root / "ansible_collections" / namespace_name / collection_name for root in roots
        ]
        present = [directory for directory in directories if directory.is_dir()]
        require(present, "runtime_collection_mismatch")
        entries = []
        for directory in present:
            content, raw = read_json(directory / "MANIFEST.json", 1048576)
            info = content["collection_info"]
            require(info["namespace"] == namespace_name and info["name"] == collection_name,
                    "runtime_collection_mismatch")
            version = info["version"]
            require(public_string(version) and re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", version
            ) is not None, "runtime_collection_mismatch")
            entries.append({
                "name": name, "version": version, "manifest_sha256": hashlib.sha256(raw).hexdigest()
            })
        require(all(entry == entries[0] for entry in entries), "runtime_collection_mismatch")
        if expected is not None:
            require(entries[0] == expected[index], "runtime_collection_mismatch")
        module = importlib.import_module("ansible_collections." + name)
        module_paths = [Path(path).resolve() for path in module.__path__]
        require(module_paths and all(path in [directory.resolve() for directory in present]
                                     for path in module_paths), "runtime_collection_mismatch")
        observed.append(entries[0])
    return observed


def check():
    require(len(sys.argv) == 2)
    payload, _ = read_json(Path(sys.argv[1]), 16384)
    require(type(payload) is dict and type(payload.get("schema")) is int and payload["schema"] == 1)
    source = payload.get("source")
    if source == "bundle":
        exact_keys(payload, ("schema", "source", "runtime_root"))
        root = absolute_path(payload["runtime_root"])
        require(root.resolve(strict=True) == root)
        manifest = load_manifest(root)
        expected = manifest["identity"]
        site_packages = root / manifest["site_packages"]
        if not any(Path(path).resolve() == site_packages.resolve() for path in sys.path if path):
            sys.path.insert(0, str(site_packages))
        collection_roots = [root / "collections"]
        scripts = root / "python" / "bin"
        config = root / "ansible.cfg"
        provenance = {"kind": "nix_bundle", "runtime_id": expected["runtime_id"]}
    elif source == "python_environment":
        exact_keys(payload, ("schema", "source", "interpreter", "prefix"))
        collection_roots, scripts = environment_paths(payload)
        expected = None
        provenance = {"kind": "python_environment"}
        config = None
    else:
        raise HealthFailure("runtime_check_failed")
    temporary = absolute_path(os.environ.get("TMPDIR"))
    require(temporary.is_dir())
    for key in list(os.environ):
        if key.startswith("ANSIBLE_"):
            del os.environ[key]
    if config is None:
        config = temporary / "ansible.cfg"
        config.write_text("[defaults]\ncollections_scan_sys_path = False\n", encoding="ascii")
    os.environ["HOME"] = str(temporary)
    os.environ["PATH"] = str(scripts) + os.pathsep + "/usr/bin:/bin"
    os.environ["ANSIBLE_CONFIG"] = str(config)
    os.environ["ANSIBLE_COLLECTIONS_PATH"] = os.pathsep.join(str(root) for root in collection_roots)
    os.environ["ANSIBLE_COLLECTIONS_SCAN_SYS_PATH"] = "False"
    os.environ["ANSIBLE_HOME"] = str(temporary / "ansible")
    os.environ["ANSIBLE_LOCAL_TEMP"] = str(temporary / "ansible-local")
    try:
        from ansible_runner import Runner, run, run_async
        from ansible.module_utils.basic import AnsibleModule
        require(all(callable(value) for value in (Runner, run, run_async, AnsibleModule)),
                "runtime_import_failed")
    except BaseException:
        raise HealthFailure("runtime_import_failed") from None
    try:
        observed = {
            "provenance": provenance,
            "platform": ("aarch64" if platform.machine() == "arm64" else platform.machine()) + "-" + sys.platform,
            "python": ".".join(str(value) for value in sys.version_info[:3]),
        }
        for field, (distribution, version) in ENVIRONMENT_VERSIONS.items():
            observed[field] = importlib.metadata.version(distribution)
            require(public_string(observed[field]), "runtime_version_mismatch")
            require(observed[field] == (expected[field] if expected is not None else version),
                    "runtime_version_mismatch")
        if expected is not None:
            require(all(observed[key] == expected[key] for key in ("platform", "python")),
                    "runtime_version_mismatch")
        else:
            require(sys.version_info[:2] == (3, 14), "runtime_version_mismatch")
        require(public_string(observed["platform"]) and public_string(observed["python"]),
                "runtime_version_mismatch")
    except BaseException:
        raise HealthFailure("runtime_version_mismatch") from None
    try:
        observed["collections"] = check_collections(
            collection_roots, expected["collections"] if expected is not None else None
        )
    except BaseException:
        raise HealthFailure("runtime_collection_mismatch") from None
    return observed


def main():
    try:
        # The controller captures stderr privately. Dependency chatter must not corrupt JSON.
        with contextlib.redirect_stdout(sys.stderr):
            identity = check()
        report = {"schema": 2, "status": "passed", "identity": identity}
    except HealthFailure as error:
        report = {"schema": 2, "status": "failed", "error_code": error.code}
    except BaseException:
        report = {"schema": 2, "status": "failed", "error_code": "runtime_check_failed"}
    sys.stdout.write(json.dumps(report, separators=(",", ":"), ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
