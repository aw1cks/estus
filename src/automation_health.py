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


def check_collections(root, expected):
    collection_root = root / "collections"
    spec = importlib.machinery.PathFinder.find_spec("ansible_collections", [str(collection_root)])
    require(spec is not None and spec.loader is None, "runtime_collection_mismatch")
    # Resolve namespaces only through the selected bundle links, never ambient collections.
    namespace = importlib.util.module_from_spec(spec)
    sys.modules["ansible_collections"] = namespace
    observed = []
    for entry in expected:
        namespace_name, collection_name = entry["name"].split(".")
        directory = collection_root / "ansible_collections" / namespace_name / collection_name
        content, raw = read_json(directory / "MANIFEST.json", 1048576)
        info = content["collection_info"]
        require(info["namespace"] == namespace_name and info["name"] == collection_name,
                "runtime_collection_mismatch")
        version = info["version"]
        manifest_hash = hashlib.sha256(raw).hexdigest()
        require(version == entry["version"] and manifest_hash == entry["manifest_sha256"],
                "runtime_collection_mismatch")
        module = importlib.import_module("ansible_collections." + entry["name"])
        require(any(Path(path).resolve() == directory.resolve() for path in module.__path__),
                "runtime_collection_mismatch")
        observed.append({"name": entry["name"], "version": version, "manifest_sha256": manifest_hash})
    return observed


def check():
    require(len(sys.argv) == 2)
    payload, _ = read_json(Path(sys.argv[1]), 8192)
    exact_keys(payload, ("runtime_root",))
    root_value = payload["runtime_root"]
    require(isinstance(root_value, str) and 0 < len(root_value) <= 4096 and "\x00" not in root_value)
    root = Path(root_value)
    require(root.is_absolute() and root.resolve() == root)
    manifest = load_manifest(root)
    expected = manifest["identity"]
    temporary = os.environ.get("TMPDIR")
    require(temporary is not None and Path(temporary).is_absolute())
    for key in list(os.environ):
        if key.startswith("ANSIBLE_"):
            del os.environ[key]
    os.environ["HOME"] = temporary
    os.environ["ANSIBLE_CONFIG"] = str(root / "ansible.cfg")
    os.environ["ANSIBLE_COLLECTIONS_PATH"] = str(root / "collections")
    os.environ["ANSIBLE_COLLECTIONS_SCAN_SYS_PATH"] = "False"
    os.environ["ANSIBLE_HOME"] = str(Path(temporary) / "ansible")
    os.environ["ANSIBLE_LOCAL_TEMP"] = str(Path(temporary) / "ansible-local")
    site_packages = root / manifest["site_packages"]
    if not any(Path(path).resolve() == site_packages.resolve() for path in sys.path if path):
        sys.path.insert(0, str(site_packages))
    try:
        from ansible_runner import Runner, run, run_async
        from ansible.module_utils.basic import AnsibleModule
        require(all(callable(value) for value in (Runner, run, run_async, AnsibleModule)),
                "runtime_import_failed")
    except BaseException:
        raise HealthFailure("runtime_import_failed") from None
    try:
        observed = {
            "runtime_id": expected["runtime_id"],
            "platform": ("aarch64" if platform.machine() == "arm64" else platform.machine()) + "-" + sys.platform,
            "python": ".".join(str(value) for value in sys.version_info[:3]),
            "ansible_core": importlib.metadata.version("ansible-core"),
            "ansible_runner": importlib.metadata.version("ansible-runner"),
            "collection_bundle": importlib.metadata.version("ansible"),
        }
        require(all(observed[key] == expected[key] for key in observed), "runtime_version_mismatch")
    except BaseException:
        raise HealthFailure("runtime_version_mismatch") from None
    try:
        observed["collections"] = check_collections(root, expected["collections"])
    except BaseException:
        raise HealthFailure("runtime_collection_mismatch") from None
    return observed


def main():
    try:
        # The controller captures stderr privately. Dependency chatter must not corrupt JSON.
        with contextlib.redirect_stdout(sys.stderr):
            identity = check()
        report = {"schema": 1, "status": "passed", "identity": identity}
    except HealthFailure as error:
        report = {"schema": 1, "status": "failed", "error_code": error.code}
    except BaseException:
        report = {"schema": 1, "status": "failed", "error_code": "runtime_check_failed"}
    sys.stdout.write(json.dumps(report, separators=(",", ":"), ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
