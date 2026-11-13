"""Private selected-runtime identity and explicit public documentation importer."""

import contextlib
import hashlib
import importlib
import importlib.machinery
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import io
import platform
import re
import runpy
import stat
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
    package_root = absolute_path(payload["package_root"]).resolve(strict=True)
    scripts = absolute_path(payload["scripts"]).resolve(strict=True)
    require(package_root.name == "ssh_mcp" and (package_root / "__init__.py").is_file()
            and (package_root / "_bin" / "ssh-mcp").is_file())
    require(scripts.is_dir() and (scripts / "ssh-mcp").is_file())
    paths = sysconfig.get_paths()
    interpreter_sites = list(dict.fromkeys(absolute_path(paths[key]) for key in ("purelib", "platlib")))
    require(all(path.resolve().is_relative_to(prefix.resolve()) for path in interpreter_sites))
    # uv run's requirements live outside its ephemeral interpreter prefix. Trust
    # only the launcher's concrete installation root, not its ambient sys.path,
    # PYTHONPATH, arbitrary .pth additions, or the caller's current directory.
    sites = list(dict.fromkeys((package_root.parent, *interpreter_sites)))
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


def check(payload):
    require(type(payload) is dict and type(payload.get("schema")) is int and payload["schema"] == 2)
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
        exact_keys(payload, ("schema", "source", "interpreter", "prefix", "package_root", "scripts"))
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
    os.environ["ANSIBLE_NOCOWS"] = "True"
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
    return observed, collection_roots


# Limits apply to actual bytes and entries, not distribution version metadata.
DOCUMENT_LIMIT = 2 * 1024 * 1024
TREE_LIMIT = 256 * 1024 * 1024
FILE_LIMIT = 32 * 1024 * 1024
ENTRY_LIMIT = 50000


class BoundedOutput(io.StringIO):
    def __init__(self):
        super().__init__()
        self.size = 0

    def write(self, value):
        self.size += len(value.encode("utf-8"))
        require(self.size <= DOCUMENT_LIMIT, "module_output_limit")
        return super().write(value)


def content_hash(trees, documented):
    result = hashlib.sha256(b"ssh-mcp-module-content-v1\0")
    total = 0
    entries = 0
    found = False
    for label, root in trees:
        # Installation roots may legitimately be Nix symlinks. Interior links
        # are rejected rather than silently omitted or followed outside the tree.
        root = root.resolve(strict=True)
        require(root.is_dir(), "module_content_failed")

        def visit(directory, relative, depth):
            nonlocal total, entries, found
            require(depth <= 32, "module_content_limit")
            children = []
            with os.scandir(directory) as iterator:
                for child in iterator:
                    entries += 1
                    require(entries <= ENTRY_LIMIT, "module_content_limit")
                    if child.name == "__pycache__" or child.name.endswith((".pyc", ".pyo")):
                        continue
                    children.append(child)
            for child in sorted(children, key=lambda item: item.name):
                name = relative / child.name
                encoded = (label + "/" + name.as_posix()).encode("utf-8")
                require(len(encoded) <= 4096, "module_content_limit")
                mode = child.stat(follow_symlinks=False).st_mode
                require(not stat.S_ISLNK(mode), "module_content_symlink")
                if stat.S_ISDIR(mode):
                    result.update(b"D" + len(encoded).to_bytes(4, "big") + encoded)
                    visit(Path(child.path), name, depth + 1)
                else:
                    require(stat.S_ISREG(mode), "module_content_failed")
                    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                    with os.fdopen(os.open(child.path, flags), "rb") as stream:
                        metadata = os.fstat(stream.fileno())
                        require(stat.S_ISREG(metadata.st_mode), "module_content_failed")
                        size = metadata.st_size
                        require(size <= FILE_LIMIT and total + size <= TREE_LIMIT,
                                "module_content_limit")
                        result.update(b"F" + len(encoded).to_bytes(4, "big") + encoded
                                      + size.to_bytes(8, "big"))
                        read = 0
                        while True:
                            chunk = stream.read(65536)
                            if not chunk:
                                break
                            read += len(chunk)
                            total += len(chunk)
                            require(read <= FILE_LIMIT and total <= TREE_LIMIT,
                                    "module_content_limit")
                            result.update(chunk)
                        require(read == size, "module_content_failed")
                    if Path(child.path) == documented:
                        found = True
        visit(root, PurePosixPath(), 0)
    require(found, "module_content_failed")
    return result.hexdigest()


def import_document(module, roots):
    require(isinstance(module, str) and len(module) <= 256
            and re.fullmatch(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){2,}", module),
            "invalid_module_identifier")
    # The controller's health locale is deliberately C; the public console
    # requires a real UTF-8 locale even when Python itself uses UTF-8 mode.
    os.environ["LC_ALL"] = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    os.environ["LANG"] = os.environ["LC_ALL"]
    import ansible
    core = Path(ansible.__file__).parent.resolve(strict=True)
    collection = ".".join(module.split(".")[:2])
    trees = [("ansible", core)]
    selected_collection = None
    if collection == "ansible.builtin":
        module_root = core / "modules"
    else:
        namespace, name = collection.split(".")
        candidates = list(dict.fromkeys(
            (root / "ansible_collections" / namespace / name).resolve(strict=True)
            for root in roots
            if (root / "ansible_collections" / namespace / name).is_dir()
        ))
        require(len(candidates) == 1, "module_not_found")
        trees.append((collection, candidates[0]))
        module_root = candidates[0] / "plugins" / "modules"
        try:
            manifest, raw = read_json(candidates[0] / "MANIFEST.json", 1048576)
            info = manifest["collection_info"]
            require(info["namespace"] == namespace and info["name"] == name,
                    "runtime_collection_mismatch")
            version = info["version"]
            require(public_string(version) and re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", version
            ) is not None, "runtime_collection_mismatch")
            selected_collection = {
                "name": collection, "version": version,
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            }
        except BaseException:
            raise HealthFailure("runtime_collection_mismatch") from None
    # Health verifies ordinary namespace imports first. The public CLI installs
    # Ansible's collection loader, which must initialize those namespaces itself.
    for name in tuple(sys.modules):
        if name == "ansible_collections" or name.startswith("ansible_collections."):
            del sys.modules[name]
    output = BoundedOutput()
    argv = sys.argv
    try:
        sys.argv = ["ansible-doc", "--json", "--type", "module", module]
        with contextlib.redirect_stdout(output):
            try:
                runpy.run_module("ansible.cli.doc", run_name="__main__")
            except SystemExit as error:
                require(error.code in (None, 0), "module_documentation_failed")
    finally:
        sys.argv = argv
    entries = json.loads(output.getvalue(), object_pairs_hook=unique_object)
    require(type(entries) is dict and list(entries) == [module], "module_not_found")
    entry = entries[module]
    require(type(entry) is dict and type(entry.get("doc")) is dict,
            "module_documentation_failed")
    doc = entry["doc"]
    require(doc.get("plugin_name") == module and doc.get("collection") == collection,
            "module_identifier_mismatch")
    filename = absolute_path(doc.get("filename"))
    require(filename.suffix in (".py", ".yml", ".yaml"), "module_documentation_failed")
    expected = module_root.joinpath(*module.split(".")[2:]).with_suffix(filename.suffix)
    # Resolve legitimate installation-root links, but never accept a module alias.
    require(not expected.is_symlink() and filename.resolve(strict=True) == expected.resolve(strict=True),
            "module_identifier_mismatch")
    documented = filename.resolve(strict=True)
    require(documented.is_relative_to(module_root.resolve(strict=True)),
            "module_identifier_mismatch")
    try:
        content = content_hash(trees, documented)
    except (OSError, UnicodeError, ValueError):
        raise HealthFailure("module_content_failed") from None
    # ansible-doc adds its private installation path; retain a public logical
    # source name instead, while hashing the actual original source bytes.
    label, tree = trees[-1]
    doc["filename"] = label + "/" + documented.relative_to(tree).as_posix()
    return entry, content, selected_collection


def main():
    try:
        # The controller captures stderr privately. Dependency chatter must not corrupt JSON.
        payload, _ = read_json(Path(sys.argv[1]), 66560) if len(sys.argv) == 2 else (None, None)
        require(type(payload) is dict)
        module = payload.pop("module", None)
        with contextlib.redirect_stdout(sys.stderr):
            identity, roots = check(payload)
            if module is not None:
                document, content, collection = import_document(module, roots)
        report = {"schema": 2, "status": "passed", "identity": identity}
        if module is not None:
            report.update(document=document, content_sha256=content, collection=collection)
    except HealthFailure as error:
        report = {"schema": 2, "status": "failed", "error_code": error.code}
    except BaseException:
        report = {"schema": 2, "status": "failed", "error_code": "runtime_check_failed"}
    sys.stdout.write(json.dumps(report, separators=(",", ":"), ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
