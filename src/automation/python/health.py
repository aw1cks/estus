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
    require(type(collections) is list and 2 <= len(collections) <= 16)
    for entry in collections:
        exact_keys(entry, ("name", "version", "manifest_sha256"))
        require(type(entry["name"]) is str and re.fullmatch(
            r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*", entry["name"]))
        require(public_string(entry["version"]) and digest(entry["manifest_sha256"]))
    names = [entry["name"] for entry in collections]
    require(names == sorted(set(names)) and set(BASELINE_COLLECTIONS).issubset(names))
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
    require(package_root.name == "estus" and (package_root / "__init__.py").is_file()
            and (package_root / "_bin" / "estus").is_file())
    require(scripts.is_dir() and (scripts / "estus").is_file())
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
    names = [entry["name"] for entry in expected] if expected is not None else BASELINE_COLLECTIONS
    for index, name in enumerate(names):
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


def check(payload, role_request=False):
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
    if role_request:
        try:
            collection_roots = [root.resolve(strict=True) for root in collection_roots]
            require(all(not any(token in str(root) for token in (":", "$", "{{", "{%", "{#"))
                        for root in collection_roots), "invalid_role_source")
        except (OSError, RuntimeError, ValueError):
            raise HealthFailure("invalid_role_source") from None
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


def content_hash(trees, documented, domain=b"estus-module-content-v1\0", skip_generated=True):
    result = hashlib.sha256(domain)
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
                    if skip_generated and (child.name == "__pycache__" or child.name.endswith((".pyc", ".pyo"))):
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


def role_collection_trees(roots):
    """Attest every installed collection made searchable, including additions."""
    trees = []
    entries = 0

    def children(directory):
        nonlocal entries
        result = []
        for child in directory.iterdir():
            entries += 1
            require(entries <= ENTRY_LIMIT, "role_content_limit")
            result.append(child)
        return sorted(result)

    for index, root in enumerate(roots):
        namespace_root = root / "ansible_collections"
        require(namespace_root.is_dir(), "role_collection_source_invalid")
        for namespace in children(namespace_root):
            if namespace.name == "__pycache__" or namespace.suffix in (".pyc", ".pyo"):
                continue
            if namespace.name in ("ansible_community.py", "ansible_release.py"):
                require(namespace.is_file() and not namespace.is_symlink(),
                        "role_collection_source_invalid")
                continue
            require(re.fullmatch(r"[a-z_][a-z0-9_]*", namespace.name)
                    and namespace.is_dir(), "role_collection_source_invalid")
            collections = children(namespace)
            require(collections, "role_collection_source_invalid")
            for collection in collections:
                require(re.fullmatch(r"[a-z_][a-z0-9_]*", collection.name)
                        and collection.is_dir(), "role_collection_source_invalid")
                # Installation anchors may be links (notably Nix); interior
                # links remain forbidden by the common bounded content walker.
                trees.append(("collections/" + str(index) + "/" + namespace.name
                              + "/" + collection.name, collection.resolve(strict=True)))
    return trees


def role_collection_dependencies(name, roots, checked):
    """Validate manifest closure only for collections explicitly used by roles."""
    pending = [name]
    while pending:
        name = pending.pop()
        require(type(name) is str and re.fullmatch(
            r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*", name),
            "role_collection_dependency_invalid")
        if name == "ansible.builtin" or name in checked:
            continue
        checked.add(name)
        require(len(checked) <= ENTRY_LIMIT, "role_content_limit")
        namespace, package = name.split(".")
        directories = list(dict.fromkeys(
            (root / "ansible_collections" / namespace / package).resolve(strict=True)
            for root in roots if (root / "ansible_collections" / namespace / package).is_dir()))
        require(directories, "role_collection_dependency_not_found")
        for directory in directories:
            manifest, _ = read_json(directory / "MANIFEST.json", DOCUMENT_LIMIT)
            info = manifest.get("collection_info")
            require(type(info) is dict, "role_collection_dependency_invalid")
            dependencies = info.get("dependencies", {})
            require(type(dependencies) is dict, "role_collection_dependency_invalid")
            pending.extend(dependencies)
            require(len(pending) <= ENTRY_LIMIT, "role_content_limit")


def role_dependencies(directory, search_root, collection, roots, checked):
    """Reject declared role paths outside the executable reviewed search roots."""
    import yaml
    related = []
    for candidate in directory.glob("meta/main.*"):
        if candidate.suffix not in (".yml", ".yaml", ".json"):
            continue
        require(not candidate.is_symlink() and candidate.stat().st_size <= DOCUMENT_LIMIT,
                "role_dependency_invalid")
        try:
            metadata = yaml.safe_load(candidate.read_bytes())
        except BaseException:
            raise HealthFailure("role_dependency_invalid") from None
        if metadata is None:
            continue
        require(type(metadata) is dict, "role_dependency_invalid")
        collections = metadata.get("collections", [])
        require(type(collections) is list, "role_collection_dependency_invalid")
        for name in collections:
            role_collection_dependencies(name, roots, checked)
        dependencies = metadata.get("dependencies", [])
        require(type(dependencies) is list, "role_dependency_invalid")
        for dependency in dependencies:
            name = dependency if type(dependency) is str else (
                dependency.get("role", dependency.get("name"))
                if type(dependency) is dict else None)
            require(type(name) is str and re.fullmatch(
                r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){0,2}", name)
                and len(name.split(".")) in (1, 3), "role_dependency_outside_bundle")
            if "." in name:
                namespace, package, simple = name.split(".")
                role_collection_dependencies(namespace + "." + package, roots, checked)
                candidates = [root / "ansible_collections" / namespace / package / "roles" / simple
                              for root in roots]
            else:
                candidates = [search_root / name]
                if collection is not None:
                    namespace, package = collection.split(".")
                    candidates.extend(root / "ansible_collections" / namespace / package
                                      / "roles" / name for root in roots)
            present = [path for path in candidates if path.is_dir() and not path.is_symlink()]
            require(present, "role_dependency_not_found")
            dependency_collection = namespace + "." + package if "." in name else collection
            related.extend((path.resolve(strict=True), path.parent.resolve(strict=True),
                            dependency_collection) for path in present)
    return related


def role_content(role, entry_point, role_path, roots):
    """Resolve and attest role/Core/collection bytes without invoking ansible-doc."""
    require(isinstance(role, str) and len(role) <= 256 and re.fullmatch(
        r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){0,2}", role)
        and len(role.split(".")) in (1, 3)
        and all(len(part) <= 128 for part in role.split(".")), "invalid_role_name")
    require(isinstance(entry_point, str) and len(entry_point) <= 128
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", entry_point),
            "invalid_role_entry_point")
    import ansible
    trees = [("ansible", Path(ansible.__file__).parent.resolve(strict=True))]
    selected_collection = None
    collection = None
    if "." in role:
        require(role_path is None, "invalid_role_source")
        namespace, name, simple = role.split(".")
        collection = namespace + "." + name
        candidates = list(dict.fromkeys(
            (root / "ansible_collections" / namespace / name).resolve(strict=True)
            for root in roots
            if (root / "ansible_collections" / namespace / name).is_dir()
        ))
        require(len(candidates) == 1, "role_not_found")
        collection_root = candidates[0]
        directory = collection_root / "roles" / simple
        trees.append((collection, collection_root))
        try:
            manifest, raw = read_json(collection_root / "MANIFEST.json", 1048576)
            info = manifest["collection_info"]
            version = info["version"]
            require(info["namespace"] == namespace and info["name"] == name
                    and public_string(version) and re.fullmatch(
                        r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?", version
                    ), "runtime_collection_mismatch")
            selected_collection = {
                "name": collection, "version": version,
                "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            }
        except BaseException:
            raise HealthFailure("runtime_collection_mismatch") from None
        expected_path = collection_root
    else:
        require(role_path is not None, "role_source_required")
        try:
            require(isinstance(role_path, str) and 0 < len(role_path.encode("utf-8")) <= 4096
                    and "\0" not in role_path and Path(role_path).is_absolute()
                    and Path(role_path).name == role, "invalid_role_source")
            directory = Path(role_path).resolve(strict=True)
        except (OSError, RuntimeError, UnicodeError, ValueError):
            raise HealthFailure("invalid_role_source") from None
        require(directory.name == role and directory.is_dir()
                and not any(token in str(directory.parent) for token in (":", "$", "{{", "{%", "{#")),
                "invalid_role_source")
        expected_path = directory
        trees.append(("roles", directory.parent))
    require(directory.is_dir(), "role_not_found")
    tasks = [directory / "tasks" / (entry_point + suffix) for suffix in ("", ".yml", ".yaml")]
    present = [path for path in tasks if path.exists() or path.is_symlink()]
    require(len(present) == 1, "role_entry_point_not_found")
    require(not present[0].is_symlink() and present[0].is_file(), "role_content_failed")
    trees.extend(role_collection_trees(roots))
    # Hash before ansible-doc reads metadata, bounding and rejecting unsafe tree
    # entries first. The common walker retains module hashes exactly as before.
    try:
        domain = b"estus-role-bundle-content-v2\0" + role.encode("ascii") + b"\0" + entry_point.encode("ascii") + b"\0"
        content = content_hash(trees, present[0], domain, skip_generated=False)
    except HealthFailure as error:
        raise HealthFailure(error.code.replace("module_", "role_", 1)) from None
    except (OSError, UnicodeError, ValueError):
        raise HealthFailure("role_content_failed") from None
    # All searchable bytes above are approved, including unused collections.
    # Availability checks apply only to the selected role and its declared
    # dependency closure; an unused collection cannot execute a missing source.
    checked_collections = set()
    if collection is not None:
        role_collection_dependencies(collection, roots, checked_collections)
    pending = [(directory, directory.parent, collection)]
    checked_roles = set()
    while pending:
        selected_directory, search_root, selected_collection_name = pending.pop()
        key = selected_directory.resolve(strict=True)
        if key in checked_roles:
            continue
        checked_roles.add(key)
        require(len(checked_roles) <= ENTRY_LIMIT, "role_content_limit")
        pending.extend(role_dependencies(
            selected_directory, search_root, selected_collection_name, roots, checked_collections))
        require(len(pending) <= ENTRY_LIMIT, "role_content_limit")
    return directory, expected_path, collection, content, selected_collection, trees


def playbook_contains(directory, path):
    """Compare existing directory identities, including case-insensitive aliases."""
    return any(parent.samefile(directory) for parent in (path, *path.parents))


def playbook_content(playbook, project_root, roots, output=None):
    """Hash Core and the complete fixed project without loading YAML or project code."""
    require(isinstance(playbook, str) and 0 < len(playbook.encode("utf-8")) <= 4096
            and not playbook.startswith(("/", "-")) and "\\" not in playbook
            and not any(token in playbook for token in ("\0", "$", "{{", "{%", "{#"))
            and all(part not in ("", ".", "..") for part in playbook.split("/"))
            and playbook.endswith((".yml", ".yaml")), "invalid_playbook")
    try:
        require(isinstance(project_root, str)
                and 0 < len(project_root.encode("utf-8")) <= 4096
                and "\0" not in project_root and Path(project_root).is_absolute(),
                "invalid_playbook_source")
        directory = Path(project_root).resolve(strict=True)
        require(directory.is_dir()
                and not any(token in str(directory) for token in (":", "$", "{{", "{%", "{#")),
                "invalid_playbook_source")
        temporary = absolute_path(os.environ.get("TMPDIR")).resolve(strict=True)
        require(not playbook_contains(directory, temporary), "invalid_playbook_source")
    except (OSError, RuntimeError, UnicodeError, ValueError):
        raise HealthFailure("invalid_playbook_source") from None
    import ansible
    try:
        core = Path(ansible.__file__).parent.resolve(strict=True)
        trees = [("ansible", core), ("project", directory)]
        if output is not None:
            try:
                require(isinstance(output, str) and 0 < len(output.encode("utf-8")) <= 4096
                        and "\0" not in output and Path(output).is_absolute()
                        and Path(output).name not in ("", ".", ".."),
                        "invalid_playbook_output")
                destination = Path(output).parent.resolve(strict=True) / Path(output).name
                require(destination.parent.is_dir(), "invalid_playbook_output")
            except (OSError, RuntimeError, UnicodeError, ValueError):
                raise HealthFailure("invalid_playbook_output") from None
            require(not any(playbook_contains(tree, destination.parent) for _, tree in trees),
                    "playbook_output_inside_source")
        entry = directory / playbook
        require(entry.exists() and entry.is_file() and not entry.is_symlink(),
                "playbook_not_found")
        domain = b"estus-playbook-content-v1\0" + playbook.encode("utf-8") + b"\0"
        content = content_hash(trees, entry, domain, skip_generated=False)
    except HealthFailure as error:
        raise HealthFailure(error.code.replace("module_", "playbook_", 1)) from None
    except (OSError, RuntimeError, UnicodeError, ValueError):
        raise HealthFailure("playbook_content_failed") from None
    return directory, content


def role_documentation(role, entry_point, role_path, output, roots):
    """Acquire public metadata only; output must remain outside every hashed tree."""
    destination = None
    if output is not None:
        try:
            require(isinstance(output, str) and 0 < len(output.encode("utf-8")) <= 4096
                    and "\0" not in output and Path(output).is_absolute()
                    and Path(output).name not in ("", ".", ".."), "invalid_role_output")
            # Publication replaces the final directory entry: resolve only its
            # existing parent, not an existing final symlink's target.
            path = Path(output)
            parent = path.parent.resolve(strict=True)
            require(parent.is_dir(), "invalid_role_output")
            destination = parent / path.name
        except (OSError, RuntimeError, UnicodeError, ValueError):
            raise HealthFailure("invalid_role_output") from None
    os.environ["LC_ALL"] = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    os.environ["LANG"] = os.environ["LC_ALL"]
    # Defaults and playbook-relative role paths must not participate in selection.
    private = absolute_path(os.environ.get("TMPDIR"))
    os.environ["ANSIBLE_ROLES_PATH"] = str(private / "no-roles")
    os.chdir(private)
    directory, expected_path, collection, content, selected_collection, trees = role_content(
        role, entry_point, role_path, roots)
    if destination is not None:
        require(not any(destination.is_relative_to(root) for _, root in trees),
                "role_output_inside_source")
    arguments = ["ansible-doc", "--type", "role", "--json"]
    if role_path is not None:
        arguments.extend(["--roles-path", str(directory.parent)])
    for name in tuple(sys.modules):
        if name == "ansible_collections" or name.startswith("ansible_collections."):
            del sys.modules[name]

    def acquire(selected):
        output = BoundedOutput()
        argv = sys.argv
        try:
            sys.argv = arguments + (["--entry-point", selected] if selected is not None else []) + [role]
            with contextlib.redirect_stdout(output):
                try:
                    runpy.run_module("ansible.cli.doc", run_name="__main__")
                except SystemExit as error:
                    require(error.code in (None, 0), "role_documentation_failed")
            entries = json.loads(output.getvalue(), object_pairs_hook=unique_object)
            require(type(entries) is dict, "role_documentation_failed")
            return entries
        except HealthFailure as error:
            if error.code == "module_output_limit":
                raise HealthFailure("role_output_limit") from None
            raise
        except BaseException:
            raise HealthFailure("role_documentation_failed") from None
        finally:
            sys.argv = argv

    entries = acquire(entry_point)
    if not entries:
        # The public CLI omits roles without specs and also omits unmatched entry
        # points. An unfiltered public query distinguishes the latter; a dedicated
        # argspec file must never silently degrade to an explicit-schema import.
        all_entries = acquire(None)
        dedicated = any((directory / "meta" / ("argument_specs" + suffix)).exists()
                        for suffix in (".yml", ".yaml", ".json"))
        require(not all_entries, "role_entry_point_not_found")
        require(not dedicated, "role_documentation_failed")
        return {"role": role, "collection": collection, "entry_points": {}}, content, selected_collection
    require(list(entries) == [role], "role_identifier_mismatch")
    document = entries[role]
    require(type(document) is dict and set(document) == {"collection", "path", "entry_points"}
            and document["collection"] == collection, "role_identifier_mismatch")
    require(isinstance(document["path"], str)
            and Path(document["path"]).resolve(strict=True) == expected_path,
            "role_identifier_mismatch")
    points = document["entry_points"]
    require(type(points) is dict and list(points) == [entry_point],
            "role_entry_point_not_found")
    # Only public argspec semantics survive. Neither runtime nor role source
    # paths are persisted in the private report or the eventual snapshot.
    del document["path"]
    document["role"] = role
    return document, content, selected_collection


def generic_inventory(roots, documentation=False):
    """Canonical module inventory plus the entire searchable runtime closure.

    Documentation is deliberately not a prerequisite for generic execution.
    Redirects and filesystem aliases are omitted, never authorized as identities.
    """
    import ansible
    import ansible_runner
    for name in tuple(sys.modules):
        if name == "ansible_collections" or name.startswith("ansible_collections."):
            del sys.modules[name]
    from ansible.plugins.loader import module_loader, init_plugin_loader
    init_plugin_loader()
    core = Path(ansible.__file__).parent.resolve(strict=True)
    trees = [("ansible", core), ("ansible_runner", Path(ansible_runner.__file__).parent.resolve(strict=True))]
    trees.extend(role_collection_trees([root for root in roots
                                        if (root / "ansible_collections").is_dir()]))
    modules = {}
    candidates = [("ansible.builtin", core / "modules")]
    for label, directory in trees[2:]:
        collection = ".".join(label.split("/")[-2:])
        role_collection_dependencies(collection, roots, set())
        candidates.append((collection, directory / "plugins" / "modules"))
    for collection, directory in candidates:
        if not directory.is_dir():
            continue
        for source in sorted(directory.rglob("*")):
            if source.suffix not in (".py", ".ps1") or source.name.startswith("_"):
                continue
            relative = source.relative_to(directory).with_suffix("")
            if any(not re.fullmatch(r"[a-z_][a-z0-9_]*", part) for part in relative.parts):
                continue
            fqcn = collection + "." + ".".join(relative.parts)
            require(len(modules) < 16384, "module_output_limit")
            resolved = module_loader.find_plugin_with_context(fqcn)
            if (not resolved.resolved or resolved.resolved_fqcn != fqcn
                    or Path(resolved.plugin_resolved_path).resolve(strict=True) != source.resolve(strict=True)):
                continue
            modules[fqcn] = {"collection": collection}
    if documentation:
        # Public discovery is captured once at explicit import/activation, never
        # refreshed by a request. Opaque module option types need no converter.
        output = BoundedOutput()
        argv = sys.argv
        summaries = {}
        failure = "not_documented"
        try:
            os.environ["LC_ALL"] = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
            os.environ["LANG"] = os.environ["LC_ALL"]
            sys.argv = ["ansible-doc", "--list", "--json", "--type", "module"]
            with contextlib.redirect_stdout(output):
                try:
                    runpy.run_module("ansible.cli.doc", run_name="__main__")
                except SystemExit as error:
                    require(error.code in (None, 0), "module_documentation_failed")
            summaries = json.loads(output.getvalue(), object_pairs_hook=unique_object)
            require(type(summaries) is dict, "module_documentation_failed")
        except HealthFailure as error:
            failure = error.code
        except Exception:
            failure = "module_documentation_failed"
        finally:
            sys.argv = argv
        for fqcn, module in modules.items():
            summary = summaries.get(fqcn)
            if (type(summary) is str and summary.strip()
                    and summary.strip() not in ("UNDOCUMENTED", "INVALID SHORT DESCRIPTION")):
                raw = summary.strip().encode("utf-8")
                module["documentation"] = {
                    "status": "partial", "short_description": raw[:512].decode("utf-8", errors="ignore"),
                    "reason": "summary_truncated" if len(raw) > 512 else "summary_only",
                }
            else:
                module["documentation"] = {
                    "status": "unavailable", "short_description": None, "reason": failure,
                }
    # This includes collection routing, action plugins and module utilities, not
    # only selected module files. Addition of a module changes the generation.
    content = content_hash(trees, core / "__init__.py", domain=b"estus-generic-inventory-v1\0")
    # The installed Ansible distribution also exposes these Python metadata
    # modules beside collection namespaces. They are not collections, but remain
    # executable selected-runtime content and therefore participate in approval.
    approved = hashlib.sha256(b"estus-generic-namespace-v1\0" + bytes.fromhex(content))
    for index, root in enumerate(roots):
        for name in ("ansible_community.py", "ansible_release.py"):
            path = root / "ansible_collections" / name
            if not path.exists() and not path.is_symlink():
                continue
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
            with os.fdopen(os.open(path, flags), "rb") as stream:
                require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "module_content_failed")
                data = stream.read(DOCUMENT_LIMIT + 1)
                require(len(data) <= DOCUMENT_LIMIT, "module_content_limit")
            label = (str(index) + "/" + name).encode("ascii")
            approved.update(len(label).to_bytes(4, "big") + label
                            + len(data).to_bytes(8, "big") + data)
    return {"modules": modules, "content_sha256": approved.hexdigest()}


def main():
    try:
        # The controller captures stderr privately. Dependency chatter must not corrupt JSON.
        payload, _ = read_json(Path(sys.argv[1]), 66560) if len(sys.argv) == 2 else (None, None)
        require(type(payload) is dict)
        module = payload.pop("module", None)
        role = payload.pop("role", None)
        playbook = payload.pop("playbook", None)
        inventory = payload.pop("inventory", None)
        require(sum(value is not None for value in (module, role, playbook, inventory)) <= 1)
        with contextlib.redirect_stdout(sys.stderr):
            try:
                identity, roots = check(payload, role_request=role is not None or playbook is not None)
            except HealthFailure as error:
                if playbook is not None and error.code == "invalid_role_source":
                    raise HealthFailure("invalid_playbook_source") from None
                raise
            if module is not None:
                document, content, collection = import_document(module, roots)
            if inventory is not None:
                require(inventory is True)
                inventory = generic_inventory(roots, documentation=True)
            elif role is not None:
                exact_keys(role, ("name", "entry_point", "path", "output"))
                document, content, collection = role_documentation(
                    role["name"], role["entry_point"], role["path"], role["output"], roots
                )
            elif playbook is not None:
                exact_keys(playbook, ("name", "project_root", "output"))
                _, content = playbook_content(
                    playbook["name"], playbook["project_root"], roots, playbook["output"]
                )
                document = {"playbook": playbook["name"]}
        report = {"schema": 2, "status": "passed", "identity": identity}
        if module is not None or role is not None:
            report.update(document=document, content_sha256=content, collection=collection)
        elif playbook is not None:
            report.update(document=document, content_sha256=content)
        if inventory is not None:
            report["inventory"] = inventory
    except HealthFailure as error:
        report = {"schema": 2, "status": "failed", "error_code": error.code}
    except BaseException:
        report = {"schema": 2, "status": "failed", "error_code": "runtime_check_failed"}
    sys.stdout.write(json.dumps(report, separators=(",", ":"), ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
