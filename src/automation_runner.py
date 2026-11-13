"""Private foreground Runner bridge. Only bounded, payload-free frames leave fd 1."""

import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import sys
import threading
import time


HOST = "ssh_mcp_target"
TASK = "ssh_mcp_module"
LIMIT = 256 * 1024


class Invalid(Exception):
    pass


def require(value):
    if not value:
        raise Invalid()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected))


def absolute(value):
    require(type(value) is str and 0 < len(value.encode("utf-8")) <= 4096
            and "\x00" not in value and Path(value).is_absolute())
    return Path(value)


def identifier(value):
    return type(value) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}", value) is not None


def arguments(value, depth=0, nodes=None):
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    require(depth <= 32 and nodes[0] <= 16384)
    if type(value) is dict:
        for key, child in value.items():
            require(identifier(key) and not key.startswith("ansible_"))
            arguments(child, depth + 1, nodes)
    elif type(value) is list:
        for child in value:
            arguments(child, depth + 1, nodes)
    elif type(value) in (int, float):
        require(math.isfinite(value) and abs(value) <= 9007199254740991)
    else:
        require(value is None or type(value) in (str, bool))


class Frames:
    def __init__(self):
        # The duplicate is non-inheritable; imports, native writes and children use stderr.
        self.fd = os.dup(1)
        os.set_inheritable(self.fd, False)
        os.dup2(2, 1)
        self.id = None
        self.bytes = 0
        self.terminal = False

    def emit(self, kind, **values):
        require(self.id is not None and not self.terminal)
        raw = (json.dumps(dict(schema=1, id=self.id, kind=kind, **values),
                          ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")
        require(len(raw) <= 8192 and self.bytes + len(raw) <= 65536)
        self.bytes += len(raw)
        while raw:
            count = os.write(self.fd, raw)
            require(count > 0)
            raw = raw[count:]
        self.terminal = kind == "terminal"


class Evidence:
    def __init__(self, frames, module, no_log):
        self.frames = frames
        self.module = module
        self.censored = no_log
        self.invalid = False
        self.task_uuid = None
        self.task_started = False
        self.outcome = None
        self.changed = None
        self.stats = None
        self.statuses = []
        self.tasks = dict(ok=0, failed=0, unreachable=0, skipped=0)

    def status(self, data, runner_config):
        # Starting data contains argv/env: never retain it or serialize it.
        status = data.get("status") if type(data) is dict else None
        if status not in ("starting", "running", "successful", "failed", "canceled", "timeout"):
            self.invalid = True
        elif len(self.statuses) >= 4:
            self.invalid = True
        else:
            self.statuses.append(status)

    def event(self, event):
        try:
            self.consume(event)
        except (Invalid, KeyError, TypeError, ValueError, OverflowError):
            self.invalid = True
        return False

    def consume(self, event):
        require(type(event) is dict and type(event.get("event")) is str)
        kind = event["event"]
        data = event.get("event_data", {})
        require(type(data) is dict)
        if "host" in data:
            require(data["host"] == HOST)
        if kind == "playbook_on_task_start":
            require(not self.task_started and self.stats is None)
            require(data.get("task") == TASK and data.get("task_action") == self.module)
            uuid = data.get("task_uuid")
            require(type(uuid) is str and 0 < len(uuid) <= 128)
            self.task_uuid = uuid
            self.task_started = True
        elif kind in ("runner_on_ok", "runner_on_failed", "runner_on_unreachable", "runner_on_skipped"):
            require(self.task_started and self.outcome is None and self.stats is None)
            require(data.get("host") == HOST and data.get("task_uuid") == self.task_uuid
                    and data.get("task_action") == self.module and data.get("task") == TASK)
            require(not data.get("ignore_errors", False) and not data.get("event_loop"))
            result = data.get("res", {})
            require(type(result) is dict)
            self.censored = self.censored or bool(result.get("_ansible_no_log")) or "censored" in result
            changed = result.get("changed")
            require(changed is None or type(changed) is bool)
            self.changed = None if self.censored else changed
            self.outcome = kind.removeprefix("runner_on_")
            self.tasks[self.outcome] = 1
            self.frames.emit("task", outcome=self.outcome, changed=self.changed, censored=self.censored)
        elif kind == "playbook_on_stats":
            require(self.stats is None and self.outcome is not None)
            observed = {}
            for name in ("ok", "failures", "dark", "skipped", "changed", "processed", "rescued", "ignored"):
                counts = data.get(name)
                require(type(counts) is dict and set(counts).issubset({HOST}))
                require(all(type(v) is int and 0 <= v <= 1 for v in counts.values()))
                observed[name] = counts.get(HOST, 0)
            require(observed["processed"] == 1 and not observed["rescued"] and not observed["ignored"])
            for source, target in (("ok", "ok"), ("failures", "failed"), ("dark", "unreachable"), ("skipped", "skipped")):
                require(observed[source] == self.tasks[target])
            if self.changed is not None:
                require(observed["changed"] == int(self.changed))
            require(not observed["changed"] or self.outcome in ("ok", "failed"))
            self.changed = None if self.censored else bool(observed["changed"])
            self.stats = observed
        elif kind.startswith("runner_on_") and kind != "runner_on_start":
            raise Invalid()
        elif kind in ("playbook_on_include", "playbook_on_import_for_host", "playbook_on_not_import_for_host", "playbook_on_no_hosts_matched", "playbook_on_no_hosts_remaining"):
            raise Invalid()

    def reconcile(self, runner):
        rc = runner.rc
        require(rc is None or type(rc) is int and -(2**31) <= rc < 2**31)
        require(not self.invalid and self.stats is not None)
        require(self.statuses == ["starting", "running", runner.status])
        if self.outcome == "ok":
            require(runner.status == "successful" and rc == 0)
            return "successful"
        if self.outcome == "unreachable":
            require(runner.status == "failed" and rc == 4)
            return "unreachable"
        require(self.outcome == "failed" and runner.status == "failed" and rc == 2)
        return "failed"


class Cancellation:
    def __init__(self, workspace, spec):
        self.workspace = workspace
        self.spec = spec
        self.control = threading.Event()
        self.reason = None
        self.requested_at = None
        self.deadline = time.monotonic() + spec["timeout_secs"]
        self.next_scan = 0
        threading.Thread(target=self.read_control, daemon=True).start()

    def read_control(self):
        try:
            os.read(0, 1)
        except OSError:
            pass
        finally:
            self.control.set()

    def scratch(self):
        size = 0
        count = 0
        def visit(fd, depth):
            nonlocal size, count
            require(depth <= 32)
            with os.scandir(fd) as entries:
                for entry in entries:
                    count += 1
                    require(count <= self.spec["scratch_files"])
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    require(not stat.S_ISLNK(info.st_mode))
                    size += info.st_size
                    require(size <= self.spec["scratch_bytes"])
                    if stat.S_ISDIR(info.st_mode):
                        try:
                            child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        except FileNotFoundError:
                            continue
                        try:
                            visit(child, depth + 1)
                        finally:
                            os.close(child)
                    elif depth == 0 and entry.name == "runner.lease":
                        require(stat.S_ISFIFO(info.st_mode) and info.st_uid == os.getuid()
                                and stat.S_IMODE(info.st_mode) == 0o600)
                    else:
                        require(stat.S_ISREG(info.st_mode))
        fd = os.open(self.workspace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            visit(fd, 0)
        finally:
            os.close(fd)

    def requested(self):
        if self.reason is not None:
            return True
        if self.control.is_set():
            self.reason = "cancelled"
        elif time.monotonic() >= self.deadline:
            self.reason = "timeout"
        elif time.monotonic() >= self.next_scan:
            self.next_scan = time.monotonic() + 0.05
            try:
                self.scratch()
            except (Invalid, OSError):
                self.reason = "resource_limit"
        if self.reason is not None:
            self.requested_at = time.monotonic()
            try:
                marker = self.workspace / "control" / "cancel"
                fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except OSError:
                # The independent owner-PID check still covers adapter loss.
                # If scratch is exhausted, hard cancellation remains the fallback.
                self.reason = "resource_limit"
        return self.reason is not None

    def __call__(self):
        return self.requested() and time.monotonic() - self.requested_at >= 1.5


def validate(spec):
    keys(spec, ("schema", "invocation_id", "runtime", "expected", "destination", "target_python",
                "ssh_config", "ssh_executable", "arguments", "no_log", "timeout_secs", "scratch_bytes", "scratch_files"))
    require(type(spec["schema"]) is int and spec["schema"] == 1)
    require(type(spec["invocation_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", spec["invocation_id"]))
    keys(spec["expected"], ("identity", "collection", "content_sha256", "source", "module"))
    expected = spec["expected"]
    require(type(expected["module"]) is str and len(expected["module"]) <= 256 and re.fullmatch(
        r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){2,}", expected["module"]))
    require(type(expected["content_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", expected["content_sha256"]))
    require(type(expected["source"]) is str and 0 < len(expected["source"]) <= 4096)
    destination = spec["destination"]
    whitespace = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    require(type(destination) is str and destination and not destination.startswith("-")
            and "\x00" not in destination and not any(char in whitespace for char in destination))
    absolute(spec["target_python"])
    ssh = absolute(spec["ssh_executable"])
    require(ssh.is_file() and os.access(ssh, os.X_OK))
    if spec["ssh_config"] is not None:
        require(absolute(spec["ssh_config"]).is_file())
    require(type(spec["no_log"]) is bool and type(spec["arguments"]) is dict)
    arguments(spec["arguments"])
    require(type(spec["timeout_secs"]) in (int, float) and math.isfinite(spec["timeout_secs"])
            and 0 < spec["timeout_secs"])
    require(type(spec["scratch_bytes"]) is int and 0 < spec["scratch_bytes"] <= 64 * 1024 * 1024)
    require(type(spec["scratch_files"]) is int and 0 < spec["scratch_files"] <= 4096)


def selected_runtime(spec, workspace):
    helper = workspace / "health.py"
    helper.write_text(_SSH_MCP_HEALTH_SOURCE, encoding="utf-8")
    namespace = {"__name__": "ssh_mcp_health", "__file__": str(helper)}
    exec(compile(_SSH_MCP_HEALTH_SOURCE, str(helper), "exec"), namespace)
    observed, roots = namespace["check"](spec["runtime"])
    expected = spec["expected"]
    require(observed == expected["identity"])
    import ansible
    core = Path(ansible.__file__).parent.resolve(strict=True)
    trees = [("ansible", core)]
    collection = ".".join(expected["module"].split(".")[:2])
    selected = None
    if collection != "ansible.builtin":
        namespace_name, name = collection.split(".")
        candidates = list(dict.fromkeys((root / "ansible_collections" / namespace_name / name).resolve(strict=True)
                                       for root in roots if (root / "ansible_collections" / namespace_name / name).is_dir()))
        require(len(candidates) == 1)
        manifest, raw = namespace["read_json"](candidates[0] / "MANIFEST.json", 1048576)
        info = manifest["collection_info"]
        require(info["namespace"] == namespace_name and info["name"] == name)
        selected = dict(name=collection, version=info["version"], manifest_sha256=hashlib.sha256(raw).hexdigest())
        trees.append((collection, candidates[0]))
    require(selected == expected["collection"])
    label, root = trees[-1]
    source = PurePosixPath(expected["source"])
    require(source.as_posix() == expected["source"] and not source.is_absolute()
            and all(part not in (".", "..") for part in source.parts))
    require(source.parts[0] == label)
    documented = root.joinpath(*source.parts[1:])
    module_root = root / ("modules" if collection == "ansible.builtin" else "plugins/modules")
    require(documented.suffix in (".py", ".yml", ".yaml"))
    require(documented == module_root.joinpath(*expected["module"].split(".")[2:]).with_suffix(documented.suffix))
    require(namespace["content_hash"](trees, documented) == expected["content_sha256"])
    return roots


def layout(workspace, spec, roots, selected_path):
    import yaml

    class Literal(str):
        pass

    class Dumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    Dumper.add_representer(Literal, lambda dumper, value: dumper.represent_scalar("!unsafe", value, style="'"))

    def literal(value):
        if type(value) is str:
            return Literal(value)
        if type(value) is dict:
            return {Literal(key): literal(child) for key, child in value.items()}
        if type(value) is list:
            return [literal(child) for child in value]
        return value

    def document(path, value):
        path.write_text(yaml.dump(value, Dumper=Dumper, allow_unicode=True, sort_keys=False), encoding="utf-8")

    for name in ("project", "inventory", "artifacts", "home", "tmp", "bin", "control", "env"):
        (workspace / name).mkdir(mode=0o700)
    document(workspace / "env" / "settings", {
        "pexpect_timeout": 0.1, "pexpect_use_poll": True,
        "suppress_output_file": True, "suppress_ansible_output": True,
    })
    (workspace / "control" / "owner.json").write_text(
        json.dumps({"schema": 1, "pid": os.getpid()}, separators=(",", ":")), encoding="ascii")
    project = workspace / "project"
    document(project / "arguments.yml", {"ssh_mcp_arguments": literal(spec["arguments"])})
    document(project / "playbook.yml", [{
        "name": "ssh_mcp_play", "hosts": HOST, "gather_facts": False, "become": False,
        "strategy": "linear", "vars_files": ["arguments.yml"],
        "tasks": [{"name": TASK, "no_log": spec["no_log"], "become": False,
                   spec["expected"]["module"]: {key: "{{ ssh_mcp_arguments['" + key + "'] }}"
                                                  for key in spec["arguments"]}}],
    }])
    ssh_args = (
        "-o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=yes "
        "-o UpdateHostKeys=no -o ForwardAgent=no -o ForwardX11=no "
        "-o ClearAllForwardings=yes -o PermitLocalCommand=no -o RequestTTY=no "
        "-o RemoteCommand=none -o ForkAfterAuthentication=no -o SessionType=default "
        "-o ControlMaster=no -o ControlPath=none -o ControlPersist=no"
    )
    if spec["ssh_config"] is not None:
        ssh_args += " -F " + shlex.quote(spec["ssh_config"])
    inventory = {"all": {"hosts": {HOST: literal({
        "ansible_host": spec["destination"], "ansible_connection": "ssh",
        "ansible_python_interpreter": spec["target_python"],
        "ansible_ssh_executable": spec["ssh_executable"],
        "ansible_ssh_args": ssh_args, "ansible_ssh_transfer_method": "piped",
        "ansible_ssh_use_tty": False,
        "ansible_ssh_password_mechanism": "disable",
        "ansible_become": False,
    })}}}
    document(workspace / "inventory" / "hosts.yml", inventory)
    config = workspace / "ansible.cfg"
    config.write_text("[defaults]\ncollections_scan_sys_path = False\nretry_files_enabled = False\n"
                      "fact_caching = memory\nhost_key_checking = True\ndisplay_args_to_stdout = False\n"
                      "[ssh_connection]\nssh_transfer_method = piped\n", encoding="ascii")
    # A selected uv overlay may not be on the interpreter's isolated sys.path.
    # Rebuild the public CLI's path from health-validated roots, never PYTHONPATH.
    cli = workspace / "control" / "playbook.py"
    cli.write_text(_SSH_MCP_CLI_SOURCE, encoding="utf-8")
    (workspace / "control" / "playbook_main.py").write_text(
        "import sys, runpy\nsys.path[:] = " + repr(sys.path) +
        "\nrunpy.run_module('ansible.cli.playbook', run_name='__main__')\n", encoding="utf-8")
    shim = workspace / "bin" / "ansible-playbook"
    shim.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I -B " + shlex.quote(str(cli)) + ' "$@"\n', encoding="utf-8")
    shim.chmod(0o700)
    locale = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
    environment = {
        "PATH": os.pathsep.join((str(workspace / "bin"), str(Path(spec["ssh_executable"]).parent), selected_path)),
        "HOME": str(workspace / "home"), "TMPDIR": str(workspace / "tmp"),
        "LANG": locale, "LC_ALL": locale, "PYTHONDONTWRITEBYTECODE": "1",
        "ANSIBLE_CONFIG": str(config), "ANSIBLE_HOME": str(workspace / "home" / "ansible"),
        "ANSIBLE_LOCAL_TEMP": str(workspace / "tmp" / "ansible-local"),
        "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join(str(root) for root in roots),
        "ANSIBLE_COLLECTIONS_SCAN_SYS_PATH": "False", "ANSIBLE_NOCOWS": "True",
        "ANSIBLE_RETRY_FILES_ENABLED": "False", "ANSIBLE_PIPELINING": "True",
    }
    agent = os.environ.get("SSH_AUTH_SOCK")
    if agent is not None:
        absolute(agent)
        environment["SSH_AUTH_SOCK"] = agent
    os.environ.clear()
    os.environ.update(environment)


def main():
    os.umask(0o077)
    frames = Frames()
    evidence = None
    cancellation = None
    rc = None
    complete = False
    status = "invalid_result"
    try:
        require(len(sys.argv) == 2)
        source = absolute(sys.argv[1])
        workspace = Path.cwd().resolve(strict=True)
        require(source.parent.resolve(strict=True) == workspace and not source.is_symlink())
        require(stat.S_IMODE(workspace.stat().st_mode) & 0o077 == 0)
        with source.open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        require(len(raw) <= LIMIT)
        spec = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(Invalid()))
        if type(spec) is dict and type(spec.get("invocation_id")) is str and re.fullmatch(r"[0-9a-f]{32}", spec["invocation_id"]):
            frames.id = spec["invocation_id"]
        validate(spec)
        cancellation = Cancellation(workspace, spec)
        require(absolute(os.environ.get("TMPDIR")).resolve(strict=True).is_relative_to(workspace))
        roots = selected_runtime(spec, workspace)
        selected_path = os.environ.get("PATH", "")
        require(selected_path and all(part and Path(part).is_absolute() for part in selected_path.split(os.pathsep)))
        layout(workspace, spec, roots, selected_path)
        from ansible_runner import run
        evidence = Evidence(frames, spec["expected"]["module"], spec["no_log"])
        if cancellation.requested():
            status = cancellation.reason
        else:
            frames.emit("ready")
            runner = run(private_data_dir=str(workspace), project_dir=str(workspace / "project"),
                         artifact_dir=str(workspace / "artifacts"), ident="run",
                         inventory=str(workspace / "inventory" / "hosts.yml"), playbook="playbook.yml",
                         forks=1, quiet=True, process_isolation=False, fact_cache_type="memory",
                         suppress_env_files=True, suppress_output_file=True, suppress_ansible_output=True,
                         omit_event_data=False, only_failed_event_data=False,
                         event_handler=evidence.event, status_handler=evidence.status,
                         cancel_callback=cancellation)
            require(runner.rc is None or type(runner.rc) is int and -(2**31) <= runner.rc < 2**31)
            rc = runner.rc
            cancellation.next_scan = 0
            cancellation.requested()
            if cancellation.reason is not None:
                status = cancellation.reason
            else:
                status = evidence.reconcile(runner)
                complete = True
    except BaseException:
        # Exceptions can include arguments, paths, environment or remote output.
        # They deliberately do not cross either diagnostic or protocol boundaries.
        status = cancellation.reason if cancellation is not None and cancellation.reason else "invalid_result"
    if frames.id is not None:
        frames.emit("terminal", status=status, rc=rc,
                    changed=evidence.changed if evidence is not None else None,
                    tasks=evidence.tasks if evidence is not None else dict(ok=0, failed=0, unreachable=0, skipped=0),
                    censored=evidence.censored if evidence is not None else False, complete=complete)


if __name__ == "__main__":
    main()
