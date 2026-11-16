"""Private foreground Runner bridge with bounded summaries and declared projections."""

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


HOST = "estus_target"
TASK = "estus_module"
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


def arguments(value, depth=0, nodes=None, generic=False):
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    require(depth <= 32 and nodes[0] <= 16384)
    if type(value) is dict:
        for key, child in value.items():
            if generic:
                require(type(key) is str and "\x00" not in key and len(key.encode("utf-8")) <= 4096)
                if depth == 0:
                    require(identifier(key) and not key.startswith("ansible_") and not key.startswith("_"))
            else:
                require(identifier(key) and not key.startswith("ansible_"))
            arguments(child, depth + 1, nodes, generic)
    elif type(value) is list:
        for child in value:
            arguments(child, depth + 1, nodes, generic)
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
        raw = (json.dumps(dict(schema=2, id=self.id, kind=kind, **values),
                          ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n").encode("ascii")
        require(len(raw) <= 8192 and self.bytes + len(raw) <= 65536)
        self.bytes += len(raw)
        while raw:
            count = os.write(self.fd, raw)
            require(count > 0)
            raw = raw[count:]
        self.terminal = kind in ("terminal", "role_terminal")


class ProjectionLimit(Exception):
    pass


class ProjectionCensored(Exception):
    pass


def projection_key(key):
    return (type(key) is str and not key.startswith("_")
            and key not in ("invocation", "module_args", "args", "argv", "cmd",
                            "env", "environment", "ansible_env", "diff"))


def projection_censorship(value):
    if type(value) is dict and (value.get("_ansible_no_log") or "censored" in value):
        raise ProjectionCensored()


def projection_equal(left, right):
    # JSON equality distinguishes booleans from numbers, unlike Python equality.
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (left.keys() == right.keys()
                and all(projection_equal(value, right[key]) for key, value in left.items()))
    if type(left) is list:
        return len(left) == len(right) and all(map(projection_equal, left, right))
    return left == right


class Projection:
    """Copy only reviewed schema members; budgets account for ASCII JSON on the wire.

    No event/result is retained. Rust validates the resulting bounded candidate
    against the full schema, including conditional assertions.
    """

    def __init__(self, plan):
        self.plan = plan
        self.bytes = 0
        self.nodes = 0
        self.truncated = False

    def charge(self, size):
        if self.bytes + size > self.plan["max_bytes"]:
            raise ProjectionLimit()
        self.bytes += size

    def constraints(self, schema, value):
        if "const" in schema:
            require(projection_equal(value, schema["const"]))
        if "enum" in schema:
            require(any(projection_equal(value, choice) for choice in schema["enum"]))
        if type(value) in (str, list, dict):
            names = {str: ("minLength", "maxLength"), list: ("minItems", "maxItems"),
                     dict: ("minProperties", "maxProperties")}[type(value)]
            require(len(value) >= schema.get(names[0], 0))
            require(names[1] not in schema or len(value) <= schema[names[1]])
        if type(value) in (int, float):
            for key, valid in (("minimum", lambda limit: value >= limit),
                               ("maximum", lambda limit: value <= limit),
                               ("exclusiveMinimum", lambda limit: value > limit),
                               ("exclusiveMaximum", lambda limit: value < limit)):
                require(key not in schema or valid(schema[key]))
        if type(value) is list and schema.get("uniqueItems"):
            require(not any(projection_equal(value[i], prior)
                            for i in range(len(value)) for prior in value[:i]))

    def source_type(self, source, schema, selected_root=False):
        require(type(schema) is dict)
        kind = schema.get("type")
        valid = {
            "object": type(source) is dict,
            "array": type(source) is list,
            "string": type(source) is str,
            "integer": (type(source) is int or type(source) is float
                        and math.isfinite(source) and source.is_integer()),
            "number": type(source) in (int, float),
            "boolean": type(source) is bool,
            "null": source is None,
        }
        require(kind in valid and valid[kind])
        if type(source) in (int, float):
            require(math.isfinite(source) and abs(source) <= 9007199254740991)
        projection_censorship(source)
        if kind == "object" and not selected_root:
            properties = schema.get("properties")
            required = schema.get("required", [])
            require(type(properties) is dict and type(required) is list)
            require(all(type(key) is str and key in properties and key in source
                        for key in required))
        return kind

    def member(self, target, key, source, schema, depth, required):
        require(type(key) is str)
        # Check type/censorship even if an optional member cannot fit.
        self.source_type(source, schema)
        before = (self.bytes, self.nodes)
        try:
            self.charge(len(json.dumps(key, ensure_ascii=True)) + 1 + bool(target))
            value = self.copy(source, schema, depth)
        except ProjectionLimit:
            self.bytes, self.nodes = before
            if required:
                raise
            self.truncated = True
        else:
            target[key] = value

    def copy(self, source, schema, depth, fields=None):
        kind = self.source_type(source, schema, selected_root=fields is not None)
        if depth > self.plan["max_depth"] or self.nodes >= self.plan["max_items"]:
            raise ProjectionLimit()
        self.nodes += 1
        if kind == "object":
            self.charge(2)
            value = {}
            properties = schema["properties"]
            require(type(properties) is dict and schema.get("additionalProperties") is False)
            required = schema.get("required", [])
            require(type(required) is list and all(key in properties for key in required))
            for key in sorted(properties, key=lambda key: (key not in required, key)):
                child_schema = properties[key]
                if fields is None:
                    require(projection_key(key))
                    child = source.get(key)
                    present = key in source
                else:
                    child = source
                    present = True
                    path = fields[key]
                    require(type(path) is list and 1 <= len(path) <= 8)
                    for segment in path:
                        require(projection_key(segment))
                        require(type(child) is dict)
                        projection_censorship(child)
                        if segment not in child:
                            present = False
                            break
                        child = child[segment]
                if not present:
                    require(key not in required)
                    continue
                self.member(value, key, child, child_schema, depth + 1, key in required)
        elif kind == "array":
            self.charge(2)
            value = []
            maximum = schema["maxItems"]
            require(type(maximum) is int and maximum >= 0)
            for index in range(min(len(source), maximum)):
                before = (self.bytes, self.nodes)
                try:
                    self.charge(bool(value))
                    child = self.copy(source[index], schema["items"], depth + 1)
                except ProjectionLimit:
                    self.bytes, self.nodes = before
                    break
                value.append(child)
            if len(value) < len(source):
                self.truncated = True
        elif kind == "string":
            self.charge(2)
            characters = []
            maximum = schema["maxLength"]
            require(type(maximum) is int and maximum >= 0)
            for char in source:
                require(not 0xD800 <= ord(char) <= 0xDFFF)
                if len(characters) >= maximum:
                    break
                size = len(json.dumps(char, ensure_ascii=True)) - 2
                if self.bytes + size > self.plan["max_bytes"]:
                    break
                self.charge(size)
                characters.append(char)
            value = "".join(characters)
            if len(value) < len(source):
                self.truncated = True
        else:
            # Only a bounded scalar, never an unbounded result/container, is serialized.
            size = len(json.dumps(source, ensure_ascii=True, allow_nan=False,
                                  separators=(",", ":")))
            # Both encoders use shortest binary64 decimals. Pinned zmij 1.0.23
            # uses fixed exponents -5..15, while Python uses -4..15:
            # 1e-05 can therefore grow by two bytes to 0.00001 in Rust.
            # Reserve this allowance for floats only; Rust checks actual bytes.
            self.charge(size + (2 if type(source) is float else 0))
            value = source
        self.constraints(schema, value)
        return value

    def reduce(self, result, censored):
        try:
            if censored:
                raise ProjectionCensored()
            projection_censorship(result)
            if result == {}:
                return dict(status="unavailable")
            keys(self.plan, ("fields", "schema", "max_bytes", "max_items", "max_depth"))
            for name, minimum, maximum in (("max_bytes", 64, 4096), ("max_items", 1, 256),
                                            ("max_depth", 1, 8)):
                require(type(self.plan[name]) is int and minimum <= self.plan[name] <= maximum)
            fields = self.plan["fields"]
            require(type(fields) is dict and 1 <= len(fields) <= 16)
            require(all(type(key) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key)
                        for key in fields))
            require(type(self.plan["schema"]) is dict
                    and self.plan["schema"].get("type") == "object"
                    and set(fields) == set(self.plan["schema"]["properties"]))
            value = self.copy(result, self.plan["schema"], 0, fields)
            return dict(status="truncated" if self.truncated else "complete", value=value)
        except ProjectionCensored:
            return dict(status="censored")
        except Exception:
            # Projection policy/copy failures never invalidate execution evidence.
            return dict(status="invalid")


def module_result(result, censored, policy):
    """Explicit secret-bearing JSON disclosure, without invocation/internal data."""
    if censored:
        return dict(status="censored")
    nodes = [0]

    def copy(value, depth=0):
        nodes[0] += 1
        if depth > policy["max_depth"] or nodes[0] > policy["max_items"]:
            raise ProjectionLimit()
        projection_censorship(value)
        if type(value) is dict:
            return {key: copy(child, depth + 1) for key, child in value.items()
                    if projection_key(key)}
        if type(value) is list:
            return [copy(child, depth + 1) for child in value]
        require(value is None or type(value) in (str, int, float, bool))
        if type(value) in (int, float):
            require(math.isfinite(value) and abs(value) <= 9007199254740991)
        return value

    try:
        value = copy(result)
        text = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if len(text.encode("ascii")) > policy["max_bytes"]:
            raise ProjectionLimit()
        return dict(status="complete", value={"module_result_json": text})
    except ProjectionCensored:
        return dict(status="censored")
    except ProjectionLimit:
        return dict(status="truncated", value={"module_result_json": "{}"})
    except Exception:
        return dict(status="invalid")


class Evidence:
    def __init__(self, frames, module, no_log, projection=None, disclosure=None):
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
        self.projection = projection
        self.disclosure = disclosure

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
            if self.projection is not None:
                selected = (module_result(result, self.censored, self.disclosure)
                            if self.disclosure is not None and self.disclosure.get("kind") == "module_result"
                            else Projection(self.projection).reduce(result, self.censored))
                self.frames.emit("projection", projection=selected)
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
                # Core's changed stats can omit a failed task's observed mutation.
                require(observed["changed"] <= int(self.changed))
                require(self.outcome == "failed" or observed["changed"] == int(self.changed))
            require(not observed["changed"] or self.outcome in ("ok", "failed"))
            if self.censored:
                self.changed = None
            elif self.changed is None and self.outcome in ("ok", "skipped"):
                self.changed = bool(observed["changed"])
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
        if self.outcome in ("ok", "skipped"):
            require(runner.status == "successful" and rc == 0)
            return "successful"
        if self.outcome == "unreachable":
            require(runner.status == "failed" and rc == 4)
            return "unreachable"
        require(self.outcome == "failed" and runner.status == "failed" and rc == 2)
        return "failed"


class RoleEvidence(Evidence):
    """Bounded root observations, reconciled against Core's authoritative stats."""

    def __init__(self, frames, no_log, projection, playbook):
        super().__init__(frames, None, no_log, projection)
        self.starts = []
        self.results = set()
        self.active = None
        self.observations = 0
        self.event_ids = set()
        self.pending_include = None
        self.include_completed = 0
        self.raw = dict(ok=0, failed=0, unreachable=0, skipped=0)
        self.tasks.update(rescued=0, ignored=0)
        self.ignored = 0
        self.include_ok = 0
        self.meta_skipped = 0
        self.playbook = str(playbook)
        self.collected = False
        self.change_unknown = False

    def consume(self, event):
        require(not self.invalid)
        require(type(event) is dict and type(event.get("event")) is str)
        kind = event["event"]
        data = event.get("event_data", {})
        require(type(data) is dict)
        if "host" in data:
            require(data["host"] == HOST)
        relevant = (kind in ("playbook_on_task_start", "playbook_on_handler_task_start", "playbook_on_stats")
                    or kind.startswith("runner_") or kind == "playbook_on_include")
        if relevant:
            require(self.stats is None)
        if kind in ("playbook_on_task_start", "playbook_on_handler_task_start"):
            require(len(self.starts) < 256)
            if self.active is not None and self.active not in self.results:
                require(self.starts[self.active][1] in ("meta", "ansible.builtin.meta", "ansible.legacy.meta"))
            uuid = data.get("task_uuid")
            require(type(uuid) is str and 0 < len(uuid) <= 128)
            action = data.get("task_action")
            require(type(action) is str and 0 < len(action) <= 256)
            # Meta controls generate starts but usually no root result.
            self.starts.append((uuid, action))
            self.active = len(self.starts) - 1
            self.pending_include = None
        elif kind in ("runner_on_ok", "runner_on_failed", "runner_on_unreachable", "runner_on_skipped"):
            uuid = data.get("task_uuid")
            require(data.get("host") == HOST and self.active is not None
                    and uuid == self.starts[self.active][0])
            action = self.starts[self.active][1]
            # A successfully executed include first emits OK, then loading can
            # emit a failed result for that same occurrence in linear strategy.
            require(self.active not in self.results or
                    (self.pending_include == self.active and kind == "runner_on_failed"))
            self.observe(event)
            require(data.get("task_action") == action)
            result = data.get("res", {})
            require(type(result) is dict and not any(
                key in result for key in ("ansible_job_id", "results_file", "started", "finished")))
            outcome = kind.removeprefix("runner_on_")
            ignored = data.get("ignore_errors", False)
            require(type(ignored) is bool and (not ignored or outcome == "failed"))
            changed = result.get("changed")
            require(changed is None or type(changed) is bool)
            # A failed task's false bit is not evidence that it made no changes:
            # Core's stats exclude failed-task changes. Preserve true, otherwise
            # retain uncertainty through stats, rescue and ignored failures.
            if outcome == "failed" and changed is not True:
                changed = None
                self.change_unknown = True
            # Runner replaces no_log root/item results with {"censored": ...}.
            pending = [result]
            nodes = 0
            while pending:
                value = pending.pop()
                nodes += 1
                require(nodes <= 16384)
                if type(value) is dict:
                    require(not any(key in value for key in (
                        "ansible_job_id", "results_file", "started", "finished")))
                    self.censored = self.censored or bool(value.get("_ansible_no_log")) or "censored" in value
                    children = value.get("results", [])
                    require(type(children) is list)
                    require(len(pending) + len(children) <= 16384)
                    pending.extend(children)
            if self.censored:
                self.changed = None
            elif changed is True:
                self.changed = True
            self.results.add(self.active)
            self.raw[outcome] += 1
            self.ignored += int(ignored)
            short = action.removeprefix("ansible.builtin.").removeprefix("ansible.legacy.")
            if outcome == "ok" and short in ("include_role", "include_tasks"):
                self.include_ok += 1
                self.pending_include = self.active
            if outcome == "skipped" and short == "meta":
                self.meta_skipped += 1
            self.tasks.update(self.raw)
            self.tasks["failed"] -= self.ignored
            self.tasks["ok"] += self.ignored - self.include_ok + self.include_completed
            self.tasks["skipped"] -= self.meta_skipped
            self.tasks["ignored"] = self.ignored
            # Initial include OK is deferred: linear strategy counts successful
            # loads at playbook_on_include, potentially once per loop inclusion.
            # Skipped meta controls never contribute to Core's skipped count.
            counted = not ((outcome == "ok" and short in ("include_role", "include_tasks"))
                           or (outcome == "skipped" and short == "meta"))
            if counted:
                self.frames.emit("role_task", outcome=outcome,
                                 changed=None if self.censored else changed,
                                 censored=self.censored, ignored=ignored)
            collector = (data.get("task") == "estus_result" and short == "debug"
                         and data.get("task_path", "").rsplit(":", 1)[0] == self.playbook)
            if collector:
                require(self.projection is not None and not self.collected)
                self.collected = True
                selected = dict(status="invalid")
                envelope = result.get("msg")
                if self.censored:
                    selected = dict(status="censored")
                elif (outcome == "ok" and type(envelope) is dict
                      and set(envelope) == {"present", "value"} and type(envelope["present"]) is bool):
                    if not envelope["present"]:
                        selected = dict(status="unavailable")
                    elif type(envelope["value"]) is dict:
                        selected = Projection(self.projection).reduce(
                            {"mcp_result": envelope["value"]}, False)
                self.frames.emit("projection", projection=selected)
        elif kind == "playbook_on_include":
            require(self.active is not None and self.pending_include == self.active
                    and self.active in self.results)
            require(data.get("task_uuid") == self.starts[self.active][0])
            self.observe(event)
            self.include_completed += 1
            self.tasks["ok"] += 1
            self.frames.emit("role_task", outcome="ok", changed=None if self.censored else False,
                             censored=self.censored, ignored=False)
        elif kind == "playbook_on_stats":
            require(self.results)
            observed = {}
            if self.active not in self.results:
                require(self.active is not None and self.starts[self.active][1] in (
                    "meta", "ansible.builtin.meta", "ansible.legacy.meta"))
            for name in ("ok", "failures", "dark", "skipped", "changed", "processed", "rescued", "ignored"):
                counts = data.get(name)
                require(type(counts) is dict and set(counts).issubset({HOST}))
                require(all(type(value) is int and 0 <= value <= 128 for value in counts.values()))
                observed[name] = counts.get(HOST, 0)
            require(observed["processed"] == 1 or
                    (observed["processed"] == 0 and not any(
                        observed[name] for name in observed if name != "processed")))
            require(self.raw["failed"] == observed["failures"] + observed["rescued"] + observed["ignored"])
            require(self.ignored == observed["ignored"])
            require(self.raw["ok"] - self.include_ok + self.include_completed + self.ignored == observed["ok"])
            require(self.raw["unreachable"] == observed["dark"])
            require(self.raw["skipped"] - self.meta_skipped == observed["skipped"])
            require(observed["changed"] <= observed["ok"])
            if not self.censored and self.changed is not True:
                self.changed = (True if observed["changed"] else
                                None if self.change_unknown else False)
            self.tasks = dict(ok=observed["ok"], failed=observed["failures"],
                              unreachable=observed["dark"], skipped=observed["skipped"],
                              rescued=observed["rescued"], ignored=observed["ignored"])
            self.stats = observed
        elif kind.startswith("runner_on_async") or kind in ("playbook_on_no_hosts_matched",):
            raise Invalid()
        elif kind.startswith("runner_") and kind not in (
                "runner_on_start", "runner_item_on_ok", "runner_item_on_failed",
                "runner_item_on_skipped", "runner_on_file_diff", "runner_retry"):
            raise Invalid()

    def observe(self, event):
        """Bound root/completion observations and reject replayed result events."""
        event_id = event.get("uuid")
        require(type(event_id) is str and 0 < len(event_id) <= 128
                and event_id not in self.event_ids and self.observations < 128)
        self.event_ids.add(event_id)
        self.observations += 1

    def reconcile(self, runner):
        require(not self.invalid and self.stats is not None)
        require(self.statuses == ["starting", "running", runner.status])
        if self.tasks["unreachable"]:
            require(runner.status == "failed" and runner.rc == 4)
            return "unreachable"
        if self.tasks["failed"]:
            require(runner.status == "failed" and runner.rc == 2)
            return "failed"
        require(runner.status == "successful" and runner.rc == 0)
        return "successful"


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
        def visit(fd, depth, temporary=False):
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
                            visit(child, depth + 1, temporary or (depth == 0 and entry.name == "tmp"))
                        finally:
                            os.close(child)
                    elif depth == 0 and entry.name == "runner.lease":
                        require(stat.S_ISFIFO(info.st_mode) and info.st_uid == os.getuid()
                                and stat.S_IMODE(info.st_mode) == 0o600)
                    elif temporary and stat.S_ISSOCK(info.st_mode):
                        # Python multiprocessing IPC stays inside private TMPDIR.
                        require(info.st_uid == os.getuid())
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
                "ssh_config", "ssh_executable", "become", "agent", "arguments", "no_log",
                "timeout_secs", "scratch_bytes", "scratch_files", "projection"))
    require(type(spec["schema"]) is int and spec["schema"] == 2)
    require(type(spec["invocation_id"]) is str and re.fullmatch(r"[0-9a-f]{32}", spec["invocation_id"]))
    expected = spec["expected"]
    if expected.get("generic") is True:
        keys(expected, ("generic", "module", "identity", "content_sha256", "generation",
                        "policy_generation", "disclosure"))
        require(type(expected["module"]) is str and len(expected["module"]) <= 256 and re.fullmatch(
            r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){2,}", expected["module"]))
        require(all(type(expected[key]) is str and re.fullmatch(r"[0-9a-f]{64}", expected[key])
                    for key in ("generation", "policy_generation")))
    elif "playbook" in expected:
        keys(expected, ("identity", "content_sha256", "playbook", "project_root"))
        # The content verifier owns canonical entry syntax before any dispatch.
        require(type(expected["playbook"]) is str
                and 0 < len(expected["playbook"].encode("utf-8")) <= 4096)
        absolute(expected["project_root"])
    elif "role" in expected:
        keys(expected, ("identity", "collection", "content_sha256", "role", "entry_point",
                        "role_path", "bundle_root"))
        require(type(expected["role"]) is str and re.fullmatch(
            r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){0,2}", expected["role"])
                and len(expected["role"].split(".")) in (1, 3))
        require(type(expected["entry_point"]) is str and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]{0,127}", expected["entry_point"]))
        if expected["role_path"] is not None:
            absolute(expected["role_path"])
            absolute(expected["bundle_root"])
        else:
            require(expected["bundle_root"] is None)
    else:
        keys(expected, ("identity", "collection", "content_sha256", "source", "module"))
        require(type(expected["module"]) is str and len(expected["module"]) <= 256 and re.fullmatch(
            r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){2,}", expected["module"]))
        require(type(expected["source"]) is str and 0 < len(expected["source"]) <= 4096)
    require(type(expected["content_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", expected["content_sha256"]))
    destination = spec["destination"]
    whitespace = "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    require(type(destination) is str and destination and not destination.startswith("-")
            and "\x00" not in destination and not any(char in whitespace for char in destination))
    absolute(spec["target_python"])
    ssh = absolute(spec["ssh_executable"])
    require(ssh.is_file() and os.access(ssh, os.X_OK))
    if spec["ssh_config"] is not None:
        require(absolute(spec["ssh_config"]).is_file())
    become = spec["become"]
    if become is not None:
        keys(become, ("method", "user"))
        require(become["method"] == "sudo" and type(become["user"]) is str
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", become["user"]) is not None)
    agent = spec["agent"]
    require(type(agent) is dict)
    if agent.get("mode") == "fixed":
        keys(agent, ("mode", "socket"))
        absolute(agent["socket"])
    else:
        keys(agent, ("mode",))
        require(agent["mode"] in ("inherit", "disabled"))
    require(type(spec["no_log"]) is bool and type(spec["arguments"]) is dict)
    arguments(spec["arguments"], generic=expected.get("generic") is True)
    require(type(spec["timeout_secs"]) in (int, float) and math.isfinite(spec["timeout_secs"])
            and 0 < spec["timeout_secs"])
    require(type(spec["scratch_bytes"]) is int and 0 < spec["scratch_bytes"] <= 64 * 1024 * 1024)
    require(type(spec["scratch_files"]) is int and 0 < spec["scratch_files"] <= 4096)


def selected_runtime(spec, workspace):
    helper = workspace / "health.py"
    helper.write_text(_ESTUS_HEALTH_SOURCE, encoding="utf-8")
    namespace = {"__name__": "estus_health", "__file__": str(helper)}
    exec(compile(_ESTUS_HEALTH_SOURCE, str(helper), "exec"), namespace)
    observed, roots = namespace["check"](
        spec["runtime"], role_request=any(key in spec["expected"] for key in ("role", "playbook")))
    expected = spec["expected"]
    require(observed == expected["identity"])
    if expected.get("generic") is True:
        inventory = namespace["generic_inventory"](roots)
        require(inventory["content_sha256"] == expected["content_sha256"]
                and expected["module"] in inventory["modules"])
        return roots
    if "playbook" in expected:
        directory, content = namespace["playbook_content"](
            expected["playbook"], expected["project_root"], roots)
        require(content == expected["content_sha256"])
        expected["project_root"] = str(directory)
        return roots
    if "role" in expected:
        directory, _, _, content, collection, _ = namespace["role_content"](
            expected["role"], expected["entry_point"], expected["role_path"], roots)
        require(content == expected["content_sha256"] and collection == expected["collection"])
        if expected["bundle_root"] is not None:
            root = absolute(expected["bundle_root"]).resolve(strict=True)
            require(directory.parent == root)
            expected["bundle_root"] = str(root)
        if expected["role_path"] is not None:
            # Use the exact verified parent, not a lexical path that Ansible
            # could expand or split differently from the content verifier.
            expected["role_path"] = str(directory)
        return roots
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

    class Literal(dict):
        pass

    class Dumper(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    # Core resolves !unsafe scalars implicitly, even if quoted: "" becomes
    # None and "false"/"0" become booleans/integers. Tag the containing mapping
    # instead so ordinary YAML scalar tags preserve types before recursive
    # unsafe wrapping prevents templating at every depth.
    Dumper.add_representer(Literal, lambda dumper, value: dumper.represent_mapping("!unsafe", value))

    def literal(value):
        require(type(value) is dict)
        return Literal(value)

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
    expected = spec["expected"]
    role = "role" in expected
    playbook = "playbook" in expected
    become = spec["become"] is not None
    if playbook:
        tasks = []
    elif role:
        tasks = [{"name": "estus_role", "no_log": spec["no_log"],
                  "ansible.builtin.include_role": {
                      "name": expected["role"], "tasks_from": expected["entry_point"],
                      "public": False, "apply": {"no_log": spec["no_log"], "become": become}},
                  "vars": {key: "{{ estus_arguments['" + key + "'] }}"
                           for key in spec["arguments"]}}]
    else:
        tasks = [{"name": TASK, "no_log": spec["no_log"], "become": become,
                  expected["module"]: {key: "{{ estus_arguments['" + key + "'] }}"
                                       for key in spec["arguments"]}}]
    play = {"name": "estus_play", "hosts": HOST, "gather_facts": False, "become": become,
            "strategy": "linear", "vars_files": ["arguments.yml"], "tasks": tasks}
    if (role or playbook) and spec["projection"] is not None:
        # post_tasks run after ordinary role handlers, so their censorship is
        # known before the only domain-bearing result can leave this process.
        play["post_tasks"] = [{"name": "estus_result", "no_log": spec["no_log"],
                               "ansible.builtin.debug": {"msg": {
                                   "present": "{{ mcp_result is defined }}",
                                   "value": "{{ mcp_result | default(none) }}"}}}]
    if playbook:
        imported = Path(expected["project_root"]) / expected["playbook"]
        plays = [{"name": "estus_import", "ansible.builtin.import_playbook": str(imported)}]
        if spec["projection"] is not None:
            plays.append(play)
        document(project / "playbook.yml", plays)
    else:
        document(project / "playbook.yml", [play])
    ssh_args = (
        "-o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=yes "
        "-o UpdateHostKeys=no -o ForwardAgent=no -o ForwardX11=no "
        "-o ClearAllForwardings=yes -o PermitLocalCommand=no -o RequestTTY=no "
        "-o RemoteCommand=none -o ForkAfterAuthentication=no -o SessionType=default "
        "-o ControlMaster=no -o ControlPath=none -o ControlPersist=no"
    )
    if spec["ssh_config"] is not None:
        ssh_args += " -F " + shlex.quote(spec["ssh_config"])
    transport = {
        "ansible_host": spec["destination"], "ansible_connection": "ssh",
        "ansible_python_interpreter": spec["target_python"],
        "ansible_ssh_executable": spec["ssh_executable"],
        "ansible_ssh_args": ssh_args, "ansible_ssh_transfer_method": "piped",
        "ansible_ssh_use_tty": False,
        "ansible_ssh_password_mechanism": "disable",
        "ansible_become": become,
    }
    if become:
        # The sudo plugin's aliases can override the generic become variables.
        # Fix both public forms; never provide a password or sudo's stdin flag.
        transport.update({
            "ansible_become_method": "ansible.builtin.sudo",
            "ansible_become_user": spec["become"]["user"],
            "ansible_become_exe": "/usr/bin/sudo",
            "ansible_become_flags": "-H -n -k",
            "ansible_sudo_user": spec["become"]["user"],
            "ansible_sudo_exe": "/usr/bin/sudo",
            "ansible_sudo_flags": "-H -n -k",
            # A truthy password option makes Core remove -n and enable prompts.
            "ansible_become_password": "",
            "ansible_become_pass": "",
            "ansible_sudo_pass": "",
        })
    inventory = {"all": {"hosts": {HOST: literal(transport)}}}
    document(workspace / "inventory" / "hosts.yml", inventory)
    # Every execution mode uses this generated, high-precedence transport.
    # Caller literals stay nested and role argument variables stay task-scoped.
    controls = dict(inventory["all"]["hosts"][HOST])
    controls["estus_arguments"] = spec["arguments"]
    document(project / "arguments.yml", literal(controls))
    config = workspace / "ansible.cfg"
    config.write_text("[defaults]\ncollections_scan_sys_path = False\nretry_files_enabled = False\n"
                      "fact_caching = memory\nhost_key_checking = True\ndisplay_args_to_stdout = False\n"
                      "[ssh_connection]\nssh_transfer_method = piped\n", encoding="ascii")
    # A selected uv overlay may not be on the interpreter's isolated sys.path.
    # Rebuild the public CLI's path from health-validated roots, never PYTHONPATH.
    cli = workspace / "control" / "playbook.py"
    cli.write_text(_ESTUS_CLI_SOURCE, encoding="utf-8")
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
    if playbook:
        root = Path(expected["project_root"])
        environment.update({
            "ANSIBLE_STRATEGY": "linear",
            "ANSIBLE_NO_LOG": "True" if spec["no_log"] else "False",
            "ANSIBLE_ROLES_PATH": str(root / "roles"),
            "ANSIBLE_LIBRARY": str(root / "library"),
            "ANSIBLE_MODULE_UTILS": str(root / "module_utils"),
            "ANSIBLE_COLLECTIONS_PATH": os.pathsep.join(
                (str(root / "collections"), *(str(path) for path in roots))),
        })
        for kind in ("action", "become", "cache", "callback", "cliconf", "connection",
                     "filter", "httpapi", "inventory", "lookup", "netconf", "shell",
                     "strategy", "terminal", "test", "vars"):
            environment["ANSIBLE_" + kind.upper() + "_PLUGINS"] = str(root / (kind + "_plugins"))
    if role:
        # This is the entire root hashed under the reviewed v2 content contract,
        # never the original authoring source or an ambient/default role path.
        environment["ANSIBLE_ROLES_PATH"] = (
            expected["bundle_root"] if expected["bundle_root"] is not None
            else str(workspace / "no-roles"))
    agent = spec["agent"]
    socket = (os.environ.get("SSH_AUTH_SOCK") if agent["mode"] == "inherit"
              else agent["socket"] if agent["mode"] == "fixed" else None)
    if socket is not None:
        absolute(socket)
        environment["SSH_AUTH_SOCK"] = socket
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
        evidence = (RoleEvidence(frames, spec["no_log"], spec["projection"],
                                 workspace / "project" / "playbook.yml")
                    if any(key in spec["expected"] for key in ("role", "playbook")) else
                    Evidence(frames, spec["expected"]["module"], spec["no_log"], spec["projection"],
                             spec["expected"].get("disclosure")))
        if cancellation.requested():
            status = cancellation.reason
        else:
            frames.emit("ready")
            runner = run(private_data_dir=str(workspace), project_dir=str(workspace / "project"),
                         artifact_dir=str(workspace / "artifacts"), ident="run",
                         inventory=str(workspace / "inventory" / "hosts.yml"), playbook="playbook.yml",
                         limit=HOST,
                         cmdline="--extra-vars " + shlex.quote(
                             "@" + str(workspace / "project" / "arguments.yml")),
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
        role = (type(spec) is dict and type(spec.get("expected")) is dict
                and any(key in spec["expected"] for key in ("role", "playbook")))
        empty = dict(ok=0, failed=0, unreachable=0, skipped=0)
        if role:
            empty.update(rescued=0, ignored=0)
        frames.emit("role_terminal" if role else "terminal", status=status, rc=rc,
                    changed=evidence.changed if evidence is not None else None,
                    tasks=evidence.tasks if evidence is not None else empty,
                    censored=evidence.censored if evidence is not None else False, complete=complete)


if __name__ == "__main__":
    main()
