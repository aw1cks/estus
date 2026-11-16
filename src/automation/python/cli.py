"""Private public-CLI child owner; FIFO EOF proves this owner has exited."""

import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time


def require(condition):
    if not condition:
        raise ValueError()


def owner_pid(control):
    fd = os.open(control / "owner.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600)
        raw = stream.read(1025)
    require(len(raw) <= 1024)
    value = json.loads(raw)
    require(type(value) is dict and set(value) == {"schema", "pid"}
            and type(value["schema"]) is int and value["schema"] == 1
            and type(value["pid"]) is int and value["pid"] > 1)
    return value["pid"]


def write_byte(fd, value):
    require(os.write(fd, value) == 1)


def stop(child):
    """Retain the Popen handle until the direct child is reaped; never guess PIDs."""
    if child.poll() is not None:
        return False
    child.terminate()
    try:
        child.wait(timeout=1.0)
        return False
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()
        return True


def main():
    os.umask(0o077)
    lease = None
    registered = False
    child = None
    forced = False
    result = 1
    interrupted = False

    def request_stop(signum, frame):
        nonlocal interrupted
        interrupted = True

    try:
        control = Path(__file__).absolute().parent
        require(control.name == "control")
        workspace = control.parent
        expected_parent = owner_pid(control)
        require(os.getppid() == expected_parent)
        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(signum, request_stop)
        lease = os.open(workspace / "runner.lease", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        metadata = os.fstat(lease)
        require(stat.S_ISFIFO(metadata.st_mode) and metadata.st_uid == os.getuid()
                and stat.S_IMODE(metadata.st_mode) == 0o600)
        os.set_inheritable(lease, False)
        write_byte(lease, b"R")
        registered = True
        # Registration precedes every possible Core spawn. Only this wrapper owns
        # the lease writer, and no Core child inherits it through Popen.
        if not interrupted and os.getppid() == expected_parent and not (control / "cancel").exists():
            child = subprocess.Popen(
                [sys.executable, "-I", "-B", str(control / "playbook_main.py"), *sys.argv[1:]],
                close_fds=True,
            )
            while child.poll() is None:
                if interrupted or os.getppid() != expected_parent or (control / "cancel").exists():
                    forced = stop(child)
                    break
                time.sleep(0.01)
            result = child.wait()
        else:
            result = 143
    except BaseException:
        # No exception text: CLI exceptions may carry arguments or remote output.
        forced = True
    finally:
        if child is not None:
            try:
                forced = stop(child) or forced
                result = child.wait()
            except BaseException:
                forced = True
                # Keep ownership through a final public Popen kill/wait attempt.
                try:
                    child.kill()
                    child.wait()
                except BaseException:
                    pass
        if registered:
            try:
                write_byte(lease, b"F" if forced else b"C")
            except BaseException:
                forced = True
        if forced:
            result = 1
        elif type(result) is not int:
            result = 1
        elif result < 0:
            result = min(255, 128 - result)
        elif result > 255:
            result = 1
        # Never explicitly close the lease: EOF is kernel exit evidence, not an
        # in-process claim made while this wrapper could still own the child.
        os._exit(result)


if __name__ == "__main__":
    main()
