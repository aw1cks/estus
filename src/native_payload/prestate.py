import hashlib
import json
import os
import stat
import subprocess
import sys


def canonical_file(path, limit=1048576):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return {"exists": False}
    except OSError:
        raise ValueError("not a regular file")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError("not a regular file")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data.extend(chunk)
        if len(data) > limit:
            raise ValueError("file exceeds prestate bound")
        return {
            "exists": True,
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "size": st.st_size,
            "mtime_ns": st.st_mtime_ns,
            "sha256": hashlib.sha256(bytes(data)).hexdigest(),
        }
    finally:
        os.close(fd)


def _resolve_bin(name):
    for path in (
        "/usr/bin/" + name,
        "/bin/" + name,
        "/usr/sbin/" + name,
        "/sbin/" + name,
        "/run/current-system/sw/bin/" + name,
    ):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise RuntimeError(name + " unavailable")


def stat_identity(path):
    st = os.stat(path)
    return {
        "dev": st.st_dev,
        "ino": st.st_ino,
        "size": st.st_size,
        "mtime_ns": st.st_mtime_ns,
    }


def valid_name(value):
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
        and not any(ch.isspace() for ch in value)
        and not value.startswith("-")
    )


def package_names(args):
    raw = args.get("name")
    if raw is None:
        raw = args.get("pkg")
    if raw is None:
        return []
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = raw
    else:
        raise ValueError("invalid package names")
    out = []
    for item in items:
        if not valid_name(item):
            raise ValueError("invalid package name")
        out.append(item)
    return sorted(set(out))


def observe_systemd(args):
    unit = args.get("name")
    if not valid_name(unit):
        raise ValueError("invalid unit")
    scope = args.get("scope", "system")
    if scope not in ("system", "user", "global"):
        raise ValueError("invalid scope")
    cmd = [_resolve_bin("systemctl")]
    if scope == "user":
        cmd.append("--user")
    elif scope == "global":
        cmd.append("--global")
    cmd.extend([
        "show",
        "--no-pager",
        "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,ExecMainStartTimestampMonotonic,FragmentPath,DropInPaths",
        "--",
        unit,
    ])
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=15)
    if proc.returncode != 0 or len(proc.stdout.encode("utf-8")) > 65536:
        raise RuntimeError("systemctl show failed")
    fragment = None
    for line in proc.stdout.splitlines():
        if line.startswith("FragmentPath="):
            value = line.split("=", 1)[1].strip()
            if value:
                fragment = canonical_file(value)
            break
    return {
        "module": "ansible.builtin.systemd_service",
        "unit": unit,
        "scope": scope,
        "show": proc.stdout,
        "fragment": fragment,
    }


def observe_sysctl(args):
    key = args.get("name")
    if not valid_name(key) or ".." in key or "/" in key:
        raise ValueError("invalid sysctl key")
    sysctl_file = args.get("sysctl_file")
    if sysctl_file is not None and (
        not isinstance(sysctl_file, str)
        or not sysctl_file.startswith("/")
        or len(sysctl_file) > 4096
        or "\x00" in sysctl_file
    ):
        raise ValueError("invalid sysctl_file")
    file_state = None if sysctl_file is None else canonical_file(sysctl_file)
    proc_path = "/proc/sys/" + key.replace(".", "/")
    try:
        fd = os.open(proc_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            data = os.read(fd, 65537)
        finally:
            os.close(fd)
        if len(data) > 65536:
            raise ValueError("proc sysctl value exceeds bound")
        proc_state = {"exists": True, "sha256": hashlib.sha256(data).hexdigest()}
    except FileNotFoundError:
        proc_state = {"exists": False}
    return {
        "module": "ansible.posix.sysctl",
        "key": key,
        "sysctl_file": sysctl_file,
        "proc_sys": proc_state,
        "file": file_state,
    }


def observe_apt(args):
    names = package_names(args)
    dpkg_status = stat_identity("/var/lib/dpkg/status")
    query_rc = None
    query_out = ""
    if names:
        proc = subprocess.run(
            [_resolve_bin("dpkg-query"), "-W", "-f=${Package}\t${db:Status-Status}\t${Version}\n", "--"] + names,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        if proc.returncode not in (0, 1) or len(proc.stdout.encode("utf-8")) > 65536:
            raise RuntimeError("dpkg-query failed")
        query_rc = proc.returncode
        query_out = proc.stdout
    return {
        "module": "estus.packages",
        "backend": "apt",
        "names": names,
        "dpkg_status": dpkg_status,
        "query_rc": query_rc,
        "query_out": query_out,
    }


def observe_dnf(args):
    names = package_names(args)
    rpmdb = None
    for candidate in ("/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"):
        if os.path.exists(candidate):
            rpmdb = stat_identity(candidate)
            break
    if rpmdb is None:
        raise RuntimeError("rpmdb unavailable")
    query_rc = None
    query_out = ""
    if names:
        proc = subprocess.run(
            [_resolve_bin("rpm"), "-q", "--qf", "%{NAME}\t%{EPOCH}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n", "--"] + names,
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        if proc.returncode < 0 or proc.returncode > len(names) or len(proc.stdout.encode("utf-8")) > 65536:
            raise RuntimeError("rpm query failed")
        query_rc = proc.returncode
        query_out = proc.stdout
    return {
        "module": "estus.packages",
        "backend": "dnf",
        "names": names,
        "rpmdb": rpmdb,
        "query_rc": query_rc,
        "query_out": query_out,
    }


def observe_apk(args):
    names = package_names(args)
    database = canonical_file("/lib/apk/db/installed", 16777216)
    if not database["exists"]:
        raise RuntimeError("apk database unavailable")
    return {"module": "estus.packages", "backend": "apk", "names": names, "database": database}


def observe_pacman(args):
    names = package_names(args)
    database = stat_identity("/var/lib/pacman/local")
    proc = subprocess.run([_resolve_bin("pacman"), "-Q", "--"] + names, capture_output=True,
                          text=True, check=False, timeout=15)
    if proc.returncode not in (0, 1) or len(proc.stdout.encode("utf-8")) > 65536:
        raise RuntimeError("pacman query failed")
    return {"module": "estus.packages", "backend": "pacman", "names": names,
            "database": database, "query_rc": proc.returncode, "query_out": proc.stdout}


def observe_packages(args):
    if os.path.exists("/lib/apk/db/installed"):
        return observe_apk(args)
    if os.path.isdir("/var/lib/pacman/local"):
        return observe_pacman(args)
    if os.path.exists("/var/lib/dpkg/status"):
        return observe_apt(args)
    for candidate in ("/usr/lib/sysimage/rpm/rpmdb.sqlite", "/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"):
        if os.path.exists(candidate):
            return observe_dnf(args)
    raise RuntimeError("no supported package database")


def observe_kernel_module(args):
    name = args.get("name")
    if (
        not isinstance(name, str)
        or not name
        or len(name) > 64
        or not all(ch.isalnum() or ch in "_-" for ch in name)
    ):
        raise ValueError("invalid module name")
    canonical_target = name.replace("-", "_")
    fd = os.open("/proc/modules", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw_modules = os.read(fd, 262145)
    finally:
        os.close(fd)
    if len(raw_modules) > 262144:
        raise ValueError("/proc/modules exceeds bound")
    matched = None
    for line in raw_modules.decode("ascii", "replace").splitlines():
        parts = line.split()
        if parts and parts[0].replace("-", "_") == canonical_target:
            matched = {"name": parts[0], "state": parts[4] if len(parts) > 4 else "unknown"}
            break
    return {
        "module": "estus.kernel_module",
        "name": canonical_target,
        "loaded": matched,
        "tainted": canonical_file("/proc/sys/kernel/tainted", 4096),
    }


def main():
    raw = sys.stdin.read(65537)
    if len(raw) > 65536:
        raise ValueError("prestate input exceeds bound")
    req = json.loads(raw)
    module = req.get("module")
    args = req.get("arguments")
    if not isinstance(args, dict):
        raise ValueError("invalid arguments")
    if module == "ansible.builtin.systemd_service":
        snapshot = observe_systemd(args)
    elif module == "ansible.posix.sysctl":
        snapshot = observe_sysctl(args)
    elif module == "ansible.builtin.apt":
        snapshot = observe_apt(args)
    elif module == "ansible.builtin.dnf":
        snapshot = observe_dnf(args)
    elif module == "estus.packages":
        snapshot = observe_packages(args)
    elif module == "estus.kernel_module":
        snapshot = observe_kernel_module(args)
    else:
        raise ValueError("unqualified module")
    encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("ascii")) > 65536:
        raise ValueError("prestate snapshot exceeds bound")
    sys.stdout.write(encoded)


if __name__ == "__main__":
    main()
