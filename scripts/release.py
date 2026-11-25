#!/usr/bin/env python3
"""Build, check and smoke-test the release artifacts.

The same commands run on a developer machine and in CI (inside `nix develop
.#release`), so a release is never the first time any of this runs.

    release.py binaries [--out DIR] [--target T ...]   tarballs: bin/estus + catalog
    release.py wheels   [--out DIR] [--target T ...]   py3-none-<platform> wheels
    release.py sdist    [--out DIR]                    source distribution
    release.py checksums DIR                           write DIR/SHA256SUMS
    release.py sbom     [--out DIR] [--target T ...]   CycloneDX SBOM per release target
    release.py sbom-subjects DIR --out DIR [--expect T ...]
                                                       per-target checksums of what each SBOM describes
    release.py smoke DIR [--mode docker|native]        install and run what was built

Linux artifacts are cross-built with cargo-zigbuild: a glibc build with a 2.34
floor and a fully static musl build, for x86_64 and aarch64. macOS builds natively.
"""

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import shlex
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent

# Linux targets. `zig` is the target as cargo-zigbuild spells it: the suffix after
# the triple pins the glibc version the binary may require.
GLIBC_FLOOR = (2, 34)
LINUX_TARGETS = {
    "x86_64-unknown-linux-gnu": {
        "zig": "x86_64-unknown-linux-gnu.2.34",
        "arch": "x86_64",
        "docker": "linux/amd64",
        "static": False,
    },
    "aarch64-unknown-linux-gnu": {
        "zig": "aarch64-unknown-linux-gnu.2.34",
        "arch": "aarch64",
        "docker": "linux/arm64",
        "static": False,
    },
    "x86_64-unknown-linux-musl": {
        "zig": "x86_64-unknown-linux-musl",
        "arch": "x86_64",
        "docker": "linux/amd64",
        "static": True,
    },
    "aarch64-unknown-linux-musl": {
        "zig": "aarch64-unknown-linux-musl",
        "arch": "aarch64",
        "docker": "linux/arm64",
        "static": True,
    },
}
DARWIN_TARGETS = {"aarch64-apple-darwin": {"arch": "arm64"}}
# The macOS version the wheel tag (macosx_11_0_arm64) promises: the first release
# for Apple silicon. Binaries are built for it and checked against it.
DARWIN_MIN_OS = (11, 0)
# Every target a release ships, in the order the release lists them.
RELEASE_TARGETS = [*LINUX_TARGETS, *DARWIN_TARGETS]

# Wheel platform tags per Linux target. A glibc wheel needs glibc 2.34. The
# static wheel has no libc dependency, so it claims both musl and the oldest
# glibc baseline, which lets pip on RHEL 8 or Ubuntu 20.04 install it too; pip
# prefers the glibc wheel wherever that one is installable.
WHEEL_TAGS = {
    "x86_64-unknown-linux-gnu": ("manylinux_2_34_x86_64", None),
    "aarch64-unknown-linux-gnu": ("manylinux_2_34_aarch64", None),
    "x86_64-unknown-linux-musl": (
        "musllinux_1_2_x86_64",
        "manylinux2014_x86_64.musllinux_1_2_x86_64",
    ),
    "aarch64-unknown-linux-musl": (
        "musllinux_1_2_aarch64",
        "manylinux2014_aarch64.musllinux_1_2_aarch64",
    ),
}


def log(message):
    print(f"==> {message}", flush=True)


def fail(message) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run(command, **kwargs):
    log(" ".join(str(part) for part in command))
    subprocess.run([str(part) for part in command], check=True, **kwargs)


def version():
    """The package version, read the way release-please rewrites it."""
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
    if not match:
        fail("cannot find the version in Cargo.toml")
    return match.group(1)


def host_targets():
    if sys.platform == "darwin":
        return list(DARWIN_TARGETS)
    return list(LINUX_TARGETS)


def require_tool(name):
    path = shutil.which(name)
    if path is None:
        fail(f"{name} is not on PATH; run this inside `nix develop .#release`")
    return path


# ---------------------------------------------------------------------------
# ELF inspection: what a Linux binary needs from the system it runs on.
# ---------------------------------------------------------------------------

PT_LOAD, PT_DYNAMIC, PT_INTERP = 1, 2, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_VERNEED, DT_VERNEEDNUM = 0, 1, 5, 0x6FFFFFFE, 0x6FFFFFFF


def inspect_elf(path):
    """Return (interpreter, needed libraries, glibc symbol versions) of an ELF64 file."""
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        fail(f"{path} is not a little-endian ELF64 file")
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    loads, interp, dynamic = [], None, None
    for index in range(phnum):
        base = phoff + index * phentsize
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = struct.unpack_from(
            "<IIQQQQQQ", data, base
        )
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_INTERP:
            interp = data[p_offset : p_offset + p_filesz].split(b"\0", 1)[0].decode()
        elif p_type == PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)

    def offset_of(vaddr):
        for start, file_offset, size in loads:
            if start <= vaddr < start + size:
                return file_offset + (vaddr - start)
        fail(f"{path}: address {vaddr:#x} is not in a loadable segment")

    def cstring(offset):
        return data[offset : data.index(b"\0", offset)].decode()

    needed, glibc = [], []
    if dynamic is not None:
        entries, strtab, verneed, verneed_count = [], None, None, 0
        offset, size = dynamic
        for position in range(offset, offset + size, 16):
            tag, value = struct.unpack_from("<qQ", data, position)
            if tag == DT_NULL:
                break
            if tag == DT_NEEDED:
                entries.append(value)
            elif tag == DT_STRTAB:
                strtab = offset_of(value)
            elif tag == DT_VERNEED:
                verneed = offset_of(value)
            elif tag == DT_VERNEEDNUM:
                verneed_count = value
        if strtab is not None:
            needed = [cstring(strtab + name) for name in entries]
            cursor = verneed
            if cursor is not None:
                for _ in range(verneed_count):
                    _version, count, _file, aux, nxt = struct.unpack_from("<HHIII", data, cursor)
                    aux_cursor = cursor + aux
                    for _ in range(count):
                        _hash, _flags, _other, name, aux_next = struct.unpack_from("<IHHII", data, aux_cursor)
                        text = cstring(strtab + name)
                        if text.startswith("GLIBC_"):
                            glibc.append(tuple(int(part) for part in text[6:].split(".")))
                        aux_cursor += aux_next
                    cursor += nxt
    return interp, needed, glibc


def check_linux_binary(path, target):
    """Fail unless the binary honours its target's promise about the host libc."""
    interp, needed, glibc = inspect_elf(path)
    if LINUX_TARGETS[target]["static"]:
        if interp is not None or needed or glibc:
            fail(f"{target} must be fully static, found interpreter={interp} needed={needed}")
        log(f"{target}: static, no interpreter, no shared libraries")
        return
    newest = max(glibc) if glibc else ()
    if newest > GLIBC_FLOOR:
        fail(f"{target} needs GLIBC_{'.'.join(map(str, newest))}, above the {GLIBC_FLOOR} floor")
    log(f"{target}: dynamic, needs at most GLIBC_{'.'.join(map(str, newest))}")


def check_darwin_binary(path):
    """Fail unless the executable is as portable as its wheel tag says.

    It may link only the system's own libraries (a Nix build can pick up a
    /nix/store libiconv that no other Mac has), and it may require no newer
    macOS than the macosx_11_0 tag on the wheel.
    """
    otool = shutil.which("otool")
    if otool is None:
        log("otool is not available; skipping the macOS checks")
        return
    libraries = subprocess.run([otool, "-L", str(path)], capture_output=True, text=True, check=True)
    names = [line.split()[0] for line in libraries.stdout.splitlines()[1:] if line.strip()]
    outside = [name for name in names if not name.startswith(("/usr/lib/", "/System/"))]
    if outside:
        fail(f"{path} links libraries outside the system: {outside}")
    commands = subprocess.run([otool, "-l", str(path)], capture_output=True, text=True, check=True)
    minimum = re.search(r"cmd LC_BUILD_VERSION.*?minos (\d+)\.(\d+)", commands.stdout, re.DOTALL)
    if minimum and (int(minimum.group(1)), int(minimum.group(2))) > DARWIN_MIN_OS:
        fail(f"{path} needs macOS {minimum.group(1)}.{minimum.group(2)}, above {DARWIN_MIN_OS}")
    log(f"darwin: links only system libraries ({len(names)}), minimum macOS "
        f"{minimum.group(1) + '.' + minimum.group(2) if minimum else 'unknown'}")


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------

def catalog_files():
    """The files `build.rs` embeds: regular files under catalog/, minus caches."""
    root = ROOT / "catalog"
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        parts = relative.parts
        if any(p.startswith(".") or p == "__pycache__" or p.endswith("~") for p in parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_file() and not path.is_symlink():
            yield path, relative


def cargo_release_env(target):
    """The environment for building `target`: ours, minus anything that could redirect the build.

    A stray CARGO, CARGO_BUILD_TARGET or zig path left in a shell would otherwise
    quietly change what gets built, so every release build starts without them.
    """
    inherited = {"CARGO", "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "CARGO_ZIGBUILD_ZIG_PATH",
                 "ESTUS_WHEEL_PLATFORM_TAGS"}
    env = {key: value for key, value in os.environ.items() if key not in inherited}
    # Smaller artifacts; set here so the committed Cargo.toml is unaffected.
    env["CARGO_PROFILE_RELEASE_STRIP"] = "symbols"
    if target in LINUX_TARGETS:
        # zig is the linker. Name its binary: inside uv's isolated build
        # environment `python -m ziglang` is not available to find it.
        env["CARGO_ZIGBUILD_ZIG_PATH"] = require_tool("zig")
    elif target in DARWIN_TARGETS:
        # The release shell's Rust toolchain brings Nix's C compiler and sets a
        # newer deployment target. Link with the system compiler instead, and
        # build for the macOS version the wheel tag promises.
        env["MACOSX_DEPLOYMENT_TARGET"] = "%d.%d" % DARWIN_MIN_OS
        env["CARGO_TARGET_" + target.upper().replace("-", "_") + "_LINKER"] = "/usr/bin/cc"
    return env


def build_binary(target, target_dir):
    env = cargo_release_env(target)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    if target in LINUX_TARGETS:
        require_tool("zig")
        require_tool("cargo-zigbuild")
        run(
            ["cargo", "zigbuild", "--release", "--locked", "--bin", "estus",
             "--target", LINUX_TARGETS[target]["zig"]],
            cwd=ROOT, env=env,
        )
        binary = target_dir / target / "release" / "estus"
        check_linux_binary(binary, target)
    else:
        run(["cargo", "build", "--release", "--locked", "--bin", "estus", "--target", target],
            cwd=ROOT, env=env)
        binary = target_dir / target / "release" / "estus"
        check_darwin_binary(binary)
    return binary


def write_tarball(binary, target, out_dir):
    """estus-<target>.tar.gz holding estus-<target>/bin/estus and share/estus/catalog.

    Extracted anywhere, the binary finds the catalog next to itself, so no
    `estus catalog install` step is needed. The name has no version, so
    releases/latest/download/<name> is a stable URL.
    """
    name = f"estus-{target}"
    out = out_dir / f"{name}.tar.gz"
    with tempfile.TemporaryDirectory() as scratch:
        tree = Path(scratch) / name
        (tree / "bin").mkdir(parents=True)
        shutil.copy2(binary, tree / "bin" / "estus")
        (tree / "bin" / "estus").chmod(0o755)
        for source, relative in catalog_files():
            destination = tree / "share" / "estus" / "catalog" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        for document in ("LICENSE", "README.md"):
            shutil.copy2(ROOT / document, tree / document)
        # Deterministic archive: sorted members, no owner or timestamps.
        with tarfile.open(out, "w:gz", format=tarfile.PAX_FORMAT, compresslevel=9) as archive:
            members = sorted(tree.rglob("*"))
            for path in [tree] + members:
                info = archive.gettarinfo(str(path), arcname=str(Path(name) / path.relative_to(tree)))
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 0
                info.mode = 0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644
                if path.is_file():
                    with path.open("rb") as handle:
                        archive.addfile(info, handle)
                else:
                    archive.addfile(info)
    log(f"wrote {out} ({out.stat().st_size / 1e6:.1f} MB)")
    return out


def cmd_binaries(args):
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    targets = args.target or host_targets()
    with tempfile.TemporaryDirectory() as scratch:
        for target in targets:
            if target not in LINUX_TARGETS and target not in DARWIN_TARGETS:
                fail(f"unknown target {target}")
            binary = build_binary(target, Path(args.target_dir or scratch))
            write_tarball(binary, target, out)


def zigbuild_cargo(directory):
    """A `cargo` for setuptools-rust that compiles through cargo-zigbuild.

    setuptools-rust runs `$CARGO build --target T ...`. zigbuild's own subcommand
    already means build, so `build` is forwarded to it; everything else, such as
    `cargo metadata`, goes to the real cargo.
    """
    shim = directory / "zigcargo"
    shim.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = build ]; then shift; exec cargo zigbuild "$@"; fi\n'
        'exec cargo "$@"\n',
        encoding="utf-8",
    )
    shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
    return shim


def build_wheel(target, out_dir, scratch):
    env = cargo_release_env(target)
    env["CARGO_TARGET_DIR"] = str(scratch / "target")
    command = ["uv", "build", "--wheel", "--out-dir", out_dir]
    if target in LINUX_TARGETS:
        plat, tags = WHEEL_TAGS[target]
        env["CARGO"] = str(zigbuild_cargo(scratch))
        env["CARGO_BUILD_TARGET"] = LINUX_TARGETS[target]["zig"]
        # uv builds in an isolated environment, so the shim and target travel in
        # the environment rather than on PATH.
        if tags:
            env["ESTUS_WHEEL_PLATFORM_TAGS"] = tags
        command.append(f"--config-setting=--build-option=--plat-name={plat}")
    else:
        # Without this the tag comes from the build interpreter, whose own
        # deployment target (Nix's Python is built for a newer macOS) would make
        # the wheel claim a newer macOS than the binary needs.
        command.append(f"--config-setting=--build-option=--plat-name={expected_wheel_tags(target)}")
    run(command, cwd=ROOT, env=env)


def expected_wheel_tags(target):
    """The platform tag set a wheel for `target` must carry."""
    if target in LINUX_TARGETS:
        plat, tags = WHEEL_TAGS[target]
        return tags or plat
    return "macosx_%d_%d_arm64" % DARWIN_MIN_OS


def check_wheel_tag(wheel, target):
    """Fail if the wheel's filename claims a different platform than intended."""
    expected = f"-py3-none-{expected_wheel_tags(target)}.whl"
    if not wheel.name.endswith(expected):
        fail(f"{wheel.name} should end with {expected}")
    log(f"{wheel.name}: platform tag is as intended")


def check_wheel_binary(wheel, target):
    """Apply the same libc or linkage checks to the executable inside a wheel."""
    with zipfile.ZipFile(wheel) as archive, tempfile.TemporaryDirectory() as scratch:
        member = next((n for n in archive.namelist() if n.endswith("estus/_bin/estus")), None)
        if member is None:
            fail(f"{wheel.name} has no estus/_bin/estus")
        extracted = Path(archive.extract(member, scratch))
        if target in LINUX_TARGETS:
            check_linux_binary(extracted, target)
        else:
            check_darwin_binary(extracted)


def cmd_wheels(args):
    require_tool("uv")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for target in args.target or host_targets():
        if target in LINUX_TARGETS:
            require_tool("zig")
            require_tool("cargo-zigbuild")
        with tempfile.TemporaryDirectory() as scratch:
            before = set(out.glob("*.whl"))
            build_wheel(target, out, Path(scratch))
            built = set(out.glob("*.whl")) - before
            if len(built) != 1:
                fail(f"expected one new wheel for {target}, found {sorted(built)}")
            log(f"wheel for {target}: {next(iter(built)).name}")
            check_wheel_tag(next(iter(built)), target)
            check_wheel_binary(next(iter(built)), target)


def cmd_sdist(args):
    require_tool("uv")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    run(["uv", "build", "--sdist", "--out-dir", out], cwd=ROOT)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cmd_checksums(args):
    directory = Path(args.dir).resolve()
    lines = []
    for path in sorted(directory.iterdir()):
        if path.name == "SHA256SUMS" or not path.is_file():
            continue
        lines.append(f"{sha256(path)}  {path.name}")
    (directory / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"wrote {directory / 'SHA256SUMS'} ({len(lines)} files)")


def sbom_name(target):
    return f"estus-{target}.cdx.json"


def check_sbom(path, target):
    try:
        bom = json.loads(path.read_text(encoding="utf-8"))
        component = bom["metadata"]["component"]
    except (OSError, ValueError, KeyError) as error:
        fail(f"{path.name}: not a CycloneDX SBOM: {error}")
    expected = version()
    if bom.get("bomFormat") != "CycloneDX" or (component.get("name"), component.get("version")) != ("estus-mcp", expected):
        fail(f"{path.name}: describes {component.get('name')} {component.get('version')}, not estus-mcp {expected}")
    if not bom.get("components"):
        fail(f"{path.name}: lists no dependencies for {target}")
    return len(bom["components"])


def cmd_sbom(args):
    """One CycloneDX SBOM per release target: the crates compiled into that binary.

    Dependencies differ by target (libc, platform crates), so each binary gets its
    own. Build-time dependencies (build scripts, cc) are left out: they aren't
    shipped. SOURCE_DATE_EPOCH, from the commit, makes the files reproducible.
    """
    require_tool("cargo-cyclonedx")
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    if "SOURCE_DATE_EPOCH" not in env:
        commit_time = subprocess.run(["git", "log", "-1", "--format=%ct"], cwd=ROOT, capture_output=True, text=True)
        if commit_time.returncode == 0 and commit_time.stdout.strip():
            env["SOURCE_DATE_EPOCH"] = commit_time.stdout.strip()
    for target in args.target or RELEASE_TARGETS:
        stem = sbom_name(target).removesuffix(".json")
        run(["cargo", "cyclonedx", "--format", "json", "--spec-version", "1.5", "--target", target,
             "--no-build-deps", "--override-filename", stem, "-q"], cwd=ROOT, env=env)
        produced = ROOT / sbom_name(target)
        count = check_sbom(produced, target)
        shutil.move(produced, out / produced.name)
        log(f"{produced.name}: {count} dependencies")


def cmd_sbom_subjects(args):
    """For each SBOM in DIR, a sha256sum-format list of the files it describes.

    That is the target's binary tarball and its wheels; actions/attest reads the
    list as the attestation's subjects. With --expect, the SBOMs present must be
    for exactly those targets, so the workflow can't attest a different set from
    the one that was built.
    """
    dist = Path(args.dist).resolve()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    found = sorted(p.name.removeprefix("estus-").removesuffix(".cdx.json") for p in dist.glob(sbom_name("*")))
    if args.expect is not None and found != sorted(args.expect):
        fail(f"{dist} has SBOMs for {found}, but the workflow attests {sorted(args.expect)}")
    for target in found:
        if target not in RELEASE_TARGETS:
            fail(f"{sbom_name(target)} is not for a release target")
        tag = expected_wheel_tags(target)
        wheels = [w for w in sorted(dist.glob("*.whl")) if w.name.removesuffix(".whl").rsplit("-", 1)[1] == tag]
        tarball = dist / f"estus-{target}.tar.gz"
        if not tarball.is_file() or not wheels:
            fail(f"{sbom_name(target)}: expected {tarball.name} and a {tag} wheel in {dist}")
        subjects = [tarball, *wheels]
        (out / f"{target}.sha256").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in subjects), encoding="utf-8")
        log(f"{sbom_name(target)} describes {', '.join(p.name for p in subjects)}")


# ---------------------------------------------------------------------------
# Smoke tests: install what was built on the systems it claims to support.
# ---------------------------------------------------------------------------

HANDSHAKE = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":'
    '"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
)

# Each profile names the image, how it installs OpenSSH (Estus needs `ssh`), and,
# for wheels, how it gets a Python with venv and pip.
PROFILES = {
    "almalinux9": {
        "image": "almalinux:9",  # glibc 2.34: exactly the floor
        "ssh": "dnf -q -y install openssh-clients",
        "python": "dnf -q -y install python3 python3-pip",
    },
    "ubuntu2004": {
        "image": "ubuntu:20.04",  # glibc 2.31 and Python 3.8: below the floor
        "ssh": "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-client",
        "python": "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv python3-pip",
    },
    "alpine": {
        "image": "alpine:3.20",  # musl
        "ssh": "apk add -q openssh-client",
        "python": "apk add -q python3 py3-pip",
    },
}

# Which profiles each artifact is tested on, and which must refuse it.
BINARY_PROFILES = {
    "gnu": ["almalinux9"],
    "musl": ["alpine", "almalinux9", "ubuntu2004"],
}
WHEEL_PROFILES = {
    "manylinux_2_34": {"install": ["almalinux9"], "refuse": ["ubuntu2004"]},
    "musllinux_1_2": {"install": ["alpine", "ubuntu2004"], "refuse": []},
}


def docker_run(profile, platform_name, files, script):
    """Run `script` in a fresh container with `files` copied to /."""
    spec = PROFILES[profile]
    create = subprocess.run(
        ["docker", "create", "--platform", platform_name, spec["image"], "sh", "-c", script],
        capture_output=True, text=True,
    )
    if create.returncode != 0:
        fail(f"docker create failed: {create.stderr.strip()}")
    container = create.stdout.strip()
    try:
        for source, name in files:
            subprocess.run(["docker", "cp", str(source), f"{container}:/{name}"],
                           check=True, capture_output=True)
        result = subprocess.run(["docker", "start", "-a", container], capture_output=True, text=True)
        return result.returncode, result.stdout + result.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)


def expect(label, ok, output=""):
    if ok:
        log(f"PASS {label}")
        return
    print(f"FAIL {label}\n{output}", file=sys.stderr)
    sys.exit(1)


def smoke_commands(binary_expr, expected_version):
    """Shell fragment exercising an estus invocation: version, catalog, handshake."""
    return (
        f'v=$({binary_expr} --version) && echo "$v" && [ "$v" = "estus {expected_version}" ] && '
        f"{binary_expr} catalog list | head -1 && "
        f"printf '%s\\n' '{HANDSHAKE}' | {binary_expr} --workstation | "
        f"head -c 400 | grep -q '\"serverInfo\":{{\"name\":\"estus\",\"version\":\"{expected_version}\"'"
    )


def setup(command):
    """Shell that runs a container's setup, which needs the network, up to three times.

    Package mirrors fail now and then. Quiet when it works; when every attempt
    fails it prints the last attempt's output and exits, so a failed smoke test
    says why instead of failing with no output.
    """
    return (
        f"n=0; until sh -c {shlex.quote(command)} >/tmp/setup.log 2>&1; do "
        "n=$((n + 1)); "
        'if [ "$n" -ge 3 ]; then echo "container setup failed 3 times; last attempt:"; '
        "cat /tmp/setup.log; exit 1; fi; "
        'sleep $((n * 10)); done; '
    )


def smoke_docker(dist, expected_version):
    host = platform.machine().lower()
    host_arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}[host]
    for target, spec in LINUX_TARGETS.items():
        if spec["arch"] != host_arch:
            continue  # each architecture is tested on a runner of its own kind
        libc = "musl" if spec["static"] else "gnu"
        tarball = dist / f"estus-{target}.tar.gz"
        if not tarball.exists():
            fail(f"missing {tarball.name}")
        for profile in BINARY_PROFILES[libc]:
            script = (
                f"set -e; {setup(PROFILES[profile]['ssh'])}"
                f"tar xzf /{tarball.name} -C /opt; "
                f"{smoke_commands(f'/opt/estus-{target}/bin/estus', expected_version)}"
            )
            code, output = docker_run(profile, spec["docker"], [(tarball, tarball.name)], script)
            expect(f"{tarball.name} on {profile}", code == 0, output)
            # The tarball carries its own catalog; nothing was installed.
            expect(f"{tarball.name} on {profile} finds its bundled catalog",
                   "Catalog" in output, output)

    for wheel in sorted(dist.glob("estus-*.whl")):
        arch_match = re.search(r"(x86_64|aarch64)\.whl$", wheel.name)
        if not arch_match or arch_match.group(1) != host_arch:
            continue
        docker_platform = "linux/amd64" if host_arch == "x86_64" else "linux/arm64"
        family = "manylinux_2_34" if "manylinux_2_34" in wheel.name else "musllinux_1_2"
        for profile in WHEEL_PROFILES[family]["install"]:
            script = (
                f"set -e; {setup(PROFILES[profile]['ssh'])}"
                f"{setup(PROFILES[profile]['python'])}"
                "python3 -m venv /v; /v/bin/pip install -q --disable-pip-version-check "
                f"/{wheel.name}; {smoke_commands('/v/bin/estus', expected_version)}"
            )
            code, output = docker_run(profile, docker_platform, [(wheel, wheel.name)], script)
            expect(f"{wheel.name} installs on {profile}", code == 0, output)
        for profile in WHEEL_PROFILES[family]["refuse"]:
            script = (
                f"{setup(PROFILES[profile]['python'])}python3 -m venv /v; "
                f"/v/bin/pip install -q --disable-pip-version-check --no-index /{wheel.name}"
            )
            code, output = docker_run(profile, docker_platform, [(wheel, wheel.name)], script)
            expect(f"{wheel.name} is refused on {profile}",
                   code != 0 and "not a supported wheel" in output, output)


def smoke_native(dist, expected_version):
    for target in DARWIN_TARGETS:
        tarball = dist / f"estus-{target}.tar.gz"
        if not tarball.exists():
            fail(f"missing {tarball.name}")
        with tempfile.TemporaryDirectory() as scratch:
            with tarfile.open(tarball) as archive:
                archive.extractall(scratch)
            binary = Path(scratch) / f"estus-{target}" / "bin" / "estus"
            script = smoke_commands(str(binary), expected_version)
            result = subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                                    env={k: v for k, v in os.environ.items() if k != "ESTUS_CATALOG_ROOT"})
            expect(f"{tarball.name} runs and finds its bundled catalog",
                   result.returncode == 0 and "Catalog" in result.stdout, result.stdout + result.stderr)
    for wheel in sorted(dist.glob("estus-*macosx*.whl")):
        require_tool("uv")
        with tempfile.TemporaryDirectory() as scratch:
            venv = Path(scratch) / "v"
            run(["uv", "venv", "-q", venv])
            run(["uv", "pip", "install", "-q", "--python", venv / "bin" / "python", wheel])
            script = smoke_commands(str(venv / "bin" / "estus"), expected_version)
            result = subprocess.run(["sh", "-c", script], capture_output=True, text=True)
            expect(f"{wheel.name} installs and runs", result.returncode == 0, result.stdout + result.stderr)


def cmd_smoke(args):
    dist = Path(args.dist).resolve()
    mode = args.mode or ("native" if sys.platform == "darwin" else "docker")
    expected = version()
    log(f"smoke testing {dist} ({mode}) for version {expected}")
    if mode == "docker":
        require_tool("docker")
        smoke_docker(dist, expected)
    else:
        smoke_native(dist, expected)
    log("smoke tests passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name, handler in (("binaries", cmd_binaries), ("wheels", cmd_wheels)):
        p = sub.add_parser(name)
        p.add_argument("--out", default=str(ROOT / "dist" / "release"))
        p.add_argument("--target", action="append", help="repeatable; default: every target for this host")
        if name == "binaries":
            p.add_argument("--target-dir", help="cargo target directory (default: a temporary one)")
        p.set_defaults(func=handler)
    p = sub.add_parser("sdist")
    p.add_argument("--out", default=str(ROOT / "dist" / "release"))
    p.set_defaults(func=cmd_sdist)
    p = sub.add_parser("checksums")
    p.add_argument("dir")
    p.set_defaults(func=cmd_checksums)
    p = sub.add_parser("sbom")
    p.add_argument("--out", default=str(ROOT / "dist" / "release"))
    p.add_argument("--target", action="append", help="repeatable; default: every release target")
    p.set_defaults(func=cmd_sbom)
    p = sub.add_parser("sbom-subjects")
    p.add_argument("dist")
    p.add_argument("--out", required=True)
    p.add_argument("--expect", nargs="+", help="the targets the SBOMs must be for, no more and no fewer")
    p.set_defaults(func=cmd_sbom_subjects)
    p = sub.add_parser("smoke")
    p.add_argument("dist")
    p.add_argument("--mode", choices=["docker", "native"])
    p.set_defaults(func=cmd_smoke)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
