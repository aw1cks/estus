{ inputs, ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) package msrvBuild craneLib commonArgs cargoArtifacts acceptance wheel;
    in
    {
      checks.package = package;
      # Compile every test target and run the network-free suite on the MSRV.
      # Never reuse artifacts produced by the default (newer) compiler.
      checks.msrv = msrvBuild.package;
      checks.formatting = craneLib.cargoFmt {
        src = commonArgs.src;
      };
      checks.wheel = wheel;
      checks.clippy = craneLib.cargoClippy (commonArgs // {
        inherit cargoArtifacts;
        cargoExtraArgs = "--locked";
        cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
      });
      checks.audit = craneLib.cargoAudit {
        inherit (inputs) advisory-db;
        src = commonArgs.src;
        cargoAuditExtraArgs = "--no-yanked";
      };
      checks.bootstrap-tests = pkgs.runCommand "estus-bootstrap-tests" {
        nativeBuildInputs = [ pkgs.python3 ];
      } ''
        # Keep the repository layout: the allowlist regression imports a shipped
        # collector from catalog/payloads relative to src/native_payload.
        mkdir -p src
        cp -r ${commonArgs.src}/src/native_payload src/native_payload
        cp -r ${commonArgs.src}/catalog catalog
        python3 -I -m unittest discover -s src/native_payload -p 'test_bootstrap.py' -v
        touch "$out"
      '';
      checks.python-min-version = pkgs.runCommand "estus-python-min-version" {
        nativeBuildInputs = [ pkgs.python3 pkgs.vermin pkgs.python3Packages.pyflakes ];
      } ''
        python3 - <<'PY'
        import json, pathlib, subprocess, sys
        src = pathlib.Path("${commonArgs.src}")
        vermin = "vermin"
        def check(py_min, files):
            cmd = [vermin, "-q", f"-t={py_min}-", "--violations", "--no-tips", "--no-parse-comments", *[str(f) for f in files]]
            res = subprocess.run(cmd, check=False)
            if res.returncode != 0:
                sys.exit(res.returncode)
        check("3.8", [src / "src/native_payload/bootstrap.py", src / "src/native_payload/prestate.py"])
        check("3.10", [src / "python/estus/__init__.py", src / "setup.py"])
        groups = {}
        for p in sorted((src / "catalog/payloads").iterdir()):
            manifest = json.loads((p / "manifest.json").read_text())
            maj, mino = manifest["requirements"]["python_min"]
            groups.setdefault(f"{maj}.{mino}", []).append(p / "collector.py")
        for py_min, files in sorted(groups.items()):
            check(py_min, files)
        # A NameError only surfaces when the collector runs on a target, and the
        # parser tables do not reach every code path; reject undefined names here.
        undefined = subprocess.run(
            ["pyflakes", *[str(p) for p in sorted((src / "catalog/payloads").glob("*/collector.py"))]],
            check=False, capture_output=True, text=True,
        ).stdout.splitlines()
        undefined = [line for line in undefined if "undefined name" in line]
        if undefined:
            raise SystemExit("undefined names in collectors:\n" + "\n".join(undefined))
        import ast, re
        guarded = [src / "src/native_payload/prestate.py", src / "python/estus/__init__.py", src / "setup.py"]
        guarded.extend(sorted((src / "catalog/payloads").glob("*/collector.py")))
        binpath = re.compile(r"^(?:/(?:usr/)?s?bin/[^/:]+$)")
        for path in guarded:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        raise SystemExit(f"forbidden dynamic {node.func.id}() in {path}")
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            raise SystemExit(f"forbidden shell=True in {path}")
                # `for f in ('x')` walks characters; a one-field tuple needs a comma.
                if isinstance(node, (ast.For, ast.comprehension)) and isinstance(node.iter, ast.Constant) and isinstance(node.iter.value, str):
                    raise SystemExit(f"iteration over a string literal in {path}:{getattr(node, 'lineno', node.iter.lineno)}")
        ast.parse((src / "src/native_payload/bootstrap.py").read_text(encoding="utf-8"))
        collectors = sorted((src / "catalog/payloads").glob("*/collector.py"))
        if not collectors:
            raise SystemExit("no catalog payload collectors found")
        for path in collectors:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            parents = {}
            for node in ast.walk(tree):
                for child in ast.iter_child_nodes(node):
                    parents[child] = node
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                if not binpath.match(node.value):
                    continue
                parent = parents.get(node)
                if isinstance(parent, (ast.Tuple, ast.List)):
                    siblings = [e.value for e in parent.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                    if len(siblings) >= 2 and len(set(siblings)) == len(siblings) and all(binpath.match(s) for s in siblings):
                        continue
                raise SystemExit(f"hardcoded single-location binary path in {path}")
        PY
        touch "$out"
      '';
      # Compilation only: SSH listeners and containers stay outside sandboxes.
      checks.ssh-acceptance-build = acceptance;
      checks.ssh-acceptance-msrv-build = msrvBuild.acceptance;
    };
}
