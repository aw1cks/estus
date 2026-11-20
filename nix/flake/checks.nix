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
        cp -r ${commonArgs.src}/src/native_payload native_payload
        python3 -I -m unittest discover -s native_payload -p 'test_bootstrap.py' -v
        touch "$out"
      '';
      checks.python-min-version = pkgs.runCommand "estus-python-min-version" {
        nativeBuildInputs = [ pkgs.python3 pkgs.vermin ];
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
        import ast
        guarded = [src / "src/native_payload/prestate.py", src / "python/estus/__init__.py", src / "setup.py"]
        guarded.extend(sorted((src / "catalog/payloads").glob("*/collector.py")))
        for path in guarded:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
                        raise SystemExit(f"forbidden dynamic {node.func.id}() in {path}")
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            raise SystemExit(f"forbidden shell=True in {path}")
        ast.parse((src / "src/native_payload/bootstrap.py").read_text(encoding="utf-8"))
        PY
        touch "$out"
      '';
      # Compilation only: SSH listeners and containers stay outside sandboxes.
      checks.ssh-acceptance-build = acceptance;
      checks.ssh-acceptance-msrv-build = msrvBuild.acceptance;
    };
}
