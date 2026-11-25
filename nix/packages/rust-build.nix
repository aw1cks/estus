{ pkgs, craneLib, commonArgs, cargoTestExtraArgs ? "" }:
let
  controllerTestPrograms = [ pkgs.bash pkgs.coreutils ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ];
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
  package = craneLib.buildPackage (commonArgs // {
    inherit cargoArtifacts cargoTestExtraArgs;
    nativeBuildInputs = [ pkgs.makeWrapper pkgs.jq ];
    # Parser and shim tests use isolated stdlib Python, not Ansible.
    nativeCheckInputs = controllerTestPrograms ++ [ pkgs.openssh pkgs.python314 ];
    postInstall = ''
      catalog="$out/share/estus/catalog"
      mkdir -p "$catalog/payloads"
      install -m644 catalog/catalog.json "$catalog/catalog.json"
      for entry in catalog/*; do
        base=$(basename "$entry")
        case "$base" in
          catalog.json|payloads) ;;
          *.toml)
            tool="''${base%.toml}"
            if ! jq -e --arg name "$tool" '.tools | has($name)' catalog/catalog.json >/dev/null; then
              echo "unexpected catalog definition: $entry" >&2
              exit 1
            fi
            ;;
          *)
            echo "unexpected catalog entry: $entry" >&2
            exit 1
            ;;
        esac
      done
      if [ -d "catalog/payloads" ]; then
        for dir in "catalog/payloads"/*; do
          [ -e "$dir" ] || continue
          name=$(basename "$dir")
          if [ -L "$dir" ] || [ ! -d "$dir" ] || \
             ! jq -e --arg name "$name" --arg path "payloads/$name" \
               '.tools[$name] | .executor.kind == "native_payload" and .executor.path == $path' catalog/catalog.json >/dev/null; then
            echo "unexpected catalog asset directory: $dir" >&2
            exit 1
          fi
        done
      fi
      for name in $(jq -r '.tools | keys[]' catalog/catalog.json); do
        install -m644 "catalog/$name.toml" "$catalog/$name.toml"
        assets=$(jq -r --arg name "$name" '.tools[$name].executor.path // empty' catalog/catalog.json)
        if [ -z "$assets" ]; then continue; fi
        while IFS= read -r source; do
          relative="''${source#catalog/}"
          sub="''${relative#"$assets"/}"
          case "$sub" in
            __pycache__|__pycache__/*|*/__pycache__|*/__pycache__/*|*.pyc|*.pyo) continue ;;
          esac
          if [ -L "$source" ]; then
            echo "symlink in catalog source: $source" >&2
            exit 1
          fi
          if [ -d "$source" ]; then continue; fi
          if [ ! -f "$source" ]; then
            echo "unexpected non-regular catalog asset: $source" >&2
            exit 1
          fi
          case "$source" in
            *.yml|*.yaml|*.py|*.json|*.toml) ;;
            *)
              echo "unexpected catalog asset extension: $source" >&2
              exit 1
              ;;
          esac
          mkdir -p "$catalog/$(dirname "$relative")"
          install -m644 "$source" "$catalog/$relative"
        done < <(find "catalog/$assets" -mindepth 1)
      done
    '';
    postFixup = ''
      wrapProgram "$out/bin/estus" \
        --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]} \
        --set ESTUS_CATALOG_ROOT "$out/share/estus/catalog"
    '';
  });
  acceptance = import ../tests/ssh/ssh-acceptance.nix {
    inherit pkgs craneLib commonArgs cargoArtifacts package;
    inherit controllerTestPrograms;
  };
  # `cargo build --timings` of the release binary from scratch, dependencies
  # included: cargo-timing.html (timeline and concurrency) and summary.md (the
  # slowest units), for the CI job summary.
  buildTimings = craneLib.mkCargoDerivation (commonArgs // {
    pname = "estus-build-timings";
    cargoArtifacts = null;
    doCheck = false;
    nativeBuildInputs = [ pkgs.python3 ];
    buildPhaseCargoCommand = "cargo build --release --locked --timings";
    installPhaseCommand = ''
      mkdir -p "$out"
      install -m644 target/cargo-timings/cargo-timing.html "$out/"
      python3 ${../../scripts/build-timings-summary.py} "$out/cargo-timing.html" > "$out/summary.md"
    '';
  });
in
{
  inherit cargoArtifacts package acceptance buildTimings controllerTestPrograms;
}