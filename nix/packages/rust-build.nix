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
      mkdir -p "$catalog/roles" "$catalog/payloads"
      install -m644 catalog/catalog.json "$catalog/catalog.json"
      for entry in catalog/*; do
        base=$(basename "$entry")
        case "$base" in
          catalog.json|roles|payloads) ;;
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
      for group in roles payloads; do
        if [ ! -d "catalog/$group" ]; then continue; fi
        kind=$([ "$group" = roles ] && echo ansible_role || echo native_payload)
        for dir in "catalog/$group"/*; do
          [ -e "$dir" ] || continue
          name=$(basename "$dir")
          if [ -L "$dir" ] || [ ! -d "$dir" ] || \
             ! jq -e --arg name "$name" --arg kind "$kind" --arg path "$group/$name" \
               '.tools[$name] | .executor.kind == $kind and .executor.path == $path' catalog/catalog.json >/dev/null; then
            echo "unexpected catalog asset directory: $dir" >&2
            exit 1
          fi
        done
      done
      for name in $(jq -r '.tools | keys[]' catalog/catalog.json); do
        install -m644 "catalog/$name.toml" "$catalog/$name.toml"
        assets=$(jq -r --arg name "$name" '.tools[$name].executor.path // empty' catalog/catalog.json)
        kind=$(jq -r --arg name "$name" '.tools[$name].executor.kind' catalog/catalog.json)
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
          if [ "$kind" = "ansible_role" ]; then
            top="''${sub%%/*}"
            case "$top" in
              tasks|meta|files|defaults|vars|handlers)
                if [ "$top" = "$sub" ]; then
                  echo "unexpected top-level role file: $source" >&2
                  exit 1
                fi
                ;;
              *)
                echo "unexpected role subdirectory in $source" >&2
                exit 1
                ;;
            esac
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
in
{
  inherit cargoArtifacts package acceptance;
}
