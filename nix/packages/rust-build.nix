{ pkgs, craneLib, commonArgs, cargoTestExtraArgs ? "" }:
let
  controllerTestPrograms = [ pkgs.bash pkgs.coreutils ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ];
  cargoArtifacts = craneLib.buildDepsOnly commonArgs;
  package = craneLib.buildPackage (commonArgs // {
    inherit cargoArtifacts cargoTestExtraArgs;
    nativeBuildInputs = [ pkgs.makeWrapper pkgs.jq ];
    # Captured production parsers need only isolated stdlib Python, not Ansible.
    nativeCheckInputs = controllerTestPrograms ++ [ pkgs.openssh pkgs.python3 ];
    postInstall = ''
      catalog="$out/share/estus/catalog"
      mkdir -p "$catalog/roles" "$catalog/payloads"
      install -m644 catalog/catalog.json "$catalog/catalog.json"
      for name in $(jq -r '.tools | keys[]' catalog/catalog.json); do
        install -m644 "catalog/$name.toml" "$catalog/$name.toml"
        assets=$(jq -r --arg name "$name" '.tools[$name].executor.path // empty' catalog/catalog.json)
        if [ -z "$assets" ]; then continue; fi
        while IFS= read -r source; do
          relative="''${source#catalog/}"
          mkdir -p "$catalog/$(dirname "$relative")"
          install -m644 "$source" "$catalog/$relative"
        done < <(find "catalog/$assets" -type f \
          \( -name '*.yml' -o -name '*.yaml' -o -name '*.py' \
             -o -name '*.json' -o -name '*.toml' \))
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
