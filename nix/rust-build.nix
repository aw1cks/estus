{ pkgs, craneLib, commonArgs, cargoTestExtraArgs ? "" }:
let
  controllerTestPrograms = [ pkgs.bash pkgs.coreutils ]
    ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ];
  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
    dummySrc = craneLib.mkDummySrc {
      src = commonArgs.src;
      # Registry consumers need this patched path dependency's real API,
      # not crane's empty local-crate replacement.
      extraDummyScript = ''
        rm -r "$out/vendor/openssh-sftp-protocol/src"
        cp -r ${../vendor/openssh-sftp-protocol/src} \
          "$out/vendor/openssh-sftp-protocol/src"
      '';
    };
  });
  package = craneLib.buildPackage (commonArgs // {
    inherit cargoArtifacts cargoTestExtraArgs;
    nativeBuildInputs = [ pkgs.makeWrapper pkgs.jq ];
    # Captured production parsers need only isolated stdlib Python, not Ansible.
    nativeCheckInputs = controllerTestPrograms ++ [ pkgs.openssh pkgs.python3 ];
    postInstall = ''
      catalog="$out/share/estus/catalog"
      mkdir -p "$catalog/roles"
      install -m644 examples/catalog.json "$catalog/catalog.json"
      for name in $(jq -r '.tools | keys[]' examples/catalog.json); do
        install -m644 "examples/$name.toml" "$catalog/$name.toml"
        while IFS= read -r source; do
          relative="''${source#examples/}"
          mkdir -p "$catalog/$(dirname "$relative")"
          install -m644 "$source" "$catalog/$relative"
        done < <(find "examples/roles/$name" -type f \
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
  acceptance = import ./ssh-acceptance.nix {
    inherit pkgs craneLib commonArgs cargoArtifacts package;
    inherit controllerTestPrograms;
  };
in
{
  inherit package acceptance;
}
