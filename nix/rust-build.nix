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
    nativeBuildInputs = [ pkgs.makeWrapper ];
    # Captured production parsers need only isolated stdlib Python, not Ansible.
    nativeCheckInputs = controllerTestPrograms ++ [ pkgs.openssh pkgs.python3 ];
    postFixup = ''
      wrapProgram "$out/bin/estus" \
        --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]}
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
