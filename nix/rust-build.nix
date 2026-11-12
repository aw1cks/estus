{ pkgs, craneLib, commonArgs, cargoTestExtraArgs ? "" }:
let
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
    postFixup = ''
      wrapProgram "$out/bin/ssh-mcp" \
        --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]}
    '';
  });
  acceptance = import ./ssh-acceptance.nix {
    inherit pkgs craneLib commonArgs cargoArtifacts package;
  };
in
{
  inherit package acceptance;
}
