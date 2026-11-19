{ inputs, ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) package msrvBuild craneLib commonArgs cargoArtifacts acceptance;
    in
    {
      checks.package = package;
      # Compile every test target and run the network-free suite on the MSRV.
      # Never reuse artifacts produced by the default (newer) compiler.
      checks.msrv = msrvBuild.package;
      checks.formatting = craneLib.cargoFmt {
        src = commonArgs.src;
      };
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
      # Compilation only: SSH listeners and containers stay outside sandboxes.
      checks.ssh-acceptance-build = acceptance;
      checks.ssh-acceptance-msrv-build = msrvBuild.acceptance;
    };
}
