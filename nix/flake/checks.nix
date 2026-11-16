{ ... }:
{
  perSystem = { estusBuild, ... }:
    let
      inherit (estusBuild) package msrvBuild craneLib commonArgs acceptance;
    in
    {
      checks.package = package;
      # Compile every test target and run the network-free suite on the MSRV.
      # Never reuse artifacts produced by the default (newer) compiler.
      checks.msrv = msrvBuild.package;
      checks.formatting = craneLib.cargoFmt {
        src = commonArgs.src;
      };
      # Compilation only: SSH listeners and containers stay outside sandboxes.
      checks.ssh-acceptance-build = acceptance;
      checks.ssh-acceptance-msrv-build = msrvBuild.acceptance;
    };
}
