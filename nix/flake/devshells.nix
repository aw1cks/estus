{ ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) craneLib fuzzLib package;
      devPrepare = pkgs.writeShellApplication {
        name = "estus-dev-prepare";
        runtimeInputs = [ pkgs.nix pkgs.git pkgs.coreutils ];
        text = ''
          safe_config=${../../examples/dev-no-targets.toml}
        '' + builtins.readFile ../scripts/estus-dev-prepare.sh;
      };
    in
    {
      apps.dev-prepare = {
        type = "app";
        program = "${devPrepare}/bin/estus-dev-prepare";
      };
      devShells.default = craneLib.devShell {
        checks = { inherit package; };
        # crane supplies cargo, rustc, rustfmt, and clippy from its toolchain.
        packages = [
          devPrepare
          pkgs.openssh
          pkgs.coreutils
          pkgs.docker-client
          pkgs.gnutar
        ];
      };
      # Optional tooling only; normal builds/checks retain their stable toolchain.
      devShells.fuzz = fuzzLib.devShell {
        packages = [ pkgs.cargo-fuzz pkgs.clang ];
        CC = "${pkgs.clang}/bin/clang";
        CXX = "${pkgs.clang}/bin/clang++";
      };
    };
}
