{ ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) craneLib fuzzLib package directModuleBundle;
      devMcp = pkgs.writeShellScriptBin "estus-dev-mcp" ''
        unset ESTUS_CONFIG ESTUS_SSH_CONFIG ESTUS_SSH ESTUS_CATALOG_ROOT \
          ESTUS_ANSIBLE_BUNDLE ESTUS_PYTHON_RUNTIME
        export ESTUS_ANSIBLE_BUNDLE=${directModuleBundle}
        exec ${package}/bin/estus "$@"
      '';
    in
    {
      packages.dev-mcp = devMcp;
      apps.dev-mcp = {
        type = "app";
        program = "${devMcp}/bin/estus-dev-mcp";
      };
      devShells.default = craneLib.devShell {
        checks = { inherit package; };
        # crane supplies cargo, rustc, rustfmt, and clippy from its toolchain.
        packages = [
          devMcp
          pkgs.openssh
          pkgs.python314
          pkgs.coreutils
          pkgs.docker-client
          pkgs.gnutar
          pkgs.cargo-audit
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
