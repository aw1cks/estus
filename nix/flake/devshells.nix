{ ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) craneLib fuzzLib package;
      devMcp = pkgs.writeShellScriptBin "estus-dev-mcp" ''
        unset ESTUS_CONFIG ESTUS_SSH_CONFIG ESTUS_SSH ESTUS_CATALOG_ROOT \
          ESTUS_ANSIBLE_RUNTIME ESTUS_PYTHON_RUNTIME
        exec ${package}/bin/estus --config ${../../examples/dev-no-targets.toml} "$@"
      '';
    in
    {
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
