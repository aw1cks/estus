{ ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) craneLib fuzzLib package;
    in
    {
      devShells.default = craneLib.devShell {
        checks = { inherit package; };
        # crane supplies cargo, rustc, rustfmt, and clippy from its toolchain.
        packages = [
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
