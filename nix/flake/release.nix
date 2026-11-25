{ inputs, ... }:
{
  perSystem = { pkgs, ... }:
    let
      rustPkgs = pkgs.extend inputs.rust-overlay.overlays.default;
      # Linux release binaries are cross-built with zig as the linker; macOS
      # builds its own host target. flake.lock pins the Rust and zig versions, so
      # the same shell gives the same compiler on a laptop and on a runner.
      toolchain = rustPkgs.rust-bin.stable.latest.minimal.override {
        targets = [
          "x86_64-unknown-linux-gnu"
          "aarch64-unknown-linux-gnu"
          "x86_64-unknown-linux-musl"
          "aarch64-unknown-linux-musl"
        ];
      };
      # On macOS the binary must link the system libraries. Nix's C compiler
      # would put its own libiconv first, leaving a /nix/store path in the
      # executable that no other Mac has, so use the shell without it and let
      # `cc` be the system compiler.
      mkReleaseShell = if pkgs.stdenv.hostPlatform.isDarwin then pkgs.mkShellNoCC else pkgs.mkShell;
    in
    {
      # `nix develop .#release -c python3 scripts/release.py ...`
      devShells.release = mkReleaseShell {
        packages = [
          toolchain
          pkgs.cargo-zigbuild
          pkgs.cargo-cyclonedx
          pkgs.zig
          pkgs.uv
          pkgs.python3
          pkgs.docker-client
        ];
      };
    };
}
