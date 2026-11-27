{ inputs, ... }:
{
  # Builds Estus with the consumer's package set, so it shares their toolchain
  # and libraries. `estus` needs a Rust 1.88 or newer in that set.
  flake.overlays.default = final: _prev:
    let
      native = import ../packages/estus.nix {
        inherit inputs;
        pkgs = final;
        sourceRoot = ../..;
      };
    in
    {
      estus = native.defaultBuild.package;
      estus-automation = native.automation;
    };
}
