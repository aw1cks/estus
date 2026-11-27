{ self, ... }:
{
  flake.homeModules.default = import ../hm-module.nix self;
}
