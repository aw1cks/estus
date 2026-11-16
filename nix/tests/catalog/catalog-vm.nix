{ inputs, hostPkgs, sourceRoot, lab ? false }:
let
  guestSystem = "x86_64-linux";
  packageFixture = import ./catalog-package-fixture.nix {
    inherit sourceRoot;
    pkgs = import inputs.nixpkgs { system = guestSystem; };
  };
  guest = inputs.nixpkgs.lib.nixosSystem {
    system = guestSystem;
    modules = [
      (import ./guest.nix { inherit sourceRoot lab packageFixture; })
    ];
  };
  disk = import ./catalog-disk-image.nix {
    pkgs = guest.pkgs;
    nixpkgs = inputs.nixpkgs;
    config = guest.config;
  };
in
import ./launcher.nix {
  inherit hostPkgs lab disk;
  firmware = guest.pkgs.OVMFFull;
}
