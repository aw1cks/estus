{
  description = "A stdio MCP server using OpenSSH";

  # Used when this flake is the one you run, e.g. `nix run github:aw1cks/estus`,
  # and only if you accept it. Flakes used as inputs cannot set substituters;
  # see docs/clients.md#home-manager. Keep in sync with `binaryCache` in nix/ci.nix.
  nixConfig = {
    extra-substituters = [ "https://aw1cks-estus.cachix.org" ];
    extra-trusted-public-keys = [ "aw1cks-estus.cachix.org-1:J4jI1cSMiSkNNjHbyA1wyavdwMeqT2EHAwuboKZ/jNk=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = inputs: inputs.flake-parts.lib.mkFlake { inherit inputs; } {
    imports = [
      ./nix/ci.nix
      ./nix/flake/packages.nix
      ./nix/flake/overlays.nix
      ./nix/flake/acceptance.nix
      ./nix/flake/checks.nix
      ./nix/flake/devshells.nix
      ./nix/flake/release.nix
      ./nix/flake/modules.nix
    ];

    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-linux"
    ];

  };
}
