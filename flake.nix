{
  description = "A stdio MCP server using OpenSSH";

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
    ];

    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-linux"
    ];

  };
}
