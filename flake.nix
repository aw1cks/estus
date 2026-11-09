{
  description = "A stdio MCP server using OpenSSH";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs = inputs: inputs.flake-parts.lib.mkFlake { inherit inputs; } {
    systems = [
      "aarch64-darwin"
      "x86_64-darwin"
      "aarch64-linux"
      "x86_64-linux"
    ];

    perSystem = { pkgs, ... }:
      let
        craneLib = inputs.crane.mkLib pkgs;
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          doCheck = true;
        };
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        package = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postFixup = ''
            wrapProgram "$out/bin/ssh-mcp" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]}
          '';
        });
      in
      {
        packages.default = package;
        apps.default = {
          type = "app";
          program = "${package}/bin/ssh-mcp";
        };
        checks.package = package;
        devShells.default = craneLib.devShell {
          checks = { inherit package; };
          # crane supplies cargo, rustc, rustfmt, and clippy from its toolchain.
          packages = [
            pkgs.openssh
            pkgs.coreutils
          ] ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [
            pkgs.docker-client
          ];
        };
      };
  };
}
