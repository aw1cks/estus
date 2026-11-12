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
  };

  outputs = inputs: inputs.flake-parts.lib.mkFlake { inherit inputs; } {
    imports = [ ./nix/ci.nix ];

    systems = [
      "aarch64-darwin"
      "aarch64-linux"
      "x86_64-linux"
    ];

    perSystem = { pkgs, ... }:
      let
        craneLib = inputs.crane.mkLib pkgs;
        msrvLib = craneLib.overrideToolchain (p:
          (p.extend inputs.rust-overlay.overlays.default).rust-bin.stable."1.88.0".minimal
        );
        commonArgs = {
          src = craneLib.cleanCargoSource ./.;
          strictDeps = true;
          doCheck = true;
        };
        buildWith = craneLib: import ./nix/rust-build.nix {
          inherit pkgs craneLib commonArgs;
        };
        inherit (buildWith craneLib) package acceptance;
      in
      {
        packages = {
          default = package;
          ssh-acceptance = acceptance;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          ssh-fixture-image = import ./nix/ssh-fixture.nix { inherit pkgs; };
        };
        apps.default = {
          type = "app";
          program = "${package}/bin/ssh-mcp";
        };
        apps.ssh-baseline = {
          type = "app";
          program = "${acceptance}/bin/ssh-baseline";
        };
        apps.ssh-stdio = {
          type = "app";
          program = "${acceptance}/bin/ssh-stdio";
        };
        apps.ssh-native = {
          type = "app";
          program = "${acceptance}/bin/ssh-native";
        };
        checks.package = package;
        # Compile every test target and run the network-free suite on the MSRV.
        # Never reuse artifacts produced by the default (newer) compiler.
        checks.msrv = msrvLib.cargoTest (commonArgs // {
          cargoArtifacts = null;
          doInstallCargoArtifacts = false;
          cargoTestExtraArgs = "--all-targets";
          preBuild = "rustc --version";
        });
        checks.formatting = craneLib.cargoFmt {
          src = commonArgs.src;
        };
        # Compilation only: SSH listeners and containers stay outside sandboxes.
        checks.ssh-acceptance-build = acceptance;
        devShells.default = craneLib.devShell {
          checks = { inherit package; };
          # crane supplies cargo, rustc, rustfmt, and clippy from its toolchain.
          packages = [
            pkgs.openssh
            pkgs.coreutils
            pkgs.docker-client
          ];
        };
      };
  };
}
