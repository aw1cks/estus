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
        fuzzLib = craneLib.overrideToolchain (p:
          (p.extend inputs.rust-overlay.overlays.default).rust-bin.nightly."2026-11-10".default.override {
            extensions = [ "rust-src" ];
          }
        );
        commonArgs = {
          src = craneLib.cleanCargoSource (pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: _: path != "${toString ./.}/fuzz";
          });
          strictDeps = true;
          doCheck = true;
        };
        defaultBuild = import ./nix/rust-build.nix {
          inherit pkgs craneLib commonArgs;
        };
        msrvBuild = import ./nix/rust-build.nix {
          inherit pkgs;
          craneLib = msrvLib;
          commonArgs = commonArgs // { preBuild = "rustc --version"; };
          cargoTestExtraArgs = "--all-targets";
        };
        inherit (defaultBuild) package acceptance;
      in
      {
        packages = {
          default = package;
          msrv = msrvBuild.package;
          ssh-acceptance = acceptance;
          ssh-acceptance-msrv = msrvBuild.acceptance;
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
        apps.ssh-native-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/ssh-native";
        };
        checks.package = package;
        # Compile every test target and run the network-free suite on the MSRV.
        # Never reuse artifacts produced by the default (newer) compiler.
        checks.msrv = msrvBuild.package;
        checks.formatting = craneLib.cargoFmt {
          src = commonArgs.src;
        };
        # Compilation only: SSH listeners and containers stay outside sandboxes.
        checks.ssh-acceptance-build = acceptance;
        checks.ssh-acceptance-msrv-build = msrvBuild.acceptance;
        devShells.default = craneLib.devShell {
          checks = { inherit package; };
          # crane supplies cargo, rustc, rustfmt, and clippy from its toolchain.
          packages = [
            pkgs.openssh
            pkgs.coreutils
            pkgs.docker-client
          ];
        };
        # Optional tooling only; normal builds/checks retain their stable toolchain.
        devShells.fuzz = fuzzLib.devShell {
          packages = [ pkgs.cargo-fuzz pkgs.clang ];
          CC = "${pkgs.clang}/bin/clang";
          CXX = "${pkgs.clang}/bin/clang++";
        };
      };
  };
}
