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
    imports = [ ./nix/ci.nix ];

    systems = [
      "aarch64-darwin"
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
        cargoArtifacts = craneLib.buildDepsOnly (commonArgs // {
          dummySrc = craneLib.mkDummySrc {
            src = commonArgs.src;
            # Registry consumers need this patched path dependency's real API,
            # not crane's empty local-crate replacement.
            extraDummyScript = ''
              rm -r "$out/vendor/openssh-sftp-protocol/src"
              cp -r ${./vendor/openssh-sftp-protocol/src} \
                "$out/vendor/openssh-sftp-protocol/src"
            '';
          };
        });
        package = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postFixup = ''
            wrapProgram "$out/bin/ssh-mcp" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]}
          '';
        });
        acceptance = import ./nix/ssh-acceptance.nix {
          inherit pkgs craneLib commonArgs cargoArtifacts package;
        };
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
        checks.package = package;
        checks.formatting = craneLib.cargoFmt {
          src = commonArgs.src;
        };
        # Compilation only: daemon-dependent execution stays outside sandboxes.
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
