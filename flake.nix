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
        msrvToolchain = (pkgs.extend inputs.rust-overlay.overlays.default).rust-bin.stable."1.88.0".minimal;
        msrvLib = craneLib.overrideToolchain msrvToolchain;
        fuzzLib = craneLib.overrideToolchain (p:
          (p.extend inputs.rust-overlay.overlays.default).rust-bin.nightly."2026-11-10".default.override {
            extensions = [ "rust-src" ];
          }
        );
        commonArgs = {
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              path != "${toString ./.}/fuzz"
              && (craneLib.filterCargoSources path type
                || path == "${toString ./.}/src/automation_health.py");
          };
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
        automationRuntime = import ./nix/automation-runtime.nix { inherit pkgs; };
        wheel = import ./nix/wheel.nix { inherit pkgs; craneLib = msrvLib; };
        wheelAcceptance = pkgs.runCommand "ssh-mcp-wheel-acceptance" {
          nativeBuildInputs = [ pkgs.makeWrapper ];
        } ''
          mkdir -p "$out/bin"
          makeWrapper ${msrvBuild.acceptance}/libexec/wheel "$out/bin/wheel-acceptance" \
            --set SSH_MCP_TEST_WHEEL ${wheel}/${wheel.wheelName} \
            --set SSH_MCP_TEST_STDIO_SUITE ${msrvBuild.acceptance}/libexec/stdio \
            --set SSH_MCP_TEST_CONTROLLER_SUITE ${msrvBuild.acceptance}/libexec/controller \
            --set SSH_MCP_TEST_AUTOMATION_SUITE ${msrvBuild.acceptance}/libexec/automation \
            --set SSH_MCP_TEST_BINARY ${msrvBuild.package}/bin/ssh-mcp \
            --set SSH_MCP_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
            --prefix PATH : ${pkgs.lib.makeBinPath (
              [ pkgs.uv pkgs.openssh pkgs.coreutils pkgs.bash pkgs.unzip pkgs.llvmPackages.llvm ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ]
            )} \
            --add-flags '--ignored --nocapture --test-threads=1'
        '';
        withAutomation = native: pkgs.runCommand "ssh-mcp-automation-${native.version}" {
          nativeBuildInputs = [ pkgs.makeWrapper ];
          meta.mainProgram = "ssh-mcp";
        } ''
          mkdir -p "$out/bin"
          makeWrapper ${native}/bin/ssh-mcp "$out/bin/ssh-mcp" \
            --set SSH_MCP_ANSIBLE_RUNTIME ${automationRuntime}
        '';
        automation = withAutomation package;
        automationMsrv = withAutomation msrvBuild.package;
        automationAcceptance = native: harness: optional:
          pkgs.runCommand "ssh-mcp-automation-acceptance" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          } ''
            mkdir -p "$out/bin"
            # Wheel cases require separately provisioned installer environments.
            makeWrapper ${harness}/libexec/automation "$out/bin/automation-acceptance" \
              --set SSH_MCP_TEST_BINARY ${native}/bin/ssh-mcp \
              --set SSH_MCP_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
              --set SSH_MCP_TEST_AUTOMATION_BINARY ${optional}/bin/ssh-mcp \
              --add-flags '--include-ignored --nocapture --test-threads=2 --skip wheel::'
          '';
      in
      {
        packages = {
          default = package;
          msrv = msrvBuild.package;
          ssh-acceptance = acceptance;
          ssh-acceptance-msrv = msrvBuild.acceptance;
          automation-runtime = automationRuntime;
          inherit automation;
          inherit wheel;
          automation-msrv = automationMsrv;
          automation-acceptance = automationAcceptance package acceptance automation;
          automation-acceptance-msrv = automationAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          ssh-fixture-image = import ./nix/ssh-fixture.nix { inherit pkgs; };
        };
        apps.default = {
          type = "app";
          program = "${package}/bin/ssh-mcp";
        };
        apps.automation = {
          type = "app";
          program = "${automation}/bin/ssh-mcp";
        };
        apps.automation-msrv = {
          type = "app";
          program = "${automationMsrv}/bin/ssh-mcp";
        };
        apps.automation-acceptance = {
          type = "app";
          program = "${automationAcceptance package acceptance automation}/bin/automation-acceptance";
        };
        apps.automation-acceptance-msrv = {
          type = "app";
          program = "${automationAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv}/bin/automation-acceptance";
        };
        apps.wheel-acceptance = {
          type = "app";
          program = "${wheelAcceptance}/bin/wheel-acceptance";
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
        apps.controller-scripts = {
          type = "app";
          program = "${acceptance}/bin/controller-scripts";
        };
        apps.controller-scripts-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/controller-scripts";
        };
        apps.doctor-acceptance = {
          type = "app";
          program = "${acceptance}/bin/doctor-acceptance";
        };
        apps.doctor-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/doctor-acceptance";
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
