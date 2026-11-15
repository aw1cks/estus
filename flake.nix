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
                || (pkgs.lib.hasPrefix "${toString ./.}/src/" path
                  && pkgs.lib.hasSuffix ".py" path)
                || pkgs.lib.hasPrefix "${toString ./.}/examples/" path
                || pkgs.lib.hasPrefix "${toString ./.}/vendor/openssh-sftp-client/" path
                || pkgs.lib.hasPrefix "${toString ./.}/tests/catalog/fixtures/" path);
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
        wheelAcceptance = pkgs.runCommand "estus-wheel-acceptance" {
          nativeBuildInputs = [ pkgs.makeWrapper ];
        } ''
          mkdir -p "$out/bin"
          makeWrapper ${msrvBuild.acceptance}/libexec/wheel "$out/bin/wheel-acceptance" \
            --set ESTUS_TEST_WHEEL ${wheel}/${wheel.wheelName} \
            --set ESTUS_TEST_STDIO_SUITE ${msrvBuild.acceptance}/libexec/stdio \
            --set ESTUS_TEST_CONTROLLER_SUITE ${msrvBuild.acceptance}/libexec/controller \
            --set ESTUS_TEST_AUTOMATION_SUITE ${msrvBuild.acceptance}/libexec/automation \
            --set ESTUS_TEST_BINARY ${msrvBuild.package}/bin/estus \
            --set ESTUS_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
            --prefix PATH : ${pkgs.lib.makeBinPath (
              [ pkgs.uv pkgs.openssh pkgs.coreutils pkgs.bash pkgs.unzip pkgs.llvmPackages.llvm ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ]
            )} \
            --add-flags '--ignored --nocapture --test-threads=1'
        '';
        withAutomation = native: pkgs.runCommand "estus-automation-${native.version}" {
          nativeBuildInputs = [ pkgs.makeWrapper ];
          meta.mainProgram = "estus";
        } ''
          mkdir -p "$out/bin"
          makeWrapper ${native}/bin/estus "$out/bin/estus" \
            --set ESTUS_ANSIBLE_RUNTIME ${automationRuntime}
        '';
        automation = withAutomation package;
        automationMsrv = withAutomation msrvBuild.package;
        automationAcceptance = native: harness: optional:
          pkgs.runCommand "estus-automation-acceptance" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          } ''
            mkdir -p "$out/bin"
            # Wheel cases require separately provisioned installer environments.
            makeWrapper ${harness}/libexec/automation "$out/bin/automation-acceptance" \
              --set ESTUS_TEST_BINARY ${native}/bin/estus \
              --set ESTUS_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
              --set ESTUS_TEST_AUTOMATION_BINARY ${optional}/bin/estus \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh ]} \
              --add-flags '--include-ignored --nocapture --test-threads=2 --skip wheel::'
          '';
        runnerAcceptance = native: harness:
          pkgs.runCommand "estus-runner-acceptance" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          } ''
            mkdir -p "$out/bin"
            ${pkgs.lib.concatMapStrings (entry: ''
            makeWrapper ${harness}/libexec/automation_exec "$out/bin/${entry.name}" \
              --set ESTUS_TEST_BINARY ${native}/bin/estus \
              --set ESTUS_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
              --set ESTUS_TEST_TARGET_PYTHON ${pkgs.python314}/bin/python3 \
              --prefix PATH : ${pkgs.lib.makeBinPath (
                [ pkgs.openssh pkgs.coreutils pkgs.bash ]
                ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ]
                ++ pkgs.lib.optionals (entry.isolated or false) [ pkgs.docker-client pkgs.gnutar ]
              )} \
              --add-flags '--ignored --exact ${entry.scenario} --nocapture'
            '') [
              { name = "runner-acceptance"; scenario = "real_runner_fixture_acceptance"; }
              { name = "projection-acceptance"; scenario = "real_runner_projection_acceptance"; }
              { name = "role-acceptance"; scenario = "real_runner_role_acceptance"; }
              { name = "playbook-acceptance"; scenario = "real_runner_playbook_acceptance"; }
              { name = "authority-acceptance"; scenario = "real_runner_authority_acceptance"; isolated = true; }
              { name = "isolated-runner-acceptance"; scenario = "real_runner_isolated_fixture_smoke"; isolated = true; }
              { name = "progress-acceptance"; scenario = "real_runner_progress_setup_acceptance"; }
              { name = "host-summary-acceptance"; scenario = "real_host_summary_acceptance"; isolated = true; }
              { name = "cpu-stats-acceptance"; scenario = "real_cpu_stats_acceptance"; isolated = true; }
              { name = "memory-stats-acceptance"; scenario = "real_memory_stats_acceptance"; isolated = true; }
            ]}
          '';
        catalogVm = import ./nix/catalog-vm.nix { inherit inputs; hostPkgs = pkgs; };
        catalogLabVm = import ./nix/catalog-vm.nix { inherit inputs; hostPkgs = pkgs; lab = true; };
        catalogAcceptance = native: harness: pkgs.runCommand "estus-catalog-acceptance" {
          nativeBuildInputs = [ pkgs.makeWrapper ];
        } ''
          mkdir -p "$out/bin"
          makeWrapper ${harness}/libexec/catalog "$out/bin/catalog-acceptance" \
            --set ESTUS_TEST_BINARY ${native}/bin/estus \
            --set ESTUS_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
            --set ESTUS_TEST_CATALOG_ASSETS ${commonArgs.src}/examples \
            --set ESTUS_TEST_CATALOG_VM ${catalogVm}/bin/catalog-guest \
            --set ESTUS_TEST_CATALOG_LAB_VM ${catalogLabVm}/bin/catalog-lab-guest \
            --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
            --add-flags '--ignored --nocapture --test-threads=2'
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
          catalog-vm = catalogVm;
          catalog-lab-vm = catalogLabVm;
          catalog-acceptance = catalogAcceptance package acceptance;
          catalog-acceptance-msrv = catalogAcceptance msrvBuild.package msrvBuild.acceptance;
          automation-msrv = automationMsrv;
          automation-acceptance = automationAcceptance package acceptance automation;
          automation-acceptance-msrv = automationAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv;
          runner-acceptance = runnerAcceptance package acceptance;
          runner-acceptance-msrv = runnerAcceptance msrvBuild.package msrvBuild.acceptance;
        } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          ssh-fixture-image = import ./nix/ssh-fixture.nix { inherit pkgs; };
          ssh-automation-fixture-image = import ./nix/ssh-fixture.nix {
            inherit pkgs;
            automation = true;
          };
        };
        apps.catalog-acceptance = {
          type = "app";
          program = "${catalogAcceptance package acceptance}/bin/catalog-acceptance";
        };
        apps.catalog-acceptance-msrv = {
          type = "app";
          program = "${catalogAcceptance msrvBuild.package msrvBuild.acceptance}/bin/catalog-acceptance";
        };
        apps.default = {
          type = "app";
          program = "${package}/bin/estus";
        };
        apps.automation = {
          type = "app";
          program = "${automation}/bin/estus";
        };
        apps.automation-msrv = {
          type = "app";
          program = "${automationMsrv}/bin/estus";
        };
        apps.automation-acceptance = {
          type = "app";
          program = "${automationAcceptance package acceptance automation}/bin/automation-acceptance";
        };
        apps.automation-acceptance-msrv = {
          type = "app";
          program = "${automationAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv}/bin/automation-acceptance";
        };
        apps.runner-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/runner-acceptance";
        };
        apps.runner-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/runner-acceptance";
        };
        apps.projection-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/projection-acceptance";
        };
        apps.projection-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/projection-acceptance";
        };
        apps.role-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/role-acceptance";
        };
        apps.role-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/role-acceptance";
        };
        apps.playbook-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/playbook-acceptance";
        };
        apps.playbook-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/playbook-acceptance";
        };
        apps.authority-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/authority-acceptance";
        };
        apps.authority-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/authority-acceptance";
        };
        apps.isolated-runner-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/isolated-runner-acceptance";
        };
        apps.isolated-runner-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/isolated-runner-acceptance";
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
        apps.mkdir-acceptance = {
          type = "app";
          program = "${acceptance}/bin/mkdir-acceptance";
        };
        apps.mkdir-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/mkdir-acceptance";
        };
        apps.rename-acceptance = {
          type = "app";
          program = "${acceptance}/bin/rename-acceptance";
        };
        apps.rename-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/rename-acceptance";
        };
        apps.remove-file-acceptance = {
          type = "app";
          program = "${acceptance}/bin/remove-file-acceptance";
        };
        apps.remove-file-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/remove-file-acceptance";
        };
        apps.remove-directory-acceptance = {
          type = "app";
          program = "${acceptance}/bin/remove-directory-acceptance";
        };
        apps.remove-directory-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/remove-directory-acceptance";
        };
        apps.replace-file-acceptance = {
          type = "app";
          program = "${acceptance}/bin/replace-file-acceptance";
        };
        apps.replace-file-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/replace-file-acceptance";
        };
        apps.output-acceptance = {
          type = "app";
          program = "${acceptance}/bin/output-acceptance";
        };
        apps.output-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/output-acceptance";
        };
        apps.progress-acceptance = {
          type = "app";
          program = "${acceptance}/bin/progress-acceptance";
        };
        apps.progress-acceptance-msrv = {
          type = "app";
          program = "${msrvBuild.acceptance}/bin/progress-acceptance";
        };
        apps.runner-progress-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/progress-acceptance";
        };
        apps.runner-progress-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/progress-acceptance";
        };
        apps.host-summary-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/host-summary-acceptance";
        };
        apps.host-summary-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/host-summary-acceptance";
        };
        apps.cpu-stats-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/cpu-stats-acceptance";
        };
        apps.cpu-stats-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/cpu-stats-acceptance";
        };
        apps.memory-stats-acceptance = {
          type = "app";
          program = "${runnerAcceptance package acceptance}/bin/memory-stats-acceptance";
        };
        apps.memory-stats-acceptance-msrv = {
          type = "app";
          program = "${runnerAcceptance msrvBuild.package msrvBuild.acceptance}/bin/memory-stats-acceptance";
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
            pkgs.gnutar
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
