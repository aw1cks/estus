{ ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) package acceptance msrvBuild msrvToolchain cargoVendor automationRuntime
        directModuleBundle wheel automation automationMsrv commonArgs catalogVm catalogLabVm;
      inherit (import ../tests/libtest.nix { inherit pkgs; }) mkTestScript;
      runExactTest = { name, harness, scenario, extraFlags ? [ "--nocapture" ], extraSetup ? "" }:
        mkTestScript {
          inherit name harness extraSetup;
          exactScenario = scenario;
          listArgs = [ "--ignored" "--exact" scenario ];
          runArgs = [ "--ignored" "--exact" scenario ] ++ extraFlags;
        };
      runFilteredTest = { name, harness, listArgs, runArgs }:
        mkTestScript {
          inherit name harness listArgs runArgs;
        };
      wheelFlags = [
        "--ignored"
        "--skip"
        "source_distribution_roundtrip_preserves_manifest_selected_assets"
      ];
      wheelRunner = runFilteredTest {
        name = "wheel-acceptance";
        harness = "${msrvBuild.acceptance}/libexec/wheel";
        listArgs = wheelFlags;
        runArgs = wheelFlags ++ [ "--nocapture" "--test-threads=1" ];
      };
      wheelAcceptance = pkgs.runCommand "estus-wheel-acceptance" {
        nativeBuildInputs = [ pkgs.makeWrapper ];
      } ''
        mkdir -p "$out/bin"
        makeWrapper ${wheelRunner} "$out/bin/wheel-acceptance" \
          --set ESTUS_TEST_WHEEL ${wheel}/${wheel.wheelName} \
          --set ESTUS_TEST_STDIO_PROTOCOL ${msrvBuild.acceptance}/libexec/stdio_protocol \
          --set ESTUS_TEST_STDIO_CATALOG ${msrvBuild.acceptance}/libexec/stdio_catalog \
          --set ESTUS_TEST_STDIO_FILES ${msrvBuild.acceptance}/libexec/stdio_files \
          --set ESTUS_TEST_STDIO_OUTPUT ${msrvBuild.acceptance}/libexec/stdio_output \
          --set ESTUS_TEST_STDIO_EXEC ${msrvBuild.acceptance}/libexec/stdio_exec \
          --set ESTUS_TEST_STDIO_POLICY ${msrvBuild.acceptance}/libexec/stdio_policy \
          --set ESTUS_TEST_STDIO_TOOLS ${msrvBuild.acceptance}/libexec/stdio_tools \
          --set ESTUS_TEST_STDIO_CONTROLLER ${msrvBuild.acceptance}/libexec/stdio_controller \
          --set ESTUS_TEST_CONTROLLER_SUITE ${msrvBuild.acceptance}/libexec/controller \
          --set ESTUS_TEST_BINARY ${msrvBuild.package}/bin/estus \
          --set ESTUS_TEST_ANSIBLE_BUNDLE ${directModuleBundle} \
          --set ESTUS_TEST_CATALOG_ASSETS ${msrvBuild.package}/share/estus/catalog \
          --prefix PATH : ${pkgs.lib.makeBinPath (
            [ pkgs.uv pkgs.openssh pkgs.coreutils pkgs.bash pkgs.unzip pkgs.llvmPackages.llvm ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ]
          )}
      '';
      sourceArchive = pkgs.runCommand "estus-source-archive.tar.gz" {
        nativeBuildInputs = [ pkgs.gnutar pkgs.gzip ];
      } ''
        tar --mode='u+w' -czf "$out" -C ${wheel.wheelSrc} .
      '';
      sdistRunner = runExactTest {
        name = "sdist-acceptance";
        harness = "${msrvBuild.acceptance}/libexec/wheel";
        scenario = "source_distribution_roundtrip_preserves_manifest_selected_assets";
        extraFlags = [ "--nocapture" "--test-threads=1" ];
        extraSetup = ''
          ESTUS_CLEANUP_DIR=$(${pkgs.coreutils}/bin/mktemp -d)
          export ESTUS_CLEANUP_DIR
          export CARGO_HOME="$ESTUS_CLEANUP_DIR"
          export CARGO_NET_OFFLINE=true
          ${pkgs.coreutils}/bin/install -m600 ${cargoVendor}/config.toml "$CARGO_HOME/config.toml"
        '';
      };
      sdistAcceptance = pkgs.runCommand "estus-sdist-acceptance" {
        nativeBuildInputs = [ pkgs.makeWrapper ];
      } ''
        mkdir -p "$out/bin"
        makeWrapper ${sdistRunner} "$out/bin/sdist-acceptance" \
          --set ESTUS_TEST_SOURCE_ARCHIVE ${sourceArchive} \
          --set ESTUS_TEST_BUILD_PYTHON ${wheel.buildPython}/bin/python \
          --set ESTUS_TEST_NATIVE_CATALOG ${msrvBuild.package}/share/estus/catalog \
          --set ESTUS_TEST_WHEEL ${wheel}/${wheel.wheelName} \
          --set ESTUS_TEST_STDIO_PROTOCOL ${msrvBuild.acceptance}/libexec/stdio_protocol \
          --set ESTUS_TEST_STDIO_CATALOG ${msrvBuild.acceptance}/libexec/stdio_catalog \
          --set ESTUS_TEST_STDIO_FILES ${msrvBuild.acceptance}/libexec/stdio_files \
          --set ESTUS_TEST_STDIO_OUTPUT ${msrvBuild.acceptance}/libexec/stdio_output \
          --set ESTUS_TEST_STDIO_EXEC ${msrvBuild.acceptance}/libexec/stdio_exec \
          --set ESTUS_TEST_STDIO_POLICY ${msrvBuild.acceptance}/libexec/stdio_policy \
          --set ESTUS_TEST_STDIO_TOOLS ${msrvBuild.acceptance}/libexec/stdio_tools \
          --set ESTUS_TEST_STDIO_CONTROLLER ${msrvBuild.acceptance}/libexec/stdio_controller \
          --set ESTUS_TEST_CONTROLLER_SUITE ${msrvBuild.acceptance}/libexec/controller \
          --set ESTUS_TEST_BINARY ${msrvBuild.package}/bin/estus \
          --set ESTUS_TEST_ANSIBLE_BUNDLE ${directModuleBundle} \
          --set ESTUS_TEST_CATALOG_ASSETS ${msrvBuild.package}/share/estus/catalog \
          --prefix PATH : ${pkgs.lib.makeBinPath (
            [ pkgs.uv pkgs.openssh pkgs.coreutils pkgs.bash pkgs.unzip pkgs.llvmPackages.llvm
              pkgs.gnutar pkgs.gzip msrvToolchain pkgs.stdenv.cc ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ]
          )} \
          ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin
            # Rust links -liconv on Darwin. The cc wrapper only finds it inside a
            # Nix build environment, and this test builds the sdist outside one.
            "--prefix LIBRARY_PATH : ${pkgs.libiconv}/lib"}
      '';
      bundleAcceptance = native: harness: optional:
        pkgs.runCommand "estus-bundle-acceptance" {
          nativeBuildInputs = [ pkgs.makeWrapper ];
        } ''
          mkdir -p "$out/bin"
          makeWrapper ${harness}/libexec/bundle_cli "$out/bin/bundle-acceptance" \
            --set ESTUS_TEST_BINARY ${native}/bin/estus \
            --set ESTUS_TEST_AUTOMATION_BINARY ${optional}/bin/estus \
            --set ESTUS_TEST_ANSIBLE_PYTHON ${automationRuntime}/bin/python3 \
            --set ESTUS_TEST_ANSIBLE_BUNDLE ${directModuleBundle} \
            --set ANSIBLE_COLLECTIONS_PATH ${automationRuntime}/collections \
            --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
            --add-flags '--include-ignored --nocapture --test-threads=2'
        '';
      catalogAcceptance = native: harness: pkgs.runCommand "estus-catalog-acceptance" {
        nativeBuildInputs = [ pkgs.makeWrapper ];
      } ''
        mkdir -p "$out/bin"
        makeWrapper ${harness}/libexec/catalog "$out/bin/catalog-acceptance" \
          --set ESTUS_TEST_BINARY ${native}/bin/estus \
          --set ESTUS_TEST_ANSIBLE_BUNDLE ${directModuleBundle} \
          --set ESTUS_TEST_CATALOG_ASSETS ${commonArgs.src}/catalog \
          --set ESTUS_TEST_CATALOG_VM ${catalogVm}/bin/catalog-guest \
          --set ESTUS_TEST_CATALOG_LAB_VM ${catalogLabVm}/bin/catalog-lab-guest \
          --prefix PATH : ${pkgs.lib.makeBinPath ([ pkgs.openssh pkgs.coreutils ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ])} \
          --add-flags '--ignored --nocapture --test-threads=2'
      '';
      workflowAcceptance = native: harness:
        let
          catalogRunner = runFilteredTest {
            name = "workflow-catalog-acceptance";
            harness = "${harness}/libexec/catalog";
            listArgs = [ "--ignored" "workflows::" ];
            runArgs = [ "--ignored" "--nocapture" "--test-threads=2" "workflows::" ];
          };
          catalog = pkgs.runCommand "estus-workflow-catalog-acceptance" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          } ''
            mkdir -p "$out/bin"
            makeWrapper ${catalogRunner} "$out/bin/workflow-catalog-acceptance" \
              --set ESTUS_TEST_BINARY ${native}/bin/estus \
              --set ESTUS_TEST_ANSIBLE_BUNDLE ${directModuleBundle} \
              --set ESTUS_TEST_CATALOG_ASSETS ${commonArgs.src}/catalog \
              --set ESTUS_TEST_CATALOG_VM ${catalogVm}/bin/catalog-guest \
              --set ESTUS_TEST_CATALOG_LAB_VM ${catalogLabVm}/bin/catalog-lab-guest \
              --prefix PATH : ${pkgs.lib.makeBinPath ([ pkgs.openssh pkgs.coreutils ]
                ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ])}
          '';
          filesRunner = runExactTest {
            name = "workflow-files-acceptance";
            harness = "${harness}/libexec/deployment_boundary";
            scenario = "configuration_replacement_workflow";
          };
          files = pkgs.runCommand "estus-workflow-files-acceptance" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          } ''
            mkdir -p "$out/bin"
            makeWrapper ${filesRunner} "$out/bin/workflow-files-acceptance" \
              --set ESTUS_TEST_BINARY ${native}/bin/estus \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils pkgs.bash pkgs.docker-client pkgs.gnutar ]}
          '';
          all = pkgs.writeShellScriptBin "workflow-acceptance" ''
            set -eu
            ${catalog}/bin/workflow-catalog-acceptance
            exec ${files}/bin/workflow-files-acceptance "$@"
          '';
        in { inherit catalog files all; };
    in
    {
      packages = {
        catalog-acceptance = catalogAcceptance package acceptance;
        catalog-acceptance-msrv = catalogAcceptance msrvBuild.package msrvBuild.acceptance;
        bundle-acceptance = bundleAcceptance package acceptance automation;
        bundle-acceptance-msrv = bundleAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv;
        workflow-acceptance = (workflowAcceptance package acceptance).all;
        workflow-acceptance-msrv = (workflowAcceptance msrvBuild.package msrvBuild.acceptance).all;
      };
      apps.catalog-acceptance = {
        type = "app";
        program = "${catalogAcceptance package acceptance}/bin/catalog-acceptance";
      };
      apps.catalog-acceptance-msrv = {
        type = "app";
        program = "${catalogAcceptance msrvBuild.package msrvBuild.acceptance}/bin/catalog-acceptance";
      };
      apps.workflow-acceptance = {
        type = "app";
        program = "${(workflowAcceptance package acceptance).all}/bin/workflow-acceptance";
      };
      apps.workflow-acceptance-msrv = {
        type = "app";
        program = "${(workflowAcceptance msrvBuild.package msrvBuild.acceptance).all}/bin/workflow-acceptance";
      };
      apps.workflow-catalog-acceptance = {
        type = "app";
        program = "${(workflowAcceptance package acceptance).catalog}/bin/workflow-catalog-acceptance";
      };
      apps.workflow-catalog-acceptance-msrv = {
        type = "app";
        program = "${(workflowAcceptance msrvBuild.package msrvBuild.acceptance).catalog}/bin/workflow-catalog-acceptance";
      };
      apps.workflow-files-acceptance = {
        type = "app";
        program = "${(workflowAcceptance package acceptance).files}/bin/workflow-files-acceptance";
      };
      apps.workflow-files-acceptance-msrv = {
        type = "app";
        program = "${(workflowAcceptance msrvBuild.package msrvBuild.acceptance).files}/bin/workflow-files-acceptance";
      };
      apps.bundle-acceptance = {
        type = "app";
        program = "${bundleAcceptance package acceptance automation}/bin/bundle-acceptance";
      };
      apps.bundle-acceptance-msrv = {
        type = "app";
        program = "${bundleAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv}/bin/bundle-acceptance";
      };
      apps.wheel-acceptance = {
        type = "app";
        program = "${wheelAcceptance}/bin/wheel-acceptance";
      };
      apps.sdist-acceptance = {
        type = "app";
        program = "${sdistAcceptance}/bin/sdist-acceptance";
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
    };
}
