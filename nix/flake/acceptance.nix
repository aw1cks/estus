{ ... }:
{
  perSystem = { pkgs, estusBuild, ... }:
    let
      inherit (estusBuild) package acceptance msrvBuild automationRuntime wheel
        automation automationMsrv commonArgs catalogVm catalogLabVm;
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
      catalogAcceptance = native: harness: pkgs.runCommand "estus-catalog-acceptance" {
        nativeBuildInputs = [ pkgs.makeWrapper ];
      } ''
        mkdir -p "$out/bin"
        makeWrapper ${harness}/libexec/catalog "$out/bin/catalog-acceptance" \
          --set ESTUS_TEST_BINARY ${native}/bin/estus \
          --set ESTUS_TEST_ANSIBLE_RUNTIME ${automationRuntime} \
          --set ESTUS_TEST_CATALOG_ASSETS ${commonArgs.src}/catalog \
          --set ESTUS_TEST_CATALOG_VM ${catalogVm}/bin/catalog-guest \
          --set ESTUS_TEST_CATALOG_LAB_VM ${catalogLabVm}/bin/catalog-lab-guest \
          --prefix PATH : ${pkgs.lib.makeBinPath ([ pkgs.openssh pkgs.coreutils ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.procps ])} \
          --add-flags '--ignored --nocapture --test-threads=2'
      '';
      workflowAcceptance = native: harness:
        let
          catalog = pkgs.writeShellScriptBin "workflow-catalog-acceptance" ''
            exec ${catalogAcceptance native harness}/bin/catalog-acceptance workflows:: "$@"
          '';
          files = pkgs.runCommand "estus-workflow-files-acceptance" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
          } ''
            mkdir -p "$out/bin"
            makeWrapper ${harness}/libexec/deployment_boundary "$out/bin/workflow-files-acceptance" \
              --set ESTUS_TEST_BINARY ${native}/bin/estus \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils pkgs.bash pkgs.docker-client pkgs.gnutar ]} \
              --add-flags '--ignored --exact configuration_replacement_workflow --nocapture'
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
        automation-acceptance = automationAcceptance package acceptance automation;
        automation-acceptance-msrv = automationAcceptance msrvBuild.package msrvBuild.acceptance automationMsrv;
        runner-acceptance = runnerAcceptance package acceptance;
        runner-acceptance-msrv = runnerAcceptance msrvBuild.package msrvBuild.acceptance;
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
    };
}
