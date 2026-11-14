{ pkgs, craneLib, commonArgs, cargoArtifacts, package, controllerTestPrograms }:
craneLib.mkCargoDerivation (commonArgs // {
  pnameSuffix = "-acceptance";
  inherit cargoArtifacts;
  doCheck = false;
  doInstallCargoArtifacts = false;
  nativeBuildInputs = [ pkgs.jq pkgs.makeWrapper ];
  # Compile the installed test executables against the actual wrapped package,
  # not a build-directory Cargo executable that disappears after installation.
  ESTUS_TEST_BINARY = "${package}/bin/estus";
  buildPhaseCargoCommand = ''
    cargo test --release --locked --no-run --test stdio --test ssh_e2e --test ssh_local --test controller --test doctor --test automation --test automation_exec --test wheel --test progress \
      --message-format=json-render-diagnostics > test-artifacts.json
  '';
  installPhaseCommand = ''
    mkdir -p "$out/bin" "$out/libexec"
    for name in stdio ssh_e2e ssh_local controller doctor automation automation_exec wheel progress; do
      executable=$(jq -ers --arg name "$name" '
        [.[] | select(.reason == "compiler-artifact" and .profile.test
          and .target.name == $name and .executable != null)]
        | if length == 1 then .[0].executable
          else error("expected one compiled acceptance executable") end
      ' test-artifacts.json)
      install -m755 "$executable" "$out/libexec/$name"
    done
    makeWrapper "$out/libexec/stdio" "$out/bin/ssh-stdio" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --add-flags '--nocapture'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/ssh-native" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/mkdir-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2 ssh_mkdir'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/rename-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2 ssh_rename'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/remove-file-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2 ssh_remove_file'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/remove-directory-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2 ssh_remove_directory'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/replace-file-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2 ssh_replace_file'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/output-native" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2 ssh_output_'
    makeWrapper "$out/libexec/controller" "$out/bin/output-controller" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath controllerTestPrograms} \
      --add-flags '--include-ignored --nocapture --test-threads=2 controller_output_'
    cat > "$out/bin/output-acceptance" <<EOF
    #!${pkgs.runtimeShell}
    set -eu
    "$out/bin/output-native"
    "$out/bin/output-controller"
    EOF
    chmod +x "$out/bin/output-acceptance"
    makeWrapper "$out/libexec/progress" "$out/bin/progress-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2'
    makeWrapper "$out/libexec/ssh_e2e" "$out/bin/ssh-baseline" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.docker-client pkgs.coreutils pkgs.gnutar ]} \
      --add-flags '--ignored --nocapture --test-threads=2'
    makeWrapper "$out/libexec/controller" "$out/bin/controller-scripts" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath controllerTestPrograms} \
      --add-flags '--include-ignored --nocapture --test-threads=2'
    makeWrapper "$out/libexec/doctor" "$out/bin/doctor-acceptance" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils pkgs.bash ]} \
      --add-flags '--include-ignored --nocapture --test-threads=2'
  '';
})
