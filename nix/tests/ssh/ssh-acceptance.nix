{ pkgs, craneLib, commonArgs, cargoArtifacts, package, controllerTestPrograms }:
let
  inherit (import ../libtest.nix { inherit pkgs; }) mkTestScript;
  mkFilteredRunner = name: listArgs: runArgs:
    mkTestScript {
      inherit name listArgs runArgs;
      harness = "\${ESTUS_LIBTEST_HARNESS:?}";
    };
in
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
    cargo test --release --locked --no-run --test stdio_protocol --test stdio_catalog --test stdio_files --test stdio_output --test stdio_exec --test stdio_policy --test stdio_tools --test stdio_controller --test ssh_e2e --test ssh_local_exec --test ssh_local_files --test ssh_local_output --test ssh_local_payload --test ssh_local_quarantine --test controller --test doctor --test bundle_cli --test wheel --test progress --test catalog --test catalog_cli --test catalog_distribution --test deployment_boundary --test payloads --test sftp_protocol \
      --message-format=json-render-diagnostics > test-artifacts.json
  '';
  installPhaseCommand = ''
    mkdir -p "$out/bin" "$out/libexec"
    for name in stdio_protocol stdio_catalog stdio_files stdio_output stdio_exec stdio_policy stdio_tools stdio_controller ssh_e2e ssh_local_exec ssh_local_files ssh_local_output ssh_local_payload ssh_local_quarantine controller doctor bundle_cli wheel progress catalog catalog_cli catalog_distribution deployment_boundary payloads sftp_protocol; do
      executable=$(jq -ers --arg name "$name" '
        [.[] | select(.reason == "compiler-artifact" and .profile.test
          and .target.name == $name and .executable != null)]
        | if length == 1 then .[0].executable
          else error("expected one compiled acceptance executable") end
      ' test-artifacts.json)
      install -m755 "$executable" "$out/libexec/$name"
    done
    cat > "$out/bin/ssh-stdio" <<EOF
    #!${pkgs.runtimeShell}
    set -eu
    export ESTUS_TEST_BINARY=${package}/bin/estus
    for suite in stdio_protocol stdio_catalog stdio_files stdio_output stdio_exec stdio_policy stdio_tools stdio_controller; do
      "$out/libexec/\$suite" --nocapture
    done
    EOF
    chmod +x "$out/bin/ssh-stdio"
    cat > "$out/bin/ssh-native" <<EOF
    #!${pkgs.runtimeShell}
    set -eu
    export ESTUS_TEST_BINARY=${package}/bin/estus
    for suite in ssh_local_exec ssh_local_files ssh_local_output ssh_local_payload ssh_local_quarantine; do
      "$out/libexec/\$suite" --ignored --nocapture --test-threads=2
    done
    EOF
    chmod +x "$out/bin/ssh-native"
    makeWrapper ${mkFilteredRunner "mkdir-acceptance" [ "--ignored" "ssh_mkdir" ] [ "--ignored" "--nocapture" "--test-threads=2" "ssh_mkdir" ]} "$out/bin/mkdir-acceptance" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/ssh_local_files" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}
    makeWrapper ${mkFilteredRunner "rename-acceptance" [ "--ignored" "ssh_rename" ] [ "--ignored" "--nocapture" "--test-threads=2" "ssh_rename" ]} "$out/bin/rename-acceptance" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/ssh_local_files" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}
    makeWrapper ${mkFilteredRunner "remove-file-acceptance" [ "--ignored" "ssh_remove_file" ] [ "--ignored" "--nocapture" "--test-threads=2" "ssh_remove_file" ]} "$out/bin/remove-file-acceptance" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/ssh_local_files" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}
    makeWrapper ${mkFilteredRunner "remove-directory-acceptance" [ "--ignored" "ssh_remove_directory" ] [ "--ignored" "--nocapture" "--test-threads=2" "ssh_remove_directory" ]} "$out/bin/remove-directory-acceptance" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/ssh_local_files" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}
    makeWrapper ${mkFilteredRunner "replace-file-acceptance" [ "--ignored" "ssh_replace_file" ] [ "--ignored" "--nocapture" "--test-threads=2" "ssh_replace_file" ]} "$out/bin/replace-file-acceptance" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/ssh_local_files" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}
    makeWrapper ${mkFilteredRunner "output-native" [ "--ignored" "ssh_output_" ] [ "--ignored" "--nocapture" "--test-threads=2" "ssh_output_" ]} "$out/bin/output-native" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/ssh_local_output" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]}
    makeWrapper ${mkFilteredRunner "output-controller" [ "--include-ignored" "controller_output_" ] [ "--include-ignored" "--nocapture" "--test-threads=2" "controller_output_" ]} "$out/bin/output-controller" \
      --set ESTUS_LIBTEST_HARNESS "$out/libexec/controller" \
      --set ESTUS_TEST_BINARY ${package}/bin/estus \
      --prefix PATH : ${pkgs.lib.makeBinPath controllerTestPrograms}
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
