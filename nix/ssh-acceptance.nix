{ pkgs, craneLib, commonArgs, cargoArtifacts, package }:
craneLib.mkCargoDerivation (commonArgs // {
  pnameSuffix = "-acceptance";
  inherit cargoArtifacts;
  doCheck = false;
  doInstallCargoArtifacts = false;
  nativeBuildInputs = [ pkgs.jq pkgs.makeWrapper ];
  # Compile the installed test executables against the actual wrapped package,
  # not a build-directory Cargo executable that disappears after installation.
  SSH_MCP_TEST_BINARY = "${package}/bin/ssh-mcp";
  buildPhaseCargoCommand = ''
    cargo test --release --locked --no-run --test stdio --test ssh_e2e --test ssh_local \
      --message-format=json-render-diagnostics > test-artifacts.json
  '';
  installPhaseCommand = ''
    mkdir -p "$out/bin" "$out/libexec"
    for name in stdio ssh_e2e ssh_local; do
      executable=$(jq -ers --arg name "$name" '
        [.[] | select(.reason == "compiler-artifact" and .profile.test
          and .target.name == $name and .executable != null)]
        | if length == 1 then .[0].executable
          else error("expected one compiled acceptance executable") end
      ' test-artifacts.json)
      install -m755 "$executable" "$out/libexec/$name"
    done
    makeWrapper "$out/libexec/stdio" "$out/bin/ssh-stdio" \
      --set SSH_MCP_TEST_BINARY ${package}/bin/ssh-mcp \
      --add-flags '--nocapture'
    makeWrapper "$out/libexec/ssh_local" "$out/bin/ssh-native" \
      --set SSH_MCP_TEST_BINARY ${package}/bin/ssh-mcp \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2'
    makeWrapper "$out/libexec/ssh_e2e" "$out/bin/ssh-baseline" \
      --set SSH_MCP_TEST_BINARY ${package}/bin/ssh-mcp \
      --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.openssh pkgs.docker-client pkgs.coreutils ]} \
      --add-flags '--ignored --nocapture --test-threads=2'
  '';
})
