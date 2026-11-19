{ pkgs, sourceRoot, automationRuntime }:
pkgs.runCommand "estus-direct-module-bundle" {
  nativeBuildInputs = [ pkgs.coreutils ];
} ''
  export HOME="$TMPDIR"
  export ANSIBLE_HOME="$TMPDIR/ansible"
  export ANSIBLE_LOCAL_TEMP="$TMPDIR/ansible-local"
  export ANSIBLE_CONFIG="${automationRuntime}/ansible.cfg"
  export ANSIBLE_COLLECTIONS_PATH="${automationRuntime}/collections"
  export ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False"
  ${automationRuntime}/bin/python3 -I -B \
    ${sourceRoot}/nix/scripts/build-direct-module-bundle.py \
    ${automationRuntime} \
    "$out"
''
