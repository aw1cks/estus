{ pkgs, sourceRoot, automationRuntime }:
pkgs.runCommand "estus-direct-module-bundle" {
  nativeBuildInputs = [ pkgs.coreutils ];
} ''
  export HOME="$TMPDIR"
  export LC_ALL="C.UTF-8"
  export LANG="C.UTF-8"
  export ANSIBLE_HOME="$TMPDIR/ansible"
  export ANSIBLE_LOCAL_TEMP="$TMPDIR/ansible-local"
  export ANSIBLE_CONFIG="${automationRuntime}/ansible.cfg"
  export ANSIBLE_COLLECTIONS_PATH="${automationRuntime}/collections"
  export ANSIBLE_COLLECTIONS_SCAN_SYS_PATH="False"
  ${automationRuntime}/bin/python3 -I -X utf8 -B \
    ${sourceRoot}/src/bundle/builder.py \
    --runtime-root ${automationRuntime} \
    --output "$out"
''
