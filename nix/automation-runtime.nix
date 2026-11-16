{ pkgs }:
let
  python = pkgs.python3;
  core = python.pkgs.ansible-core;
  runner = python.pkgs.ansible-runner;
  bundle = python.pkgs.ansible;
  environment = python.withPackages (_: [ core runner ]);
  healthSha256 = builtins.hashFile "sha256" ../src/automation/python/health.py;
  platform = pkgs.stdenv.hostPlatform.system;
  # Output and source identities pin the complete upstream provisioning choice.
  # Only the digest, never these store paths, is exposed in the public identity.
  runtimeId = builtins.hashString "sha256" (builtins.toJSON {
    schema = 1;
    inherit platform healthSha256;
    python = { output = toString python; source = toString python.src; };
    ansible_core = { output = toString core; source = toString core.src; };
    ansible_runner = { output = toString runner; source = toString runner.src; };
    collection_bundle = { output = toString bundle; source = toString bundle.src; };
    environment = toString environment;
  });
  collectionSource = "${bundle}/${python.sitePackages}/ansible_collections";
in
pkgs.runCommand "estus-automation-runtime" {
  nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
} ''
  mkdir -p "$out/bin" "$out/collections/ansible_collections/ansible" \
    "$out/collections/ansible_collections/community"
  ln -s ${environment} "$out/python"
  ln -s ${environment}/bin/python3 "$out/bin/python3"
  ln -s ${collectionSource}/ansible/posix "$out/collections/ansible_collections/ansible/posix"
  ln -s ${collectionSource}/community/general "$out/collections/ansible_collections/community/general"

  # No home/cwd config discovery or ambient collection registration is needed.
  cat > "$out/ansible.cfg" <<EOF
  [defaults]
  collections_path = $out/collections
  collections_scan_sys_path = False
  EOF

  collections='[]'
  for name in ansible.posix community.general; do
    namespace="''${name%%.*}"
    collection="''${name#*.}"
    manifest="$out/collections/ansible_collections/$namespace/$collection/MANIFEST.json"
    version=$(jq -er --arg namespace "$namespace" --arg collection "$collection" '
      .collection_info
      | select(.namespace == $namespace and .name == $collection)
      | .version | select(type == "string" and test("^[A-Za-z0-9_.+\\-]{1,128}$"))
    ' "$manifest")
    manifest_hash=$(sha256sum "$manifest")
    manifest_hash="''${manifest_hash%% *}"
    collections=$(jq -cn --argjson previous "$collections" --arg name "$name" \
      --arg version "$version" --arg hash "$manifest_hash" \
      '$previous + [{name: $name, version: $version, manifest_sha256: $hash}]')
  done

  jq -n --arg health ${pkgs.lib.escapeShellArg healthSha256} \
    --arg runtime ${pkgs.lib.escapeShellArg runtimeId} \
    --arg platform ${pkgs.lib.escapeShellArg platform} \
    --arg python ${pkgs.lib.escapeShellArg python.version} \
    --arg core ${pkgs.lib.escapeShellArg core.version} \
    --arg runner ${pkgs.lib.escapeShellArg runner.version} \
    --arg bundle ${pkgs.lib.escapeShellArg bundle.version} \
    --arg site ${pkgs.lib.escapeShellArg "python/${python.sitePackages}"} \
    --argjson collections "$collections" '
    {schema: 1, health_sha256: $health, site_packages: $site,
     identity: {runtime_id: $runtime, platform: $platform, python: $python,
       ansible_core: $core, ansible_runner: $runner, collection_bundle: $bundle,
       collections: ($collections | sort_by(.name))}}
  ' > "$out/runtime.json"
  test "$(wc -c < "$out/runtime.json")" -le 16384
  chmod 0444 "$out/ansible.cfg" "$out/runtime.json"
''
