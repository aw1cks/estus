{ pkgs, sourceRoot }:
let
  python = pkgs.python3;
  core = python.pkgs.ansible-core;
  bundle = python.pkgs.ansible;
  environment = python.withPackages (_: [ core ]);
  selectedCollections = [
    "ansible.posix"
    "community.general"
    "community.library_inventory_filtering_v1"
  ];
  builderSha256 = builtins.hashFile "sha256" (sourceRoot + "/src/bundle/builder.py");
  platform = pkgs.stdenv.hostPlatform.system;
  runtimeId = builtins.hashString "sha256" (builtins.toJSON {
    schema = 1;
    inherit platform builderSha256 selectedCollections;
    python = { output = toString python; source = toString python.src; };
    ansible_core = { output = toString core; source = toString core.src; };
    collection_bundle = { output = toString bundle; source = toString bundle.src; };
    environment = toString environment;
  });
  collectionSource = "${bundle}/${python.sitePackages}/ansible_collections";
in
pkgs.runCommand "estus-automation-runtime" {
  nativeBuildInputs = [ pkgs.jq pkgs.coreutils ];
} ''
  mkdir -p "$out/bin" "$out/collections/ansible_collections"
  ln -s ${environment} "$out/python"
  ln -s ${environment}/bin/python3 "$out/bin/python3"
  for name in ${pkgs.lib.concatStringsSep " " selectedCollections}; do
    namespace="''${name%%.*}"
    collection="''${name#*.}"
    mkdir -p "$out/collections/ansible_collections/$namespace"
    ln -s "${collectionSource}/$namespace/$collection" \
      "$out/collections/ansible_collections/$namespace/$collection"
  done

  # No home/cwd config discovery or ambient collection registration is needed.
  cat > "$out/ansible.cfg" <<EOF
  [defaults]
  collections_path = $out/collections
  collections_scan_sys_path = False
  EOF

  collections='[]'
  for name in ${pkgs.lib.concatStringsSep " " selectedCollections}; do
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

  jq -n --arg builder ${pkgs.lib.escapeShellArg builderSha256} \
    --arg runtime ${pkgs.lib.escapeShellArg runtimeId} \
    --arg platform ${pkgs.lib.escapeShellArg platform} \
    --arg python ${pkgs.lib.escapeShellArg python.version} \
    --arg core ${pkgs.lib.escapeShellArg core.version} \
    --arg bundle ${pkgs.lib.escapeShellArg bundle.version} \
    --arg site ${pkgs.lib.escapeShellArg "python/${python.sitePackages}"} \
    --argjson collections "$collections" '
    {schema: 1, builder_sha256: $builder, site_packages: $site,
     identity: {runtime_id: $runtime, platform: $platform, python: $python,
       ansible_core: $core, collection_bundle: $bundle,
       collections: ($collections | sort_by(.name))}}
  ' > "$out/runtime.json"
  test "$(wc -c < "$out/runtime.json")" -le 16384
  chmod 0444 "$out/ansible.cfg" "$out/runtime.json"
''
