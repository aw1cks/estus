# The native Estus build against one package set. The flake's own packages and
# `overlays.default` both come from here, so an overlay user builds exactly
# what CI builds, only on their nixpkgs.
{ inputs, pkgs, sourceRoot }:
let
  craneLib = inputs.crane.mkLib pkgs;
  commonArgs = {
    src = pkgs.lib.cleanSourceWith {
      src = sourceRoot;
      filter = path: type:
        path != "${toString sourceRoot}/fuzz"
        && path != "${toString sourceRoot}/nix/result"
        && !pkgs.lib.hasPrefix "${toString sourceRoot}/nix/result/" path
        && (craneLib.filterCargoSources path type
          || (pkgs.lib.hasPrefix "${toString sourceRoot}/src/" path
            && pkgs.lib.hasSuffix ".py" path)
          || pkgs.lib.hasPrefix "${toString sourceRoot}/examples/" path
          || pkgs.lib.hasPrefix "${toString sourceRoot}/catalog/" path
          || path == "${toString sourceRoot}/skills/estus-sre/SKILL.md"
          || path == "${toString sourceRoot}/pyproject.toml"
          || path == "${toString sourceRoot}/python/estus/__init__.py"
          || path == "${toString sourceRoot}/setup.py"
          || pkgs.lib.hasPrefix "${toString sourceRoot}/tests/fixtures/catalog/" path);
    };
    strictDeps = true;
    doCheck = true;
  };
  defaultBuild = import ./rust-build.nix { inherit pkgs craneLib commonArgs; };
  automationRuntime = import ./automation-runtime.nix { inherit pkgs sourceRoot; };
  directModuleBundle = import ./direct-module-bundle.nix { inherit pkgs sourceRoot automationRuntime; };
  withAutomation = native: pkgs.runCommand "estus-automation-${native.version}" {
    nativeBuildInputs = [ pkgs.makeWrapper ];
    meta.mainProgram = "estus";
  } ''
    mkdir -p "$out/bin"
    makeWrapper ${native}/bin/estus "$out/bin/estus" \
      --set ESTUS_ANSIBLE_BUNDLE ${directModuleBundle}
  '';
in
{
  inherit craneLib commonArgs defaultBuild automationRuntime directModuleBundle withAutomation;
  automation = withAutomation defaultBuild.package;
}
