{ inputs, ... }:
{
  perSystem = { pkgs, ... }:
    let
      sourceRoot = ../..;
      native = import ../packages/estus.nix { inherit inputs pkgs sourceRoot; };
      inherit (native) craneLib commonArgs defaultBuild automationRuntime directModuleBundle withAutomation automation;
      msrvToolchain = (pkgs.extend inputs.rust-overlay.overlays.default).rust-bin.stable."1.88.0".minimal;
      msrvLib = craneLib.overrideToolchain msrvToolchain;
      fuzzLib = craneLib.overrideToolchain (p:
        (p.extend inputs.rust-overlay.overlays.default).rust-bin.nightly."2026-11-10".default.override {
          extensions = [ "rust-src" ];
        }
      );
      # Coverage needs an official toolchain with llvm-tools; see coverage.nix.
      coverageLib = craneLib.overrideToolchain (p:
        (p.extend inputs.rust-overlay.overlays.default).rust-bin.stable.latest.minimal.override {
          extensions = [ "llvm-tools-preview" ];
        }
      );
      msrvBuild = import ../packages/rust-build.nix {
        inherit pkgs;
        craneLib = msrvLib;
        commonArgs = commonArgs // { preBuild = "rustc --version"; };
        cargoTestExtraArgs = "--all-targets";
      };
      inherit (defaultBuild) cargoArtifacts package acceptance buildTimings;
      coverage = import ../packages/coverage.nix {
        inherit pkgs commonArgs;
        craneLib = coverageLib;
        inherit (defaultBuild) controllerTestPrograms;
      };
      wheel = import ../packages/wheel.nix { inherit pkgs sourceRoot; craneLib = msrvLib; };
      cargoVendor = msrvLib.vendorCargoDeps commonArgs;
      automationMsrv = withAutomation msrvBuild.package;
      catalogVm = import ../tests/catalog/catalog-vm.nix { inherit inputs sourceRoot; hostPkgs = pkgs; };
      catalogLabVm = import ../tests/catalog/catalog-vm.nix { inherit inputs sourceRoot; hostPkgs = pkgs; lab = true; };
    in
    {
      _module.args.estusBuild = {
        inherit craneLib fuzzLib commonArgs msrvBuild msrvToolchain cargoVendor cargoArtifacts
          package acceptance automationRuntime directModuleBundle wheel automation automationMsrv catalogVm
          catalogLabVm;
      };
      packages = {
        default = package;
        msrv = msrvBuild.package;
        ssh-acceptance = acceptance;
        ssh-acceptance-msrv = msrvBuild.acceptance;
        automation-runtime = automationRuntime;
        direct-module-bundle = directModuleBundle;
        inherit automation wheel coverage;
        build-timings = buildTimings;
        automation-msrv = automationMsrv;
        catalog-vm = catalogVm;
        catalog-lab-vm = catalogLabVm;
      } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        ssh-fixture-image = import ../tests/ssh/ssh-fixture.nix { inherit pkgs sourceRoot; };
        ssh-automation-fixture-image = import ../tests/ssh/ssh-fixture.nix {
          inherit pkgs sourceRoot;
          automation = true;
        };
        deployment-fixture-image = import ../tests/ssh/ssh-fixture.nix {
          inherit pkgs sourceRoot;
          servicePackage = package;
        };
      };
      apps.default = {
        type = "app";
        program = "${package}/bin/estus";
      };
      apps.automation = {
        type = "app";
        program = "${automation}/bin/estus";
      };
      apps.automation-msrv = {
        type = "app";
        program = "${automationMsrv}/bin/estus";
      };
    };
}
