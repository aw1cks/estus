{ inputs, ... }:
{
  perSystem = { pkgs, ... }:
    let
      sourceRoot = ../..;
      craneLib = inputs.crane.mkLib pkgs;
      msrvToolchain = (pkgs.extend inputs.rust-overlay.overlays.default).rust-bin.stable."1.88.0".minimal;
      msrvLib = craneLib.overrideToolchain msrvToolchain;
      fuzzLib = craneLib.overrideToolchain (p:
        (p.extend inputs.rust-overlay.overlays.default).rust-bin.nightly."2026-11-10".default.override {
          extensions = [ "rust-src" ];
        }
      );
      commonArgs = {
        src = pkgs.lib.cleanSourceWith {
          src = sourceRoot;
          filter = path: type:
            path != "${toString sourceRoot}/fuzz"
            && (craneLib.filterCargoSources path type
              || (pkgs.lib.hasPrefix "${toString sourceRoot}/src/" path
                && pkgs.lib.hasSuffix ".py" path)
              || pkgs.lib.hasPrefix "${toString sourceRoot}/examples/" path
              || pkgs.lib.hasPrefix "${toString sourceRoot}/catalog/" path
              || pkgs.lib.hasPrefix "${toString sourceRoot}/vendor/openssh-sftp-client/" path
              || pkgs.lib.hasPrefix "${toString sourceRoot}/tests/catalog/fixtures/" path);
        };
        strictDeps = true;
        doCheck = true;
      };
      defaultBuild = import ../rust-build.nix {
        inherit pkgs craneLib commonArgs;
      };
      msrvBuild = import ../rust-build.nix {
        inherit pkgs;
        craneLib = msrvLib;
        commonArgs = commonArgs // { preBuild = "rustc --version"; };
        cargoTestExtraArgs = "--all-targets";
      };
      inherit (defaultBuild) package acceptance;
      automationRuntime = import ../automation-runtime.nix { inherit pkgs; };
      wheel = import ../wheel.nix { inherit pkgs; craneLib = msrvLib; };
      withAutomation = native: pkgs.runCommand "estus-automation-${native.version}" {
        nativeBuildInputs = [ pkgs.makeWrapper ];
        meta.mainProgram = "estus";
      } ''
        mkdir -p "$out/bin"
        makeWrapper ${native}/bin/estus "$out/bin/estus" \
          --set ESTUS_ANSIBLE_RUNTIME ${automationRuntime}
      '';
      automation = withAutomation package;
      automationMsrv = withAutomation msrvBuild.package;
      catalogVm = import ../catalog-vm.nix { inherit inputs; hostPkgs = pkgs; };
      catalogLabVm = import ../catalog-vm.nix { inherit inputs; hostPkgs = pkgs; lab = true; };
    in
    {
      _module.args.estusBuild = {
        inherit craneLib fuzzLib commonArgs msrvBuild package acceptance automationRuntime
          wheel automation automationMsrv catalogVm catalogLabVm;
      };
      packages = {
        default = package;
        msrv = msrvBuild.package;
        ssh-acceptance = acceptance;
        ssh-acceptance-msrv = msrvBuild.acceptance;
        automation-runtime = automationRuntime;
        inherit automation wheel;
        automation-msrv = automationMsrv;
        catalog-vm = catalogVm;
        catalog-lab-vm = catalogLabVm;
      } // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        ssh-fixture-image = import ../ssh-fixture.nix { inherit pkgs; };
        ssh-automation-fixture-image = import ../ssh-fixture.nix {
          inherit pkgs;
          automation = true;
        };
        deployment-fixture-image = import ../ssh-fixture.nix {
          inherit pkgs;
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
