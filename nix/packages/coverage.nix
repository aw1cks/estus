# Line coverage of the network-free Rust tests, for Codecov: $out/lcov.info,
# and nextest's JUnit report, $out/junit.xml, for its test analytics.
#
# A failing test still yields both (--ignore-run-fail), so failures reach
# Codecov; CI fails the job afterwards from the JUnit report. The tests' gate is
# the ordinary `cargo test` in `nix flake check`.
#
# `craneLib` must use an official Rust toolchain with llvm-tools-preview:
# instrumented build scripts crash at exit with nixpkgs' rustc.
{ pkgs, craneLib, commonArgs, controllerTestPrograms }:
let
  # nixpkgs builds cargo-llvm-cov against a newer LLVM than its rustc, and the
  # package's own tests fail for that, so it isn't in the binary cache. The tool
  # is fine: it uses the toolchain's llvm-tools, not that LLVM.
  coverageLib = craneLib.overrideScope (_final: _prev: {
    cargo-llvm-cov = pkgs.cargo-llvm-cov.overrideAttrs { doCheck = false; };
  });
in
coverageLib.cargoNextest (commonArgs // {
  pname = "estus-coverage";
  cargoArtifacts = coverageLib.buildDepsOnly commonArgs;
  nativeCheckInputs = controllerTestPrograms ++ [ pkgs.openssh pkgs.python314 ];
  withLlvmCov = true;
  cargoLlvmCovExtraArgs = "--ignore-run-fail --lcov --output-path $out/lcov.info";
  cargoNextestExtraArgs = "--config-file ${../../.config/nextest.toml} --profile ci";
  doInstallCargoArtifacts = false;
  postCheck = ''
    install -m644 "$(find target -path '*/nextest/ci/junit.xml' | head -n1)" "$out/junit.xml"
  '';
})
