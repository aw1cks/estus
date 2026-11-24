{ pkgs, craneLib, sourceRoot }:
let
  lib = pkgs.lib;
  metadata = (lib.importTOML (sourceRoot + "/pyproject.toml")).project;
  # Use the upstream backend wheel, not nixpkgs' older setuptools or a
  # second implementation of our project's packaging metadata.
  python = pkgs.python3.override {
    packageOverrides = final: prev: {
      setuptools = final.buildPythonPackage {
        pname = "setuptools";
        version = "84.2.1";
        format = "wheel";
        src = pkgs.fetchurl {
          url = "https://files.pythonhosted.org/packages/py3/s/setuptools/setuptools-84.2.1-py3-none-any.whl";
          hash = "sha256-yhQLRdUyWpR4+IDjUUhPYv7xXzNkYuRJygwDyHPVicI=";
        };
        doCheck = false;
      };
    };
  };
  buildPython = python.withPackages (p: [ p.build p.setuptools p.setuptools-rust ]);
  linux = pkgs.stdenv.hostPlatform.isLinux;
  target = pkgs.stdenv.hostPlatform.rust.rustcTarget;
  platformTag = if linux then
    "manylinux_2_17_${pkgs.stdenv.hostPlatform.uname.processor}"
  else
    "macosx_11_0_arm64";
  wheelName = "${lib.replaceStrings [ "-" ] [ "_" ] metadata.name}-${metadata.version}-py3-none-${platformTag}.whl";
  wheelSrc = lib.cleanSourceWith {
    src = sourceRoot;
    filter = path: type:
      let relative = lib.removePrefix "${toString sourceRoot}/" path;
      in !builtins.elem relative [ "fuzz" "tests" "nix/result" ]
      && !lib.hasPrefix "nix/result/" relative
      && !lib.hasPrefix "tests/" relative && (
        craneLib.filterCargoSources path type
        || builtins.elem relative [ "pyproject.toml" "setup.py" "MANIFEST.in" "README.md" "LICENSE" ]
        || (lib.hasPrefix "catalog/" relative
          && !lib.hasInfix "/__pycache__/" relative
          && !lib.hasSuffix ".pyc" relative
          && !lib.hasSuffix ".pyo" relative)
        || (lib.hasPrefix "python/" relative && lib.hasSuffix ".py" relative)
        || (lib.hasPrefix "src/" relative && lib.hasSuffix ".py" relative)
      );
  };
in
craneLib.mkCargoDerivation {
  pname = "${metadata.name}-wheel";
  inherit (metadata) version;
  src = wheelSrc;
  strictDeps = true;
  cargoArtifacts = null;
  doInstallCargoArtifacts = false;
  doIncludeCrossToolchainEnv = false;
  doCheck = false;
  # Never let fixup turn the portable payload into a Nix-linked executable.
  dontFixup = true;
  nativeBuildInputs = [ buildPython ] ++ (if linux then
    [ pkgs.cargo-zigbuild pkgs.zig ]
  else
    [ pkgs.llvmPackages.clang-unwrapped pkgs.llvmPackages.lld ]);
  CARGO_NET_OFFLINE = "true";
  # setuptools-rust supports cargo-zigbuild directly (including Exec bindings).
  # Use it only for Linux: Zig's macOS target defaults can override Rust's
  # deployment target. Native unwrapped Clang/LLD honor the explicit minimum.
  CARGO = if linux then "${pkgs.cargo-zigbuild}/bin/cargo-zigbuild" else "cargo";
  CARGO_BUILD_TARGET = target + lib.optionalString linux ".2.17";
  MACOSX_DEPLOYMENT_TARGET = "11.0";
  preBuild = lib.optionalString (!linux) ''
    # Reapply after Nix dependency setup hooks have selected their own minimum.
    # Cargo's documented force setting also pins every rustc/build-script child,
    # independently of the Python build interpreter's deployment baseline.
    export MACOSX_DEPLOYMENT_TARGET=11.0
    printf '\n[env]\nMACOSX_DEPLOYMENT_TARGET = { value = "11.0", force = true }\n' >> "$CARGO_HOME/config.toml"
    export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER="${lib.getBin pkgs.llvmPackages.clang-unwrapped}/bin/clang"
    # The Nix Apple SDK omits iconv. Reuse cargo-zigbuild's pinned Apple
    # system-library stubs, not GNU libiconv or a Nix-store dynamic library.
    export RUSTFLAGS="-C link-arg=-fuse-ld=${lib.getBin pkgs.llvmPackages.lld}/bin/ld64.lld -C link-arg=-Wl,-fatal_warnings -C link-arg=-mmacosx-version-min=11.0 -C link-arg=-isysroot -C link-arg=''${SDKROOT:?Apple SDK is required} -L native=${pkgs.cargo-zigbuild.src}/src/macos"
  '';
  buildPhaseCargoCommand = ''
    export HOME="$TMPDIR/wheel-home"
    export ZIG_GLOBAL_CACHE_DIR="$TMPDIR/zig-global-cache"
    export ZIG_LOCAL_CACHE_DIR="$TMPDIR/zig-local-cache"
    export CARGO_ZIGBUILD_CACHE_DIR="$TMPDIR/cargo-zigbuild"
    mkdir -p "$HOME"
    export DIST_EXTRA_CONFIG="$TMPDIR/wheel-platform.cfg"
    printf '[bdist_wheel]\nplat_name=${platformTag}\n' > "$DIST_EXTRA_CONFIG"
    python -m build --wheel --no-isolation --outdir dist
  '';
  installPhaseCommand = ''
    mkdir -p "$out"
    install -m644 "dist/${wheelName}" "$out/${wheelName}"
  '';
  passthru = {
    inherit wheelName platformTag buildPython wheelSrc;
  };
}
