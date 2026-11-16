{ pkgs, sourceRoot }:
let
  apt = pkgs.apt.overrideAttrs (old: {
    cmakeFlags = (old.cmakeFlags or [ ]) ++ [
      "-DSQV_EXECUTABLE=${pkgs.sequoia-sqv}/bin/sqv"
      "-DCMAKE_INSTALL_LIBEXECDIR=lib"
    ];
    # Runtime mutable paths differ from the immutable installation prefix.
    postPatch = (old.postPatch or "") + ''
      substituteInPlace CMake/config.h.in \
        --replace-fail '#cmakedefine CONF_DIR "''${CONF_DIR}"' '#define CONF_DIR "/etc/apt"' \
        --replace-fail '#cmakedefine STATE_DIR "''${STATE_DIR}"' '#define STATE_DIR "/var/lib/apt"' \
        --replace-fail '#cmakedefine CACHE_DIR "''${CACHE_DIR}"' '#define CACHE_DIR "/var/cache/apt"' \
        --replace-fail '#cmakedefine LOG_DIR "''${LOG_DIR}"' '#define LOG_DIR "/var/log/apt"'
    '';
  });
  python = pkgs.python3.withPackages (p: [ (p.python-apt.override { inherit apt; }) ]);
  runtimePackages = [ apt pkgs.dpkg pkgs.gnupg pkgs.sequoia-sqv python ];
  rootfs = pkgs.runCommand "estus-catalog-package-rootfs" {
    nativeBuildInputs = [ apt pkgs.dpkg pkgs.gnupg pkgs.coreutils pkgs.findutils pkgs.gnused pkgs.gzip pkgs.fakeroot ];
    fixtureSource = sourceRoot + "/tests/fixtures/catalog/packages";
    maintainerShell = "${pkgs.dash}/bin/dash";
    aptMethods = "${apt}/lib/apt/methods";
  } ''
    . ${sourceRoot + "/nix/scripts/build-catalog-package-fixture.sh"}
  '';
in
{ inherit apt rootfs python runtimePackages; }
