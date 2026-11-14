{ pkgs }:
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
  } ''
    export SOURCE_DATE_EPOCH=1700000000
    export GNUPGHOME="$TMPDIR/test-signing-key"
    mkdir -m 700 "$GNUPGHOME"
    # Checked-in unencrypted PUBLIC TEST KEY. Never trust this identity outside this disposable VM.
    gpg --batch --import ${./catalog-package-fixture/test-only-signing-key.asc}
    mkdir -p "$out"/{etc/apt/sources.list.d,etc/apt/apt.conf.d,usr/share/keyrings,opt/estus-catalog,var/lib/dpkg/{info,updates,triggers},var/lib/apt/{lists/partial,periodic},var/cache/apt/archives/partial,var/log/apt}
    touch "$out/var/lib/dpkg/status" "$out/var/lib/dpkg/available" "$out/var/lib/dpkg/diversions" "$out/var/lib/dpkg/statoverride"
    gpg --batch --export > "$out/usr/share/keyrings/estus-catalog.gpg"
    for repository in a b; do
      mkdir -p "$out/opt/estus-catalog/repo-$repository/pool"
      if [ "$repository" = a ]; then versions='1.0 2.0'; else versions='3.0'; fi
      for name in estus-catalog-base estus-catalog-demo; do
        for version in $versions; do
          tree="$TMPDIR/$name-$version"
          mkdir -p "$tree/DEBIAN" "$tree/usr/share/estus-catalog"
          cat > "$tree/DEBIAN/control" <<EOF
    Package: $name
    Version: $version
    Architecture: all
    Maintainer: Estus Fixture <fixture.invalid@example.invalid>
    Description: Tiny local signed catalog acceptance package
    Section: misc
    Priority: optional
    EOF
          printf '%s %s\n' "$name" "$version" > "$tree/usr/share/estus-catalog/$name"
          # DPKG_ROOT makes the same real scripts work during rootless image assembly and in the guest.
          cat > "$tree/DEBIAN/postinst" <<EOF
    #!${pkgs.dash}/bin/dash
    set -eu
    mkdir -p "\''${DPKG_ROOT}/var/lib/estus-catalog"
    printf '%s\\n' '$name $version configured' >> "\''${DPKG_ROOT}/var/lib/estus-catalog/package-effects"
    EOF
          cat > "$tree/DEBIAN/postrm" <<EOF
    #!${pkgs.dash}/bin/dash
    set -eu
    mkdir -p "\''${DPKG_ROOT}/var/lib/estus-catalog"
    printf '%s\\n' '$name $version removed' >> "\''${DPKG_ROOT}/var/lib/estus-catalog/package-effects"
    EOF
          chmod 755 "$tree/DEBIAN/postinst" "$tree/DEBIAN/postrm"
          dpkg-deb --root-owner-group --build "$tree" "$out/opt/estus-catalog/repo-$repository/pool/''${name}_''${version}_all.deb"
        done
      done
      (
        cd "$out/opt/estus-catalog/repo-$repository"
        # Generate indexes directly from the real .deb control records, not handwritten package facts.
        : > Packages
        for deb in pool/*.deb; do
          dpkg-deb --field "$deb" >> Packages
          printf 'Filename: %s\nSize: %s\nSHA256: %s\n\n' "$deb" "$(stat -c %s "$deb")" "$(sha256sum "$deb" | cut -d ' ' -f 1)" >> Packages
        done
        cat > Release <<EOF
    Origin: Estus Catalog Fixture
    Label: Estus Catalog Fixture $repository
    Suite: stable
    Codename: fixture
    Date: Tue, 14 Nov 2023 22:13:20 UTC
    Architectures: all
    Description: Local-only signed test repository
    SHA256:
     $(sha256sum Packages | cut -d ' ' -f 1) $(stat -c %s Packages) Packages
    EOF
        gpg --batch --yes --pinentry-mode loopback --passphrase "" --faked-system-time 1700000000 --clearsign --output InRelease Release
        gpg --batch --yes --pinentry-mode loopback --passphrase "" --faked-system-time 1700000000 --detach-sign --output Release.gpg Release
      )
    done
    # Real dpkg populates status/info and executes the baseline's actual maintainer script at build time.
    fakeroot dpkg --root="$out" --force-not-root --force-script-chrootless --force-bad-path \
      --install "$out/opt/estus-catalog/repo-a/pool/estus-catalog-base_1.0_all.deb"
    cat > "$out/etc/apt/apt.conf" <<EOF
    Dir::Etc "/etc/apt";
    Dir::State "/var/lib/apt";
    Dir::State::status "/var/lib/dpkg/status";
    Dir::Cache "/var/cache/apt";
    Dir::Bin::dpkg "/usr/bin/dpkg";
    Dir::Bin::Methods "${apt}/lib/apt/methods";
    Acquire::Retries "0";
    APT::Get::List-Cleanup "true";
    Acquire::Languages "none";
    APT::Sandbox::User "root";
    EOF
    # Authenticate and populate lists while building; only a temporary build-local file URI is used.
    printf 'deb [signed-by=%s/usr/share/keyrings/estus-catalog.gpg] file:%s/opt/estus-catalog/repo-a ./\n' "$out" "$out" > "$TMPDIR/build-sources.list"
    apt-get -o Dir::Etc::main="$out/etc/apt/apt.conf" \
      -o Dir::Etc::sourcelist="$TMPDIR/build-sources.list" -o Dir::Etc::sourceparts=- \
      -o Dir::State="$out/var/lib/apt" -o Dir::State::status="$out/var/lib/dpkg/status" \
      -o Dir::Cache="$out/var/cache/apt" -o APT::Sandbox::User=root \
      -o Acquire::Languages=none -o Acquire::AllowInsecureRepositories=false \
      -o APT::Update::Error-Mode=any update
    # URI-derived filenames must describe the final guest paths rather than the derivation assembly prefix.
    for file in "$out/var/lib/apt/lists/"*repo-a*; do
      base=$(basename "$file")
      suffix="''${base#*repo-a}"
      mv "$file" "$out/var/lib/apt/lists/_opt_estus-catalog_repo-a$suffix"
    done
    printf 'deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-a ./\n' > "$out/etc/apt/sources.list.d/estus-catalog.list"
    touch "$out/etc/apt/sources.list"
    # No freshness stamp is fabricated: prebuilt indexes are available, freshness remains explicitly unknown.
  '';
in
{ inherit apt rootfs python runtimePackages; }
