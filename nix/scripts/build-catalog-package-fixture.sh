# Sourced by runCommand with Nix-resolved fixtureSource, maintainerShell,
# aptMethods, out, TMPDIR and nativeBuildInputs. Never invoke from a checkout.
export SOURCE_DATE_EPOCH=1700000000
export GNUPGHOME="$TMPDIR/test-signing-key"
mkdir -m 700 "$GNUPGHOME"
# Unencrypted PUBLIC TEST-ONLY signing material, not a private credential.
# Never trust this identity outside the disposable catalog VM.
gpg --batch --import "$fixtureSource/signing/test-only-signing-key.asc"
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
      substitute "$fixtureSource/templates/control.in" "$tree/DEBIAN/control" \
        --replace-fail '@name@' "$name" --replace-fail '@version@' "$version"
      printf '%s %s\n' "$name" "$version" > "$tree/usr/share/estus-catalog/$name"
      # DPKG_ROOT lets the same real scripts run rootlessly and in the guest.
      for script in postinst postrm; do
        substitute "$fixtureSource/templates/$script.in" "$tree/DEBIAN/$script" \
          --replace-fail '@maintainerShell@' "$maintainerShell" \
          --replace-fail '@name@' "$name" --replace-fail '@version@' "$version"
      done
      chmod 755 "$tree/DEBIAN/postinst" "$tree/DEBIAN/postrm"
      dpkg-deb --root-owner-group --build "$tree" "$out/opt/estus-catalog/repo-$repository/pool/${name}_${version}_all.deb"
    done
  done
  (
    cd "$out/opt/estus-catalog/repo-$repository"
    # Generate indexes from real .deb control records, not handwritten facts.
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
# Real dpkg populates status/info and executes the baseline maintainer script.
fakeroot dpkg --root="$out" --force-not-root --force-script-chrootless --force-bad-path \
  --install "$out/opt/estus-catalog/repo-a/pool/estus-catalog-base_1.0_all.deb"
cat > "$out/etc/apt/apt.conf" <<EOF
Dir::Etc "/etc/apt";
Dir::State "/var/lib/apt";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache "/var/cache/apt";
Dir::Bin::dpkg "/usr/bin/dpkg";
Dir::Bin::Methods "$aptMethods";
Acquire::Retries "0";
APT::Get::List-Cleanup "true";
Acquire::Languages "none";
APT::Sandbox::User "root";
EOF
# Authenticate lists at build time with a temporary build-local file URI.
printf 'deb [signed-by=%s/usr/share/keyrings/estus-catalog.gpg] file:%s/opt/estus-catalog/repo-a ./\n' "$out" "$out" > "$TMPDIR/build-sources.list"
apt-get -o Dir::Etc::main="$out/etc/apt/apt.conf" \
  -o Dir::Etc::sourcelist="$TMPDIR/build-sources.list" -o Dir::Etc::sourceparts=- \
  -o Dir::State="$out/var/lib/apt" -o Dir::State::status="$out/var/lib/dpkg/status" \
  -o Dir::Cache="$out/var/cache/apt" -o APT::Sandbox::User=root \
  -o Acquire::Languages=none -o Acquire::AllowInsecureRepositories=false \
  -o APT::Update::Error-Mode=any update
# URI-derived filenames must describe final guest paths, not assembly paths.
for file in "$out/var/lib/apt/lists/"*repo-a*; do
  base=$(basename "$file")
  suffix="${base#*repo-a}"
  mv "$file" "$out/var/lib/apt/lists/_opt_estus-catalog_repo-a$suffix"
done
printf 'deb [signed-by=/usr/share/keyrings/estus-catalog.gpg] file:/opt/estus-catalog/repo-a ./\n' > "$out/etc/apt/sources.list.d/estus-catalog.list"
touch "$out/etc/apt/sources.list"
# No fabricated freshness stamp: prebuilt indexes exist, freshness is unknown.
