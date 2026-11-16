{ pkgs, sourceRoot, automation ? false, servicePackage ? null }:
let
  inherit (pkgs) lib;
  commandPath = "/usr/bin:/bin:${pkgs.coreutils}/bin:${pkgs.dash}/bin";

  # Pin runtime paths explicitly rather than inheriting a NixOS service setup.
  # The locked OpenSSH common.nix supports etcDir and defaults to PAM on Linux;
  # the fixture's supplied sshd_config disables PAM for public-key login.
  openssh = (pkgs.openssh.override { etcDir = "/etc/ssh"; }).overrideAttrs (old: {
    configureFlags = old.configureFlags ++ [
      "--with-privsep-user=sshd"
      "--with-privsep-path=/var/empty"
      "--with-default-path=${commandPath}"
    ] ++ lib.optionals (servicePackage != null) [
      # This fixture proves Unix account authorization, not pre-auth hardening.
      # Guest seccomp cannot run under CPU emulation, and Linux poll rejects
      # the rlimit fallback. Privilege separation and UID drops remain enabled.
      "--with-sandbox=no"
    ];
  });
  # sudo's installation notes define these configure switches. Keep the plugins
  # in its immutable closure, but read policy/PAM service files from the image.
  sudo = pkgs.sudo.overrideAttrs (old: {
    configureFlags = old.configureFlags ++ [
      "--sysconfdir=/etc"
      "--with-plugindir=\${out}/libexec/sudo"
      "--with-pam"
    ];
  });
  accounts = [
    { name = "mcp"; id = 1000; }
    { name = "mcp-sudo"; id = 1001; }
    { name = "mcp-admin"; id = 1002; }
    { name = "mcp-password"; id = 1003; }
    { name = "mcp-tty"; id = 1004; }
  ] ++ lib.optionals automation [
    { name = "mcp-automation"; id = 1005; }
    { name = "mcp-automation-password"; id = 1006; }
  ] ++ lib.optionals (servicePackage != null) [
    { name = "estus-client"; id = 1200; }
    { name = "estus-service"; id = 1201; }
    { name = "estus-target"; id = 1202; }
  ];
  accountLines = f: lib.concatMapStringsSep "\n" f accounts;
  # Fixture-only secret, used privately to prime a real sudo timestamp. It is
  # never placed in product configuration or MCP arguments.
  automationPasswordHash = pkgs.runCommand "fixture-automation-password-hash" {
    nativeBuildInputs = [ pkgs.mkpasswd ];
  } ''
    mkpasswd --method=sha-512 --salt=estusfixture fixture-cache-only > "$out"
  '';
  sudoers = pkgs.writeText "ssh-fixture-sudoers" (''
    Defaults env_reset
    Defaults secure_path="${commandPath}"
    Defaults timestamp_timeout=0
    Defaults lecture=never
    Defaults:mcp-tty requiretty
    mcp-sudo ALL=(root) NOPASSWD: /usr/bin/id, /usr/bin/printf
    mcp-admin ALL=(root) NOPASSWD: /usr/bin/id, /usr/bin/printf
    mcp-password ALL=(root) PASSWD: /usr/bin/id
    mcp-tty ALL=(root) NOPASSWD: /usr/bin/id
  '' + lib.optionalString automation ''
    Defaults:mcp-automation-password timestamp_timeout=5,timestamp_type=global
    mcp-automation ALL=(root) NOPASSWD: ALL
    mcp-automation-password ALL=(root) PASSWD: ALL
  '');
  rootfs = pkgs.runCommand "ssh-fixture-rootfs" { } ''
    mkdir -p "$out"/{bin,usr/bin,etc/ssh,etc/pam.d,home,root,run/sshd,run/sudo,var/empty,var/db/sudo,var/log,fixture/authorized_keys,tmp}
    ln -s ${pkgs.dash}/bin/dash "$out/bin/sh"
    for program in ${pkgs.coreutils}/bin/*; do
      ln -s "$program" "$out/bin/$(basename "$program")"
    done
    ln -s ${pkgs.coreutils}/bin/id "$out/usr/bin/id"
    ln -s ${pkgs.coreutils}/bin/printf "$out/usr/bin/printf"
    ${lib.optionalString (servicePackage != null) ''
      mkdir -p "$out/opt" "$out/usr/local/libexec" "$out/fixture/deployment"
      ln -s ${servicePackage} "$out/opt/estus"
      ln -s ${openssh}/bin/ssh "$out/usr/bin/ssh"
      ln -s ${openssh}/bin/ssh-keygen "$out/usr/bin/ssh-keygen"
      ln -s ${pkgs.coreutils}/bin/env "$out/usr/bin/env"
      ln -s ${pkgs.gnused}/bin/sed "$out/usr/bin/sed"
      cp ${sourceRoot + "/examples/separated-accounts/estus-ingress"} "$out/usr/local/libexec/estus-ingress"
      cp ${sourceRoot + "/examples/separated-accounts/estus-record-identity"} "$out/usr/local/libexec/estus-record-identity"
      chmod 0755 "$out/usr/local/libexec/"*
      cp ${sourceRoot + "/examples/separated-accounts/server.toml"} "$out/fixture/deployment/server.toml"
      cp ${sourceRoot + "/examples/separated-accounts/outbound_ssh_config"} "$out/fixture/deployment/outbound_ssh_config"
      cp ${sourceRoot + "/examples/separated-accounts/sshd_config"} "$out/fixture/deployment/sshd_config"
    ''}
    ${lib.optionalString automation "ln -s ${pkgs.python314}/bin/python3 \"$out/usr/bin/python3\"\n    "}cp ${sudo}/bin/sudo "$out/usr/bin/sudo"
    cat > "$out/etc/passwd" <<'EOF'
    root:x:0:0:root:/root:/bin/sh
    sshd:x:74:74:OpenSSH privilege separation:/var/empty:/bin/false
    ${accountLines (a: "${a.name}:x:${toString a.id}:${toString a.id}:SSH fixture:/home/${a.name}:/bin/sh")}
    EOF
    cat > "$out/etc/group" <<'EOF'
    root:x:0:
    sshd:x:74:
    ${accountLines (a: "${a.name}:x:${toString a.id}:")}
    EOF
    cat > "$out/etc/shadow" <<'EOF'
    root:!:1:0:99999:7:::
    sshd:!:1:0:99999:7:::
    ${accountLines (a: "${a.name}:x:1:0:99999:7:::")}
    EOF
    ${lib.optionalString automation ''
      sed -i "s|^mcp-automation-password:x:|mcp-automation-password:$(cat ${automationPasswordHash}):|" "$out/etc/shadow"
    ''}
    ${lib.optionalString automation ''
      # The locked pam_unix module invokes this NixOS wrapper path.
      # Copy only into the private image: never chmod a host/store inode.
      mkdir -p "$out/run/wrappers/bin"
      cp ${pkgs.pam}/bin/unix_chkpwd "$out/run/wrappers/bin/unix_chkpwd"
    ''}
    cat > "$out/etc/nsswitch.conf" <<'EOF'
    passwd: files
    group: files
    shadow: files
    hosts: files dns
    sudoers: files
    EOF
    cat > "$out/etc/hosts" <<'EOF'
    127.0.0.1 localhost
    ::1 localhost
    EOF
    printf '/bin/sh\n' > "$out/etc/shells"
    cp ${sudoers} "$out/etc/sudoers"
    cat > "$out/etc/sudo.conf" <<'EOF'
    Plugin sudoers_policy ${sudo}/libexec/sudo/sudoers.so
    Plugin sudoers_io ${sudo}/libexec/sudo/sudoers.so
    EOF
    # Deliberate sudo-only PAM policy: no host/NixOS PAM includes. Only the
    # automation password account has a usable fixture-only login hash.
    cat > "$out/etc/pam.d/sudo" <<'EOF'
    auth required ${pkgs.pam}/lib/security/pam_unix.so
    account required ${pkgs.pam}/lib/security/pam_permit.so
    session required ${pkgs.pam}/lib/security/pam_permit.so
    EOF
    cp "$out/etc/pam.d/sudo" "$out/etc/pam.d/sudo-i"
    ${lib.concatMapStringsSep "\n" (a: ''mkdir -p "$out/home/${a.name}"'') accounts}
    ${sudo}/sbin/visudo -cf "$out/etc/sudoers"
  '';
  image = pkgs.dockerTools.buildLayeredImage {
    name = if servicePackage != null then "estus-deployment-fixture"
      else if automation then "estus-automation-fixture" else "estus-fixture";
    # Omitting tag selects dockerTools' derivation-derived tag, never latest.
    created = "1970-01-01T00:00:01Z";
    mtime = "1970-01-01T00:00:01Z";
    compressor = "gz";
    # Copy real files, not symlinkJoin's links into rootfs: ownership and setuid
    # bits below must affect only the private layer, never a host store inode.
    extraCommands = ''
      cp -a ${rootfs}/. .
    '';
    fakeRootCommands = ''
      chown -R 0:0 .
      find . -type d -exec chmod 0755 {} +
      chmod 0700 root run/sudo var/db/sudo
      chmod 1777 tmp
      chmod 0600 etc/shadow
      chmod 0440 etc/sudoers
      chmod 4755 usr/bin/sudo
      ${lib.optionalString automation "chmod 4755 run/wrappers/bin/unix_chkpwd"}
      ${lib.concatMapStringsSep "\n" (a: ''
        chown ${toString a.id}:${toString a.id} home/${a.name}
        chmod 0700 home/${a.name}
      '') accounts}
    '';
    config = {
      User = "0:0";
      Env = [ "PATH=${commandPath}" "LANG=C" ];
      WorkingDir = "/";
      Entrypoint = [ "${openssh}/bin/sshd" "-D" "-e" "-f" "/fixture/sshd_config" ];
      ExposedPorts = { "2222/tcp" = { }; };
    };
  };
in
pkgs.runCommand "ssh-fixture-image" {
  nativeBuildInputs = [ pkgs.gnutar pkgs.gzip pkgs.jq pkgs.coreutils ];
} ''
  mkdir -p "$out" archive
  cp ${image} "$out/image.tar.gz"
  tar -xzf "$out/image.tar.gz" -C archive
  # Both identifiers come from this archive, including its generated tag and
  # the actual configuration bytes (not a layer digest or an assumed filename).
  jq -er 'if length == 1 and (.[0].RepoTags | length) == 1 then .[0].RepoTags[0] else error("unexpected image manifest") end' \
    archive/manifest.json > "$out/image-ref"
  config=$(jq -er '.[0].Config' archive/manifest.json)
  test "$(cat "$out/image-ref")" = '${image.imageName}:${image.imageTag}'
  printf 'sha256:%s\n' "$(sha256sum "archive/$config" | cut -d ' ' -f 1)" > "$out/image-id"
''
