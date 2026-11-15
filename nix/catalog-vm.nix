{ inputs, hostPkgs, lab ? false }:
let
  packageFixture = import ./catalog-package-fixture.nix {
    pkgs = import inputs.nixpkgs { system = "x86_64-linux"; };
  };
  guest = inputs.nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [ ({ config, lib, pkgs, ... }:
      let
        kernel = config.boot.kernelPackages.kernel;
        testModule = pkgs.stdenv.mkDerivation {
          pname = "estus-catalog-module";
          version = "1";
          src = pkgs.writeTextDir "estus_catalog.c" ''
            #include <linux/module.h>
            #include <linux/init.h>
            static int value = 7;
            module_param(value, int, 0644);
            MODULE_PARM_DESC(value, "Harmless catalog fixture value");
            static int __init catalog_init(void) { return 0; }
            static void __exit catalog_exit(void) { }
            module_init(catalog_init);
            module_exit(catalog_exit);
            MODULE_LICENSE("GPL");
            MODULE_DESCRIPTION("Disposable Estus qualification fixture; no hooks or devices");
          '';
          nativeBuildInputs = kernel.moduleBuildDependencies;
          buildPhase = ''
            printf 'obj-m := estus_catalog.o\n' > Makefile
            make -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build M="$PWD" \
              ${lib.escapeShellArgs config.boot.kernelPackages.kernelModuleMakeFlags} modules
          '';
          installPhase = ''
            make -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build M="$PWD" \
              ${lib.escapeShellArgs config.boot.kernelPackages.kernelModuleMakeFlags} \
              INSTALL_MOD_PATH="$out" INSTALL_MOD_DIR=extra DEPMOD=true modules_install
          '';
        };
        nicModelModule = pkgs.stdenv.mkDerivation {
          pname = "estus-nic-model";
          version = "1";
          src = pkgs.writeTextDir "estus_nic_model.c" (builtins.readFile ./catalog-nic-model.c);
          nativeBuildInputs = kernel.moduleBuildDependencies;
          buildPhase = ''
            printf 'obj-m := estus_nic_model.o\n' > Makefile
            make -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build M="$PWD" \
              ${lib.escapeShellArgs config.boot.kernelPackages.kernelModuleMakeFlags} modules
          '';
          installPhase = ''
            make -C ${kernel.dev}/lib/modules/${kernel.modDirVersion}/build M="$PWD" \
              ${lib.escapeShellArgs config.boot.kernelPackages.kernelModuleMakeFlags} \
              INSTALL_MOD_PATH="$out" INSTALL_MOD_DIR=extra DEPMOD=true modules_install
          '';
        };
        tools = [ pkgs.coreutils pkgs.bash config.systemd.package pkgs.iproute2 pkgs.ethtool
          pkgs.util-linux pkgs.pciutils pkgs.kmod pkgs.procps pkgs.dmidecode
          pkgs.iputils pkgs.traceroute pkgs.bind pkgs.gnugrep pkgs.gnused pkgs.findutils
          pkgs.openssh pkgs.acl ] ++ lib.optionals lab [ pkgs.mdadm pkgs.nvme-cli pkgs.smartmontools ];
        python = packageFixture.python;
        unitFiles = pkgs.runCommand "estus-catalog-units" {} ''
          mkdir -p "$out"
          for name in estus-fixture estus-fixture-idle; do
            cat > "$out/$name.service" <<EOF
          [Unit]
          Description=Disposable Estus catalog service
          [Service]
          ExecStart=${pkgs.writeShellScript "estus-catalog-service" ''
            echo ESTUS_CATALOG_JOURNAL_MARKER
            exec ${pkgs.coreutils}/bin/sleep infinity
          ''}
          ExecReload=${pkgs.coreutils}/bin/touch /var/lib/estus-catalog/reload-marker
          [Install]
          WantedBy=multi-user.target
          EOF
          done
          cat > "$out/estus-fixture-fail.service" <<EOF
          [Service]
          Type=oneshot
          ExecStart=${pkgs.coreutils}/bin/false
          EOF
          cat > "$out/estus-fixture.timer" <<EOF
          [Timer]
          OnBootSec=1h
          Unit=estus-fixture-idle.service
          [Install]
          WantedBy=timers.target
          EOF
          cat > "$out/estus-fixture.socket" <<EOF
          [Socket]
          ListenStream=127.0.0.1:18990
          Accept=no
          Service=estus-fixture-idle.service
          [Install]
          WantedBy=sockets.target
          EOF
        '';
      in {
        system.stateVersion = "26.05";
        networking.hostName = "estus-catalog";
        networking.firewall.enable = false;
        networking.useDHCP = false;
        networking.usePredictableInterfaceNames = false;
        networking.interfaces.${if lab then "management0" else "eth0"}.ipv4.addresses = [{ address = "10.0.2.15"; prefixLength = 24; }];
        networking.defaultGateway = "10.0.2.2";
        networking.nameservers = [ "127.0.0.1" ];
        networking.hosts."127.0.0.1" = [ "catalog.test" ];
        services.udev.extraRules = lib.optionalString lab ''
          SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="52:54:00:12:34:56", NAME="management0"
          SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="52:54:00:12:34:57", NAME="tune0"
          SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="52:54:00:12:34:58", NAME="pause0"
        '';
        boot.initrd.availableKernelModules = [ "virtio_pci" "virtio_blk" "9p" "9pnet_virtio" ];
        boot.kernelModules = [ "dummy" "estus_catalog" ]
          ++ lib.optionals lab [ "md_mod" "raid1" "e1000e" "nvme" "veth" ];
        boot.extraModulePackages = [ testModule ] ++ lib.optionals lab [ nicModelModule ];
        boot.kernelParams = [ "console=ttyS0" "psi=1" "intel_iommu=on" ];
        boot.loader.systemd-boot.enable = true;
        boot.loader.timeout = 0;
        boot.loader.efi.canTouchEfiVariables = true;
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; autoResize = true; };
        fileSystems."/boot" = { device = "/dev/disk/by-label/ESP"; fsType = "vfat"; };
        fileSystems."/run/catalog-keys" = {
          device = "keys";
          fsType = "9p";
          options = [ "trans=virtio" "version=9p2000.L" "ro" ];
        };
        users.mutableUsers = false;
        # Keys are supplied privately at runtime, before sshd can start.
        users.allowNoPasswordLogin = true;
        users.users.mcp = { isNormalUser = true; uid = 1000; };
        users.users.mcp-admin = { isNormalUser = true; uid = 1001; };
        security.sudo.extraRules = [{ users = [ "mcp-admin" ]; commands = [{ command = "ALL"; options = [ "NOPASSWD" ]; }]; }];
        services.dbus.enable = true;
        # The disposable qualification OS needs ordinary mutable unit-file
        # semantics, not NixOS's read-only directory symlink into the store.
        environment.etc."systemd/system".enable = lib.mkForce false;
        system.activationScripts.estusMutableUnits = {
          deps = [ "etc" ];
          text = ''
            ${pkgs.python3}/bin/python3 - <<'PY'
            import os
            from pathlib import Path
            import shutil
            source = Path(${builtins.toJSON (toString config.environment.etc."systemd/system".source)})
            def install_directory(source, target, depth=0):
                if depth > 8:
                    raise RuntimeError('fixture unit directory exceeds bound')
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                for entry in source.iterdir():
                    destination = target / entry.name
                    if entry.is_dir():
                        install_directory(entry, destination, depth + 1)
                    elif not destination.exists() and not destination.is_symlink():
                        if entry.is_symlink():
                            destination.symlink_to(os.readlink(entry))
                        else:
                            shutil.copy2(entry, destination)
            install_directory(source, Path('/etc/systemd/system'))
            PY
          '';
        };
        services.openssh = {
          enable = true;
          # The controller supplies this identity; the OS must not race its copy.
          generateHostKeys = false;
          hostKeys = [{ path = "/etc/ssh/catalog-host"; type = "ed25519"; }];
          settings = {
            PasswordAuthentication = false;
            KbdInteractiveAuthentication = false;
            PermitRootLogin = "prohibit-password";
            AuthorizedKeysFile = "/etc/ssh/authorized_keys.d/%u";
          };
        };
        systemd.services.sshd = {
          after = [ "estus-catalog-keys.service" "estus-catalog-setup.service" ];
          requires = [ "estus-catalog-keys.service" "estus-catalog-setup.service" ];
        };
        systemd.services.estus-catalog-keys = {
          before = [ "sshd.service" ];
          unitConfig.RequiresMountsFor = "/run/catalog-keys";
          serviceConfig = {
            Type = "oneshot";
            StandardError = "journal+console";
          };
          script = ''
            install -d -m755 /etc/ssh/authorized_keys.d
            for user in mcp mcp-admin root; do
              install -m644 /run/catalog-keys/$user.pub /etc/ssh/authorized_keys.d/$user
            done
            install -m600 /run/catalog-keys/host /etc/ssh/catalog-host
            install -m644 /run/catalog-keys/host.pub /etc/ssh/catalog-host.pub
          '';
        };
        environment.systemPackages = tools ++ [ python ] ++ packageFixture.runtimePackages;
        systemd.tmpfiles.rules = [
          "d /usr/bin 0755 root root -"
          "L+ /usr/bin/python3 - - - - ${python}/bin/python3"
          "L+ /usr/bin/sudo - - - - /run/wrappers/bin/sudo"
          "d /usr/lib/systemd 0755 root root -"
          "L+ /usr/lib/systemd/system - - - - ${unitFiles}"
          "C /var/lib/estus-catalog 0777 root root - ${packageFixture.rootfs}/var/lib/estus-catalog"
          "d /etc/estus-catalog 0755 root root -"
        ] ++ (map (name: "L+ /usr/bin/${name} - - - - /run/current-system/sw/bin/${name}") [
          "systemctl" "systemd-run" "journalctl" "ip" "ss" "ethtool" "lsblk" "lspci"
          "modprobe" "modinfo" "lsmod" "bootctl" "timedatectl" "sysctl" "dmidecode"
          "ping" "traceroute" "dig" "getent" "id" "printf" "stat" "cat" "sleep"
          "readlink" "find" "findmnt" "timeout" "touch" "mkdir" "rm" "chmod" "chown" "df" "env"
        ]) ++ [
          "L+ /opt/estus-catalog - - - - ${packageFixture.rootfs}/opt/estus-catalog"
          "C /var/lib/dpkg - - - - ${packageFixture.rootfs}/var/lib/dpkg"
          "C /var/lib/apt - - - - ${packageFixture.rootfs}/var/lib/apt"
          "C /var/cache/apt - - - - ${packageFixture.rootfs}/var/cache/apt"
          "C /etc/apt - - - - ${packageFixture.rootfs}/etc/apt"
          "C /usr/share/keyrings - - - - ${packageFixture.rootfs}/usr/share/keyrings"
          "C /usr/share/estus-catalog - - - - ${packageFixture.rootfs}/usr/share/estus-catalog"
          "C /var/log/apt - - - - ${packageFixture.rootfs}/var/log/apt"
          "L+ /usr/bin/apt-get - - - - ${packageFixture.apt}/bin/apt-get"
          "L+ /usr/bin/apt-cache - - - - ${packageFixture.apt}/bin/apt-cache"
          "L+ /usr/bin/apt-mark - - - - ${packageFixture.apt}/bin/apt-mark"
          "L+ /usr/bin/dpkg - - - - /run/current-system/sw/bin/dpkg"
          "L+ /usr/bin/dpkg-query - - - - /run/current-system/sw/bin/dpkg-query"
        ] ++ lib.optionals lab (map (name: "L+ /usr/bin/${name} - - - - /run/current-system/sw/bin/${name}") [
          "mdadm" "nvme" "smartctl"
        ]);
        systemd.services.estus-catalog-setup = {
          wantedBy = [ "multi-user.target" ];
          after = [ "systemd-tmpfiles-setup.service" ];
          path = tools;
          serviceConfig = { Type = "oneshot"; RemainAfterExit = true; };
          script = ''
            ip link add catalog0 type dummy
            ip address add 192.0.2.1/24 dev catalog0
            ip link set catalog0 up
            ${lib.optionalString lab ''
              modprobe netdevsim
              echo '42 1' > /sys/bus/netdevsim/new_device
              for device in /sys/bus/netdevsim/devices/netdevsim42/net/*; do
                ip link set "''${device##*/}" name fec0
              done
              ip link set fec0 address 52:54:00:12:34:59
              ethtool --set-fec fec0 encoding off
              # Fixed platform-backed software fixture: no address or route.
              modprobe estus_nic_model
            ''}
            # Runtime unit files are in a standard search path, outside /etc;
            # persistent mask/unmask can therefore be exercised honestly.
            mkdir -p /run/systemd/system
            cp ${unitFiles}/* /run/systemd/system/
            systemctl daemon-reload
            systemctl start estus-fixture.service estus-fixture.timer estus-fixture.socket
          '';
        };
      }) ];
  };
  disk = import ./catalog-disk-image.nix { pkgs = guest.pkgs; nixpkgs = inputs.nixpkgs; config = guest.config; };
  firmware = guest.pkgs.OVMFFull;
in hostPkgs.writeShellScriptBin (if lab then "catalog-lab-guest" else "catalog-guest") ''
  set -euo pipefail
  : "''${NIX_DISK_IMAGE:?private disk path required}"
  : "''${NIX_EFI_VARS:?private EFI state path required}"
  : "''${ESTUS_CATALOG_KEYS:?private key directory required}"
  : "''${ESTUS_CATALOG_PORT:?private SSH port required}"
  ${hostPkgs.qemu}/bin/qemu-img create -f qcow2 -F qcow2 -b ${disk}/disk.qcow2 "$NIX_DISK_IMAGE"
  ${hostPkgs.coreutils}/bin/cp ${firmware.variables} "$NIX_EFI_VARS"
  ${hostPkgs.coreutils}/bin/chmod u+w "$NIX_EFI_VARS"
  ${hostPkgs.lib.optionalString lab ''
    for device in raid-a raid-b nvme; do
      ${hostPkgs.qemu}/bin/qemu-img create -f qcow2 "$NIX_DISK_IMAGE.$device.qcow2" 64M
    done
  ''}exec ${hostPkgs.qemu}/bin/qemu-system-x86_64 \
    -machine q35,accel=tcg -cpu max -m 1536 -smp ${if lab then "4" else "2"} -display none -serial stdio -monitor none \
    -drive if=pflash,format=raw,unit=0,readonly=on,file=${firmware.firmware} \
    -drive if=pflash,format=raw,unit=1,file="$NIX_EFI_VARS" \
    -drive if=none,id=root,format=qcow2,file="$NIX_DISK_IMAGE" -device virtio-blk-pci,drive=root \
    -device virtio-rng-pci -device intel-iommu,intremap=on \
    -virtfs local,path="$ESTUS_CATALOG_KEYS",security_model=none,mount_tag=keys,readonly=on \
    -netdev user,id=net0,restrict=on,hostfwd=tcp:127.0.0.1:"$ESTUS_CATALOG_PORT"-:22 \
    -device virtio-net-pci,netdev=net0,mq=on,vectors=10,rss=on,hash=on${hostPkgs.lib.optionalString lab ",mac=52:54:00:12:34:56"} \
    ${hostPkgs.lib.optionalString lab ''
    -netdev user,id=tuning,restrict=on \
    -device virtio-net-pci,netdev=tuning,mq=on,vectors=10,rss=on,hash=on,mac=52:54:00:12:34:57 \
    -netdev user,id=pause,restrict=on -device e1000e,netdev=pause,mac=52:54:00:12:34:58 \
    -drive if=none,id=raid-a,format=qcow2,file="$NIX_DISK_IMAGE.raid-a.qcow2" -device virtio-blk-pci,drive=raid-a \
    -drive if=none,id=raid-b,format=qcow2,file="$NIX_DISK_IMAGE.raid-b.qcow2" -device virtio-blk-pci,drive=raid-b \
    -drive if=none,id=nvme,format=qcow2,file="$NIX_DISK_IMAGE.nvme.qcow2" -device nvme,drive=nvme,serial=ESTUS-LAB-NVME \
    ''}-smbios type=1,manufacturer=Estus,product=CatalogGuest,serial=ESTUS-FIXTURE-SERIAL \
    -smbios type=9,slot_designation=CatalogSlot,slot_type=165,slot_data_bus_width=13,current_usage=4,slot_length=3,slot_id=1,slot_characteristics1=4,slot_characteristics2=0
''
