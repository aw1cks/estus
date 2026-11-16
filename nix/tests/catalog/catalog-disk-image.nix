{ pkgs, nixpkgs, config }:
let
  system = config.system.build.toplevel;
  root = pkgs.callPackage "${nixpkgs}/nixos/lib/make-ext4-fs.nix" {
    storePaths = [ system ];
    volumeLabel = "nixos";
    populateImageCommands = ''
      mkdir -p etc sbin nix/var/nix/profiles
      touch etc/NIXOS
      ln -s ${system}/init sbin/init
      ln -s ${system} nix/var/nix/profiles/system
    '';
  };
  rootImage = root.overrideAttrs (_: {
    __structuredAttrs = true;
    # The filesystem contains its own complete guest store, not host references.
    unsafeDiscardReferences.out = true;
  });
in pkgs.runCommand "estus-catalog-efi-disk" {
  __structuredAttrs = true;
  unsafeDiscardReferences.out = true;
  nativeBuildInputs = [ pkgs.coreutils pkgs.dosfstools pkgs.mtools
    pkgs.gptfdisk pkgs.qemu-utils ];
} ''
  # All operations address regular build-owned files. No mounts, loop devices,
  # privileged helper VM, package bootstrap or host EFI writes are needed.
  mkdir -p "$out"
  test "$(stat -c %s ${rootImage})" -lt $((3838 * 1024 * 1024))
  truncate -s 256M esp.img
  mkfs.vfat -n ESP -i 45535455 esp.img
  for directory in EFI EFI/BOOT EFI/Linux loader loader/entries; do
    mmd -i esp.img "::/$directory"
  done
  mcopy -i esp.img ${config.systemd.package}/lib/systemd/boot/efi/systemd-bootx64.efi ::/EFI/BOOT/BOOTX64.EFI
  mcopy -i esp.img ${system}/kernel ::/EFI/Linux/catalog-kernel
  mcopy -i esp.img ${system}/initrd ::/EFI/Linux/catalog-initrd
  for entry in current alternate; do
    cat > "$entry.conf" <<EOF
  title Estus catalog $entry
  linux /EFI/Linux/catalog-kernel
  initrd /EFI/Linux/catalog-initrd
  options init=${system}/init $(cat ${system}/kernel-params)
  EOF
    mcopy -i esp.img "$entry.conf" "::/loader/entries/estus-$entry.conf"
  done
  printf 'default estus-current.conf\ntimeout 0\n' > loader.conf
  mcopy -i esp.img loader.conf ::/loader/loader.conf
  fsck.fat -n esp.img
  truncate -s 4096M disk.raw
  sgdisk --clear --disk-guid=45535455-5300-4000-8000-000000000001 \
    --new=1:2048:+256M --typecode=1:ef00 --change-name=1:ESP \
    --partition-guid=1:45535455-5300-4000-8000-000000000002 \
    --new=2:0:0 --typecode=2:8300 --change-name=2:nixos \
    --partition-guid=2:45535455-5300-4000-8000-000000000003 disk.raw
  dd if=esp.img of=disk.raw bs=1M seek=1 conv=notrunc,sparse status=none
  dd if=${rootImage} of=disk.raw bs=1M seek=257 conv=notrunc,sparse status=none
  qemu-img convert -f raw -O qcow2 -c disk.raw "$out/disk.qcow2"
''
