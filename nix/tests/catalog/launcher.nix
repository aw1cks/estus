{ hostPkgs, lab, disk, firmware }:
hostPkgs.writeShellScriptBin (if lab then "catalog-lab-guest" else "catalog-guest") ''
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
