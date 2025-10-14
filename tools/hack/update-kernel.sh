#!/usr/bin/env bash
set -euo pipefail

# This scripts allows to update local kernel version.
# Example:
# TARGET_VERSION=v5.10.15 ./tools/hack/auto-kernel-update.sh

TARGET_VERSION="${TARGET_VERSION:-v6.12.40}"

if [[ ! -f ./ubuntu-mainline-kernel.sh ]]; then
  echo "[INFO] Downloading ubuntu-mainline-kernel.sh..."
  wget -q https://raw.githubusercontent.com/pimlie/ubuntu-mainline-kernel.sh/master/ubuntu-mainline-kernel.sh
  chmod +x ubuntu-mainline-kernel.sh
fi

./ubuntu-mainline-kernel.sh -r | grep $TARGET_VERSION
./ubuntu-mainline-kernel.sh -i $TARGET_VERSION

MENUENTRY=$(grep 'menuentry \|submenu ' /boot/grub/grub.cfg \
  | cut -f2 -d "'" \
  | grep "Linux ${TARGET_VERSION#v}-" \
  | grep -v "64k" \
  | head -n 1)
echo $MENUENTRY

sudo sed -i.bak "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"Advanced options for Ubuntu>${MENUENTRY}\"|" /etc/default/grub

update-grub
reboot now
