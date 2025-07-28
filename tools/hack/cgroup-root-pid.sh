#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <cgroup_inode>" >&2
  exit 1
fi

INODE="$1"

CGROUP_PATH=$(find /sys/fs/cgroup/ -inum "$INODE" 2>/dev/null | head -n1)

if [ -z "$CGROUP_PATH" ]; then
  echo "no cgroup path"
  exit 1
fi

CONTAINER_ID=$(basename "$CGROUP_PATH" | sed -n 's/^.*cri-containerd-\([a-f0-9]\{64\}\)\.scope/\1/p')

if [ -z "$CONTAINER_ID" ]; then
  echo "no container hash in cgroup path $CGROUP_PATH"
  exit 1
fi

PIDS=$(grep -rl "$CONTAINER_ID" /proc/*/cgroup 2>/dev/null | awk -F/ '{print $3}')

if [ -z "$PIDS" ]; then
  echo "no pid"
  exit 1
fi

echo "$PIDS" | head -n1
