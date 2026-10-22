#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${MICROBOX_CGROUP:?Provide a dedicated empty cgroups v2 delegation path}"
: "${MICROBOX_ROOTFS:?Provide a dedicated empty trusted rootfs directory}"
chown root:root target/release/microbox-helper
chmod 755 target/release/microbox-helper
# Only the explicitly supplied disposable paths are modified.
mkdir -p "$MICROBOX_ROOTFS"/{bin,etc,tmp,proc,dev,sys,.microbox-old}
chmod 755 "$MICROBOX_ROOTFS" "$MICROBOX_ROOTFS"/{bin,etc,tmp,proc,dev,sys,.microbox-old}
gcc -O2 -static -Wall -Wextra -Werror tests/adversarial/probe.c -o "$MICROBOX_ROOTFS/bin/probe"
python3 tests/adversarial/run.py
python3 benchmarks/run.py
