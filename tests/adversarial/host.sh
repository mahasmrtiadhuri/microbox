#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${MICROBOX_CGROUP:?Provide a dedicated empty cgroups v2 delegation path}"
: "${MICROBOX_ROOTFS:?Provide a new trusted rootfs directory}"
chown root:root target/release/microbox-helper
chmod 755 target/release/microbox-helper
python3 scripts/rootfs.py "$MICROBOX_ROOTFS" --python /usr/bin/python3
gcc -O2 -static -Wall -Wextra -Werror tests/adversarial/probe.c -o "$MICROBOX_ROOTFS/bin/probe"
python3 -m unittest discover -s python/tests -v
python3 tests/adversarial/run.py
command -v strace >/dev/null
python3 tests/adversarial/python_workloads.py
unshare --net --mount --propagation private python3 tests/egress/fixture.py
python3 benchmarks/run.py
