# microbox

**Native Linux workloads. Explicit capabilities. Observable teardown.**

microbox is an embeddable Rust sandbox and CLI for short-lived, untrusted workloads. Namespace setup runs in a dedicated helper process; Tokio workers never change namespaces. Each execution has its own cgroup, PID tree, read-only filesystem view, bounded scratch space, strict syscall profile, and independently verifiable audit root.

[![Verify microbox](https://github.com/mahasmrtiadhuri/microbox/actions/workflows/ci.yml/badge.svg)](https://github.com/mahasmrtiadhuri/microbox/actions/workflows/ci.yml)

**v0.2 scope:** experimental Linux x86-64 runtime with air-gapped execution and an optional bounded HTTPS-fetch capability. This is a shared-kernel boundary requiring privileged setup; it is not a production certification, rootless runtime, or sub-millisecond performance claim. [Security model](SECURITY.md).

## Capabilities

| Area | Behavior |
|---|---|
| Native workloads | Static binaries, dynamically linked tools, shell commands, Python standard library and subprocesses |
| Filesystem | Private mount namespace, non-recursive root bind, pivot_root, detached old root, read-only/nosuid/nodev root |
| Scratch | Size- and inode-bounded tmpfs at /tmp; nodev/nosuid/noexec |
| Process isolation | Private PID/IPC/UTS namespaces, trusted PID 1 reaper, namespace-local read-only procfs |
| Identity | UID/GID 65534, cleared capability sets and supplementary groups, no-new-privileges, bounded file descriptors |
| Syscalls | Native x86-64 allowlist, ABI/x32 rejection, clone flag checks, explicit kill/errno modes |
| Resources | cgroups v2 memory, swap, CPU bandwidth and PID limits; whole-cgroup termination |
| Networking | No configured network interfaces; optional HTTPS GETs through one explicitly granted Unix socket |
| Lifecycle | Timeout, cancellation and output-limit handling; empty-leaf verification before successful cleanup |
| Evidence | Structured outcomes, peak memory and CPU/PID counters, bounded output prefixes, stream hashes, anchored audit chains |

Missing prerequisites and failed setup never fall back to unrestricted execution.

## Quick start

Requirements: Linux x86-64, current stable Rust, cgroups v2 with delegated cpu/memory/pids controllers, cgroup.kill and memory.peak, namespace/mount privileges, Python 3, gcc with static libc, OpenSSL, iproute2, util-linux and strace for the full test suite. Use a disposable development host.

```bash
cargo build --release --workspace --locked
sudo chown root:root target/release/microbox-helper
sudo chmod 755 target/release/microbox-helper
sudo mkdir /sys/fs/cgroup/microbox-demo
sudo python3 scripts/rootfs.py /var/tmp/microbox-demo-rootfs
sudo python3 scripts/demo.py \
  --rootfs /var/tmp/microbox-demo-rootfs \
  --cgroup /sys/fs/cgroup/microbox-demo \
  --output /var/tmp/microbox-demo-evidence
sudo rmdir /sys/fs/cgroup/microbox-demo
```

The rootfs builder copies explicitly trusted host tools, Python's distribution standard library and their shared libraries into a new directory. It never accepts an existing destination or downloads an image. Site packages and host application directories are excluded. Its manifest records file hashes and provenance; treat the prepared tree and helper as trusted, immutable inputs.

The demo runs Python as the unprivileged sandbox identity, returns JSON, and verifies the host audit file against the separately returned root. Evidence and rootfs directories remain available for inspection.

## Rust API and CLI

```rust,no_run
let config: microbox::Config = serde_json::from_reader(config_file)?;
let outcome = microbox::run(config).await?;
// Inspect termination, exit_code and signal before treating a workload as successful.
```

See [the compiling Rust example](crates/microbox/examples/run.rs). Concurrent runs use independent cgroup leaves. Dropping the future requests cancellation; the dedicated supervisor continues cleanup while the embedding process remains alive.

```bash
# Generate a complete air-gapped configuration without executing it.
target/release/microbox-cli init-config \
  /var/tmp/microbox-demo-rootfs "$PWD/target/release/microbox-helper" \
  /sys/fs/cgroup/microbox-demo /var/tmp/unique-audit.jsonl \
  /usr/bin/python3 -I -c 'print(sum(range(1000)))' > config.json
sudo target/release/microbox-cli run config.json
# Retain audit_root separately, then verify against that external anchor.
target/release/microbox-cli verify /var/tmp/unique-audit.jsonl EXPECTED_ROOT
```

A nonzero workload exit is an observed execution outcome, not a CLI initialization error. SIGSYS appears as signal 31 rather than a synthesized shell status 159. [Configuration reference](docs/configuration.md).

## Optional HTTPS access

The workload retains its empty network namespace. Instead of adding a veth, bridge, route or transparent TCP tunnel, a single pathname socket exposes a narrow HTTPS GET capability. A separate proxy running as UID/GID 65533 enforces:

- Exact canonical DNS hostnames; HTTPS on port 443 only.
- Rejection of private, loopback, link-local, reserved and transition-address ranges, including mixed public/private DNS answers.
- A validated, pinned destination address with normal TLS certificate and hostname verification.
- No redirects, environment proxies, caller-supplied headers, request bodies, cookies or arbitrary CONNECT tunneling.
- Bounded request size, session admissions, concurrency, response size and deadlines; independently anchored policy/outcome logs.

```python
import sys
sys.path.insert(0, '/opt/microbox')
from microbox_fetch import fetch
status, body = fetch('https://example.com/')
```

There is no grant in the default configuration. Explicitly configure `network.mode = "https_fetch"` and a trusted proxy socket to enable it. See [deployment and protocol](docs/egress.md). Policy-approved URLs can still carry data to an approved host; this is destination authorization, not content inspection or proof of benign intent.

## Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps --locked
```

Real-kernel tests require a new rootfs path and an empty dedicated cgroup parent. They fail rather than skip when prerequisites are unavailable:

```bash
sudo mkdir /sys/fs/cgroup/microbox-test
sudo env MICROBOX_CGROUP=/sys/fs/cgroup/microbox-test \
  MICROBOX_ROOTFS=/var/tmp/microbox-test-root \
  bash tests/adversarial/host.sh
sudo rmdir /sys/fs/cgroup/microbox-test
```

The suite covers resource exhaustion, fork-bomb containment, filesystem immutability, descriptor closure, syscall policies, cancellation, native/Python compatibility, concurrent runs, and an offline TLS fixture in a private network/mount namespace. The TLS fixture checks allowlists, private DNS results, certificate validation, redirects, malformed requests, direct-network bypass and session budgets. It never disables TLS verification or depends on a public website.

The recorded v0.2 candidate passed **17 Rust unit tests, 16 kernel containment checks, 9 dynamic/Python/concurrent workload checks, and 20 HTTPS capability checks**. The final source-tree CI repeats these checks and adds the standalone Python client contract tests. See [validation evidence](docs/validation.md).

CI uploads detailed outcomes and measurements as **kernel-tests-and-measurements**. [Recorded evidence](docs/validation.md).

## Measurements and scope

Benchmarks separate static native execution, dynamically linked ls, and Python cold start, recording every sample with CPU/kernel metadata. Setup-readiness includes helper launch, cgroup provisioning, isolation work, IPC and parent polling. It is not an exact execve timestamp. Python startup remains in its own workload class; no guessed overhead is subtracted. [Methodology](docs/measurement.md).

The initial v0.1 static-probe baseline measured 3.084 ms median parent-observed setup readiness on its shared CI runner. That historical result does not meet a 500-microsecond target. The v0.2 runner measured median CLI end-to-end times of **5.246 ms native**, **6.593 ms dynamically linked ls**, and **19.590 ms Python cold start** (30 samples per class). These include CLI/runtime and cleanup costs, not just isolation. [Raw v0.2 samples](benchmarks/baseline-v0.2-linux-x86_64.json) retain all measurements; these are shared-runner observations, not a latency guarantee.

Kernel exploits, hardware side channels, whole-host supervisor crashes, and uninterruptible kernel tasks remain outside the guarantee. CPU limits are bandwidth quotas, not instruction budgets; block-device I/O throttling and comprehensive syscall/file/packet tracing are not implemented. The rootfs and proxy are trusted inputs/components. General outbound TCP, arbitrary HTTP methods, ARM, rootless setup and cross-runtime performance comparisons are outside this release's scope.

## Workspace

| Crate | Responsibility |
|---|---|
| microbox-sys | Auditable namespace/mount/privilege wrappers and pure Rust seccomp builder |
| microbox-helper | Single-threaded setup, PID 1 reaping and payload exec protocol |
| microbox | Async API, cgroup lifecycle, bounded capture and audit verification |
| microbox-cli | Configuration generation, execution and audit commands |
| microbox-egress | Separately privileged HTTPS capability service |

[Architecture](docs/architecture.md) · [Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [MIT license](LICENSE)

Prior art includes [bubblewrap](https://github.com/containers/bubblewrap), [nsjail](https://github.com/google/nsjail), [gVisor](https://gvisor.dev/) and [Firecracker](https://firecracker-microvm.github.io/). microbox explores an embeddable Rust API and explicit lifecycle evidence; it does not claim to replace these established systems or outperform them.
