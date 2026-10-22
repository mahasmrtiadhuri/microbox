# microbox

**An experimental Linux sandbox for native, untrusted workloads.**

A Rust library and CLI that separate asynchronous orchestration from single-threaded isolation setup. Each run gets private mount, PID, network, IPC and UTS namespaces; a read-only root; bounded temporary storage; a seccomp allowlist; and a dedicated cgroups v2 leaf.

[![Verify microbox](https://github.com/mahasmrtiadhuri/microbox/actions/workflows/ci.yml/badge.svg)](https://github.com/mahasmrtiadhuri/microbox/actions/workflows/ci.yml)

**Status:** experimental Milestone 1 implementation, Linux x86-64, explicitly privileged setup. No setuid helper, daemon listener, rootless mode, production-hardening claim, or measured sub-millisecond promise. Read [SECURITY.md](SECURITY.md) before running it.

## What the boundary enforces

| Boundary | Implementation |
|---|---|
| Host filesystem | Non-recursive root bind, private mount propagation, `pivot_root`, detached old root, read-only/nosuid/nodev root |
| Writable storage | `/tmp` tmpfs with byte and inode limits, nodev/nosuid/noexec |
| Network | Fresh network namespace with no configured interfaces; socket creation may succeed but external communication cannot |
| Process visibility | Dedicated PID namespace with a trusted PID 1 reaper; fresh read-only procfs with `hidepid=2` |
| Privilege | Payload UID/GID 65534, empty supplementary groups, dropped capability bounding set, no-new-privileges |
| Syscalls | Native x86-64 allowlist; ABI/x32 rejection; argument checks for clone; clone3 returns ENOSYS for libc fallback |
| Resources | `memory.max`, zero swap, OOM group kill, CPU bandwidth quota, and `pids.max` |
| Lifecycle | Cgroup enrollment before helper setup, whole-cgroup kill on completion/timeout/output limit/cancellation, empty-group verification |
| Evidence | Exclusive host audit file, configuration and outcomes, output digests, observed cgroup counters, externally anchored hash chain |

Unknown prerequisites or failed setup abort the run. The library never silently executes outside its boundary.

## Layout

| Crate | Responsibility |
|---|---|
| `microbox-sys` | Auditable syscall wrappers, mount setup, identity drop, pure Rust BPF builder |
| `microbox-helper` | Single-threaded namespace setup, trusted PID 1, filtered payload exec |
| `microbox` | Tokio-compatible API, dedicated supervisor thread, cgroup lifecycle, bounded capture and audit |
| `microbox-cli` | JSON configuration, run, audit verification and cancellation exercise |

The embedding process never calls `unshare`. It launches the helper using `Command`; its only `pre_exec` operation is an async-signal-safe descriptor duplication. A private control socket reports readiness and payload status. Configuration travels over a pipe mapped to helper stdin and is replaced by `/dev/null` before the payload starts. A separate close-on-exec pipe distinguishes exec errors from ordinary exit 126.

## Build and verify

```bash
cargo build --release --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

The adversarial suite requires a disposable Linux host with cgroups v2, the cpu/memory/pids controllers delegated to an empty dedicated parent, writable `cgroup.kill`, and namespace/mount privileges. It deliberately fails rather than skipping on unsupported hosts.

```bash
# Operator-provisioned dedicated paths; do not use a production cgroup or host rootfs.
export MICROBOX_CGROUP=/sys/fs/cgroup/microbox-test
export MICROBOX_ROOTFS=/var/tmp/microbox-test-root
sudo mkdir "$MICROBOX_CGROUP"
sudo env MICROBOX_CGROUP="$MICROBOX_CGROUP" \
  MICROBOX_ROOTFS="$MICROBOX_ROOTFS" bash tests/adversarial/host.sh
sudo rmdir "$MICROBOX_CGROUP"
```

The host script compiles a static C probe, exercises real kernel enforcement, then records 30 baseline samples. Results go to `results/adversarial.json` and `results/benchmark.json`. CI uploads these as **kernel-tests-and-measurements** artifacts. Unit tests of BPF policy decisions and audit verification are separate from real kernel tests.

## Run a command

Prepare a trusted rootfs with root-owned, non-writable directories `tmp`, `proc`, `dev`, `sys`, and an empty `.microbox-old`. Provision the executable and all libraries it needs inside that tree. Do not pass `/`, a user-controlled tree, or a tree concurrently modified by another actor.

```json
{
  "rootfs": "/var/tmp/microbox-test-root",
  "helper": "/absolute/path/to/microbox/target/release/microbox-helper",
  "cgroup_parent": "/sys/fs/cgroup/microbox-test",
  "audit_path": "/var/tmp/unique-run-audit.jsonl",
  "argv": ["/bin/probe", "true"],
  "memory_bytes": 33554432,
  "tmp_bytes": 1048576,
  "pids": 24,
  "cpu_quota_us": 50000,
  "timeout_ms": 2000,
  "output_limit_bytes": 16384,
  "deny_mode": "kill"
}
```

```bash
sudo target/release/microbox-cli run config.json
# Keep the returned audit_root separately, then verify the file against that value:
target/release/microbox-cli verify /var/tmp/unique-run-audit.jsonl EXPECTED_ROOT
```

`microbox::run(config).await` returns a structured outcome with separate exit code and signal fields, termination reason, readiness state, observed resource counters, bounded output prefixes, output hashes and the final audit root. SIGSYS is reported as signal 31, not a synthesized shell exit code 159. A nonzero payload exit is still a successfully observed sandbox execution; callers must inspect the outcome.

Dropping the async future requests cancellation. Its dedicated supervisor thread continues teardown; read the exclusive audit file for cancellation evidence. Abrupt termination of the entire host supervisor, kernel failure, and uninterruptible tasks are not covered by a zero-leak guarantee. Cleanup has a five-second deadline and surfaces failure instead of claiming success.

## Verification and measurement

The real-kernel suite checks PID namespace entry, descriptor closure, read-only filesystems, bounded tmpfs, external network failure, kill/errno syscall policies, fork-bomb containment, group OOM handling, bounded output, async cancellation, exec failure reporting, and fail-closed preflight rejection. Every successful run is checked for cgroup removal and against its independently returned audit root.

[Measurement methodology](docs/measurement.md) describes the timing boundaries. Setup-readiness is parent-observed and includes process launch, cgroup setup, IPC and polling delay. Ready-to-helper-exit includes exec and init reaping. Neither is a claim of exact execve timing. Comparative benchmarks, dynamic utilities, Python cold starts, and proxy-mediated egress remain future work.

## Limits worth understanding

This is a shared-kernel boundary. Kernel exploits and hardware side channels are outside scope. CPU quotas throttle time rather than guaranteeing instruction counts or instant interruption. Tmpfs limits bound scratch storage; block-device I/O throttling is not implemented. `/dev` and `/sys` are empty mounts; workloads requiring devices need a separately reviewed profile. The syscall profile targets the included native probes; arbitrary Python/Node workloads may require additional reviewed calls. No terminal, host filesystem bind mounts, environment forwarding, external network, or disk-persistent workload outputs are exposed.

The hash chain authenticates collected metadata relative to an external root. It is not comprehensive syscall/file/packet tracing, hardware attestation, non-repudiation, or proof of non-compromise. [Architecture and trust model](docs/architecture.md).

Prior art: [bubblewrap](https://github.com/containers/bubblewrap), [nsjail](https://github.com/google/nsjail), [gVisor](https://gvisor.dev/), and [Firecracker](https://firecracker-microvm.github.io/) are established alternatives with different boundaries. This project explores an embeddable Rust API and explicit lifecycle evidence; it does not claim to replace them or outperform them.
