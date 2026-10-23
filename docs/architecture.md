# Execution contract

1. Validate trusted paths and bounded configuration. Create an exclusive audit file with mode 0600.
2. Validate cgroup filesystem type, controllers, empty parent and kill support. Enable controllers only in the explicitly supplied dedicated parent. Create a random leaf and write all limits before spawning.
3. Spawn a dedicated single-threaded helper with cleared environment. Preserve only one control socket as descriptor 3 across exec. Supervisor enrolls the blocked helper in the leaf before delivering configuration; helper also enrolls its own PID before any fork.
4. Helper replaces stdin with `/dev/null`, closes extra descriptors, sets control CLOEXEC, and unshares mount/PID/network/IPC/UTS namespaces. It forks into the new PID namespace.
5. Namespace PID 1 makes mounts private, binds only the rootfs mount, pivots, detaches the old root, remounts the root read-only, and mounts private tmp/proc/dev/sys. Setup requires a pre-created empty `.microbox-old` directory.
6. PID 1 forks the payload. The child drops supplementary groups, UID/GID and capability bounding set, sets no-new-privileges, installs BPF, reports readiness, closes the control socket and execs the absolute command with a minimal fixed environment. A separate CLOEXEC pipe reports setup/exec failures. PID 1 waits and reaps orphaned descendants until the main payload exits; exiting PID 1 causes the kernel to terminate namespace descendants.
7. The host supervisor polls for completion, timeout, output limit and caller cancellation. It kills the entire leaf, reaps its direct helper, waits until `populated 0`, records memory/CPU/PID counters, and removes the leaf. Reader threads hash all captured bytes while retaining only a bounded prefix. Each stream has its own capture limit.
8. An outcome record closes the audit chain. Return its final digest independently. The outcome's embedded audit_root is intentionally empty within that final record to avoid a self-referential hash; the returned outcome contains the computed root.

## Cancellation and failures

The async API runs supervision in a dedicated OS thread. Cancelling the async task closes a oneshot receiver; the supervisor observes that state and tears down the leaf. This requires the embedding process to remain alive. Child and cgroup guards provide fallback cleanup on ordinary Rust error unwinding, but cannot establish crash safety. No async-signal-unsafe mount, allocation or namespace work runs in Command pre_exec.

Oom classification is based on the fresh leaf's `memory.events.oom_kill`, not merely SIGKILL. Timeout/cancellation/output limit have explicit reasons. A setup failure never falls back to direct execution. An exit 126 is distinguished from an exec failure by the private error pipe. Runtime errors are JSON on CLI stderr; observed payload outcomes are JSON on stdout.

## Audit encoding

For sequence n, serialize the event to JSON bytes using serde_json, then compute:

`SHA256("MICROBOX-AUDIT-V1\\0" || previous_root[32] || n_be64 || event_length_be64 || event_bytes)`

Initial root is 32 zero bytes. Records contain sequence, event and hex digest. Verification recomputes every record and checks the separately supplied final root. It detects mutation, reordering, omitted records and truncation relative to that anchor. It does not prove event completeness or protect against a malicious trusted supervisor.

## Kernel references

- https://man7.org/linux/man-pages/man7/pid_namespaces.7.html
- https://man7.org/linux/man-pages/man2/pivot_root.2.html
- https://man7.org/linux/man-pages/man2/seccomp.2.html
- https://docs.kernel.org/admin-guide/cgroup-v2.html

## v0.2 capability transport

`Network::Airgap` remains the default. `Network::HttpsFetch` adds exactly one reviewed pathname-socket bind mount at `.microbox-egress/fetch.sock` before pivot_root. A prepared placeholder and its directory must be real, root-owned, non-writable entries. The source must be a trusted socket in a private canonical host directory. The source parent is never mounted. The payload's network namespace remains unconfigured.

The proxy is a fifth crate and a separately deployed process, not another privileged action in Tokio pre_exec. It accepts a single bounded JSON fetch frame, validates the host/scheme/port, resolves and rejects all nonpublic addresses, pins one address while preserving hostname verification, and returns only a bounded status/body response. Denials and fetch metadata go to a separate anchored audit stream. This deliberately provides narrower authority than transparent networking.

Error-path child guards now request termination and hand the direct child to a background reaper if necessary, rather than potentially blocking the caller forever. Normal cleanup verifies `populated 0` and removes the leaf before direct-child wait. A failure retains an explicit error; there is no successful outcome with unverified cleanup.
