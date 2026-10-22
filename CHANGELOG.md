# Changelog

## 0.2.0

- Add a separately privileged, bounded HTTPS GET capability over one explicitly granted Unix socket; leave direct networking disabled.
- Enforce exact host policies, conservative public DNS checks, per-request address pinning, ordinary TLS verification, redirect rejection, session budgets and separate audit anchors.
- Add a Python capability client, trusted rootfs preparation, a self-contained demo, configuration generation and a compiling async Rust example.
- Exercise dynamic utilities, Python startup/standard-library/subprocess behavior, concurrent runs and an offline TLS policy fixture on the real kernel.
- Record separate native, dynamic and Python benchmark classes with every sample and host context.
- Bound audit record parsing before allocation and handle incomplete delimiters; avoid blocking error unwinding on an unreapable helper.
- Retain experimental shared-kernel scope and measured performance, without production-hardening or sub-millisecond claims.

## 0.1.0

Initial Linux x86-64 implementation: dedicated setup helper, namespaces, read-only rootfs, bounded tmpfs, seccomp BPF allowlist, cgroups v2 supervision, bounded output capture and externally anchored audit chains. Recorded 9 unit tests, 16 real-kernel checks and a 30-sample static-probe baseline.
