# Recorded validation

Source validation run: [39860905395](https://github.com/mahasmrtiadhuri/microbox/actions/runs/39860905395), October 22, 2026. This run extracted the source workspace, formatted it, generated the lockfile, compiled with strict Clippy, ran unit tests, built release binaries, then exercised the real host kernel. The final source-tree CI repeats those checks without packaged-source extraction.

The runner used x86-64 Linux 6.17.0-1022-azure, glibc 2.39, and an Intel Xeon Platinum 8573C. No namespace/cgroup test was emulated or skipped.

```text
Unit tests: 9 passed; 0 failed
PASS true
PASS pid
PASS fds
PASS net
PASS fs
PASS tmp
PASS ptrace-kill
PASS ptrace-errno
PASS unshare-kill
PASS unshare-errno
PASS pids_max
PASS oom
PASS bounded-output
PASS async-cancellation
PASS exec-failure
PASS fail-closed-preflight
16 real-kernel adversarial checks passed
```

Every executed run required a removed cgroup leaf and verified its audit file against the separately returned root. The PID-max test observed an increment in pids.events.max before timeout; OOM classification required memory.events.oom_kill. Cancellation waited for the dedicated supervisor's audit outcome and leaf removal. The filesystem check required EROFS and separately demonstrated writable /tmp. The descriptor probe found no inherited descriptors above stderr.

## Initial baseline

| Boundary | Median | Maximum |
|---|---:|---:|
| Parent-observed setup readiness | 3.084 ms | 7.819 ms |
| Ready to helper completion | 0.124 ms | 0.434 ms |
| Cleanup and stream capture | 0.086 ms | 2.192 ms |
| Supervisor total before final audit serialization | 3.842 ms | 8.470 ms |
| CLI process end-to-end | 5.914 ms | 10.714 ms |

Thirty samples, static C probe, no warm-up exclusion. Medians of phase samples do not sum to the median total. Full context and every sample are committed in [baseline-linux-x86_64.json](../benchmarks/baseline-linux-x86_64.json). These observations include polling and scheduling and do not meet a 500-microsecond setup target. There is no comparison with another sandbox in this dataset.

The CI artifact kernel-tests-and-measurements includes detailed outcomes and raw samples. Artifact retention is controlled by GitHub; the committed baseline preserves the initial timing data. These tests demonstrate the exercised configurations, not an exhaustive escape proof or production security certification.


## v0.2 recorded candidate

[Validation run 39871264562](https://github.com/mahasmrtiadhuri/microbox/actions/runs/39871264562), October 22, 2026, passed strict Clippy and 17 Rust unit tests, then the following real-kernel suites:

| Suite | Passing checks |
|---|---:|
| Original containment and lifecycle suite | 16 |
| Dynamic utilities, Python, subprocesses and concurrent runs | 9 |
| HTTPS grant, policy/TLS enforcement and session lifecycle | 20 |

The HTTPS fixture ran in a private network and mount namespace with an ephemeral CA. It preserved the production address-validation and TLS checks, served a synthetic public address on its private loopback interface, and did not contact the public internet. It verified exact host policies, HTTPS-only ports, credentials/fragments/IP-literal rejection, private/mixed DNS rejection, wrong hostname/untrusted CA rejection, redirect and response bounds, method-smuggling rejection, direct-IP bypass failure, an absent grant, and admission-budget shutdown. Proxy logs were verified against their independently returned roots.

```text
17 Rust unit tests passed
16 real-kernel adversarial checks passed
PASS dynamic-ls
PASS shell
PASS python-subprocess
PASS python-cold-start
PASS python-standard-library
PASS concurrent-python-0
PASS concurrent-python-1
PASS concurrent-python-2
PASS concurrent-python-3
9 dynamic/Python/concurrent workload checks passed
20 HTTPS capability checks passed
```

### Three-class timing baseline

| Class | Median CLI end-to-end | Maximum |
|---|---:|---:|
| Static native probe | 5.246 ms | 9.598 ms |
| Dynamically linked ls | 6.593 ms | 12.361 ms |
| Python cold interpreter start | 19.590 ms | 21.733 ms |

Thirty samples per class. These include process/runtime setup and cleanup; they do not isolate the interpreter's intrinsic cost or establish a performance guarantee. [All v0.2 samples and host metadata](../benchmarks/baseline-v0.2-linux-x86_64.json) are retained separately from the historical v0.1 baseline. No competitive latency comparison or sub-millisecond claim is made.

The final source-tree CI also runs the standalone Python client's framing, malformed-response, denial-propagation and receive-bound tests, and builds Rust documentation/examples.
