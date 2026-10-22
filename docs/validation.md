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
