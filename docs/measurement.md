# Measurement boundaries

No numerical startup or competitive performance claim is published without raw data.

`benchmarks/run.py` records thirty runs by default, kernel release, CPU model, architecture, platform and delegation path. It writes every sample to results/benchmark.json. The static C probe exits immediately; it avoids interpreter and dynamic-loader startup. CI artifacts preserve each run's data, not a hand-entered table.

| Field | Boundary |
|---|---|
| call_to_setup_ready | Supervisor entry to parent receipt of post-filter readiness, including validation, audit creation, cgroup setup, helper launch, namespace/mount/privilege/filter work, IPC and polling delay |
| ready_to_helper_exit | Parent-observed readiness to helper completion; includes exec, payload, init reaping and scheduling |
| cleanup_and_capture | Whole-group kill, direct-child reap, empty-leaf checks, stats, directory removal and final stream collection |
| total | Supervisor entry through collection, before final outcome serialization/audit append |
| cli_end_to_end | External process spawn through CLI exit, including runtime initialization and JSON output |

The supervisor polls at one millisecond. Parent-observed times are conservative scheduling-inclusive measurements, not a precise pre-exec timestamp. The runner does not subtract a guessed constant or relabel Python cold-start time as isolation overhead. Cleanup_and_capture includes bounded output drain costs; the audit does not promise fsync-level crash durability.

This initial fixture measures only the static probe. Dynamic utilities and Python require an operator-provisioned rootfs and reviewed seccomp compatibility. Criterion microbenchmarks of a BPF builder would not substitute for these end-to-end kernel measurements. Warm vs cold rootfs page cache, host load, CPU governor, storage and runner variance must accompany any future comparison against bubblewrap/nsjail/gVisor/Firecracker. CI numbers are development baselines, not controlled comparative performance results.

## v0.2 workload classes

The current harness records thirty samples each for the static native probe, dynamically linked `/bin/ls /`, and `/usr/bin/python3 -I -c pass`. It retains Python interpreter startup in that class. All use the same rootfs and resource configuration; rootfs creation and dependency copying occur before measurements.

The schema-2 report includes argv and every sample per class. These are repeated process/interpreter cold starts with an uncontrolled filesystem page cache, not a claim of a cold disk/page cache. No samples are discarded, and no constant is subtracted. The optional HTTPS fixture is a correctness test, not an internet-latency benchmark. A controlled comparison with established runtimes remains outside this release, and no competitive latency values are presented.
