# Contributing

Run formatting, strict Clippy and workspace unit tests. Any isolation or lifecycle change also requires the real-kernel adversarial suite on a disposable Linux host; unavailable prerequisites must fail, never turn into a passing skipped test.

Keep unsafe FFI in microbox-sys or the single-threaded helper, document pointer/process invariants, and test BPF ABI/argument boundaries when changing the profile. Never add permissive fallback execution, blanket syscall allowances, inherited host descriptors, unbounded output collection or undocumented host bind mounts.

Publish measurements with hardware/kernel context and raw samples. Do not describe this experimental shared-kernel boundary as formally verified, hardware attested or production hardened.
