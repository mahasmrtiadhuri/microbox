# Runtime configuration

The CLI accepts one UTF-8 JSON configuration. Unknown fields are rejected. Paths to the rootfs, helper and cgroup parent must be canonical absolute paths. Audit files are created exclusively with mode 0600; use a unique name per run.

| Field | Contract |
|---|---|
| rootfs | Trusted root-owned tree; not host /; required real directories tmp/proc/dev/sys/.microbox-old; old-root directory must be empty |
| helper | Root-owned executable, not group/world writable; trusted ancestors and stable contents are operator responsibilities |
| cgroup_parent | Dedicated empty cgroups v2 parent with cpu/memory/pids controllers available; never a production task group |
| audit_path | New host audit file, inaccessible to the workload |
| argv | Nonempty command vector, absolute executable path inside rootfs, no NUL bytes; total helper configuration at most 64 KiB |
| memory_bytes | At least 16 MiB; swap is always disabled for the leaf |
| tmp_bytes | Positive and no larger than memory_bytes; tmpfs allocations also count toward cgroup memory |
| pids | 4–4096 including trusted helper/init overhead |
| cpu_quota_us | 1000–100000 per 100000-microsecond period; throttles rather than counting instructions |
| timeout_ms | 1–3600000; wall deadline observed by supervisor polling |
| output_limit_bytes | 1–16 MiB per stream; full streams are hashed, only a bounded hex prefix is retained |
| deny_mode | kill or errno; unsupported ABI/x32 always kills; clone3 always returns ENOSYS for reviewed libc fallback |
| network | Optional, defaults to {"mode":"airgap"}; explicit HTTPS mode described below |

`Config::new` and `init-config` use 128 MiB memory, 16 MiB tmpfs, 64 tasks, 50% CPU bandwidth, a five-second wall deadline, 64 KiB per output stream and kill-mode seccomp. These are convenience defaults, not recommended production capacity estimates.

## Network grant

```json
{"mode":"https_fetch","socket":"/run/microbox-fetch-session/fetch.sock"}
```

The source must be an existing canonical Unix socket owned by root or UID 65533, in a private canonical directory owned by the same trusted administrative identities. The rootfs must contain a real root-owned `.microbox-egress` directory and an empty regular `.microbox-egress/fetch.sock` placeholder, neither group/world writable. The builder provisions these automatically. Only that socket inode is bind-mounted; its parent host directory is never exposed.

Network grants do not configure interfaces, DNS inside the sandbox, host sockets, tunnels, environment variables or caller headers. Each approved fetch is mediated outside the sandbox.

## Outcomes

`termination` is one of exited, signal, seccomp, killed_by_oom, timeout, cancelled, output_limit, initialization_failed, exec_failed, helper_failed. Inspect exit_code and signal separately. A successful command requires termination=exited and exit_code=0. OOM classification requires the fresh leaf's oom_kill counter.

A normal returned outcome requires cleanup_complete=true and an empty, removed cgroup leaf. Cleanup failure is a runtime error, not a falsely successful outcome. Error returns trigger best-effort guards and can leave a leaf for inspection. A fallback reaper runs outside the caller's async future; it cannot guarantee recovery if the entire embedding process is killed.

Setup operations are synchronous kernel operations in a dedicated thread/helper; there is no hard real-time bound on a kernel-stuck setup call. After kill, active-leaf verification has a five-second deadline. Cancellation and wall timeout require the supervisor to remain scheduled and alive.

The final audit record embeds an empty audit_root to avoid self-reference. The returned outcome contains the computed external root. Keep that root outside the mutable log. Output prefixes can contain workload data; choose retention/access policies accordingly.
