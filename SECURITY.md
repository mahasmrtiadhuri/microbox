# Security scope

microbox is experimental. Do not use it as the sole isolation layer for hostile production tenants without independent review. It shares the Linux host kernel.

Trusted: host kernel and hardware, privileged supervisor/helper binaries, prepared rootfs contents, operator-owned configuration and directories, cgroup delegation, and audit storage. Untrusted: payload code and descendants. The embedding application is trusted and already privileged; this is not a setuid service or a privilege-granting API for arbitrary users.

The rootfs must be prepared by a trusted operator and remain immutable for the run. Root ownership and selected mountpoints are checked, but recursive content provenance, ancestor ownership, mount topology and concurrent rootfs mutation are operator responsibilities. Payload runs as UID/GID 65534 inside a private PID namespace, without inherited host directory/control descriptors or environment values.

The allowlist is a reduction of kernel attack surface, not a proof that allowed syscalls are safe against all kernel bugs. Native x86-64 only. Unknown ABIs kill the process in both modes. `clone3` returns ENOSYS; ordinary clone flags are checked. No namespaces or mount operations are permitted after exec. `/proc` exposes namespace-local process information; it is not an all-zero metadata view.

Cgroups limit resources and provide a kill boundary. They cannot guarantee a kernel-stuck task disappears instantly. A successful outcome requires an empty and removed leaf. Errors can leave an empty or populated leaf for operator inspection; Drop performs a best-effort kill and removal, not a crash-recovery service. Host supervisor SIGKILL, host reboot, lost privilege and compromised kernel are outside the lifecycle guarantee.

Audit records are canonical JSON as serialized by this workspace, length-framed and domain-separated in a SHA-256 chain. Persist the returned root separately. Without that root an attacker controlling the file can replace or truncate the log. No signing service, remote timestamp, every-syscall tracing, or power-loss durability guarantee is implemented.

Report suspected issues privately through the maintainer's contact on the GitHub profile. Include kernel, architecture, reproduction, configuration, and observed boundary failure; remove secrets from logs.
