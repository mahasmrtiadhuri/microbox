# Security scope

microbox is experimental. Do not use it as the sole isolation layer for hostile production tenants without independent review. It shares the Linux host kernel.

Trusted: host kernel and hardware, privileged supervisor/helper binaries, prepared rootfs contents, operator-owned configuration and directories, cgroup delegation, and audit storage. Untrusted: payload code and descendants. The embedding application is trusted and already privileged; this is not a setuid service or a privilege-granting API for arbitrary users.

The rootfs must be prepared by a trusted operator and remain immutable for the run. Root ownership and selected mountpoints are checked, but recursive content provenance, ancestor ownership, mount topology and concurrent rootfs mutation are operator responsibilities. Payload runs as UID/GID 65534 inside a private PID namespace, without inherited host directory/control descriptors or environment values.

The allowlist is a reduction of kernel attack surface, not a proof that allowed syscalls are safe against all kernel bugs. Native x86-64 only. Unknown ABIs kill the process in both modes. `clone3` returns ENOSYS; ordinary clone flags are checked. No namespaces or mount operations are permitted after exec. `/proc` exposes namespace-local process information; it is not an all-zero metadata view.

Cgroups limit resources and provide a kill boundary. They cannot guarantee a kernel-stuck task disappears instantly. A successful outcome requires an empty and removed leaf. Errors can leave an empty or populated leaf for operator inspection; Drop performs a best-effort kill and removal, not a crash-recovery service. Host supervisor SIGKILL, host reboot, lost privilege and compromised kernel are outside the lifecycle guarantee.

Audit records are canonical JSON as serialized by this workspace, length-framed and domain-separated in a SHA-256 chain. Persist the returned root separately. Without that root an attacker controlling the file can replace or truncate the log. No signing service, remote timestamp, every-syscall tracing, or power-loss durability guarantee is implemented.

Report suspected issues privately through the maintainer's contact on the GitHub profile. Include kernel, architecture, reproduction, configuration, and observed boundary failure; remove secrets from logs.

## Optional HTTPS capability (v0.2)

The egress service is a separate trusted component under dedicated UID/GID 65533. Workloads remain UID/GID 65534 in an empty network namespace. An operator-selected pathname socket is bind-mounted at a reserved read-only rootfs path; no interface, route, bridge, TCP tunnel or general host socket is exposed.

The proxy authorizes exact DNS names and HTTPS GETs on port 443, rejects nonpublic/mixed DNS results, pins the selected destination address, and preserves TLS SNI/hostname/certificate verification. Redirects, caller headers, request bodies, arbitrary methods, environment proxies and CONNECT are not accepted. Optional DNS pins and additional CAs are operator-controlled policy inputs, not workload inputs. They never bypass public-address or TLS verification checks.

A compromised authorized workload can still send data in URLs to an approved host and exhaust its session budget. A compromised proxy can violate its policy; proxy compromise is outside the workload isolation guarantee. Run it without credentials or access to secrets, and provision its own service cgroup/resource policy. Do not mistake response/session bounds for complete host-resource isolation of the proxy itself.

Proxy policy and outcome logs have an independent final anchor. Shared proxy sessions cannot establish cryptographic attribution to individual runs; use a separate socket/session per run when needed. Logs do not establish complete packet observation, non-repudiation, or a proof of non-compromise.

## Trusted configuration and images

The embedding caller controls privileged Config values. Never forward an untrusted user's rootfs/helper/cgroup/socket paths as administrative configuration. The rootfs builder executes and inspects explicitly trusted distribution tools, including ldd and Python; do not use it to inspect arbitrary uploaded binaries. The generated manifest is an inventory whose anchor must be retained independently if provenance matters, not a signature or a defense against a malicious image producer.

Ordinary error unwinding requests whole-cgroup kill and starts a fallback direct-child reaper without blocking the error return indefinitely. Empty-leaf verification precedes the normal direct-child reap. If a kernel task remains uninterruptible, cleanup reports failure and the operator may need to inspect the retained leaf. Setup syscalls and scheduling do not have hard real-time guarantees.
