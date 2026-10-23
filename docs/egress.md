# HTTPS-fetch capability

This release deliberately exposes a narrow fetch operation rather than a transparent HTTP CONNECT proxy or veth/bridge. The payload keeps its empty network namespace. One pathname Unix socket is its only authority to ask a separate service for HTTPS GETs. There are no IP route or host firewall changes.

## Boundary and policy

The proxy is a trusted component outside the sandbox, running under dedicated UID/GID 65533. Workloads use UID/GID 65534. The proxy must not inherit credentials or access to production secrets. Its memory, CPU and file access are separate from workload cgroup limits; apply an operator-managed service cgroup in deployments. Its own admission, response, concurrency and time bounds limit a session, not every possible host-side resource cost.

A policy contains exact lowercase DNS hostnames. Public addresses are accepted conservatively; local/private/link-local/reserved IPv4 and IPv6 ranges, IPv4-mapped IPv6, NAT64 and 6to4/Teredo-style transition ranges are rejected. Any nonpublic answer invalidates the entire DNS result. Resolution happens outside the sandbox; the resulting selected address is pinned for that request. TLS SNI and certificate validation still use the authorized hostname.

All redirects are rejected before following them. URLs with userinfo, fragments, literals, another scheme or another port are rejected. No arbitrary request headers, body, method, cookies or CONNECT channel are accepted. Environment proxy variables are disabled in the HTTP client. A validated URL path/query may carry data to an authorized endpoint; no claim of application-level content safety is made.

## Provision a session

Use a new private directory and audit file for each session. For example:

```bash
sudo install -d -m 0700 -o 65533 -g 65533 /run/microbox-fetch-session
```

Create an operator-owned policy readable by UID 65533:

```json
{
  "socket":"/run/microbox-fetch-session/fetch.sock",
  "audit_path":"/run/microbox-fetch-session/audit.jsonl",
  "allowed_hosts":["example.com"],
  "dns_pins":{},
  "additional_ca_pem":null,
  "max_response_bytes":65536,
  "max_requests":64,
  "concurrency":4,
  "timeout_ms":5000
}
```

```bash
sudo setpriv --reuid=65533 --regid=65533 --clear-groups \
  target/release/microbox-egress serve /absolute/path/to/policy.json
```

The process prints a readiness record. Give the sandbox the explicit socket grant in its configuration, then use python/microbox_fetch.py inside the prepared rootfs. The session closes on SIGTERM/SIGINT or after its admission budget, drains timed in-flight requests, removes its socket path and returns its final audit root on stdout. Verify that anchor with microbox-cli verify. Do not reuse an audit file or silently accept a stale socket from an earlier session.

`dns_pins` is an optional operator-controlled static mapping for allowlisted names. Every pinned address must pass the same public-address check. It does not disable certificate verification. `additional_ca_pem` adds a trusted operator-provisioned CA; it never turns verification off. The offline fixture uses these controls with an ephemeral CA and a synthetic public address inside a private test network namespace.

## Wire protocol

One newline-terminated JSON object per Unix stream, at most 4096 wire bytes:

```json
{"url":"https://example.com/path"}
```

Unknown fields and pipelined bytes are rejected. EOF before the delimiter is invalid. A successful response is newline-terminated JSON:

```json
{"outcome":"fetched","status":200,"body_hex":"6869","peer_ip":"93.184.216.34"}
```

The address above is illustrative; production resolution is validated and pinned anew per request. The body is capped before hex encoding. A rejection is `{"outcome":"denied","reason":"..."}`. Treat any malformed/closed/timed-out connection as failure. The Python client also bounds received bytes and raises FetchDenied for proxy denials.

## Evidence and attribution

The proxy appends authorization metadata before outbound requests and appends outcome metadata before returning fetched content. It records hosts, selected addresses, status/byte counts and denials, not URL queries, caller headers or bodies. An audit write failure stops the session from admitting further requests.

Proxy and execution logs have separate externally retained roots. A shared session does not cryptographically identify which workload made a request. Use a dedicated session/socket per run when attribution matters. These are metadata logs, not exhaustive packet captures, instruction tracing or hardware attestation. Host kernel/proxy compromise is outside scope.
