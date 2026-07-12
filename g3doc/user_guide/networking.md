# Networking

[TOC]

gVisor implements its own network stack called [netstack][netstack]. All aspects
of the network stack are handled inside the Sentry — including TCP connection
state, control messages, and packet assembly — keeping it isolated from the host
network stack. Data link layer packets are written directly to the virtual
device inside the network namespace setup by Docker or Kubernetes.

Configuring the network stack may provide performance benefits, but isn't the
only step to optimizing gVisor performance. See the
[Production guide][Production guide] for more.

The IP address and routes configured for the device are transferred inside the
sandbox. The loopback device runs exclusively inside the sandbox and does not
use the host. You can inspect them by running:

```bash
docker run --rm --runtime=runsc alpine ip addr
```

## Network passthrough

For high-performance networking applications, you may choose to disable the user
space network stack and instead use the host network stack, including the
loopback. Note that this mode decreases the isolation to the host.

Add the following `runtimeArgs` to your Docker configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=host"
            ]
       }
    }
}
```

## Disabling external networking

To completely isolate the host and network from the sandbox, external networking
can be disabled. The sandbox will still contain a loopback provided by netstack.

Add the following `runtimeArgs` to your Docker configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=none"
            ]
       }
    }
}
```

## Egress traffic shaping (TBF)

gVisor can rate limit outbound sandbox traffic with a
[Token Bucket Filter (TBF)][tc-tbf] queueing discipline. TBF is modeled after
Linux's `tbf` qdisc and supports a single-rate bucket. It applies to
non-loopback NICs when using netstack; ingress and loopback traffic are not
shaped. The implementation lives in [pkg/tcpip/link/qdisc/tbf][tbf-source].

To enable TBF globally, add the following `runtimeArgs` to your Docker
configuration (`/etc/docker/daemon.json`) and restart the Docker daemon. For
example, 100 Mbps is 12,500,000 bytes/sec:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=sandbox",
                "--qdisc=tbf",
                "--qdisc-tbf-rate=12500000",
                "--qdisc-tbf-burst=1048576"
            ]
       }
    }
}
```

`--qdisc=tbf` selects TBF instead of the default FIFO qdisc. `--qdisc-tbf-rate`
is the sustained egress rate in bytes/sec. `--qdisc-tbf-burst` is the bucket
depth in bytes. After an idle period, up to `qdisc-tbf-burst` bytes can transmit
at line rate before throttling engages; sustained throughput is bounded by
`qdisc-tbf-rate`. Both flags take plain integers; unlike Linux `tc(8)`, gVisor
does not accept unit-suffixed strings like `1mbit` or `1mbps`. Both
`--qdisc-tbf-rate` and `--qdisc-tbf-burst` are required when `--qdisc=tbf`; the
sandbox refuses to start otherwise. There is no universal default for either:
rate is policy and burst depends on the workload's MTU, GSO configuration, and
acceptable latency.

Per-sandbox overrides can be set via OCI runtime annotations from any client
that supports them, including Kubernetes pod annotations propagated by
containerd, Docker (`--annotation key=value`), podman, and a raw OCI bundle's
`config.json`. The relevant keys are:

```
dev.gvisor.flag.qdisc: "tbf"
dev.gvisor.flag.qdisc-tbf-rate: "12500000"
dev.gvisor.flag.qdisc-tbf-burst: "1048576"
```

For example, on a Kubernetes pod:

```yaml
metadata:
  annotations:
    dev.gvisor.flag.qdisc: "tbf"
    dev.gvisor.flag.qdisc-tbf-rate: "12500000"
    dev.gvisor.flag.qdisc-tbf-burst: "1048576"
```

The `qdisc` annotation can only select TBF unless `--allow-flag-override` is
enabled; selecting `fifo` or `none` by annotation is rejected. The
`qdisc-tbf-rate` and `qdisc-tbf-burst` annotations can only lower or match the
runtime-configured values unless `--allow-flag-override` is enabled.

Operators using containerd can set per-runtime ceilings in the containerd
runtime configuration that annotations cannot exceed:

```toml
[runsc_config]
  qdisc-tbf-rate = "12500000"
  qdisc-tbf-burst = "1048576"
```

### Disable GSO {#gso}

If your Linux is older than 4.14.77, you can disable Generic Segmentation
Offload (GSO) to run with a kernel that is newer than 3.17. Add the
`--gso=false` flag to your Docker runtime configuration
(`/etc/docker/daemon.json`) and restart the Docker daemon:

> Note: Network performance, especially for large payloads, will be greatly
> reduced.

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--gso=false"
            ]
       }
    }
}
```

## DNS-based egress allowlist {#egress-allowlist}

When using the netstack network stack (`--network=sandbox`, the default), the
Sentry can enforce a destination allowlist on all outbound traffic. You specify
a set of allowed domains and/or allowed IPs. The Sentry snoops plain UDP DNS
responses for the allowed domains, learns the resolved addresses, and permits
egress only to those addresses (plus any statically allowed IPs). All other
egress is dropped, except that a TCP segment to a blocked destination is
answered with a **RST** synthesized by the Sentry, so a `connect()` returns
`ECONNREFUSED` at once instead of hanging until its own timeout. DNS itself is
never blocked: a query for a name outside the domain allowlist is still
forwarded and resolves normally, but connecting to the result succeeds only if
the address is statically allowlisted.

Because enforcement lives in the Sentry's link layer, it is not reachable by any
syscall inside the sandbox. Unlike in-sandbox `iptables`/`nftables` rules (which
a workload with `CAP_NET_ADMIN` can flush), and unlike transport-level checks
(which raw and packet sockets bypass), this allowlist applies to every outbound
packet, including those crafted with `--net-raw` or `--allow-packet-socket-write`.

Two flags control it, and the allowlist becomes active when either is non-empty:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--egress-allow-domains=docs.github.com,*.github.com",
                "--egress-allow-ips=8.8.8.8,10.0.0.0/8"
            ]
       }
    }
}
```

*   `--egress-allow-domains` is a comma-separated list of domain patterns. An
    exact name like `docs.github.com` matches only that name. A wildcard like
    `*.github.com` matches subdomains at any depth (`a.github.com`,
    `a.b.github.com`) but **not** the bare `github.com`. List the apex
    separately if you need it. Matching is case-insensitive. Supply
    internationalized names in punycode (A-label) form.
*   `--egress-allow-ips` is a comma-separated list of IPs and CIDRs (IPv4 and
    IPv6). A listed address is allowed on **all** ports and protocols.
*   Each list is capped at 1024 distinct entries after normalization and
    deduplication. The cap keeps the per-packet CIDR check cheap; it is far
    above any hand-written policy, but machine-generated lists (e.g. a cloud
    provider's full published IP ranges) will not fit.

### Finding your resolver {#egress-resolver}

The sandbox learns addresses only by observing DNS queries **leave** the
sandbox, so the query must first be allowed to reach the resolver. **You must
add the resolver's IP to `--egress-allow-ips`.** The resolver is whatever
`/etc/resolv.conf` inside the container points at, which is often *not* a
public resolver (e.g. `10.96.0.10` for Kubernetes CoreDNS, `169.254.169.253`
on AWS). Check it with `cat /etc/resolv.conf` inside the sandbox. If a
connection hangs, the Sentry log carries a rate-limited line naming the
dropped destination.

Setting `--egress-allow-domains` with no `--egress-allow-ips` at all is
rejected outright: with no static IP, the resolver itself could never be
reached, so no domain could ever resolve.

These flags are only supported with `--network=sandbox`. Combining them with
`--network=host`, `none`, or `plugin` (or with XDP redirect/tunnel mode) is a
hard error.

The flags may be set per-container via OCI annotations
(`dev.gvisor.flag.egress-allow-domains` / `dev.gvisor.flag.egress-allow-ips`),
but an annotation may only **narrow** the allowlist, never widen it, so a
container author cannot weaken the operator's policy:

*   If the runtime configured no allowlist, an annotation may add one (that only
    restricts egress).
*   If the runtime configured an allowlist, an annotation's domains must each be
    covered by a runtime domain pattern, and its IPs/CIDRs must each fall within
    a runtime IP/CIDR. Anything outside the runtime allowlist is rejected unless
    the operator sets `--allow-flag-override`.

This mirrors how the `--qdisc-tbf-rate`/`--qdisc-tbf-burst` annotations may only
lower the configured rate limit.

### Limitations {#egress-limitations}

*   Only plain UDP DNS (port 53) is snooped. DNS-over-HTTPS/TLS/QUIC and
    DNS-over-TCP (including the TC-bit truncation fallback) are not observed,
    so their resolved addresses are never learned. A response fragmented at the
    IP layer (a large EDNS0 answer) is not reassembled for snooping either, so
    its addresses are not learned. Disable encrypted DNS in the workload, or
    list target IPs statically.
*   Only A/AAAA answers grow the learned set. Other query types (MX, TXT,
    PTR, etc.) resolve normally but grant no egress.
*   A resolver reachable only over loopback (`127.0.0.53` systemd-resolved,
    `127.0.0.11` Docker) is not snooped, because loopback traffic is not
    filtered. DNS will appear to work but no addresses will be learned.
*   Address learning acts only on queries sent through the normal socket path,
    where the Sentry has already parsed the UDP header. A DNS query a workload
    crafts itself with `--net-raw` or `--allow-packet-socket-write` is
    forwarded verbatim. Destination-IP enforcement still applies (it can only
    reach a statically allowed resolver), but the query is not tracked and its
    response is not snooped, so addresses it resolves for an allowed *domain*
    are never learned and connections to them are dropped. Resolve allowed
    domains through the normal resolver path, or list their addresses in
    `--egress-allow-ips`.
*   The allowlist trusts the resolver: an allowed resolver can map an allowed
    domain to any address. The query/response pinning (server IP, client port,
    transaction ID, and question name) defends only against off-path spoofers.
*   Learned addresses are not expired (no TTL honoring) and are lost across
    checkpoint/restore. The static allowlist is re-derived from the flags of the
    `runsc restore` invocation, so it reflects whatever policy that invocation
    sets, not necessarily the one active at checkpoint time. A connection that
    was established to a learned address before checkpoint is dropped after
    restore until the workload resolves the name again. List the peers of
    long-lived connections in `--egress-allow-ips` if they must survive restore.
*   The policy is egress-only, so replies to inbound-initiated connections are
    dropped unless the peer is allowlisted. Broadcast/multicast control traffic
    that a workload needs (DHCP, mDNS) must be added to `--egress-allow-ips`.
*   The allowlist governs routed egress to destinations, not link-layer
    behavior. Control traffic needed to operate the link (ARP, IPv6 neighbor
    discovery, IGMP/MLD) is exempt from the allowlist, but only to link-local
    destinations (`fe80::/10`, `ff02::/16`, `224.0.0.0/24`) and only for
    specific message types, with source-routing and IPv6 Router
    Advertisement/Redirect dropped. A link-local destination is never routed off
    the local segment, so this exemption cannot reach a destination off the
    allowlist, whatever socket produced the packet. Global-scope multicast and
    legacy IGMPv2/MLDv1 reports addressed to their own group are not exempt;
    allowlist those group addresses if a workload needs them. A destination
    reached by tunneling or proxying through an allowlisted peer is likewise the
    peer's responsibility, as with any IP allowlist.
*   The learned-IP set has a fixed capacity (65536 addresses) and never evicts:
    once full, newly-resolved addresses stop being learned, even for
    allowlisted domains. This is intentional: evicting an address a live
    connection still depends on would drop that connection, which is worse for
    a security boundary than refusing to learn a new one. A sandbox resolving
    an unusually large number of distinct addresses over its lifetime (e.g. a
    workload that queries many different CDN-backed hostnames) can hit this
    cap. The Sentry log carries a one-time warning when it does.
*   Learning is bounded per response (at most 64 A/AAAA records) and per
    in-flight query (at most 4096 concurrently tracked). A domain served by an
    unusually large round-robin RRset, or a workload issuing an unusually
    large burst of concurrent lookups, can hit these caps. Addresses beyond
    them are not learned, and connections to them fail with a rate-limited
    drop log rather than an error the workload can act on.
*   A `--pcap-log`/`--log-packets` capture does not see egress the filter drops,
    nor the RST injected for a blocked TCP connection: both happen above the
    packet-logging layer. A workload's connection failures can therefore look
    inconsistent with the capture, so check the Sentry log's drop lines instead.

[netstack]: /docs/architecture_guide/networking/
[Production guide]: /docs/user_guide/production/
[tbf-source]: https://cs.opensource.google/gvisor/gvisor/+/master:pkg/tcpip/link/qdisc/tbf/
[tc-tbf]: https://www.man7.org/linux/man-pages/man8/tc-tbf.8.html
