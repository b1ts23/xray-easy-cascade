# Integration lab

This lab creates two disposable Ubuntu containers named `entry` and `exit` on an isolated Docker
bridge. It is intended for controller, SSH, configuration and cascade tests. It does not emulate two
independent public IP addresses or two kernels.

Safety properties:

- SSH is published only on Hetzner loopback (`127.0.0.1:2201/2202`) and is not reachable from the internet;
- the existing Docker networks and containers are not joined;
- the isolated bridge is dual-stack (`172.29.10.0/24` and `fd29:10::/64`); only entry receives
  `NET_ADMIN`, solely for exact, automatically cleaned failover fault injection;
- each node is limited to 384 MiB RAM, 0.5 CPU and 128 processes;
- only a generated lab SSH public key is mounted;
- password authentication and SSH forwarding are disabled;
- entry and exit keep separate persistent SSH host-key volumes across container recreation;
- both 3x-ui panels are published only on Hetzner loopback (`127.0.0.1:20531/20532`);
- each panel has a separate persistent SQLite volume and randomly generated first administrator;
- the exit panel uses a persistent CA-signed TLS certificate whose public CA is trusted by entry
  before 3x-ui starts; bootstrap uses a SHA-256 pin and final master-to-node calls use official
  3x-ui `mtls` mode with the API token cleared;
- the entry subscription service uses a different persistent self-signed certificate;
- the pinned RoscomVPN profile is adapted so only private destinations bypass the client tunnel;
  public routing is decided on entry and cannot expose the device ISP address;
- all state belongs to the `xray-cascade-lab` Compose project;
- every deploy snapshots both 3x-ui databases, managed geo-assets and protected certificate/system
  files under root-only
  `/var/lib/xray-cascade`, verifies the ownership manifest and holds a per-node transaction lock.
- the pinned production archive is independently staged and validated without replacing the running
  panel, activating systemd or changing firewall state.
- age-encrypted off-host backup, checksum validation and transactional two-node restore are tested
  without writing plaintext node archives to the operator disk.

The node image pins the official 3x-ui `3.11.0` release archive. 3x-ui starts and owns its bundled
Xray-core `26.10.21`; the lab does not install or edit a separate Xray runtime. The pinned
`x-ui-linux-amd64.tar.gz` SHA-256 is
`0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916`.

The lab key is local and ignored by Git:

```bash
make lab-key
docker compose -f lab/compose.yml build
docker compose -f lab/compose.yml up -d
docker compose -f lab/compose.yml ps
make lab-bootstrap
make lab-configure
make lab-e2e
```

`make lab-bootstrap` creates an `admin` API token on entry and a `node-sync` token on exit without
printing either value. It probes the node, then adds or updates the same `lab-exit` record. Repeated
runs are idempotent and must finish with `3XUI_NODE_READY ... status=online`.

`make lab-configure` uses only the pinned 3x-ui API and database ownership model. It creates an
excluded-from-subscription VLESS + REALITY hop inbound on the exit node, a client inbound on entry,
and a catch-all `cascade-exit` outbound/rule on entry. It does not write a standalone Xray config.
Repeated runs are idempotent and finish with both `3XUI_ENTRY_CONFIG_READY` and
`3XUI_EXIT_CONFIG_READY`.

`make lab-e2e` creates an ephemeral local Xray client inside the entry container, validates its
configuration with the bundled binary, connects to the entry Reality inbound through SOCKS, and
requires an HTTPS 200 through the exit. Its temporary UUID-bearing config and API header are removed
on exit. It also fetches the real HAPP subscription over HTTPS and verifies the routing header
against the adapted profile checksum. Success includes `3XUI_CASCADE_E2E_READY http=200` and
`3XUI_ROSCOMVPN_SUBSCRIPTION_READY http=200 checksum=verified`.

`vpnctl verify --lab` additionally exercises the network boundary. It temporarily rejects only
`exit IPv4:interserver-port`, only `exit IPv6:interserver-port`, and then both. A cleanup trap removes
the exact rules on success, failure or interruption. The required markers prove IPv4 primary,
automatic IPv6 fallback, fail-closed behavior without a direct leak, and recovery after both rules
are removed.

The controller commits snapshots only after those checks. A failed run automatically imports the
saved databases on both nodes and restores only manifest-owned geo-assets. A deliberately injected
post-mutation failure has exercised this path. If the controller itself is interrupted, use
`vpnctl rollback --lab ...`; it rejects conflicting transaction IDs and can finish recovery when
one node already rolled back while the other still owns the pending lock.

Portable backup/restore is separate from rollback snapshots:

```bash
./bin/vpnctl backup-keygen --output lab/.state/backup-age-identity.txt
./bin/vpnctl backup --lab --recipient age1... --output lab/.state/backups/lab.age \
  --inventory lab/inventory.example.yml --known-hosts lab/.state/known_hosts \
  --proxy-jump root@DOCKER_HOST:22
./bin/vpnctl backup-verify --input lab/.state/backups/lab.age \
  --identity lab/.state/backup-age-identity.txt
./bin/vpnctl restore --lab --yes --input lab/.state/backups/lab.age \
  --identity lab/.state/backup-age-identity.txt --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts --proxy-jump root@DOCKER_HOST:22
```

The complete sequence is also driven by the compiled controller:

```bash
go build -trimpath -o bin/vpnctl ./cmd/vpnctl
./bin/vpnctl deploy --lab --yes \
  --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts \
  --proxy-jump root@DOCKER_HOST:22
```

Read-only operational checks after deploy:

```bash
./bin/vpnctl status --lab --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts --proxy-jump root@DOCKER_HOST:22
./bin/vpnctl status --lab --json --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts --proxy-jump root@DOCKER_HOST:22
./bin/vpnctl verify --lab --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts --proxy-jump root@DOCKER_HOST:22
```

Status output contains no UUID, private key, API token, subscription ID or subscription URL.
Verify requires node mTLS with no API token, the expected listeners/inbounds, successful cascade
and HAPP routing checksum E2E, plus the four IPv4/IPv6 fault-injection checks above.

The command rejects public SSH targets, port 22 targets, public cascade addresses, privileged
transport ports, missing jump hosts and non-tunnel panel access. Two consecutive controller runs
must end with `3XUI_LAB_DEPLOY_READY` and retain node id `1` and existing Reality credentials.
The exit node TLS chain, master client identity, separate entry subscription certificate and two
Reality key pairs remain independent and stable across container recreation.

The generated panel credentials remain in each private Docker volume as `/etc/x-ui/lab-credentials`
with mode `0600`; they are not committed or printed by the bootstrap.

An operator reaches SSH and the panels through tunnels to the Docker host; the container ports remain
closed publicly. `inventory.example.yml` describes the SSH tunnel endpoints.

The tested read-only controller invocation is:

```bash
vpnctl preflight \
  --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts \
  --proxy-jump root@DOCKER_HOST:22 \
  --lab
```

`--lab` permits the intentional lack of systemd, public IPv6 and production-size memory. Without
that flag the same nodes must be reported as `BLOCKED`, so a container result cannot be mistaken for
production readiness.

The lab proves Xray/3x-ui IPv4-primary → IPv6-fallback and fail-closed behavior over an isolated ULA
dual-stack bridge. It is not proof of public-provider IPv6 routing, host UFW behavior, two independent
kernels/public IPs, or production systemd integration. Those still require tests on independent VPS.
