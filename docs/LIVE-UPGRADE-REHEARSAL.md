# Existing-cascade live-upgrade rehearsal

Date: **22.11.2026**.

This is an internal, non-public migration path for adopting an already running 3x-ui cascade. It is
not connected to `vpnctl deploy`. Three guarded transactions were run on the real RU entry on
22.11.2026: the first two rolled back and the third was explicitly committed after automated and
operator verification. The NL server was not mutated.

## Scope of the change

The generated apply script first validates the current 3x-ui template and then changes only the
existing entry runtime:

- the existing IPv4 outbound remains the balancer selector;
- the existing IPv6 outbound becomes `fallbackTag`;
- observatory is added for both paths;
- all existing BitTorrent block rules move before the client catch-all rule.

It does not create or replace inbounds, clients, outbounds, subscriptions, certificates, panel
settings, firewall rules or SSH settings. The Russian direct IP/domain rules and the private-IP
block rule remain unchanged.

## Recovery protocol

Before mutation, a launcher uses the 3x-ui API to export a consistent database and records its
SHA-256 in a root-only transaction directory. It deletes the temporary snapshot token from the live
database, arms a five-minute transient systemd rollback timer and starts the apply/verify worker as
an independent transient service.

The worker is independent of the operator's SSH and VPN session. After successful server-side E2E it
enters `verified_waiting_confirmation` and deliberately leaves the timer armed. The operator confirms
that HAPP still works before a separate commit command cancels the timer. If the VPN connection is
lost and confirmation never arrives, the deadline imports the saved database through the 3x-ui API
and marks the transaction rolled back. An apply error, verification error or killed worker also
rolls back without waiting for operator input.

## Evidence from the isolated Hetzner lab

The following paths were exercised without touching the real cascade:

1. The narrow apply script updated the actual lab entry through the 3x-ui API.
2. A forced post-apply failure restored the exported database and produced
   `3XUI_LIVE_ROLLBACK_READY`.
3. The success path ran the cascade E2E check, cancelled the watchdog and produced
   `3XUI_LIVE_UPGRADE_COMMITTED`.
4. A disposable Ubuntu 24.04 systemd container confirmed the transient-unit mechanics separately:
   a successful worker cancelled the timer, while an uncancelled timer started its rollback service.
5. After cleanup, the normal lab passed cascade HTTPS, RoscomVPN/HAPP checksum, IPv4 primary, IPv6
   fallback, fail-closed and recovery checks.
6. The no-backup-connectivity mode was exercised in both directions: explicit confirmation committed
   while the watchdog was still armed; withholding confirmation made the watchdog restore the old DB.
7. The production-style verifier now also requires at least three successful HTTPS responses from
   Yandex, FNS, mos.ru and VK through the synthetic client. A single site with its own VPN/datacenter
   filtering cannot veto the transaction.
8. On 22.11.2026 the updated verifier passed in the isolated lab with all four Russian controls, the
   NL egress check and the HAPP subscription check. A subsequent full `vpnctl verify --lab` again
   passed IPv4 primary, IPv6 fallback, fail-closed and recovery.

The temporary systemd container/image, fake scheduler files and rehearsal transactions were removed.
The application containers on Hetzner remained healthy.

## Reference RU attempts on 22.11.2026

The first guarded transaction reached the public cascade probe but failed because the synthetic
REALITY client initially dialled loopback instead of the public entry address. The independent
rollback restored the API snapshot. The verifier was corrected to use the public RU address and to
accept either the documented NL IPv4 or NL IPv6 egress.

The second transaction reached `verified_waiting_confirmation`. It was deliberately rolled back
after the operator reported that a Russian control did not open. Read-only diagnosis later showed
that the reported control, Gosuslugi, independently times out from the original RU datacenter IP
while Yandex, FNS, mos.ru and VK work. Gosuslugi is therefore documented as a site-specific
datacenter/VPN limitation and is excluded from the cascade acceptance gate.

Both rollbacks completed successfully. The rollback timers and scoped API tokens were cleaned up,
and the RU runtime was re-read as the original two-member `roundRobin` balancer without observatory
or fallback, with the original routing order restored.

The third transaction used the updated multi-site verifier,
reached `verified_waiting_confirmation`, and was committed only after the owner confirmed HAPP and
both Russian and foreign browsing. The commit cancelled the watchdog and removed the lock.
Post-commit checks confirmed:

- the IPv4 exit is the only balancer selector;
- the IPv6 exit is the fallback;
- observatory checks both paths every 10 seconds;
- BitTorrent block precedes the client catch-all;
- NL egress, Russian controls `4/4`, and HAPP subscription headers pass.

## Remaining public-release gate

The reference cascade has passed the guarded adoption. Before exposing this path as a public user
command, the project still needs a longer observation window, packaged production UX, and a clean-VPS
E2E on two independent public hosts. The internal reference migration path remains disconnected from
public `vpnctl deploy`.

The NL exit does not require a runtime mutation for this first change-set.

## XHTTP adoption rehearsal

On 22.11.2026 a second internal transaction was added for adopting one additional client transport
without replacing the working TCP/443 inbound. It copies the existing client's UUID and `subId`,
clears Vision flow for the new route, generates a separate REALITY key pair, creates VLESS + REALITY
+ XHTTP on a separate TCP port, and adds only its inbound tag to the existing cascade catch-all.
The existing TCP inbound, exit, outbounds, balancer, observatory, certificates, panel, SSH and firewall
are not changed.

The isolated Hetzner lab caught and fixed two 3x-ui 3.11.0 API compatibility details before any live
use: JSON settings may be returned as decoded objects rather than strings, and an empty VLESS `flow`
may be omitted from the API response. After normalization, the following guarded outcomes passed:

1. A forced failure after successful XHTTP apply imported the original DB and removed the lock.
2. XHTTP reached the expected cascade exit end-to-end.
3. The HAPP subscription contained both released TCP and XHTTP routes; three research-only routes
   present in that historical lab are excluded from the released profile.
4. The worker reached `verified_waiting_confirmation` while the rollback watchdog remained armed.
5. Withholding confirmation caused automatic DB rollback and removed the transaction lock.
6. All Go tests and `go vet` passed, and both lab containers remained healthy after cleanup.

The reference candidate is deliberately limited to `8443/tcp` on RU entry. Read-only preflight found
that port free and UFW inactive, so no firewall mutation is part of the transaction. The live NL exit
does not need a change for this transport.

The live adoption was completed on 22.11.2026 after an age-encrypted, checksum-verified off-host
backup of both production nodes. Two safe rollbacks preceded the final commit: one dead-man timeout,
and one operator rejection caused by testing a cached HAPP route after REALITY credentials had been
regenerated. An external Hetzner probe confirmed that RU `8443/tcp` was reachable. After refreshing
the subscription, the owner confirmed traffic through the new route and the transaction was committed.
Post-commit state has both 443 and 8443 listeners,
the XHTTP tag in the existing balancer rule, no live-upgrade lock, no active rollback timer and zero
temporary `xray-cascade-*` API tokens. The NL exit remained unchanged.
