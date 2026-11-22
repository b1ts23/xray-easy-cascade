# Fresh-host E2E

This gate is for disposable Ubuntu 24.04 VPS instances owned by a contributor. It is not permission
to modify an existing VPN, shared server or production workload. The public production command stays
disabled until this checklist has been implemented in the CLI and independently completed.

## Required topology

- two clean amd64 VPS instances with different public IPv4 addresses;
- optional global IPv6 on both instances for the fallback test;
- SSH key access as `root`, with host keys pinned before preflight;
- no existing 3x-ui, Xray, web server or service on the declared project ports;
- disposable instances that can be destroyed after the test.

The instances do not have to be in Russia and the Netherlands. They represent generic `entry` and
`exit` roles. A contributor may use any providers and regions allowed by their local rules.

## Acceptance checklist

1. Read-only preflight reports both clean hosts ready and identifies every occupied port.
2. A single deploy installs the pinned 3x-ui release without editing a standalone Xray config.
3. Entry sees exit as an online mTLS node and the temporary API token is removed.
4. One HAPP subscription contains every enabled client transport; the base profile is TCP/Vision and XHTTP.
5. Every enabled client transport completes an HTTPS request through entry and exit.
6. RoscomVPN block/direct/cascade order matches the documented server-side policy.
7. IPv4 is primary; if IPv6 is available, a scoped IPv4 failure selects IPv6.
8. Failure of all interserver paths is fail-closed and never falls back to direct internet access.
9. Re-running deploy is idempotent and preserves identities and access details.
10. A forced post-mutation failure restores both nodes from the coordinated snapshot.
11. Rebooting both instances returns the cluster to a healthy state.
12. Uninstall removes only ownership-manifest resources and preserves SSH access.

## Safe evidence

Open the **Fresh-host E2E report** issue form and provide only pass/fail results, versions, provider
names if desired, and redacted error summaries. Replace every IP, hostname, username, URL, UUID,
certificate fingerprint and token with role labels such as `<ENTRY>` and `<EXIT>`.

Do not upload logs until they have been reviewed manually. Never publish inventory files, access
handoff files, subscription links or headers, QR codes, private keys, certificates, database exports,
encrypted backups or screenshots containing panel details.

## Promotion rule

One successful report is evidence, not an automatic release. Maintainers must review rollback,
secret-redaction and fail-closed evidence before enabling any production mutation command. Preview
tags remain GitHub pre-releases until that review is complete.
