# Security policy

The guided installer is intended only for two clean VPS instances. It performs read-only preflight
before confirmation and keeps rollback armed until its end-to-end checks pass. Do not run it on an
existing VPN server or a host containing unrelated services.

For the threat model and credential rules, see [docs/SECURITY.md](docs/SECURITY.md). Never attach
inventories, subscription URLs, private keys, QR codes, database exports or encrypted backups to a
public issue.

Report vulnerabilities privately through a GitHub Security Advisory for this repository. Include the
affected release or commit and reproduction steps that do not contain live credentials.
