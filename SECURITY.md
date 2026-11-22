# Security policy

Xray Cascade is still a design preview. Production mutation commands are intentionally fail-closed.
Do not use the current repository on a real VPN server.

For the threat model and credential rules, see [docs/SECURITY.md](docs/SECURITY.md). Never attach
inventories, subscription URLs, private keys, QR codes, database exports or encrypted backups to a
public issue.

Until a dedicated private reporting channel is published with the first release, report only a
redacted description through a GitHub Security Advisory for this repository. Include the affected
commit and reproduction steps that do not contain live credentials.
