# Contributing

The project accepts fixes, tests and design discussion. Production changes must remain scoped to two
explicitly confirmed clean VPS instances and preserve automatic rollback until end-to-end checks pass.

Before a pull request:

```bash
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
./scripts/build-release.sh dev dist
```

Do not submit server dumps, inventories, real IP credentials, subscription links or generated keys.
New mutation paths must preserve the clean-host boundary, strict SSH host-key checking,
transactional rollback and redacted output. Runtime configuration belongs to the pinned 3x-ui API/DB;
do not add a second standalone Xray `config.json` source of truth.

Fresh-host validation must follow [docs/FRESH-HOST-E2E.md](docs/FRESH-HOST-E2E.md). Publish only the
redacted checklist and command outcomes. Never attach `inventory.yml`, `xray-cascade-access.txt`,
panel URLs, host addresses, subscription headers, certificates, keys or raw 3x-ui databases.
