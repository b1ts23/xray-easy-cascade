.PHONY: test build check lab-key lab-bootstrap lab-configure lab-e2e lab-validate

test:
	go test ./...

build:
	go build -trimpath -o bin/vpnctl ./cmd/vpnctl

check: test build
	./bin/vpnctl version
	./bin/vpnctl plan --inventory inventory.example.yml

lab-key:
	mkdir -p lab/.state
	test -f lab/.state/id_ed25519 || ssh-keygen -q -t ed25519 -N '' -C xray-cascade-lab -f lab/.state/id_ed25519

lab-bootstrap:
	./lab/bootstrap-3xui.sh

lab-configure:
	./lab/configure-cascade.sh

lab-e2e:
	./lab/e2e.sh

lab-validate:
	docker compose -f lab/compose.yml config --quiet
