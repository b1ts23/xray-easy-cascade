// SPDX-License-Identifier: GPL-3.0-only

// Package production describes the pinned production candidate and the exact
// network exposure intended for a clean two-node installation. It deliberately
// does not activate services or firewall rules yet.
package production

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
)

const (
	XUIVersion  = "3.11.0"
	XUIURL      = "https://github.com/MHSanaei/3x-ui/releases/download/v3.11.0/x-ui-linux-amd64.tar.gz"
	XUISHA256   = "0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916"
	ACMEVersion = "3.1.7"
	ACMECommit  = "5567d7fe7298fd37aca53194885ba444c6678669"
	ACMEURL     = "https://github.com/acmesh-official/acme.sh/archive/" + ACMECommit + ".tar.gz"
	ACMESHA256  = "22ca219a96d643910f79d2888d735a444672e5bc0179d3eb6142f0642a9682dc"
	StateRoot   = "/var/lib/xray-cascade"
)

type FirewallRule struct {
	Node     string
	Source   string
	Port     int
	Protocol string
	Purpose  string
}

type Plan struct {
	ReleaseVersion string
	ReleaseURL     string
	ReleaseSHA256  string
	Firewall       []FirewallRule
	Deferred       []string
}

type InstallStep struct {
	Name   string
	Script string
}

func BuildPlan(inv inventory.Inventory) (Plan, error) {
	entryIPv4, err := publicIP(inv.Entry.Host)
	if err != nil {
		return Plan{}, fmt.Errorf("entry.host: %w", err)
	}
	plan := Plan{
		ReleaseVersion: XUIVersion,
		ReleaseURL:     XUIURL,
		ReleaseSHA256:  XUISHA256,
		Firewall: []FirewallRule{
			{Node: "entry", Source: "any", Port: inv.Entry.SSHPort, Purpose: "preserve-ssh"},
			{Node: "entry", Source: "any", Port: inv.Transport.ClientPort, Purpose: "client-vless-reality"},
			{Node: "entry", Source: "any", Port: inv.Subscription.Port, Purpose: "happ-subscription-https"},
			{Node: "exit", Source: "any", Port: inv.Exit.SSHPort, Purpose: "preserve-ssh"},
			{Node: "exit", Source: entryIPv4.String(), Port: inv.Transport.InterserverPort, Purpose: "entry-to-exit-reality"},
			{Node: "exit", Source: entryIPv4.String(), Port: inv.Panel.Port, Purpose: "entry-to-node-api"},
		},
	}
	for _, alternative := range inv.Transport.ClientAlternatives {
		purpose := "client-" + strings.TrimPrefix(alternative.Kind, "reality-") + "-reality"
		plan.Firewall = append(plan.Firewall, FirewallRule{Node: "entry", Source: "any", Port: alternative.Port, Purpose: purpose})
	}
	if inv.Transport.Hysteria2.Enabled {
		plan.Firewall = append(plan.Firewall, FirewallRule{Node: "entry", Source: "any", Port: inv.Transport.Hysteria2.Port, Protocol: "udp", Purpose: "client-hysteria2-tls"})
	}
	if inv.Certificates.SubscriptionTLS == "acme-ip" {
		// acme.sh standalone validation binds TCP/80 only while issuing or
		// renewing. Both nodes need their own IP certificate: entry serves the
		// HAPP subscription, exit serves the trusted 3x-ui node API.
		plan.Firewall = append(plan.Firewall,
			FirewallRule{Node: "entry", Source: "any", Port: 80, Purpose: "acme-http-01"},
			FirewallRule{Node: "exit", Source: "any", Port: 80, Purpose: "acme-http-01"},
		)
	}
	if inv.Entry.PublicIPv6 != "auto" && inv.Entry.PublicIPv6 != "disabled" {
		entryIPv6, parseErr := netip.ParseAddr(strings.TrimSpace(inv.Entry.PublicIPv6))
		if parseErr != nil || !entryIPv6.Is6() || !entryIPv6.IsGlobalUnicast() {
			return Plan{}, errors.New("entry.public_ipv6 must be a global IPv6 address when explicit")
		}
		plan.Firewall = append(plan.Firewall,
			FirewallRule{Node: "exit", Source: entryIPv6.String(), Port: inv.Transport.InterserverPort, Purpose: "entry-to-exit-reality-ipv6"},
			FirewallRule{Node: "exit", Source: entryIPv6.String(), Port: inv.Panel.Port, Purpose: "entry-to-node-api-ipv6"},
		)
	} else if inv.Entry.PublicIPv6 == "auto" {
		plan.Deferred = append(plan.Deferred, "resolve entry global IPv6 during preflight before creating exit rules")
	}
	if inv.Certificates.SubscriptionTLS == "pending" {
		plan.Deferred = append(plan.Deferred, "select trusted subscription TLS mode before production activation")
	}
	if inv.Certificates.NodeTransport != "mtls" {
		plan.Deferred = append(plan.Deferred, "enroll node mTLS before production activation")
	}
	sort.SliceStable(plan.Firewall, func(i, j int) bool {
		if plan.Firewall[i].Node != plan.Firewall[j].Node {
			return plan.Firewall[i].Node < plan.Firewall[j].Node
		}
		if plan.Firewall[i].Port != plan.Firewall[j].Port {
			return plan.Firewall[i].Port < plan.Firewall[j].Port
		}
		return plan.Firewall[i].Source < plan.Firewall[j].Source
	})
	return plan, nil
}

func publicIP(raw string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, errors.New("must be an explicit public IP for deterministic firewall ownership")
	}
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return netip.Addr{}, errors.New("must be a public IPv4 address")
	}
	return address, nil
}

func (plan Plan) Lines() []string {
	lines := []string{
		"3x-ui " + plan.ReleaseVersion + " SHA-256 " + plan.ReleaseSHA256,
		"panel: loopback by default; no public panel firewall rule",
		"firewall: preserve SSH; add project rules only; never reset",
	}
	for _, rule := range plan.Firewall {
		protocol := rule.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		lines = append(lines, rule.Node+" "+protocol+"/"+strconv.Itoa(rule.Port)+" from "+rule.Source+" — "+rule.Purpose)
	}
	for _, deferred := range plan.Deferred {
		lines = append(lines, "deferred: "+deferred)
	}
	return lines
}

// BuildInstallSteps returns the only supported host-level ordering. It renders
// scripts but does not connect to either VPS or execute anything.
func BuildInstallSteps(role string, inv inventory.Inventory) ([]InstallStep, error) {
	if role != "entry" && role != "exit" {
		return nil, errors.New("install role must be entry or exit")
	}
	if err := inv.Validate(); err != nil {
		return nil, err
	}
	type builder struct {
		name string
		fn   func() (string, error)
	}
	builders := []builder{
		{"candidate", func() (string, error) { return CandidateScript(role) }},
		{"stage", func() (string, error) { return StageInstallScript(role, inv) }},
		{"firewall", func() (string, error) { return FirewallScript(role, inv) }},
		{"activate", func() (string, error) { return ActivationScript(role, inv) }},
		{"acme-ip", func() (string, error) { return ACMEIPScript(role, inv) }},
	}
	if role == "entry" {
		builders = append(builders, builder{"subscription-tls", func() (string, error) { return SubscriptionTLSScript(inv) }})
	}
	steps := make([]InstallStep, 0, len(builders))
	for _, item := range builders {
		script, err := item.fn()
		if err != nil {
			return nil, fmt.Errorf("build %s step: %w", item.name, err)
		}
		steps = append(steps, InstallStep{Name: item.name, Script: script})
	}
	return steps, nil
}

// CandidateScript downloads and validates the production artifact without
// installing it into /usr/local or changing systemd. Repeated runs are
// idempotent and accept only the exact pinned release.
func CandidateScript(role string) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("candidate role must be entry or exit")
	}
	return fmt.Sprintf(`set -eu
umask 077
role=%s
root=%s/candidates
candidate="$root/x-ui-%s"
manifest="$candidate/candidate.json"
install -d -m 0700 "$root"
if [ -f "$manifest" ] && jq -e --arg version %s --arg sha %s '.schema==1 and .version==$version and .sha256==$sha and .status=="verified"' "$manifest" >/dev/null; then
  test -x "$candidate/x-ui"
  test -f "$candidate/x-ui.service.debian"
  echo "3XUI_PRODUCTION_CANDIDATE_READY role=$role version=%s"
  exit 0
fi
test ! -e "$candidate"
work=$(mktemp -d "$root/.stage-%s-XXXXXX")
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
trap 'exit 130' INT TERM
archive="$work/x-ui.tar.gz"
list="$work/archive.list"
curl --fail --location --silent --show-error %s -o "$archive"
printf '%%s  %%s\n' %s "$archive" | sha256sum -c - >/dev/null
tar -tzf "$archive" > "$list"
if grep -Eq '(^/|(^|/)\.\.(/|$))' "$list"; then echo 'unsafe path in release archive' >&2; exit 1; fi
for required in x-ui/x-ui x-ui/x-ui.sh x-ui/x-ui.service.debian x-ui/bin/xray-linux-amd64; do grep -Fx "$required" "$list" >/dev/null; done
mkdir "$work/extracted"
tar -xzf "$archive" --no-same-owner --no-same-permissions -C "$work/extracted"
test -x "$work/extracted/x-ui/x-ui"
test -x "$work/extracted/x-ui/bin/xray-linux-amd64"
mv "$work/extracted/x-ui" "$candidate"
jq -n --arg version %s --arg sha %s --arg source %s '{schema:1,status:"verified",version:$version,sha256:$sha,source:$source}' > "$manifest"
chmod 0600 "$manifest"
echo "3XUI_PRODUCTION_CANDIDATE_READY role=$role version=%s"
`, role, StateRoot, XUIVersion, XUIVersion, XUISHA256, XUIVersion, role, XUIURL, XUISHA256, XUIVersion, XUISHA256, XUIURL, XUIVersion), nil
}

// ACMEIPScript installs the pinned acme.sh release and provisions the same
// short-lived Let's Encrypt IPv4 certificate layout used by the reference
// RU/NL cascade. The caller must open TCP/80 and start the staged x-ui service
// before running it. Subscription TLS is attached later through the 3x-ui API;
// this step installs the certificate and configures panel/server TLS only.
func ACMEIPScript(role string, inv inventory.Inventory) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("ACME role must be entry or exit")
	}
	if inv.Certificates.SubscriptionTLS != "acme-ip" {
		return "", errors.New("ACME IP script requires certificates.subscription_tls=acme-ip")
	}
	host := inv.Entry.Host
	basePath := "/entry/panel/"
	if role == "exit" {
		host = inv.Exit.Host
		basePath = "/exit/panel/"
	}
	address, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return "", errors.New("ACME IP script requires an explicit public IPv4 host")
	}
	payloadRaw, err := json.Marshal(map[string]any{
		"role":      role,
		"address":   address.String(),
		"panelPort": inv.Panel.Port,
		"basePath":  basePath,
	})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadRaw)
	return fmt.Sprintf(`set -eu
umask 077
test "$(id -u)" = 0
for command in curl jq openssl sha256sum tar ss systemctl crontab; do command -v "$command" >/dev/null; done
printf '%%s' %s | base64 -d > /run/xray-cascade-acme.json
role=$(jq -r '.role' /run/xray-cascade-acme.json)
address=$(jq -r '.address' /run/xray-cascade-acme.json)
panel_port=$(jq -r '.panelPort' /run/xray-cascade-acme.json)
base_path=$(jq -r '.basePath' /run/xray-cascade-acme.json)
test -x /usr/local/x-ui/x-ui
test -f /etc/x-ui/x-ui.db
systemctl is-active --quiet x-ui
root=%s/acme
state="$root/$role.json"
install -d -m 0700 "$root" /root/cert/ip
if [ -e "$state" ] && [ -L "$state" ]; then echo 'refusing ACME state symlink' >&2; exit 1; fi
installed_by_project=false
had_state=false
if [ -f "$state" ]; then
  had_state=true
  jq -e --arg role "$role" --arg address "$address" '.schema==1 and .manager=="vpnctl" and .role==$role and .address==$address' "$state" >/dev/null
  installed_by_project=$(jq -r '.acmeInstalledByProject==true' "$state")
elif find /root/cert/ip -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo 'unmanaged /root/cert/ip is not empty' >&2
  exit 1
fi
work=
old_cert=$(cd /usr/local/x-ui && ./x-ui setting -getCert 2>/dev/null | sed -n 's/^cert: //p' | tail -n 1)
old_key=$(cd /usr/local/x-ui && ./x-ui setting -getCert 2>/dev/null | sed -n 's/^key: //p' | tail -n 1)
web_changed=false
cron_tmp=$(mktemp "$root/.cron-XXXXXX")
cron_backup=$(mktemp "$root/.cron-backup-XXXXXX")
cron_had=true
if ! crontab -l > "$cron_backup" 2>/dev/null; then cron_had=false; : > "$cron_backup"; fi
committed=false
acme_cleanup() {
  status=$?
  trap - EXIT INT TERM
  rm -rf "$work"
  rm -f "$cron_tmp" /run/xray-cascade-acme.json
  if [ "$status" -ne 0 ] && [ "$committed" != true ]; then
    if [ "$cron_had" = true ]; then crontab "$cron_backup"; else crontab -r >/dev/null 2>&1 || true; fi
    if [ "$had_state" != true ]; then
      if [ "$web_changed" = true ]; then
        if [ -n "$old_cert" ] && [ -n "$old_key" ]; then
          (cd /usr/local/x-ui && ./x-ui cert -webCert "$old_cert" -webCertKey "$old_key" >/dev/null) || true
        else
          (cd /usr/local/x-ui && ./x-ui cert -reset >/dev/null) || true
        fi
        systemctl restart x-ui >/dev/null 2>&1 || true
      fi
      rm -f /root/cert/ip/fullchain.pem /root/cert/ip/privkey.pem
      if [ "$installed_by_project" = true ] && [ -x /root/.acme.sh/acme.sh ]; then
        /root/.acme.sh/acme.sh --uninstall >/dev/null 2>&1 || true
        rm -rf /root/.acme.sh
      fi
    fi
  fi
  rm -f "$cron_backup"
  exit "$status"
}
trap acme_cleanup EXIT
trap 'exit 130' INT TERM
if [ ! -x /root/.acme.sh/acme.sh ]; then
  test ! -e /root/.acme.sh
  installed_by_project=true
  work=$(mktemp -d "$root/.install-XXXXXX")
  curl --fail --location --silent --show-error %s -o "$work/acme.tar.gz"
  printf '%%s  %%s\n' %s "$work/acme.tar.gz" | sha256sum -c - >/dev/null
  tar -tzf "$work/acme.tar.gz" > "$work/archive.list"
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$work/archive.list"; then echo 'unsafe path in acme.sh archive' >&2; exit 1; fi
  mkdir "$work/source"
  tar -xzf "$work/acme.tar.gz" --strip-components=1 --no-same-owner --no-same-permissions -C "$work/source"
  (cd "$work/source" && ./acme.sh --install --home /root/.acme.sh --config-home /root/.acme.sh --no-cron --no-profile)
  rm -rf "$work"
  work=
fi
version=$(/root/.acme.sh/acme.sh --version 2>/dev/null | tail -n 1)
case "$version" in *%s*) ;; *) echo "unexpected acme.sh version: $version" >&2; exit 1 ;; esac
crontab -l 2>/dev/null | grep -v 'xray-cascade:acme-renew' > "$cron_tmp" || true
printf '17 2,8,14,20 * * * "/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" > /dev/null # xray-cascade:acme-renew\n' >> "$cron_tmp"
crontab "$cron_tmp"
cert=/root/cert/ip/fullchain.pem
key=/root/cert/ip/privkey.pem
ready=false
if [ -s "$cert" ] && [ -s "$key" ] && openssl x509 -in "$cert" -checkend 86400 -noout >/dev/null 2>&1; then
  if openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null | grep -F "IP Address:$address" >/dev/null; then ready=true; fi
fi
if [ "$ready" != true ]; then
  if ss -H -ltn 'sport = :80' | grep -q .; then echo 'TCP/80 is occupied; standalone HTTP-01 cannot start' >&2; exit 1; fi
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force >/dev/null
  /root/.acme.sh/acme.sh --issue -d "$address" --standalone --server letsencrypt --certificate-profile shortlived --days 6 --httpport 80 --keylength ec-256 --force
fi
/root/.acme.sh/acme.sh --install-cert --force --ecc -d "$address" \
  --key-file "$key" \
  --fullchain-file "$cert" \
  --reloadcmd 'systemctl restart x-ui'
chmod 0600 "$key"
chmod 0644 "$cert"
openssl x509 -in "$cert" -checkend 86400 -noout
openssl x509 -in "$cert" -noout -ext subjectAltName | grep -F "IP Address:$address" >/dev/null
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
key_pub=$(openssl pkey -in "$key" -pubout -outform DER | sha256sum | cut -d' ' -f1)
test -n "$cert_pub"
test "$cert_pub" = "$key_pub"
cd /usr/local/x-ui
./x-ui cert -webCert "$cert" -webCertKey "$key" >/dev/null
web_changed=true
systemctl restart x-ui
attempt=0
until curl --fail --silent --show-error --insecure --max-time 3 "https://127.0.0.1:$panel_port$base_path" >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 20 ]; then echo 'x-ui HTTPS readiness failed after ACME install' >&2; exit 1; fi
  sleep 1
done
jq -n --arg role "$role" --arg address "$address" --arg version %s --arg cert "$cert" --arg key "$key" --argjson installed "$installed_by_project" \
  '{schema:1,manager:"vpnctl",role:$role,address:$address,acmeVersion:$version,certificate:$cert,privateKey:$key,acmeInstalledByProject:$installed,status:"ready"}' > "$state.new"
chmod 0600 "$state.new"
mv -f "$state.new" "$state"
committed=true
echo "3XUI_PRODUCTION_ACME_READY role=$role address=$address"
`, payload, StateRoot, ACMEURL, ACMESHA256, ACMEVersion, ACMEVersion), nil
}

// SubscriptionTLSScript attaches the already issued entry IP certificate to
// the 3x-ui subscription service through the supported settings API. It never
// edits x-ui.db directly and verifies the public chain against the IP SAN.
func SubscriptionTLSScript(inv inventory.Inventory) (string, error) {
	if inv.Certificates.SubscriptionTLS != "acme-ip" {
		return "", errors.New("subscription TLS script requires certificates.subscription_tls=acme-ip")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(inv.Entry.Host))
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return "", errors.New("subscription TLS script requires an explicit public entry IPv4 host")
	}
	payloadRaw, err := json.Marshal(map[string]any{
		"address":          address.String(),
		"panelPort":        inv.Panel.Port,
		"panelBasePath":    "/entry/panel/",
		"subscriptionPort": inv.Subscription.Port,
	})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadRaw)
	return fmt.Sprintf(`set -eu
umask 077
test "$(id -u)" = 0
for command in curl jq openssl ss systemctl timeout; do command -v "$command" >/dev/null; done
printf '%%s' %s | base64 -d > /run/xray-cascade-sub-tls-input.json
address=$(jq -r '.address' /run/xray-cascade-sub-tls-input.json)
panel_port=$(jq -r '.panelPort' /run/xray-cascade-sub-tls-input.json)
panel_base=$(jq -r '.panelBasePath' /run/xray-cascade-sub-tls-input.json)
sub_port=$(jq -r '.subscriptionPort' /run/xray-cascade-sub-tls-input.json)
cert=/root/cert/ip/fullchain.pem
key=/root/cert/ip/privkey.pem
test -s "$cert"
test -s "$key"
openssl x509 -in "$cert" -checkend 86400 -noout
openssl x509 -in "$cert" -noout -ext subjectAltName | grep -F "IP Address:$address" >/dev/null
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-subscription-tls -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-sub-tls-header
unset token
cleanup() { rm -f /run/xray-cascade-sub-tls-input.json /run/xray-cascade-sub-tls-header /run/xray-cascade-sub-tls-*.json /run/xray-cascade-sub-tls-chain.pem; }
trap cleanup EXIT INT TERM
api="https://$address:$panel_port${panel_base}api"
curl_local() { curl --fail-with-body --silent --show-error --noproxy '*' --resolve "$address:$panel_port:127.0.0.1" "$@"; }
curl_local -H @/run/xray-cascade-sub-tls-header -X POST "$api/setting/all" > /run/xray-cascade-sub-tls-current.json
jq -e '.success==true and (.obj|type=="object")' /run/xray-cascade-sub-tls-current.json >/dev/null
jq --arg cert "$cert" --arg key "$key" --argjson port "$sub_port" \
  '.obj | .subEnable=true | .subPort=$port | .subCertFile=$cert | .subKeyFile=$key' \
  /run/xray-cascade-sub-tls-current.json > /run/xray-cascade-sub-tls-update.json
curl_local -H @/run/xray-cascade-sub-tls-header -H 'Content-Type: application/json' \
  -X POST --data @/run/xray-cascade-sub-tls-update.json "$api/setting/update" > /run/xray-cascade-sub-tls-response.json
jq -e '.success==true' /run/xray-cascade-sub-tls-response.json >/dev/null
curl_local -H @/run/xray-cascade-sub-tls-header -X POST "$api/setting/restartPanel" > /run/xray-cascade-sub-tls-restart.json
jq -e '.success==true' /run/xray-cascade-sub-tls-restart.json >/dev/null
down=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  sleep 1
  if ! curl --fail --silent --show-error --noproxy '*' --max-time 3 --resolve "$address:$panel_port:127.0.0.1" "https://$address:$panel_port$panel_base" >/dev/null 2>&1; then down=true; break; fi
done
test "$down" = true
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  sleep 1
  if curl --fail --silent --show-error --noproxy '*' --max-time 3 --resolve "$address:$panel_port:127.0.0.1" "https://$address:$panel_port$panel_base" >/dev/null 2>&1; then ready=true; break; fi
done
test "$ready" = true
ss -H -ltn "sport = :$sub_port" | grep -q .
timeout 10 openssl s_client -connect "127.0.0.1:$sub_port" -servername "$address" -verify_ip "$address" -verify_return_error -showcerts </dev/null > /run/xray-cascade-sub-tls-chain.pem 2>/dev/null
grep -F 'Verify return code: 0 (ok)' /run/xray-cascade-sub-tls-chain.pem >/dev/null
curl_local -H @/run/xray-cascade-sub-tls-header -X POST "$api/setting/all" > /run/xray-cascade-sub-tls-final.json
jq -e --arg cert "$cert" --arg key "$key" --argjson port "$sub_port" \
  '.success==true and .obj.subEnable==true and .obj.subPort==$port and .obj.subCertFile==$cert and .obj.subKeyFile==$key' \
  /run/xray-cascade-sub-tls-final.json >/dev/null
echo "3XUI_PRODUCTION_SUBSCRIPTION_TLS_READY address=$address port=$sub_port"
`, payload), nil
}

// StageInstallScript lays out a previously verified candidate on a clean VPS,
// initializes a private panel database, and validates the official systemd
// unit. It deliberately does not start/enable services or change firewall
// state; those actions require a separate host-level rehearsal.
func StageInstallScript(role string, inv inventory.Inventory) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("stage role must be entry or exit")
	}
	if _, err := BuildPlan(inv); err != nil {
		return "", err
	}
	panelIP := "127.0.0.1"
	basePath := "/entry/"
	serverAddress := ""
	if role == "exit" {
		panelIP = "0.0.0.0"
		basePath = "/exit/"
		serverAddress = inv.Exit.Host
	}
	payloadRaw, err := json.Marshal(map[string]any{
		"role":          role,
		"panelIP":       panelIP,
		"panelPort":     inv.Panel.Port,
		"basePath":      basePath,
		"serverAddress": serverAddress,
	})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadRaw)
	return fmt.Sprintf(`set -eu
umask 077
test "$(id -u)" = 0
payload=%s
printf '%%s' "$payload" | base64 -d > /run/xray-cascade-stage.json
role=$(jq -r '.role' /run/xray-cascade-stage.json)
panel_ip=$(jq -r '.panelIP' /run/xray-cascade-stage.json)
panel_port=$(jq -r '.panelPort' /run/xray-cascade-stage.json)
base_path=$(jq -r '.basePath' /run/xray-cascade-stage.json)
server_address=$(jq -r '.serverAddress' /run/xray-cascade-stage.json)
candidate=%s/candidates/x-ui-%s
test -x "$candidate/x-ui"
test -x "$candidate/bin/xray-linux-amd64"
test -f "$candidate/x-ui.service.debian"
jq -e --arg version %s --arg sha %s '.schema==1 and .status=="verified" and .version==$version and .sha256==$sha' "$candidate/candidate.json" >/dev/null
for command in jq openssl systemctl systemd-analyze; do command -v "$command" >/dev/null; done
for path in /usr/local/x-ui /etc/x-ui /var/log/x-ui /etc/default/x-ui /etc/systemd/system/x-ui.service /etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf /usr/bin/x-ui; do
  test ! -e "$path"
  test ! -L "$path"
done
test ! -e %s/ownership.json
test ! -L %s/ownership.json
installed=false
cleanup() {
  status=$?
  trap - EXIT INT TERM
  rm -f /run/xray-cascade-stage.json /run/xray-cascade-panel.csr /run/xray-cascade-panel.ext
  if [ "$status" -ne 0 ] && [ "$installed" = true ]; then
    rm -rf /usr/local/x-ui /etc/x-ui /var/log/x-ui
    rm -f /etc/default/x-ui /etc/systemd/system/x-ui.service /usr/bin/x-ui
    rm -rf /etc/systemd/system/x-ui.service.d
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  if [ "$status" -ne 0 ]; then
    rm -f %s/ownership.json
    rm -f %s/operator/bootstrap-credentials-$role
    rmdir %s/operator 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
install -d -m 0700 /etc/x-ui /var/log/x-ui %s/operator
installed=true
cp -a "$candidate" /usr/local/x-ui
chmod 0700 /usr/local/x-ui
install -m 0644 "$candidate/x-ui.service.debian" /etc/systemd/system/x-ui.service
install -d -m 0755 /etc/systemd/system/x-ui.service.d
cat > /etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf <<'XCASCADE_SYSTEMD'
[Service]
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
XCASCADE_SYSTEMD
cat > /etc/default/x-ui <<'XCASCADE_ENV'
XUI_MAIN_FOLDER=/usr/local/x-ui
XUI_DB_FOLDER=/etc/x-ui
XUI_BIN_FOLDER=/usr/local/x-ui/bin
XUI_LOG_FOLDER=/var/log/x-ui
XUI_ENABLE_FAIL2BAN=false
XUI_MEMORY_LIMIT=256
XCASCADE_ENV
chmod 0600 /etc/default/x-ui
ln -s /usr/local/x-ui/x-ui.sh /usr/bin/x-ui
panel_user="admin-$(openssl rand -hex 8)"
panel_password=$(openssl rand -base64 48 | tr -d '\n')
printf 'username=%%s\npassword=%%s\n' "$panel_user" "$panel_password" > %s/operator/bootstrap-credentials-$role
chmod 0600 %s/operator/bootstrap-credentials-$role
cd /usr/local/x-ui
./x-ui setting -username "$panel_user" -password "$panel_password" -port "$panel_port" -webBasePath "$base_path" -listenIP "$panel_ip" >/dev/null
unset panel_user panel_password
if [ "$role" = exit ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
    -subj '/CN=xray-cascade-node-ca' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout /etc/x-ui/panel-ca.key -out /etc/x-ui/panel-ca.crt >/dev/null 2>&1
  openssl req -new -newkey rsa:3072 -sha256 -nodes -subj '/CN=xray-cascade-exit' \
    -keyout /etc/x-ui/panel.key -out /run/xray-cascade-panel.csr >/dev/null 2>&1
  cat > /run/xray-cascade-panel.ext <<XCASCADE_CERT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$server_address
XCASCADE_CERT
  openssl x509 -req -sha256 -days 825 -in /run/xray-cascade-panel.csr \
    -CA /etc/x-ui/panel-ca.crt -CAkey /etc/x-ui/panel-ca.key -CAcreateserial \
    -extfile /run/xray-cascade-panel.ext -out /etc/x-ui/panel.crt >/dev/null 2>&1
  rm -f /etc/x-ui/panel-ca.srl
  chmod 0600 /etc/x-ui/panel-ca.key /etc/x-ui/panel-ca.crt /etc/x-ui/panel.key /etc/x-ui/panel.crt
  ./x-ui setting -webCert /etc/x-ui/panel.crt -webCertKey /etc/x-ui/panel.key >/dev/null
fi
./x-ui -v >/dev/null
./bin/xray-linux-amd64 version >/dev/null
systemd-analyze verify /etc/systemd/system/x-ui.service >/dev/null
jq -n --arg role "$role" --arg version %s '{schema:1,clusterRole:$role,version:$version,status:"staged",paths:["/usr/local/x-ui","/etc/x-ui","/var/log/x-ui","/etc/systemd/system/x-ui.service","/etc/systemd/system/x-ui.service.d/10-xui-sandbox.conf","/etc/default/x-ui","/usr/bin/x-ui"]}' > %s/ownership.json
chmod 0600 %s/ownership.json
systemctl daemon-reload
echo "3XUI_PRODUCTION_STAGED role=$role version=%s"
trap - EXIT INT TERM
rm -f /run/xray-cascade-stage.json /run/xray-cascade-panel.csr /run/xray-cascade-panel.ext
`, payload, StateRoot, XUIVersion, XUIVersion, XUISHA256, StateRoot, StateRoot, StateRoot, StateRoot, StateRoot, StateRoot, StateRoot, StateRoot, XUIVersion, StateRoot, StateRoot, XUIVersion), nil
}

// ActivationScript performs the first controlled systemd start after staging.
// It requires the service to be inactive and disabled, and restores that state
// if readiness fails. Network policy must already have been applied.
func ActivationScript(role string, inv inventory.Inventory) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("activation role must be entry or exit")
	}
	if _, err := BuildPlan(inv); err != nil {
		return "", err
	}
	scheme := "http"
	basePath := "/entry/panel/"
	curlTLS := ""
	if role == "exit" {
		scheme = "https"
		basePath = "/exit/panel/"
		curlTLS = "--insecure"
	}
	payloadRaw, err := json.Marshal(map[string]any{
		"role":      role,
		"panelPort": inv.Panel.Port,
		"scheme":    scheme,
		"basePath":  basePath,
		"curlTLS":   curlTLS,
	})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadRaw)
	return fmt.Sprintf(`set -eu
umask 077
test "$(id -u)" = 0
for command in curl jq systemctl; do command -v "$command" >/dev/null; done
printf '%%s' %s | base64 -d > /run/xray-cascade-activate.json
role=$(jq -r '.role' /run/xray-cascade-activate.json)
panel_port=$(jq -r '.panelPort' /run/xray-cascade-activate.json)
scheme=$(jq -r '.scheme' /run/xray-cascade-activate.json)
base_path=$(jq -r '.basePath' /run/xray-cascade-activate.json)
curl_tls=$(jq -r '.curlTLS' /run/xray-cascade-activate.json)
ownership=%s/ownership.json
test -f "$ownership"
test ! -L "$ownership"
jq -e --arg role "$role" '.schema==1 and .clusterRole==$role and .version==%q and .status=="staged"' "$ownership" >/dev/null
if systemctl is-active --quiet x-ui; then echo 'x-ui must be inactive before first activation' >&2; exit 1; fi
if systemctl is-enabled --quiet x-ui; then echo 'x-ui must be disabled before first activation' >&2; exit 1; fi
activated=false
rollback_activation() {
  status=$?
  trap - EXIT INT TERM
  rm -f /run/xray-cascade-activate.json
  if [ "$status" -ne 0 ] && [ "$activated" = true ]; then
    systemctl disable --now x-ui >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap rollback_activation EXIT INT TERM
systemctl enable --now x-ui
activated=true
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  sleep 1
  if curl --fail --silent --show-error --max-time 3 $curl_tls "$scheme://127.0.0.1:$panel_port$base_path" >/dev/null 2>&1; then ready=true; break; fi
done
test "$ready" = true
systemctl is-active --quiet x-ui
systemctl is-enabled --quiet x-ui
jq '.status="active"' "$ownership" > "$ownership.new"
chmod 0600 "$ownership.new"
mv -f "$ownership.new" "$ownership"
echo "3XUI_PRODUCTION_ACTIVATED role=$role"
trap - EXIT INT TERM
rm -f /run/xray-cascade-activate.json
`, payload, StateRoot, XUIVersion), nil
}

// InstallRollbackScript removes only resources proven to be owned by a failed
// clean-host installation and restores the exact pre-install UFW snapshot.
func InstallRollbackScript(role string) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("install rollback role must be entry or exit")
	}
	return fmt.Sprintf(`set -eu
umask 077
test "$(id -u)" = 0
role=%s
root=%s
ownership="$root/ownership.json"
test -f "$ownership"
test ! -L "$ownership"
jq -e --arg role "$role" --arg version %q '.schema==1 and .clusterRole==$role and .version==$version and (.status=="staged" or .status=="active")' "$ownership" >/dev/null
systemctl disable --now x-ui >/dev/null 2>&1 || true
snapshot=$(jq -r '.firewallSnapshot // empty' "$ownership")
if [ -n "$snapshot" ]; then
  case "$snapshot" in "$root"/firewall/*) ;; *) echo 'unsafe firewall snapshot path' >&2; exit 1 ;; esac
  test -d "$snapshot"
  for name in user.rules user6.rules; do
    state=$(cat "$snapshot/$name.state")
    if [ "$state" = present ]; then install -m 0640 "$snapshot/$name" "/etc/ufw/$name"; elif [ "$state" = absent ]; then rm -f "/etc/ufw/$name"; else exit 1; fi
  done
  state=$(cat "$snapshot/default-ufw.state")
  if [ "$state" = present ]; then install -m 0644 "$snapshot/default-ufw" /etc/default/ufw; elif [ "$state" = absent ]; then rm -f /etc/default/ufw; else exit 1; fi
  initial=$(cat "$snapshot/initial.state")
  if [ "$initial" = active ]; then ufw reload >/dev/null; elif [ "$initial" = inactive ]; then ufw --force disable >/dev/null; else exit 1; fi
fi
acme_state="$root/acme/$role.json"
if [ -f "$acme_state" ]; then
  jq -e --arg role "$role" '.schema==1 and .manager=="vpnctl" and .role==$role' "$acme_state" >/dev/null
  address=$(jq -r '.address' "$acme_state")
  installed=$(jq -r '.acmeInstalledByProject==true' "$acme_state")
  if [ -x /root/.acme.sh/acme.sh ]; then
    /root/.acme.sh/acme.sh --remove --ecc -d "$address" >/dev/null 2>&1 || true
  fi
  cron_tmp=$(mktemp "$root/.rollback-cron-XXXXXX")
  crontab -l 2>/dev/null | grep -v 'xray-cascade:acme-renew' > "$cron_tmp" || true
  crontab "$cron_tmp"
  rm -f "$cron_tmp"
  if [ "$installed" = true ] && [ -x /root/.acme.sh/acme.sh ]; then
    /root/.acme.sh/acme.sh --uninstall >/dev/null 2>&1 || true
    rm -rf /root/.acme.sh
  fi
  rm -f "$acme_state"
  rm -f /root/cert/ip/fullchain.pem /root/cert/ip/privkey.pem
  rmdir /root/cert/ip 2>/dev/null || true
  rmdir /root/cert 2>/dev/null || true
fi
rm -f /usr/bin/x-ui /etc/default/x-ui /etc/systemd/system/x-ui.service
rm -rf /etc/systemd/system/x-ui.service.d /usr/local/x-ui /etc/x-ui /var/log/x-ui
rm -f "$root/operator/bootstrap-credentials-$role"
rmdir "$root/operator" 2>/dev/null || true
rm -rf "$root/candidates/x-ui-%s"
rm -f "$ownership"
systemctl daemon-reload
echo "3XUI_PRODUCTION_INSTALL_ROLLED_BACK role=$role"
`, role, StateRoot, XUIVersion, XUIVersion), nil
}

// FirewallScript adds only comment-owned UFW rules for one role. It snapshots
// the underlying UFW files first and restores them on any error. No reset or
// deletion of unrelated rules is permitted.
func FirewallScript(role string, inv inventory.Inventory) (string, error) {
	if role != "entry" && role != "exit" {
		return "", errors.New("firewall role must be entry or exit")
	}
	plan, err := BuildPlan(inv)
	if err != nil {
		return "", err
	}
	type ownedRule struct {
		Source   string `json:"source"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Comment  string `json:"comment"`
	}
	var rules []ownedRule
	needIPv6 := false
	for _, rule := range plan.Firewall {
		if rule.Node != role {
			continue
		}
		if address, parseErr := netip.ParseAddr(rule.Source); parseErr == nil && address.Is6() {
			needIPv6 = true
		}
		protocol := rule.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		rules = append(rules, ownedRule{Source: rule.Source, Port: rule.Port, Protocol: protocol, Comment: "xray-cascade:" + rule.Purpose})
	}
	if len(rules) == 0 {
		return "", errors.New("firewall plan has no rules for role")
	}
	payloadRaw, err := json.Marshal(map[string]any{"role": role, "rules": rules, "needIPv6": needIPv6})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadRaw)
	return fmt.Sprintf(`set -eu
umask 077
test "$(id -u)" = 0
for command in ufw jq; do command -v "$command" >/dev/null; done
printf '%%s' %s | base64 -d > /run/xray-cascade-firewall.json
role=$(jq -r '.role' /run/xray-cascade-firewall.json)
install -d -m 0700 %s/firewall
snapshot=$(mktemp -d "%s/firewall/$(date -u +%%Y%%m%%dT%%H%%M%%SZ)-$role-XXXXXX")
chmod 0700 "$snapshot"
for name in user.rules user6.rules; do
  source=/etc/ufw/$name
  if [ -f "$source" ] && [ ! -L "$source" ]; then cp -p "$source" "$snapshot/$name"; printf present > "$snapshot/$name.state"; else printf absent > "$snapshot/$name.state"; fi
done
if [ -f /etc/default/ufw ] && [ ! -L /etc/default/ufw ]; then cp -p /etc/default/ufw "$snapshot/default-ufw"; printf present > "$snapshot/default-ufw.state"; else printf absent > "$snapshot/default-ufw.state"; fi
if ufw status | grep -q '^Status: active'; then initial=active; else initial=inactive; fi
printf '%%s\n' "$initial" > "$snapshot/initial.state"
rollback() {
  status=$?
  trap - EXIT INT TERM
  rm -f /run/xray-cascade-firewall.json
  if [ "$status" -ne 0 ]; then
    for name in user.rules user6.rules; do
      if [ "$(cat "$snapshot/$name.state")" = present ]; then cp -p "$snapshot/$name" "/etc/ufw/$name"; else rm -f "/etc/ufw/$name"; fi
    done
    if [ "$(cat "$snapshot/default-ufw.state")" = present ]; then cp -p "$snapshot/default-ufw" /etc/default/ufw; else rm -f /etc/default/ufw; fi
    if [ "$initial" = active ]; then ufw reload >/dev/null 2>&1 || true; else ufw --force disable >/dev/null 2>&1 || true; fi
  fi
  exit "$status"
}
trap rollback EXIT
trap 'exit 130' INT TERM
if jq -e '.needIPv6==true' /run/xray-cascade-firewall.json >/dev/null; then
  grep -Eq '^IPV6=(yes|YES)$' /etc/default/ufw
fi
jq -c '.rules[]' /run/xray-cascade-firewall.json | while IFS= read -r rule; do
  source=$(printf '%%s' "$rule" | jq -r '.source')
  port=$(printf '%%s' "$rule" | jq -r '.port')
	protocol=$(printf '%%s' "$rule" | jq -r '.protocol')
  comment=$(printf '%%s' "$rule" | jq -r '.comment')
  case "$comment" in xray-cascade:*) ;; *) exit 1 ;; esac
	case "$protocol" in tcp|udp) ;; *) exit 1 ;; esac
  if ! ufw status | grep -F "$comment" >/dev/null 2>&1; then
	ufw allow proto "$protocol" from "$source" to any port "$port" comment "$comment" >/dev/null
  fi
done
if [ "$initial" = inactive ]; then ufw --force enable >/dev/null; else ufw reload >/dev/null; fi
ufw status | grep -q '^Status: active'
jq -r '.rules[].comment' /run/xray-cascade-firewall.json | while IFS= read -r comment; do ufw status | grep -F "$comment" >/dev/null; done
ownership=%s/ownership.json
test -f "$ownership"
jq --slurpfile firewall /run/xray-cascade-firewall.json --arg snapshot "$snapshot" '.firewallRules=$firewall[0].rules | .firewallSnapshot=$snapshot' "$ownership" > "$ownership.new"
chmod 0600 "$ownership.new"
mv -f "$ownership.new" "$ownership"
echo "3XUI_PRODUCTION_FIREWALL_READY role=$role"
trap - EXIT
rm -f /run/xray-cascade-firewall.json
`, payload, StateRoot, StateRoot, StateRoot), nil
}
