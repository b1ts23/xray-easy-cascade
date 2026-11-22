// SPDX-License-Identifier: GPL-3.0-only

// Package deploylab contains the deliberately lab-only 3x-ui deployment
// protocol. It exercises the same API ownership model as production without
// pretending that two containers provide independent hosts or public IPs.
package deploylab

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/b1ts23/xray-easy-cascade/internal/inventory"
	"github.com/b1ts23/xray-easy-cascade/internal/routing"
)

const (
	tokenPrefix    = "3XUI_NODE_TOKEN\t"
	pinPrefix      = "3XUI_NODE_PIN\t"
	exitCertPrefix = "3XUI_EXIT_CERT\t"
	mtlsCAPrefix   = "3XUI_MTLS_CA\t"
)

type NodeAccess struct {
	Token string
	Pin   string
}

func parseCertificateMarker(output, prefix string) (string, error) {
	var encoded string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			if encoded != "" {
				return "", errors.New("remote returned more than one certificate marker")
			}
			encoded = strings.TrimPrefix(line, prefix)
		}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 {
		return "", errors.New("remote did not return a valid certificate marker")
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("remote certificate marker is not one PEM certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("parse remote certificate: %w", err)
	}
	return string(raw), nil
}

func ExitCertificateScript() string {
	return `set -eu
test -s /etc/x-ui/panel-ca.crt
printf '3XUI_EXIT_CERT\t'
base64 -w0 /etc/x-ui/panel-ca.crt
printf '\n'
`
}

func ParseExitCertificate(output string) (string, error) {
	return parseCertificateMarker(output, exitCertPrefix)
}

// EntryTrustExitCertificateScript installs only the lab exit panel's public
// CA on entry. The master mTLS identity is minted earlier by EntryScript while
// its already-authenticated controller request is known to be valid.
func EntryTrustExitCertificateScript(exitCertificate, exitAddress string) (string, error) {
	if _, err := parseCertificateMarker(exitCertPrefix+base64.StdEncoding.EncodeToString([]byte(exitCertificate)), exitCertPrefix); err != nil {
		return "", fmt.Errorf("exit server certificate: %w", err)
	}
	address, err := netip.ParseAddr(exitAddress)
	if err != nil || !address.IsPrivate() {
		return "", errors.New("exit mTLS address must be a private lab IP")
	}
	payloadRaw, err := json.Marshal(map[string]string{"certificate": exitCertificate, "address": address.String()})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(payloadRaw)
	return `set -eu
umask 077
printf '%s' '` + payload + `' | base64 -d > /run/xray-cascade-exit-trust-input.json
jq -r '.certificate' /run/xray-cascade-exit-trust-input.json > /run/xray-cascade-exit-ca.crt
exit_address=$(jq -r '.address' /run/xray-cascade-exit-trust-input.json)
trap 'rm -f /run/xray-cascade-exit-trust-input.json /run/xray-cascade-exit-ca.crt' EXIT INT TERM
openssl x509 -in /run/xray-cascade-exit-ca.crt -noout >/dev/null
install -m 0644 /run/xray-cascade-exit-ca.crt /usr/local/share/ca-certificates/xray-cascade-exit.crt
install -m 0644 /run/xray-cascade-exit-ca.crt /etc/x-ui/exit-node-ca.crt
update-ca-certificates >/dev/null
curl --fail -sS "https://${exit_address}:2053/exit/panel/" -o /dev/null
echo 3XUI_EXIT_CERT_TRUST_READY
`, nil
}

func ParseMtlsCA(output string) (string, error) {
	return parseCertificateMarker(output, mtlsCAPrefix)
}

func ExitTrustMtlsScript(masterCA string) (string, error) {
	return ExitTrustMtlsScriptAt(masterCA, 2053)
}

func ExitTrustMtlsScriptAt(masterCA string, panelPort int) (string, error) {
	if _, err := parseCertificateMarker(mtlsCAPrefix+base64.StdEncoding.EncodeToString([]byte(masterCA)), mtlsCAPrefix); err != nil {
		return "", fmt.Errorf("master mTLS CA: %w", err)
	}
	if panelPort < 1 || panelPort > 65535 {
		return "", errors.New("panel port must be between 1 and 65535")
	}
	payload := base64.StdEncoding.EncodeToString([]byte(masterCA))
	return fmt.Sprintf(`set -eu
umask 077
printf '%%s' '%s' | base64 -d > /run/xray-cascade-master-ca.crt
cd /usr/local/x-ui
token_name=xray-cascade-mtls-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > /run/xray-cascade-mtls-header
unset token
trap 'rm -f /run/xray-cascade-master-ca.crt /run/xray-cascade-mtls-header /run/xray-cascade-mtls-*.json' EXIT INT TERM
api=https://127.0.0.1:%d/exit/panel/api
jq -Rs '{caCert:.}' < /run/xray-cascade-master-ca.crt > /run/xray-cascade-mtls-request.json
curl --fail-with-body -k -sS -H @/run/xray-cascade-mtls-header -H 'Content-Type: application/json' -X POST --data @/run/xray-cascade-mtls-request.json "$api/nodes/mtls/trustCA" > /run/xray-cascade-mtls-response.json
jq -e '.success==true' /run/xray-cascade-mtls-response.json >/dev/null
curl --fail-with-body -k -sS -H @/run/xray-cascade-mtls-header -X POST "$api/setting/restartPanel" > /run/xray-cascade-mtls-restart.json
jq -e '.success==true' /run/xray-cascade-mtls-restart.json >/dev/null
down=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do if ! curl --fail -k -sS https://127.0.0.1:%d/exit/panel/ -o /dev/null 2>/dev/null; then down=true; break; fi; sleep 1; done
test "$down" = true
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do sleep 1; if curl --fail -k -sS https://127.0.0.1:%d/exit/panel/ -o /dev/null 2>/dev/null; then ready=true; break; fi; done
test "$ready" = true
curl --fail-with-body -k -sS -H @/run/xray-cascade-mtls-header "$api/setting/apiTokens" > /run/xray-cascade-mtls-tokens.json
token_id=$(jq -r --arg name "$token_name" '.obj[]|select(.name==$name)|.id' /run/xray-cascade-mtls-tokens.json)
test -n "$token_id"
printf '{"expectedScope":"admin"}' > /run/xray-cascade-mtls-delete-request.json
curl --fail-with-body -k -sS -H @/run/xray-cascade-mtls-header -H 'Content-Type: application/json' -X POST --data @/run/xray-cascade-mtls-delete-request.json "$api/setting/apiTokens/delete/$token_id" > /run/xray-cascade-mtls-delete.json
jq -e '.success==true' /run/xray-cascade-mtls-delete.json >/dev/null
echo 3XUI_NODE_MTLS_TRUST_READY
`, payload, panelPort, panelPort, panelPort), nil
}

func EntrySwitchNodeMtlsScript(inv inventory.Inventory) (string, error) {
	return EntrySwitchNodeMtlsScriptWithOptions(inv, LabRuntimeOptions())
}

func EntrySwitchNodeMtlsScriptWithOptions(inv inventory.Inventory, options RuntimeOptions) (string, error) {
	raw, err := json.Marshal(map[string]any{
		"exitAddress": inv.Exit.CascadeAddress, "panelPort": inv.Panel.Port,
		"nodeName": options.NodeName, "nodeRemark": options.NodeRemark,
		"allowPrivateAddress": options.AllowPrivateAddress,
		"localPanelScheme":    options.LocalPanelScheme, "localPanelCurlTLS": options.LocalPanelCurlTLS,
	})
	if err != nil {
		return "", err
	}
	payload := base64.StdEncoding.EncodeToString(raw)
	return `set -eu
umask 077
stage=init
trap 'status=$?; if [ "$status" -ne 0 ]; then echo "3XUI_NODE_MTLS_SWITCH_FAILED stage=$stage" >&2; fi; rm -f /run/xray-cascade-mtls-header /run/xray-cascade-mtls-*.json' EXIT INT TERM
printf '%s' '` + payload + `' | base64 -d > /run/xray-cascade-mtls-input.json
cd /usr/local/x-ui
token_name=xray-cascade-mtls-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %s\n' "$token" > /run/xray-cascade-mtls-header
unset token
port=$(jq -r '.panelPort' /run/xray-cascade-mtls-input.json)
panel_scheme=$(jq -r '.localPanelScheme' /run/xray-cascade-mtls-input.json)
panel_tls=$(jq -r '.localPanelCurlTLS' /run/xray-cascade-mtls-input.json)
api="${panel_scheme}://127.0.0.1:${port}/entry/panel/api"
api_json() { method=$1 path=$2 output=$3 data=${4:-}; if [ -n "$data" ]; then curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-mtls-header -H 'Content-Type: application/json' -X "$method" --data @"$data" "$api$path" > "$output"; else curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-mtls-header -X "$method" "$api$path" > "$output"; fi; if ! jq -e '.success==true' "$output" >/dev/null; then jq -c '{success,msg}' "$output" >&2; return 1; fi; }
stage=reload-client
api_json POST /nodes/mtls/reloadClient /run/xray-cascade-mtls-reload.json
stage=list-node
api_json GET /nodes/list /run/xray-cascade-mtls-list.json
node_name=$(jq -r '.nodeName' /run/xray-cascade-mtls-input.json)
node_id=$(jq -r --arg name "$node_name" '.obj[]? | select(.name==$name) | .id' /run/xray-cascade-mtls-list.json | head -n 1)
test -n "$node_id"
address=$(jq -r '.exitAddress' /run/xray-cascade-mtls-input.json)
node_remark=$(jq -r '.nodeRemark' /run/xray-cascade-mtls-input.json)
allow_private=$(jq -r '.allowPrivateAddress' /run/xray-cascade-mtls-input.json)
jq -n --argjson id "$node_id" --arg address "$address" --argjson port "$port" --arg name "$node_name" --arg remark "$node_remark" --argjson allowPrivate "$allow_private" '{id:$id,name:$name,remark:$remark,scheme:"https",address:$address,port:$port,basePath:"/exit/",clearApiToken:true,enable:true,allowPrivateAddress:$allowPrivate,tlsVerifyMode:"mtls",pinnedCertSha256:""}' > /run/xray-cascade-mtls-node.json
stage=test-node
api_json POST /nodes/test /run/xray-cascade-mtls-test.json /run/xray-cascade-mtls-node.json
stage=update-node
updated=false
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-mtls-header -H 'Content-Type: application/json' -X POST --data @/run/xray-cascade-mtls-node.json "$api/nodes/update/$node_id" > /run/xray-cascade-mtls-update.json 2>/dev/null && jq -e '.success==true' /run/xray-cascade-mtls-update.json >/dev/null; then updated=true; break; fi
  sleep 1
done
if [ "$updated" != true ]; then jq -c '{success,msg}' /run/xray-cascade-mtls-update.json >&2; exit 1; fi
stage=probe-node
online=false
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-mtls-header -X POST "$api/nodes/probe/$node_id" > /run/xray-cascade-mtls-probe.json 2>/dev/null && jq -e '.success==true and .obj.status=="online"' /run/xray-cascade-mtls-probe.json >/dev/null; then online=true; break; fi
  sleep 1
done
test "$online" = true
api_json GET /nodes/list /run/xray-cascade-mtls-list.json
jq -e --argjson id "$node_id" '.obj[]|select(.id==$id and .tlsVerifyMode=="mtls" and .status=="online")' /run/xray-cascade-mtls-list.json >/dev/null
api_json GET /setting/apiTokens /run/xray-cascade-mtls-tokens.json
token_id=$(jq -r --arg name "$token_name" '.obj[]|select(.name==$name)|.id' /run/xray-cascade-mtls-tokens.json)
test -n "$token_id"
printf '{"expectedScope":"admin"}' > /run/xray-cascade-mtls-delete-request.json
api_json POST /setting/apiTokens/delete/$token_id /run/xray-cascade-mtls-delete.json /run/xray-cascade-mtls-delete-request.json
echo "3XUI_NODE_MTLS_READY id=$node_id status=online"
trap - EXIT
rm -f /run/xray-cascade-mtls-header /run/xray-cascade-mtls-*.json
`, nil
}

// ValidateBoundary prevents the lab command from being pointed at ordinary
// public VPS endpoints. Production deploy has a separate, stricter contract.
func ValidateBoundary(inv inventory.Inventory, proxyJump string) error {
	if strings.TrimSpace(proxyJump) == "" {
		return errors.New("lab deploy requires an explicit SSH proxy-jump")
	}
	for role, server := range map[string]inventory.Server{"entry": inv.Entry, "exit": inv.Exit} {
		host, err := netip.ParseAddr(server.Host)
		if err != nil || !host.IsLoopback() {
			return fmt.Errorf("%s SSH host must be a loopback address in lab mode", role)
		}
		if server.SSHPort == 22 {
			return fmt.Errorf("%s SSH port must not be 22 in lab mode", role)
		}
		cascade, err := netip.ParseAddr(server.CascadeAddress)
		if err != nil || !cascade.IsPrivate() {
			return fmt.Errorf("%s cascade_address must be a private IP in lab mode", role)
		}
		if server.PublicIPv6 != "disabled" {
			ipv6, parseErr := netip.ParseAddr(server.PublicIPv6)
			if parseErr != nil || !ipv6.Is6() || !ipv6.IsPrivate() {
				return fmt.Errorf("%s public_ipv6 must be disabled or a private IPv6 address in lab mode", role)
			}
		}
	}
	if inv.Transport.ClientPort < 1024 || inv.Transport.InterserverPort < 1024 {
		return errors.New("lab transport ports must be unprivileged")
	}
	for _, alternative := range inv.Transport.ClientAlternatives {
		if alternative.Port < 1024 {
			return errors.New("lab alternative client transport ports must be unprivileged")
		}
	}
	for _, alternative := range inv.Transport.InterserverAlternatives {
		if alternative.Port < 1024 {
			return errors.New("lab alternative interserver transport ports must be unprivileged")
		}
	}
	if inv.Transport.Hysteria2.Enabled && inv.Transport.Hysteria2.Port < 1024 {
		return errors.New("lab Hysteria 2 port must be unprivileged")
	}
	if inv.Panel.Access != "ssh-tunnel" {
		return errors.New("lab panel access must be ssh-tunnel")
	}
	return nil
}

type entryInput struct {
	ExitToken            string `json:"exitToken"`
	ExitPin              string `json:"exitPin"`
	EntryAddress         string `json:"entryAddress"`
	ExitAddress          string `json:"exitAddress"`
	ExitIPv6             string `json:"exitIPv6"`
	PreferInterserver    string `json:"preferInterserver"`
	ClientPort           int    `json:"clientPort"`
	ClientXHTTPPort      int    `json:"clientXhttpPort"`
	ClientXHTTPPQPort    int    `json:"clientXhttpPqPort"`
	ClientGRPCPort       int    `json:"clientGrpcPort"`
	Hysteria2Port        int    `json:"hysteria2Port"`
	Hysteria2CertFile    string `json:"hysteria2CertFile"`
	Hysteria2KeyFile     string `json:"hysteria2KeyFile"`
	Hysteria2PinCert     bool   `json:"hysteria2PinCert"`
	InterserverPort      int    `json:"interserverPort"`
	InterserverXHTTPPort int    `json:"interserverXhttpPort"`
	ClientTarget         string `json:"clientTarget"`
	ClientServerName     string `json:"clientServerName"`
	HopTarget            string `json:"hopTarget"`
	HopServerName        string `json:"hopServerName"`
	HappDeeplink         string `json:"happDeeplink"`
	NodeTransport        string `json:"nodeTransport"`
	ServerRouting        string `json:"serverRouting"`
	GeoIPURL             string `json:"geoipUrl"`
	GeoIPSHA256          string `json:"geoipSha256"`
	GeoSiteURL           string `json:"geositeUrl"`
	GeoSiteSHA256        string `json:"geositeSha256"`
	SubscriptionCertFile string `json:"subscriptionCertFile"`
	SubscriptionKeyFile  string `json:"subscriptionKeyFile"`
	NodeName             string `json:"nodeName"`
	NodeRemark           string `json:"nodeRemark"`
	ExitInboundRemark    string `json:"exitInboundRemark"`
	EntryInboundRemark   string `json:"entryInboundRemark"`
	PanelPort            int    `json:"panelPort"`
	LocalPanelScheme     string `json:"localPanelScheme"`
	LocalPanelCurlTLS    string `json:"localPanelCurlTLS"`
	AllowPrivateAddress  bool   `json:"allowPrivateAddress"`
	ObservatoryInterval  string `json:"observatoryInterval"`
}

// RuntimeOptions keeps environment-specific policy out of the shared 3x-ui
// runtime script. Lab callers use private addressing and HTTP on loopback;
// production callers use public addressing and the already issued HTTPS
// panel certificate.
type RuntimeOptions struct {
	NodeName            string
	NodeRemark          string
	ExitInboundRemark   string
	EntryInboundRemark  string
	LocalPanelScheme    string
	LocalPanelCurlTLS   string
	AllowPrivateAddress bool
	ObservatoryInterval string
}

func LabRuntimeOptions() RuntimeOptions {
	return RuntimeOptions{
		NodeName: "lab-exit", NodeRemark: "isolated container lab",
		ExitInboundRemark: "lab-cascade-exit", EntryInboundRemark: "lab-client-entry",
		LocalPanelScheme: "http", AllowPrivateAddress: true, ObservatoryInterval: "2s",
	}
}

func ProductionRuntimeOptions() RuntimeOptions {
	return RuntimeOptions{
		NodeName: "xray-cascade-exit", NodeRemark: "managed exit node",
		ExitInboundRemark: "xray-cascade-exit", EntryInboundRemark: "xray-cascade-client",
		LocalPanelScheme: "https", LocalPanelCurlTLS: "--insecure", AllowPrivateAddress: false,
		ObservatoryInterval: "1m",
	}
}

// ExitTokenScript rotates one named node-sync token and returns it only to the
// controller over the already authenticated SSH stdout channel.
func ExitTokenScript() string {
	return `set -eu
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-master -tokenScope node-sync -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
pin=$(openssl x509 -in /etc/x-ui/panel.crt -outform DER | sha256sum | awk '{print $1}')
test "${#pin}" -eq 64
printf '3XUI_NODE_TOKEN\t%s\n' "$token"
printf '3XUI_NODE_PIN\t%s\n' "$pin"
unset token pin
`
}

func ParseExitAccess(output string) (NodeAccess, error) {
	var access NodeAccess
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, tokenPrefix) {
			if access.Token != "" {
				return NodeAccess{}, errors.New("exit returned more than one node token")
			}
			access.Token = strings.TrimPrefix(line, tokenPrefix)
		}
		if strings.HasPrefix(line, pinPrefix) {
			if access.Pin != "" {
				return NodeAccess{}, errors.New("exit returned more than one certificate pin")
			}
			access.Pin = strings.TrimPrefix(line, pinPrefix)
		}
	}
	if access.Token == "" || strings.ContainsAny(access.Token, "\r\n\t ") {
		return NodeAccess{}, errors.New("exit did not return a valid node token")
	}
	if len(access.Pin) != 64 || strings.Trim(access.Pin, "0123456789abcdefABCDEF") != "" {
		return NodeAccess{}, errors.New("exit did not return a valid SHA-256 certificate pin")
	}
	return access, nil
}

func EntryScript(inv inventory.Inventory, access NodeAccess, happDeeplink string) (string, error) {
	return EntryScriptWithOptions(inv, access, happDeeplink, LabRuntimeOptions())
}

// EntryScriptWithOptions builds the common 3x-ui runtime configuration for
// either the isolated lab or clean production hosts.
func EntryScriptWithOptions(inv inventory.Inventory, access NodeAccess, happDeeplink string, options RuntimeOptions) (string, error) {
	if strings.TrimSpace(options.NodeName) == "" || strings.TrimSpace(options.ExitInboundRemark) == "" || strings.TrimSpace(options.EntryInboundRemark) == "" {
		return "", errors.New("runtime resource names are required")
	}
	if options.LocalPanelScheme != "http" && options.LocalPanelScheme != "https" {
		return "", errors.New("local panel scheme must be http or https")
	}
	hysteriaCert, hysteriaKey := inv.Certificates.SubscriptionCertFile, inv.Certificates.SubscriptionKeyFile
	if inv.Certificates.SubscriptionTLS == "acme-ip" {
		hysteriaCert, hysteriaKey = "/root/cert/ip/fullchain.pem", "/root/cert/ip/privkey.pem"
	}
	hysteriaPort := 0
	if inv.Transport.Hysteria2.Enabled {
		hysteriaPort = inv.Transport.Hysteria2.Port
	}
	input := entryInput{
		ExitToken: access.Token, ExitPin: access.Pin, EntryAddress: inv.Entry.CascadeAddress, ExitAddress: inv.Exit.CascadeAddress,
		ExitIPv6: inv.Exit.PublicIPv6, PreferInterserver: inv.Transport.PreferInterserver,
		ClientPort: inv.Transport.ClientPort, ClientXHTTPPort: inv.ClientAlternativePort("reality-xhttp"), ClientXHTTPPQPort: inv.ClientAlternativePort("reality-xhttp-pq"), ClientGRPCPort: inv.ClientAlternativePort("reality-grpc"), Hysteria2Port: hysteriaPort, Hysteria2CertFile: hysteriaCert, Hysteria2KeyFile: hysteriaKey, Hysteria2PinCert: options.AllowPrivateAddress, InterserverPort: inv.Transport.InterserverPort, InterserverXHTTPPort: inv.InterserverAlternativePort("reality-xhttp"),
		ClientTarget: inv.Transport.ClientReality.Target, ClientServerName: inv.Transport.ClientReality.ServerName,
		HopTarget: inv.Transport.InterserverReality.Target, HopServerName: inv.Transport.InterserverReality.ServerName,
		HappDeeplink: happDeeplink, ServerRouting: inv.Cluster.RoutingProfile,
		NodeTransport:        inv.Certificates.NodeTransport,
		SubscriptionCertFile: inv.Certificates.SubscriptionCertFile,
		SubscriptionKeyFile:  inv.Certificates.SubscriptionKeyFile,
		NodeName:             options.NodeName, NodeRemark: options.NodeRemark,
		ExitInboundRemark: options.ExitInboundRemark, EntryInboundRemark: options.EntryInboundRemark,
		PanelPort: inv.Panel.Port, LocalPanelScheme: options.LocalPanelScheme,
		LocalPanelCurlTLS: options.LocalPanelCurlTLS, AllowPrivateAddress: options.AllowPrivateAddress,
		ObservatoryInterval: options.ObservatoryInterval,
	}
	if inv.Cluster.RoutingProfile == "roscomvpn-default" {
		input.GeoIPURL = routing.RoscomVPNGeoIPURL
		input.GeoIPSHA256 = routing.RoscomVPNGeoIPSHA256
		input.GeoSiteURL = routing.RoscomVPNGeoSiteURL
		input.GeoSiteSHA256 = routing.RoscomVPNGeoSiteSHA256
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("encode lab deploy input: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(raw)
	return `set -eu
umask 077
cd /usr/local/x-ui
printf '%s' '` + payload + `' | base64 -d > /run/xray-cascade-input.json
entry_token=$(./x-ui setting -tokenName xray-cascade-controller -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$entry_token"
printf 'Authorization: Bearer %s\n' "$entry_token" > /run/xray-cascade-header
unset entry_token
panel_port=$(jq -r '.panelPort' /run/xray-cascade-input.json)
panel_scheme=$(jq -r '.localPanelScheme' /run/xray-cascade-input.json)
panel_tls=$(jq -r '.localPanelCurlTLS' /run/xray-cascade-input.json)
api="${panel_scheme}://127.0.0.1:${panel_port}/entry/panel/api"

cleanup() {
  rm -f /run/xray-cascade-input.json /run/xray-cascade-header /run/xray-cascade-*.json
}
trap cleanup EXIT INT TERM

api_json() {
  method=$1 path=$2 output=$3 data=${4:-}
  if [ -n "$data" ]; then
    curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-header -H 'Content-Type: application/json' -X "$method" --data @"$data" "$api$path" > "$output"
  else
    curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-header -X "$method" "$api$path" > "$output"
  fi
  if ! jq -e '.success == true' "$output" >/dev/null; then
    jq -c '{success,msg}' "$output" >&2
    return 1
  fi
}

exit_token=$(jq -r '.exitToken' /run/xray-cascade-input.json)
exit_pin=$(jq -r '.exitPin' /run/xray-cascade-input.json)
exit_address=$(jq -r '.exitAddress' /run/xray-cascade-input.json)
node_name=$(jq -r '.nodeName' /run/xray-cascade-input.json)
node_remark=$(jq -r '.nodeRemark' /run/xray-cascade-input.json)
allow_private=$(jq -r '.allowPrivateAddress' /run/xray-cascade-input.json)
jq -n --arg token "$exit_token" --arg pin "$exit_pin" --arg address "$exit_address" --arg name "$node_name" --arg remark "$node_remark" --argjson port "$panel_port" --argjson allowPrivate "$allow_private" '{
  name:$name,remark:$remark,scheme:"https",address:$address,port:$port,
  basePath:"/exit/",apiToken:$token,clearApiToken:false,enable:true,allowPrivateAddress:$allowPrivate,
  tlsVerifyMode:"pin",pinnedCertSha256:$pin
}' > /run/xray-cascade-node.json
unset exit_token exit_pin

node_api=$api/nodes
api_json POST /nodes/test /run/xray-cascade-node-test.json /run/xray-cascade-node.json
api_json GET /nodes/list /run/xray-cascade-node-list.json
node_id=$(jq -r --arg name "$node_name" '.obj[]? | select(.name==$name) | .id' /run/xray-cascade-node-list.json | head -n 1)
if [ -n "$node_id" ]; then node_path=/nodes/update/$node_id; else node_path=/nodes/add; fi
api_json POST "$node_path" /run/xray-cascade-node-save.json /run/xray-cascade-node.json
api_json GET /nodes/list /run/xray-cascade-node-list.json
node_id=$(jq -r --arg name "$node_name" '.obj[]? | select(.name==$name) | .id' /run/xray-cascade-node-list.json | head -n 1)
test -n "$node_id"
api_json POST /nodes/probe/$node_id /run/xray-cascade-node-probe.json
test "$(jq -r '.obj.status' /run/xray-cascade-node-probe.json)" = online
echo "3XUI_NODE_READY id=$node_id status=online"

api_json GET /inbounds/list /run/xray-cascade-inbounds.json
exit_inbound_remark=$(jq -r '.exitInboundRemark' /run/xray-cascade-input.json)
entry_inbound_remark=$(jq -r '.entryInboundRemark' /run/xray-cascade-input.json)
if ! jq -e --arg remark "$exit_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
  api_json GET /server/getNewUUID /run/xray-cascade-uuid.json
  api_json GET /server/getNewX25519Cert /run/xray-cascade-x25519.json
  uuid=$(jq -r '.obj.uuid' /run/xray-cascade-uuid.json)
  private_key=$(jq -r '.obj.privateKey' /run/xray-cascade-x25519.json)
  public_key=$(jq -r '.obj.publicKey' /run/xray-cascade-x25519.json)
  short_id=$(openssl rand -hex 8)
  port=$(jq -r '.interserverPort' /run/xray-cascade-input.json)
  target=$(jq -r '.hopTarget' /run/xray-cascade-input.json)
  server_name=$(jq -r '.hopServerName' /run/xray-cascade-input.json)
  settings=$(jq -nc --arg id "$uuid" '{clients:[{id:$id,email:"cascade-hop",flow:"xtls-rprx-vision",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:"cascade-hop",comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
  stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --arg sni "$server_name" '{network:"tcp",tcpSettings:{header:{type:"none"}},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:[$sni],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
  sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
  jq -n --arg remark "$exit_inbound_remark" --argjson node "$node_id" --argjson port "$port" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:true,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:"in-cascade-exit",nodeId:$node,shareAddrStrategy:"node",settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
  api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
fi

# The interserver XHTTP path is deliberately hidden from subscriptions. It
# shares the hop UUID with TCP but owns independent REALITY keys, short ID and
# path, so either transport can fail without weakening the other.
interserver_xhttp_port=$(jq -r '.interserverXhttpPort' /run/xray-cascade-input.json)
if [ "$interserver_xhttp_port" -gt 0 ]; then
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  exit_xhttp_remark="${exit_inbound_remark}-xhttp"
  if ! jq -e --arg remark "$exit_xhttp_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
    primary_exit_settings=$(jq -r --arg remark "$exit_inbound_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
    hop_uuid=$(printf '%s' "$primary_exit_settings" | jq -r '.clients[0].id')
    test -n "$hop_uuid"
    api_json GET /server/getNewX25519Cert /run/xray-cascade-x25519.json
    private_key=$(jq -r '.obj.privateKey' /run/xray-cascade-x25519.json)
    public_key=$(jq -r '.obj.publicKey' /run/xray-cascade-x25519.json)
    short_id=$(openssl rand -hex 8)
    xhttp_path="/$(openssl rand -hex 8)"
    target=$(jq -r '.hopTarget' /run/xray-cascade-input.json)
    server_name=$(jq -r '.hopServerName' /run/xray-cascade-input.json)
    settings=$(jq -nc --arg id "$hop_uuid" '{clients:[{id:$id,email:"cascade-hop-xhttp",flow:"",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:"cascade-hop-xhttp",comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
    stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --arg sni "$server_name" --arg path "$xhttp_path" '{network:"xhttp",xhttpSettings:{path:$path,host:$sni,mode:"auto"},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:[$sni],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
    sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
    jq -n --arg remark "$exit_xhttp_remark" --argjson node "$node_id" --argjson port "$interserver_xhttp_port" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:true,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:"in-cascade-exit-xhttp",nodeId:$node,shareAddrStrategy:"node",settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
    api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
  fi
fi

api_json GET /inbounds/list /run/xray-cascade-inbounds.json
if ! jq -e --arg remark "$entry_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
  api_json GET /server/getNewUUID /run/xray-cascade-uuid.json
  api_json GET /server/getNewX25519Cert /run/xray-cascade-x25519.json
  uuid=$(jq -r '.obj.uuid' /run/xray-cascade-uuid.json)
  private_key=$(jq -r '.obj.privateKey' /run/xray-cascade-x25519.json)
  public_key=$(jq -r '.obj.publicKey' /run/xray-cascade-x25519.json)
  short_id=$(openssl rand -hex 8)
  sub_id=$(openssl rand -hex 8)
  port=$(jq -r '.clientPort' /run/xray-cascade-input.json)
  entry_address=$(jq -r '.entryAddress' /run/xray-cascade-input.json)
  target=$(jq -r '.clientTarget' /run/xray-cascade-input.json)
  server_name=$(jq -r '.clientServerName' /run/xray-cascade-input.json)
  settings=$(jq -nc --arg id "$uuid" --arg sub "$sub_id" '{clients:[{id:$id,email:"lab-client",flow:"xtls-rprx-vision",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
  stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --arg sni "$server_name" '{network:"tcp",tcpSettings:{header:{type:"none"}},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:[$sni],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
  sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
  jq -n --arg remark "$entry_inbound_remark" --argjson port "$port" --arg address "$entry_address" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:false,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:"in-client-entry",shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
  api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
fi

# XHTTP is a second client-facing transport, not a replacement for the
# conservative TCP/REALITY path. It deliberately shares UUID and subId with
# the primary inbound so 3x-ui publishes both choices through one HAPP
# subscription. Plain VLESS XHTTP + REALITY must not carry Vision flow.
client_xhttp_port=$(jq -r '.clientXhttpPort' /run/xray-cascade-input.json)
if [ "$client_xhttp_port" -gt 0 ]; then
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  xhttp_inbound_remark="${entry_inbound_remark}-xhttp"
  if ! jq -e --arg remark "$xhttp_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
    primary_settings=$(jq -r --arg remark "$entry_inbound_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
    primary_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].id')
    primary_sub_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].subId')
    test -n "$primary_id"
    test -n "$primary_sub_id"
    api_json GET /server/getNewX25519Cert /run/xray-cascade-x25519.json
    private_key=$(jq -r '.obj.privateKey' /run/xray-cascade-x25519.json)
    public_key=$(jq -r '.obj.publicKey' /run/xray-cascade-x25519.json)
    short_id=$(openssl rand -hex 8)
    xhttp_path="/$(openssl rand -hex 8)"
    entry_address=$(jq -r '.entryAddress' /run/xray-cascade-input.json)
    target=$(jq -r '.clientTarget' /run/xray-cascade-input.json)
    server_name=$(jq -r '.clientServerName' /run/xray-cascade-input.json)
    settings=$(jq -nc --arg id "$primary_id" --arg sub "$primary_sub_id" '{clients:[{id:$id,email:"lab-client",flow:"",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
    stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --arg sni "$server_name" --arg path "$xhttp_path" '{network:"xhttp",xhttpSettings:{path:$path,host:$sni,mode:"auto"},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:[$sni],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
    sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
    jq -n --arg remark "$xhttp_inbound_remark" --argjson port "$client_xhttp_port" --arg address "$entry_address" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:false,subSortIndex:2,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:"in-client-entry-xhttp",shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
    api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
  fi
fi

# VLESS Encryption is an inbound-level setting, so the post-quantum XHTTP
# route cannot reuse the plain XHTTP port. Generate a dedicated ML-KEM pair
# through the pinned 3x-ui API and keep the long key material out of argv.
client_xhttp_pq_port=$(jq -r '.clientXhttpPqPort' /run/xray-cascade-input.json)
if [ "$client_xhttp_pq_port" -gt 0 ]; then
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  xhttp_pq_inbound_remark="${entry_inbound_remark}-xhttp-pq"
  if ! jq -e --arg remark "$xhttp_pq_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
    primary_settings=$(jq -r --arg remark "$entry_inbound_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
    primary_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].id')
    primary_sub_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].subId')
    test -n "$primary_id"
    test -n "$primary_sub_id"
    api_json GET /server/getNewX25519Cert /run/xray-cascade-x25519.json
    api_json GET /server/getNewVlessEnc /run/xray-cascade-vlessenc.json
    jq -e '.obj.auths[] | select(.id=="mlkem768") | (.decryption|startswith("mlkem768x25519plus.native.")) and (.encryption|startswith("mlkem768x25519plus.native."))' /run/xray-cascade-vlessenc.json >/dev/null
    private_key=$(jq -r '.obj.privateKey' /run/xray-cascade-x25519.json)
    public_key=$(jq -r '.obj.publicKey' /run/xray-cascade-x25519.json)
    short_id=$(openssl rand -hex 8)
    xhttp_pq_path="/$(openssl rand -hex 8)"
    entry_address=$(jq -r '.entryAddress' /run/xray-cascade-input.json)
    target=$(jq -r '.clientTarget' /run/xray-cascade-input.json)
    server_name=$(jq -r '.clientServerName' /run/xray-cascade-input.json)
    settings=$(jq -nc --arg id "$primary_id" --arg sub "$primary_sub_id" --slurpfile enc /run/xray-cascade-vlessenc.json '{clients:[{id:$id,email:"lab-client",flow:"",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}],decryption:($enc[0].obj.auths[]|select(.id=="mlkem768")|.decryption),encryption:($enc[0].obj.auths[]|select(.id=="mlkem768")|.encryption)}')
    stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --arg sni "$server_name" --arg path "$xhttp_pq_path" '{network:"xhttp",xhttpSettings:{path:$path,host:$sni,mode:"auto"},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:[$sni],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
    sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
    jq -n --arg remark "$xhttp_pq_inbound_remark" --argjson port "$client_xhttp_pq_port" --arg address "$entry_address" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:false,subSortIndex:3,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:"in-client-entry-xhttp-pq",shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
    api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
  fi
fi

client_grpc_port=$(jq -r '.clientGrpcPort' /run/xray-cascade-input.json)
if [ "$client_grpc_port" -gt 0 ]; then
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  grpc_inbound_remark="${entry_inbound_remark}-grpc"
  if ! jq -e --arg remark "$grpc_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
    primary_settings=$(jq -r --arg remark "$entry_inbound_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
    primary_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].id')
    primary_sub_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].subId')
    test -n "$primary_id"
    test -n "$primary_sub_id"
    api_json GET /server/getNewX25519Cert /run/xray-cascade-x25519.json
    private_key=$(jq -r '.obj.privateKey' /run/xray-cascade-x25519.json)
    public_key=$(jq -r '.obj.publicKey' /run/xray-cascade-x25519.json)
    short_id=$(openssl rand -hex 8)
    grpc_service=$(openssl rand -hex 8)
    entry_address=$(jq -r '.entryAddress' /run/xray-cascade-input.json)
    target=$(jq -r '.clientTarget' /run/xray-cascade-input.json)
    server_name=$(jq -r '.clientServerName' /run/xray-cascade-input.json)
    settings=$(jq -nc --arg id "$primary_id" --arg sub "$primary_sub_id" '{clients:[{id:$id,email:"lab-client",flow:"",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
    stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --arg sni "$server_name" --arg service "$grpc_service" '{network:"grpc",grpcSettings:{serviceName:$service,authority:"",multiMode:false},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:[$sni],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
    sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
    jq -n --arg remark "$grpc_inbound_remark" --argjson port "$client_grpc_port" --arg address "$entry_address" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:false,subSortIndex:4,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:"in-client-entry-grpc",shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
    api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
  fi
fi

# Hysteria 2 is a separate UDP+TLS protocol. It shares the subscription
# identity (email/subId), but uses its own random auth credential. The same
# trusted certificate used by the HAPP subscription terminates HY2 TLS.
hysteria2_port=$(jq -r '.hysteria2Port' /run/xray-cascade-input.json)
if [ "$hysteria2_port" -gt 0 ]; then
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  hysteria2_inbound_remark="${entry_inbound_remark}-hysteria2"
  cert_file=$(jq -r '.hysteria2CertFile' /run/xray-cascade-input.json)
  key_file=$(jq -r '.hysteria2KeyFile' /run/xray-cascade-input.json)
  test -s "$cert_file"
  test -s "$key_file"
  if jq -e --arg remark "$hysteria2_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
    expected_pin=
    if [ "$(jq -r '.hysteria2PinCert' /run/xray-cascade-input.json)" = true ]; then
      expected_pin=$(openssl x509 -in "$cert_file" -outform DER | sha256sum | cut -d' ' -f1)
      test "${#expected_pin}" -eq 64
    fi
    current_pin=$(jq -r --arg remark "$hysteria2_inbound_remark" 'def decoded: if type=="string" then fromjson else . end; .obj[]|select(.remark==$remark)|.streamSettings|decoded|.tlsSettings.settings.pinnedPeerCertSha256[0]//""' /run/xray-cascade-inbounds.json)
    if [ "$current_pin" != "$expected_pin" ]; then
      stale_id=$(jq -r --arg remark "$hysteria2_inbound_remark" '.obj[]|select(.remark==$remark)|.id' /run/xray-cascade-inbounds.json)
      api_json POST "/inbounds/del/$stale_id" /run/xray-cascade-hysteria-delete.json
      api_json GET /inbounds/list /run/xray-cascade-inbounds.json
    fi
  fi
  if ! jq -e --arg remark "$hysteria2_inbound_remark" '.obj[]? | select(.remark==$remark)' /run/xray-cascade-inbounds.json >/dev/null; then
    primary_settings=$(jq -r --arg remark "$entry_inbound_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
    primary_sub_id=$(printf '%s' "$primary_settings" | jq -r '.clients[0].subId')
    test -n "$primary_sub_id"
    hysteria_auth=$(openssl rand -hex 24)
    entry_address=$(jq -r '.entryAddress' /run/xray-cascade-input.json)
	client_tls_settings='{}'
	if [ "$(jq -r '.hysteria2PinCert' /run/xray-cascade-input.json)" = true ]; then
	  cert_pin=$(openssl x509 -in "$cert_file" -outform DER | sha256sum | cut -d' ' -f1)
	  test "${#cert_pin}" -eq 64
	  client_tls_settings=$(jq -nc --arg pin "$cert_pin" '{pinnedPeerCertSha256:[$pin]}')
	fi
    settings=$(jq -nc --arg auth "$hysteria_auth" --arg sub "$primary_sub_id" '{version:2,clients:[{email:"lab-client",auth:$auth,limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}]}')
	stream=$(jq -nc --arg cert "$cert_file" --arg key "$key_file" --arg sni "$entry_address" --argjson client "$client_tls_settings" '{network:"hysteria",security:"tls",hysteriaSettings:{version:2},tlsSettings:{serverName:$sni,alpn:["h3"],certificates:[{certificateFile:$cert,keyFile:$key}],settings:$client}}')
    sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
	jq -n --arg remark "$hysteria2_inbound_remark" --argjson port "$hysteria2_port" --arg address "$entry_address" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:$remark,excludeFromSub:false,subSortIndex:5,listen:"",port:$port,protocol:"hysteria",expiryTime:0,total:0,tag:"in-client-entry-hysteria2",shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/xray-cascade-inbound.json
    api_json POST /inbounds/add /run/xray-cascade-inbound-response.json /run/xray-cascade-inbound.json
  fi
fi

# Converge optional managed inbounds as well as creating them. Removing an
# option from inventory must not leave a hidden listener or stale subscription
# record behind. Only exact remarks owned by this runtime controller qualify.
remove_disabled_inbound() {
  enabled_port=$1 remark=$2
  if [ "$enabled_port" -gt 0 ]; then return 0; fi
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  inbound_id=$(jq -r --arg remark "$remark" '.obj[]? | select(.remark==$remark) | .id' /run/xray-cascade-inbounds.json | head -n 1)
  if [ -n "$inbound_id" ]; then
    case "$inbound_id" in (*[!0-9]*|'') return 1;; esac
    api_json POST "/inbounds/del/$inbound_id" /run/xray-cascade-inbound-delete.json
  fi
}
remove_disabled_inbound "$client_xhttp_port" "${entry_inbound_remark}-xhttp"
remove_disabled_inbound "$client_xhttp_pq_port" "${entry_inbound_remark}-xhttp-pq"
remove_disabled_inbound "$client_grpc_port" "${entry_inbound_remark}-grpc"
remove_disabled_inbound "$hysteria2_port" "${entry_inbound_remark}-hysteria2"
if [ "$(jq -r '.allowPrivateAddress' /run/xray-cascade-input.json)" = true ]; then
  remove_disabled_inbound 0 in-client-entry-xhttp-adopt
fi

api_json GET /inbounds/list /run/xray-cascade-inbounds.json
exit_settings=$(jq -r --arg remark "$exit_inbound_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
exit_stream=$(jq -r --arg remark "$exit_inbound_remark" '.obj[]|select(.remark==$remark)|.streamSettings' /run/xray-cascade-inbounds.json)
hop_id=$(printf '%s' "$exit_settings" | jq -r '.clients[0].id')
public_key=$(printf '%s' "$exit_stream" | jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%s' "$exit_stream" | jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%s' "$exit_stream" | jq -r '.realitySettings.shortIds[0]')
hop_port=$(jq -r '.interserverPort' /run/xray-cascade-input.json)
outbound_v4=$(jq -nc --arg id "$hop_id" --arg address "$exit_address" --argjson port "$hop_port" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" '{tag:"cascade-exit-ipv4",protocol:"vless",settings:{address:$address,port:$port,id:$id,encryption:"none",flow:"xtls-rprx-vision"},streamSettings:{network:"tcp",security:"reality",tcpSettings:{header:{type:"none"}},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}')
outbounds=$(jq -nc --argjson v4 "$outbound_v4" '[$v4]')
observatory_selectors='["cascade-exit-ipv4"]'
exit_ipv6=$(jq -r '.exitIPv6' /run/xray-cascade-input.json)
balancer_selector='["cascade-exit-ipv4"]'
balancer_fallback=blocked
balancer_strategy=roundRobin
case "$exit_ipv6" in
  disabled|auto|'') ;;
  *)
    outbound_v6=$(jq -nc --arg id "$hop_id" --arg address "$exit_ipv6" --argjson port "$hop_port" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" '{tag:"cascade-exit-ipv6",protocol:"vless",settings:{address:$address,port:$port,id:$id,encryption:"none",flow:"xtls-rprx-vision"},streamSettings:{network:"tcp",security:"reality",tcpSettings:{header:{type:"none"}},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}')
    outbounds=$(jq -nc --argjson current "$outbounds" --argjson v6 "$outbound_v6" '$current+[$v6]')
    observatory_selectors=$(printf '%s' "$observatory_selectors" | jq -c '.+["cascade-exit-ipv6"]')
    if [ "$(jq -r '.preferInterserver' /run/xray-cascade-input.json)" = lowest-latency ]; then
      balancer_selector='["cascade-exit-ipv4","cascade-exit-ipv6"]'
      balancer_strategy=leastPing
    else
      balancer_fallback=cascade-exit-ipv6
    fi
    ;;
esac

if [ "$interserver_xhttp_port" -gt 0 ]; then
  api_json GET /inbounds/list /run/xray-cascade-inbounds.json
  exit_xhttp_remark="${exit_inbound_remark}-xhttp"
  exit_xhttp_settings=$(jq -r --arg remark "$exit_xhttp_remark" '.obj[]|select(.remark==$remark)|.settings' /run/xray-cascade-inbounds.json)
  exit_xhttp_stream=$(jq -r --arg remark "$exit_xhttp_remark" '.obj[]|select(.remark==$remark)|.streamSettings' /run/xray-cascade-inbounds.json)
  xhttp_hop_id=$(printf '%s' "$exit_xhttp_settings" | jq -r '.clients[0].id')
  xhttp_public_key=$(printf '%s' "$exit_xhttp_stream" | jq -r '.realitySettings.settings.publicKey')
  xhttp_server_name=$(printf '%s' "$exit_xhttp_stream" | jq -r '.realitySettings.serverNames[0]')
  xhttp_short_id=$(printf '%s' "$exit_xhttp_stream" | jq -r '.realitySettings.shortIds[0]')
  xhttp_path=$(printf '%s' "$exit_xhttp_stream" | jq -r '.xhttpSettings.path')
  xhttp_host=$(printf '%s' "$exit_xhttp_stream" | jq -r '.xhttpSettings.host')
  outbound_xhttp_v4=$(jq -nc --arg id "$xhttp_hop_id" --arg address "$exit_address" --argjson port "$interserver_xhttp_port" --arg public "$xhttp_public_key" --arg sni "$xhttp_server_name" --arg sid "$xhttp_short_id" --arg path "$xhttp_path" --arg host "$xhttp_host" '{tag:"cascade-exit-xhttp-ipv4",protocol:"vless",settings:{address:$address,port:$port,id:$id,encryption:"none",flow:""},streamSettings:{network:"xhttp",security:"reality",xhttpSettings:{path:$path,host:$host,mode:"auto"},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}')
  outbounds=$(jq -nc --argjson current "$outbounds" --argjson item "$outbound_xhttp_v4" '$current+[$item]')
  observatory_selectors=$(printf '%s' "$observatory_selectors" | jq -c '.+["cascade-exit-xhttp-ipv4"]')
  case "$exit_ipv6" in
    disabled|auto|'') ;;
    *)
      outbound_xhttp_v6=$(jq -nc --arg id "$xhttp_hop_id" --arg address "$exit_ipv6" --argjson port "$interserver_xhttp_port" --arg public "$xhttp_public_key" --arg sni "$xhttp_server_name" --arg sid "$xhttp_short_id" --arg path "$xhttp_path" --arg host "$xhttp_host" '{tag:"cascade-exit-xhttp-ipv6",protocol:"vless",settings:{address:$address,port:$port,id:$id,encryption:"none",flow:""},streamSettings:{network:"xhttp",security:"reality",xhttpSettings:{path:$path,host:$host,mode:"auto"},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}')
      outbounds=$(jq -nc --argjson current "$outbounds" --argjson item "$outbound_xhttp_v6" '$current+[$item]')
      observatory_selectors=$(printf '%s' "$observatory_selectors" | jq -c '.+["cascade-exit-xhttp-ipv6"]')
      ;;
  esac
  balancer_selector=$observatory_selectors
  balancer_fallback=blocked
  balancer_strategy=leastPing
fi
balancer=$(jq -nc --argjson selector "$balancer_selector" --arg fallback "$balancer_fallback" --arg strategy "$balancer_strategy" '{tag:"cascade-exit",selector:$selector,fallbackTag:$fallback,strategy:{type:$strategy}}')
client_inbound_tags='["in-client-entry"]'
if [ "$client_xhttp_port" -gt 0 ]; then
  client_inbound_tags=$(printf '%s' "$client_inbound_tags" | jq -c '.+["in-client-entry-xhttp"]')
fi
if [ "$client_xhttp_pq_port" -gt 0 ]; then
  client_inbound_tags=$(printf '%s' "$client_inbound_tags" | jq -c '.+["in-client-entry-xhttp-pq"]')
fi
if [ "$client_grpc_port" -gt 0 ]; then
  client_inbound_tags=$(printf '%s' "$client_inbound_tags" | jq -c '.+["in-client-entry-grpc"]')
fi
if [ "$hysteria2_port" -gt 0 ]; then
  client_inbound_tags=$(printf '%s' "$client_inbound_tags" | jq -c '.+["in-client-entry-hysteria2"]')
fi

server_routing=$(jq -r '.serverRouting' /run/xray-cascade-input.json)
if [ "$server_routing" = roscomvpn-default ]; then
  install_geodata() {
    url=$1 expected=$2 destination=$3 temporary=${3}.new
    if [ -s "$destination" ] && [ "$(sha256sum "$destination" | awk '{print $1}')" = "$expected" ]; then return 0; fi
    curl --fail --location --silent --show-error "$url" -o "$temporary"
    test "$(sha256sum "$temporary" | awk '{print $1}')" = "$expected"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$destination"
  }
  install_geodata "$(jq -r '.geoipUrl' /run/xray-cascade-input.json)" "$(jq -r '.geoipSha256' /run/xray-cascade-input.json)" /usr/local/x-ui/bin/roscom-geoip.dat
  install_geodata "$(jq -r '.geositeUrl' /run/xray-cascade-input.json)" "$(jq -r '.geositeSha256' /run/xray-cascade-input.json)" /usr/local/x-ui/bin/roscom-geosite.dat
  jq -n --argjson clientTags "$client_inbound_tags" '[
    {type:"field",ruleTag:"xray-cascade:block-private",ip:["geoip:private"],outboundTag:"blocked"},
    {type:"field",ruleTag:"xray-cascade:block-bittorrent",protocol:["bittorrent"],outboundTag:"blocked"},
    {type:"field",ruleTag:"xray-cascade:block-domains",domain:["ext:roscom-geosite.dat:win-spy","ext:roscom-geosite.dat:torrent","ext:roscom-geosite.dat:category-ads"],outboundTag:"blocked"},
    {type:"field",ruleTag:"xray-cascade:direct-domains",domain:["ext:roscom-geosite.dat:category-ru","ext:roscom-geosite.dat:whitelist","ext:roscom-geosite.dat:microsoft","ext:roscom-geosite.dat:apple","ext:roscom-geosite.dat:epicgames","ext:roscom-geosite.dat:riot","ext:roscom-geosite.dat:escapefromtarkov","ext:roscom-geosite.dat:steam","ext:roscom-geosite.dat:twitch","ext:roscom-geosite.dat:pinterest","ext:roscom-geosite.dat:faceit"],outboundTag:"direct"},
    {type:"field",ruleTag:"xray-cascade:direct-ip",ip:["ext:roscom-geoip.dat:direct"],outboundTag:"direct"},
    {type:"field",ruleTag:"xray-cascade:client-cascade",inboundTag:$clientTags,network:"tcp,udp",balancerTag:"cascade-exit"}
  ]' > /run/xray-cascade-managed-rules.json
else
  jq -n --argjson clientTags "$client_inbound_tags" '[
    {type:"field",ruleTag:"xray-cascade:block-private",ip:["geoip:private"],outboundTag:"blocked"},
    {type:"field",ruleTag:"xray-cascade:block-bittorrent",protocol:["bittorrent"],outboundTag:"blocked"},
    {type:"field",ruleTag:"xray-cascade:client-cascade",inboundTag:$clientTags,network:"tcp,udp",balancerTag:"cascade-exit"}
  ]' > /run/xray-cascade-managed-rules.json
fi
api_json POST /xray/ /run/xray-cascade-template-response.json
jq -r '.obj|fromjson|.xraySetting' /run/xray-cascade-template-response.json > /run/xray-cascade-template.json
managed_rules=$(cat /run/xray-cascade-managed-rules.json)
observatory_interval=$(jq -r '.observatoryInterval' /run/xray-cascade-input.json)
jq --argjson outbounds "$outbounds" --argjson balancer "$balancer" --argjson managed "$managed_rules" --argjson observers "$observatory_selectors" --arg interval "$observatory_interval" '
  .outbounds=([.outbounds[]|select(.tag!="cascade-exit")|select(.tag!="cascade-exit-ipv4")|select(.tag!="cascade-exit-ipv6")|select(.tag!="cascade-exit-xhttp-ipv4")|select(.tag!="cascade-exit-xhttp-ipv6")]+$outbounds)
  |.routing.balancers=([(.routing.balancers//[])[]|select(.tag!="cascade-exit")]+[$balancer])
  |.routing.rules=([.routing.rules[]|select(((.ruleTag//"")|startswith("xray-cascade:"))|not)|select(.outboundTag!="cascade-exit")|select(.balancerTag!="cascade-exit")|select(((.domain//[])|map(startswith("ext:roscom-geosite.dat:"))|any)|not)|select(((.ip//[])|map(startswith("ext:roscom-geoip.dat:"))|any)|not)]+$managed)
  |.observatory={subjectSelector:$observers,probeURL:"https://www.google.com/generate_204",probeInterval:$interval,enableConcurrency:true}
' /run/xray-cascade-template.json > /run/xray-cascade-updated.json
curl --fail-with-body $panel_tls -sS -H @/run/xray-cascade-header -X POST --data-urlencode xraySetting@/run/xray-cascade-updated.json "$api/xray/update" > /run/xray-cascade-update-response.json
jq -e '.success==true' /run/xray-cascade-update-response.json >/dev/null
api_json POST /server/restartXrayService /run/xray-cascade-restart.json
api_json GET /server/getConfigJson /run/xray-cascade-runtime.json
jq -e --arg fallback "$balancer_fallback" --argjson xhttpPort "$client_xhttp_port" --argjson xhttpPqPort "$client_xhttp_pq_port" --argjson grpcPort "$client_grpc_port" --argjson hysteriaPort "$hysteria2_port" --argjson hopXhttpPort "$interserver_xhttp_port" '
  (.obj.inbounds|any(.tag=="in-client-entry"))
  and ($xhttpPort==0 or (.obj.inbounds|any(.tag=="in-client-entry-xhttp" and .port==$xhttpPort and .streamSettings.network=="xhttp")))
  and ($xhttpPqPort==0 or (.obj.inbounds|any(.tag=="in-client-entry-xhttp-pq" and .port==$xhttpPqPort and .streamSettings.network=="xhttp" and (.settings.decryption|startswith("mlkem768x25519plus.native.")))))
  and ($grpcPort==0 or (.obj.inbounds|any(.tag=="in-client-entry-grpc" and .port==$grpcPort and .streamSettings.network=="grpc")))
  and ($hysteriaPort==0 or (.obj.inbounds|any(.tag=="in-client-entry-hysteria2" and .port==$hysteriaPort and .protocol=="hysteria" and .streamSettings.network=="hysteria" and .streamSettings.security=="tls")))
  and (.obj.outbounds|any(.tag=="cascade-exit-ipv4"))
  and ($hopXhttpPort==0 or (.obj.outbounds|any(.tag=="cascade-exit-xhttp-ipv4" and .streamSettings.network=="xhttp")))
  and (.obj.routing.balancers|any(.tag=="cascade-exit" and .fallbackTag==$fallback))
  and (.obj.routing.rules|any(.balancerTag=="cascade-exit" and ((.inboundTag//[])|any(.=="in-client-entry")) and ($xhttpPort==0 or ((.inboundTag//[])|any(.=="in-client-entry-xhttp"))) and ($xhttpPqPort==0 or ((.inboundTag//[])|any(.=="in-client-entry-xhttp-pq"))) and ($grpcPort==0 or ((.inboundTag//[])|any(.=="in-client-entry-grpc"))) and ($hysteriaPort==0 or ((.inboundTag//[])|any(.=="in-client-entry-hysteria2")))))
  and (.obj.observatory.subjectSelector|any(.=="cascade-exit-ipv4"))
  and ($hopXhttpPort==0 or (.obj.observatory.subjectSelector|any(.=="cascade-exit-xhttp-ipv4")))
' /run/xray-cascade-runtime.json >/dev/null
echo 3XUI_ENTRY_CONFIG_READY
if [ "$server_routing" = roscomvpn-default ]; then
  jq -e '(.obj.routing.rules|any(.outboundTag=="direct" and ((.domain//[])|any(.=="ext:roscom-geosite.dat:category-ru")))) and (.obj.routing.rules|any(.outboundTag=="direct" and ((.ip//[])|any(.=="ext:roscom-geoip.dat:direct"))))' /run/xray-cascade-runtime.json >/dev/null
  echo 3XUI_ROSCOMVPN_SERVER_READY
fi

if [ "$(jq -r '.nodeTransport' /run/xray-cascade-input.json)" = mtls ]; then
  api_json POST /nodes/mtls/ca /run/xray-cascade-mtls.json
  jq -e '(.obj.caCert|type=="string") and (.obj.caCert|contains("BEGIN CERTIFICATE"))' /run/xray-cascade-mtls.json >/dev/null
  printf '3XUI_MTLS_CA\t'
  jq -r '.obj.caCert' /run/xray-cascade-mtls.json | base64 -w0
  printf '\n'
fi

happ_deeplink=$(jq -r '.happDeeplink' /run/xray-cascade-input.json)
if [ -n "$happ_deeplink" ]; then
  api_json POST /setting/all /run/xray-cascade-settings-response.json
  jq --arg rules "$happ_deeplink" '.obj | .subEnable=true | .subEncrypt=false | .subEnableRouting=true | .subHappAutoDetect=true | .subHappNoLimit=false | .subRoutingRules=$rules' /run/xray-cascade-settings-response.json > /run/xray-cascade-settings.json
  subscription_cert=$(jq -r '.subscriptionCertFile' /run/xray-cascade-input.json)
  subscription_key=$(jq -r '.subscriptionKeyFile' /run/xray-cascade-input.json)
  if [ -n "$subscription_cert" ] || [ -n "$subscription_key" ]; then
    test -s "$subscription_cert"
    test -s "$subscription_key"
    jq --arg cert "$subscription_cert" --arg key "$subscription_key" '.subCertFile=$cert | .subKeyFile=$key' /run/xray-cascade-settings.json > /run/xray-cascade-settings-tls.json
    mv -f /run/xray-cascade-settings-tls.json /run/xray-cascade-settings.json
  fi
  api_json POST /setting/update /run/xray-cascade-settings-update.json /run/xray-cascade-settings.json
  api_json POST /setting/all /run/xray-cascade-settings-response.json
  jq -e --arg rules "$happ_deeplink" '.obj.subEnable==true and .obj.subEncrypt==false and .obj.subEnableRouting==true and .obj.subHappAutoDetect==true and .obj.subHappNoLimit==false and .obj.subRoutingRules==$rules' /run/xray-cascade-settings-response.json >/dev/null
  api_json POST /setting/restartPanel /run/xray-cascade-panel-restart.json
  panel_down=false
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if ! curl --fail $panel_tls -sS "${panel_scheme}://127.0.0.1:${panel_port}/entry/panel/" -o /dev/null 2>/dev/null; then panel_down=true; break; fi
    sleep 1
  done
  test "$panel_down" = true
  panel_ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    sleep 1
    if curl --fail $panel_tls -sS -H @/run/xray-cascade-header -X POST "$api/setting/all" > /run/xray-cascade-settings-response.json 2>/dev/null && jq -e '.success==true' /run/xray-cascade-settings-response.json >/dev/null; then
      panel_ready=true
      break
    fi
  done
  test "$panel_ready" = true
  echo 3XUI_ROSCOMVPN_READY
fi
`, nil
}

func ExitVerifyScript(interserverXHTTPPort int) string {
	return `set -eu
cd /usr/local/x-ui
token=$(./x-ui setting -tokenName xray-cascade-verifier -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
umask 077
printf 'Authorization: Bearer %s\n' "$token" > /run/xray-cascade-header
unset token
trap 'rm -f /run/xray-cascade-header /run/xray-cascade-runtime.json' EXIT INT TERM
xhttp_port=` + strconv.Itoa(interserverXHTTPPort) + `
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  curl --fail-with-body -k -sS -H @/run/xray-cascade-header https://127.0.0.1:2053/exit/panel/api/server/getConfigJson > /run/xray-cascade-runtime.json
  if jq -e --argjson xhttpPort "$xhttp_port" '.success==true and (.obj.inbounds|any(.tag=="in-cascade-exit")) and ($xhttpPort==0 or (.obj.inbounds|any(.tag=="in-cascade-exit-xhttp" and .port==$xhttpPort and .streamSettings.network=="xhttp")))' /run/xray-cascade-runtime.json >/dev/null; then ready=true; break; fi
  sleep 2
done
test "$ready" = true
echo 3XUI_EXIT_CONFIG_READY
`
}

func E2EScript(inv inventory.Inventory, happSHA string) (string, error) {
	if inv.Subscription.HappRouting == "roscomvpn-default" && happSHA == "" {
		return "", errors.New("adapted HAPP routing checksum is required")
	}
	hysteriaPort := 0
	if inv.Transport.Hysteria2.Enabled {
		hysteriaPort = inv.Transport.Hysteria2.Port
	}
	raw, err := json.Marshal(map[string]any{"entryAddress": inv.Entry.CascadeAddress, "clientPort": inv.Transport.ClientPort, "clientXhttpPort": inv.ClientAlternativePort("reality-xhttp"), "clientXhttpPqPort": inv.ClientAlternativePort("reality-xhttp-pq"), "clientGrpcPort": inv.ClientAlternativePort("reality-grpc"), "hysteria2Port": hysteriaPort, "happRoutingSHA": happSHA, "subscriptionTLS": inv.Certificates.SubscriptionTLS})
	if err != nil {
		return "", fmt.Errorf("encode lab E2E input: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(raw)
	return `set -eu
umask 077
cd /usr/local/x-ui
printf '%s' '` + payload + `' | base64 -d > /run/xray-cascade-e2e-input.json
token=$(./x-ui setting -tokenName xray-cascade-e2e -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %s\n' "$token" > /run/xray-cascade-e2e-header
unset token
client_pid=
primary_blocked=false
stage=init
cleanup() {
  status=$?
  if [ "$primary_blocked" = true ]; then iptables -D OUTPUT -d "$entry_address" -p tcp --dport "$client_port" -j REJECT 2>/dev/null || true; fi
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
  if [ "$status" -ne 0 ]; then
    echo "3XUI_CASCADE_E2E_FAILED stage=$stage" >&2
    if [ -s /run/xray-cascade-e2e.log ]; then sed -n '1,120p' /run/xray-cascade-e2e.log >&2; fi
  fi
  rm -f /run/xray-cascade-e2e-*.json /run/xray-cascade-e2e-header /run/xray-cascade-e2e.log \
    /run/xray-cascade-e2e-sub-headers /run/xray-cascade-e2e-sub-body /run/xray-cascade-e2e-sub-links
  exit "$status"
}

trap cleanup EXIT INT TERM
probe_http() {
  socks_port=$1
  for _ in 1 2 3 4 5 6; do
    code=$(curl --fail -sS --max-time 10 --socks5-hostname "127.0.0.1:${socks_port}" -o /dev/null -w '%{http_code}' https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null || true)
    if [ "$code" = 200 ]; then printf '200\n'; return 0; fi
    code=$(curl --fail -sS --max-time 10 --socks5-hostname "127.0.0.1:${socks_port}" -o /dev/null -w '%{http_code}' https://www.google.com/generate_204 2>/dev/null || true)
    if [ "$code" = 204 ]; then printf '200\n'; return 0; fi
    sleep 2
  done
  return 1
}
curl --fail-with-body -sS -H @/run/xray-cascade-e2e-header http://127.0.0.1:2053/entry/panel/api/inbounds/list > /run/xray-cascade-e2e-inbounds.json
jq -e '.success==true' /run/xray-cascade-e2e-inbounds.json >/dev/null
settings=$(jq -r '.obj[]|select(.remark=="lab-client-entry")|.settings' /run/xray-cascade-e2e-inbounds.json)
stream=$(jq -r '.obj[]|select(.remark=="lab-client-entry")|.streamSettings' /run/xray-cascade-e2e-inbounds.json)
client_id=$(printf '%s' "$settings"|jq -r '.clients[0].id')
public_key=$(printf '%s' "$stream"|jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%s' "$stream"|jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%s' "$stream"|jq -r '.realitySettings.shortIds[0]')
entry_address=$(jq -r '.entryAddress' /run/xray-cascade-e2e-input.json)
client_port=$(jq -r '.clientPort' /run/xray-cascade-e2e-input.json)
jq -n --arg id "$client_id" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" --arg address "$entry_address" --argjson port "$client_port" '{log:{loglevel:"warning"},inbounds:[{tag:"e2e-socks",listen:"127.0.0.1",port:10808,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-e2e-client.json
bin=/usr/local/x-ui/bin/xray-linux-amd64
stage=tcp-client-config
$bin run -test -config /run/xray-cascade-e2e-client.json >/dev/null
stage=tcp-e2e
$bin run -config /run/xray-cascade-e2e-client.json > /run/xray-cascade-e2e.log 2>&1 &
client_pid=$!
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn|grep -q '127.0.0.1:10808'; then ready=true; break; fi; sleep 1; done
test "$ready" = true
http_code=$(probe_http 10808)
test "$http_code" = 200
echo "3XUI_CASCADE_TCP_E2E_READY http=$http_code"

client_xhttp_port=$(jq -r '.clientXhttpPort' /run/xray-cascade-e2e-input.json)
if [ "$client_xhttp_port" -gt 0 ]; then
	stage=xhttp-client-config
  kill "$client_pid" 2>/dev/null || true
  wait "$client_pid" 2>/dev/null || true
  client_pid=
  xsettings=$(jq -r '.obj[]|select(.remark=="lab-client-entry-xhttp")|.settings' /run/xray-cascade-e2e-inbounds.json)
  xstream=$(jq -r '.obj[]|select(.remark=="lab-client-entry-xhttp")|.streamSettings' /run/xray-cascade-e2e-inbounds.json)
  xclient_id=$(printf '%s' "$xsettings" | jq -r '.clients[0].id')
  xpublic_key=$(printf '%s' "$xstream" | jq -r '.realitySettings.settings.publicKey')
  xserver_name=$(printf '%s' "$xstream" | jq -r '.realitySettings.serverNames[0]')
  xshort_id=$(printf '%s' "$xstream" | jq -r '.realitySettings.shortIds[0]')
  xpath=$(printf '%s' "$xstream" | jq -r '.xhttpSettings.path')
  xhost=$(printf '%s' "$xstream" | jq -r '.xhttpSettings.host')
  xmode=$(printf '%s' "$xstream" | jq -r '.xhttpSettings.mode')
  test "$xclient_id" = "$client_id"
  test "$(printf '%s' "$xsettings" | jq -r '.clients[0].subId')" = "$(printf '%s' "$settings" | jq -r '.clients[0].subId')"
  test "$xmode" = auto
  case "$xpath" in /*) ;; *) exit 1;; esac
  jq -n --arg id "$xclient_id" --arg public "$xpublic_key" --arg sni "$xserver_name" --arg sid "$xshort_id" --arg address "$entry_address" --arg path "$xpath" --arg host "$xhost" --arg mode "$xmode" --argjson port "$client_xhttp_port" '{log:{loglevel:"warning"},inbounds:[{tag:"e2e-xhttp-socks",listen:"127.0.0.1",port:10810,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry-xhttp",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:""}]}]},streamSettings:{network:"xhttp",security:"reality",xhttpSettings:{path:$path,host:$host,mode:$mode},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-e2e-xhttp-client.json
  $bin run -test -config /run/xray-cascade-e2e-xhttp-client.json >/dev/null
	stage=xhttp-e2e
  $bin run -config /run/xray-cascade-e2e-xhttp-client.json > /run/xray-cascade-e2e.log 2>&1 &
  client_pid=$!
  ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn|grep -q '127.0.0.1:10810'; then ready=true; break; fi; sleep 1; done
  test "$ready" = true
  http_code=$(probe_http 10810)
  test "$http_code" = 200
  echo "3XUI_CASCADE_XHTTP_E2E_READY http=$http_code"
  command -v iptables >/dev/null
  iptables -I OUTPUT 1 -d "$entry_address" -p tcp --dport "$client_port" -j REJECT
  primary_blocked=true
  iptables -C OUTPUT -d "$entry_address" -p tcp --dport "$client_port" -j REJECT
  http_code=$(probe_http 10810)
  test "$http_code" = 200
  iptables -D OUTPUT -d "$entry_address" -p tcp --dport "$client_port" -j REJECT
  primary_blocked=false
  echo "3XUI_CLIENT_TRANSPORT_FALLBACK_READY primary=tcp alternative=xhttp"
fi

client_xhttp_pq_port=$(jq -r '.clientXhttpPqPort' /run/xray-cascade-e2e-input.json)
if [ "$client_xhttp_pq_port" -gt 0 ]; then
	stage=xhttp-pq-client-config
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; client_pid=; fi
  pqsettings=$(jq -r '.obj[]|select(.remark=="lab-client-entry-xhttp-pq")|.settings' /run/xray-cascade-e2e-inbounds.json)
  pqstream=$(jq -r '.obj[]|select(.remark=="lab-client-entry-xhttp-pq")|.streamSettings' /run/xray-cascade-e2e-inbounds.json)
  pqclient_id=$(printf '%s' "$pqsettings" | jq -r '.clients[0].id')
  pqencryption=$(printf '%s' "$pqsettings" | jq -r '.encryption')
  pqdecryption=$(printf '%s' "$pqsettings" | jq -r '.decryption')
  pqpublic_key=$(printf '%s' "$pqstream" | jq -r '.realitySettings.settings.publicKey')
  pqserver_name=$(printf '%s' "$pqstream" | jq -r '.realitySettings.serverNames[0]')
  pqshort_id=$(printf '%s' "$pqstream" | jq -r '.realitySettings.shortIds[0]')
  pqpath=$(printf '%s' "$pqstream" | jq -r '.xhttpSettings.path')
  pqhost=$(printf '%s' "$pqstream" | jq -r '.xhttpSettings.host')
  pqmode=$(printf '%s' "$pqstream" | jq -r '.xhttpSettings.mode')
  test "$pqclient_id" = "$client_id"
  test "$(printf '%s' "$pqsettings" | jq -r '.clients[0].subId')" = "$(printf '%s' "$settings" | jq -r '.clients[0].subId')"
  case "$pqencryption" in mlkem768x25519plus.native.*) ;; *) exit 1;; esac
  case "$pqdecryption" in mlkem768x25519plus.native.*) ;; *) exit 1;; esac
  test "$pqmode" = auto
  case "$pqpath" in /*) ;; *) exit 1;; esac
  jq -n --arg id "$pqclient_id" --arg encryption "$pqencryption" --arg public "$pqpublic_key" --arg sni "$pqserver_name" --arg sid "$pqshort_id" --arg address "$entry_address" --arg path "$pqpath" --arg host "$pqhost" --arg mode "$pqmode" --argjson port "$client_xhttp_pq_port" '{log:{loglevel:"warning"},inbounds:[{tag:"e2e-xhttp-pq-socks",listen:"127.0.0.1",port:10813,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry-xhttp-pq",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:$encryption,flow:""}]}]},streamSettings:{network:"xhttp",security:"reality",xhttpSettings:{path:$path,host:$host,mode:$mode},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-e2e-xhttp-pq-client.json
  $bin run -test -config /run/xray-cascade-e2e-xhttp-pq-client.json >/dev/null
	stage=xhttp-pq-e2e
  $bin run -config /run/xray-cascade-e2e-xhttp-pq-client.json > /run/xray-cascade-e2e.log 2>&1 &
  client_pid=$!
  ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn|grep -q '127.0.0.1:10813'; then ready=true; break; fi; sleep 1; done
  test "$ready" = true
  http_code=$(probe_http 10813)
  test "$http_code" = 200
  echo "3XUI_CASCADE_XHTTP_PQ_E2E_READY http=$http_code"
fi

client_grpc_port=$(jq -r '.clientGrpcPort' /run/xray-cascade-e2e-input.json)
if [ "$client_grpc_port" -gt 0 ]; then
	stage=grpc-client-config
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; client_pid=; fi
  gsettings=$(jq -r '.obj[]|select(.remark=="lab-client-entry-grpc")|.settings' /run/xray-cascade-e2e-inbounds.json)
  gstream=$(jq -r '.obj[]|select(.remark=="lab-client-entry-grpc")|.streamSettings' /run/xray-cascade-e2e-inbounds.json)
  gclient_id=$(printf '%s' "$gsettings" | jq -r '.clients[0].id')
  gpublic_key=$(printf '%s' "$gstream" | jq -r '.realitySettings.settings.publicKey')
  gserver_name=$(printf '%s' "$gstream" | jq -r '.realitySettings.serverNames[0]')
  gshort_id=$(printf '%s' "$gstream" | jq -r '.realitySettings.shortIds[0]')
  gservice=$(printf '%s' "$gstream" | jq -r '.grpcSettings.serviceName')
  test "$gclient_id" = "$client_id"
  test "$(printf '%s' "$gsettings" | jq -r '.clients[0].subId')" = "$(printf '%s' "$settings" | jq -r '.clients[0].subId')"
  test -n "$gservice"
  jq -n --arg id "$gclient_id" --arg public "$gpublic_key" --arg sni "$gserver_name" --arg sid "$gshort_id" --arg address "$entry_address" --arg service "$gservice" --argjson port "$client_grpc_port" '{log:{loglevel:"warning"},inbounds:[{tag:"e2e-grpc-socks",listen:"127.0.0.1",port:10811,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry-grpc",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:""}]}]},streamSettings:{network:"grpc",security:"reality",grpcSettings:{serviceName:$service,authority:"",multiMode:false},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-e2e-grpc-client.json
  $bin run -test -config /run/xray-cascade-e2e-grpc-client.json >/dev/null
	stage=grpc-e2e
  $bin run -config /run/xray-cascade-e2e-grpc-client.json > /run/xray-cascade-e2e.log 2>&1 &
  client_pid=$!
  ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn|grep -q '127.0.0.1:10811'; then ready=true; break; fi; sleep 1; done
  test "$ready" = true
  http_code=$(probe_http 10811)
  test "$http_code" = 200
  echo "3XUI_CASCADE_GRPC_E2E_READY http=$http_code"
fi

hysteria2_port=$(jq -r '.hysteria2Port' /run/xray-cascade-e2e-input.json)
if [ "$hysteria2_port" -gt 0 ]; then
	stage=hysteria2-client-config
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; client_pid=; fi
  hsettings=$(jq -r '.obj[]|select(.remark=="lab-client-entry-hysteria2")|.settings' /run/xray-cascade-e2e-inbounds.json)
  hstream=$(jq -r '.obj[]|select(.remark=="lab-client-entry-hysteria2")|.streamSettings' /run/xray-cascade-e2e-inbounds.json)
  hauth=$(printf '%s' "$hsettings" | jq -r '.clients[0].auth')
  hsni=$(printf '%s' "$hstream" | jq -r '.tlsSettings.serverName')
	hpin=$(printf '%s' "$hstream" | jq -r '.tlsSettings.settings.pinnedPeerCertSha256[0]')
  test -n "$hauth"
	test "${#hpin}" -eq 64
  test "$(printf '%s' "$hsettings" | jq -r '.clients[0].subId')" = "$(printf '%s' "$settings" | jq -r '.clients[0].subId')"
	jq -n --arg auth "$hauth" --arg sni "$hsni" --arg pin "$hpin" --arg address "$entry_address" --argjson port "$hysteria2_port" '{log:{loglevel:"warning"},inbounds:[{tag:"e2e-hysteria2-socks",listen:"127.0.0.1",port:10812,protocol:"socks",settings:{udp:true}}],outbounds:[{tag:"entry-hysteria2",protocol:"hysteria",settings:{address:$address,port:$port,version:2},streamSettings:{network:"hysteria",security:"tls",hysteriaSettings:{version:2,auth:$auth,udpIdleTimeout:60},tlsSettings:{serverName:$sni,alpn:["h3"],pinnedPeerCertSha256:$pin}}}]}' > /run/xray-cascade-e2e-hysteria2-client.json
  $bin run -test -config /run/xray-cascade-e2e-hysteria2-client.json >/dev/null
	stage=hysteria2-e2e
  $bin run -config /run/xray-cascade-e2e-hysteria2-client.json > /run/xray-cascade-e2e.log 2>&1 &
  client_pid=$!
  ready=false
  for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn|grep -q '127.0.0.1:10812'; then ready=true; break; fi; sleep 1; done
  test "$ready" = true
  http_code=$(probe_http 10812)
  test "$http_code" = 200
  echo "3XUI_CASCADE_HYSTERIA2_E2E_READY http=$http_code"
fi
echo "3XUI_CASCADE_E2E_READY http=$http_code"

expected_routing_sha=$(jq -r '.happRoutingSHA' /run/xray-cascade-e2e-input.json)
if [ -n "$expected_routing_sha" ]; then
	stage=subscription
  curl --fail-with-body -sS -H @/run/xray-cascade-e2e-header -X POST http://127.0.0.1:2053/entry/panel/api/setting/all > /run/xray-cascade-e2e-settings.json
  jq -e '.success==true and .obj.subEnable==true and .obj.subEnableRouting==true and .obj.subHappAutoDetect==true' /run/xray-cascade-e2e-settings.json >/dev/null
  sub_path=$(jq -r '.obj.subPath' /run/xray-cascade-e2e-settings.json)
  sub_id=$(printf '%s' "$settings" | jq -r '.clients[0].subId')
  subscription_scheme=http
  subscription_tls_args=
  if [ "$(jq -r '.subscriptionTLS' /run/xray-cascade-e2e-input.json)" != pending ]; then
    subscription_scheme=https
    subscription_tls_args=-k
  fi
  subscription_code=$(curl --fail -sS --max-time 20 $subscription_tls_args -A 'Happ/4.0' -D /run/xray-cascade-e2e-sub-headers -o /run/xray-cascade-e2e-sub-body -w '%{http_code}' "${subscription_scheme}://127.0.0.1:2096${sub_path}${sub_id}")
  routing_enabled=$(awk -F': ' 'tolower($1)=="routing-enable" {gsub("\r", "", $2); print tolower($2)}' /run/xray-cascade-e2e-sub-headers | tail -n 1)
  routing_header=$(awk -F': ' 'tolower($1)=="routing" {sub(/^[^:]*: /, ""); sub(/\r$/, ""); print}' /run/xray-cascade-e2e-sub-headers | tail -n 1)
  actual_routing_sha=$(printf '%s\n' "$routing_header" | sha256sum | awk '{print $1}')
  routing_present=false
  checksum_match=false
  if [ -n "$routing_header" ]; then routing_present=true; fi
  if [ "$actual_routing_sha" = "$expected_routing_sha" ]; then checksum_match=true; fi
  if [ "$subscription_code" != 200 ] || [ "$routing_enabled" != true ] || [ "$checksum_match" != true ]; then
    echo "3XUI_ROSCOMVPN_SUBSCRIPTION_FAILED http=$subscription_code routing_enable=${routing_enabled:-missing} routing_present=$routing_present checksum_match=$checksum_match" >&2
    exit 1
  fi
  if [ "$client_xhttp_port" -gt 0 ]; then
    if base64 -d /run/xray-cascade-e2e-sub-body > /run/xray-cascade-e2e-sub-links 2>/dev/null; then :; else cp /run/xray-cascade-e2e-sub-body /run/xray-cascade-e2e-sub-links; fi
    tcp_links=$(grep -c 'type=tcp' /run/xray-cascade-e2e-sub-links || true)
    xhttp_links=$(grep -c 'type=xhttp' /run/xray-cascade-e2e-sub-links || true)
    if [ "$tcp_links" -lt 1 ] || [ "$xhttp_links" -lt 1 ]; then
      echo "3XUI_MULTI_TRANSPORT_SUBSCRIPTION_FAILED tcp=$tcp_links xhttp=$xhttp_links" >&2
      exit 1
    fi
    echo "3XUI_MULTI_TRANSPORT_SUBSCRIPTION_READY tcp=$tcp_links xhttp=$xhttp_links"
  fi
  if [ "$client_xhttp_pq_port" -gt 0 ]; then
    test -s /run/xray-cascade-e2e-sub-links || { if base64 -d /run/xray-cascade-e2e-sub-body > /run/xray-cascade-e2e-sub-links 2>/dev/null; then :; else cp /run/xray-cascade-e2e-sub-body /run/xray-cascade-e2e-sub-links; fi; }
    xhttp_pq_links=$(grep 'type=xhttp' /run/xray-cascade-e2e-sub-links | grep -c 'encryption=mlkem768x25519plus' || true)
    if [ "$xhttp_pq_links" -lt 1 ]; then
      echo "3XUI_XHTTP_PQ_SUBSCRIPTION_FAILED xhttp_pq=$xhttp_pq_links" >&2
      exit 1
    fi
    echo "3XUI_XHTTP_PQ_SUBSCRIPTION_READY xhttp_pq=$xhttp_pq_links"
  fi
  if [ "$client_grpc_port" -gt 0 ]; then
    test -s /run/xray-cascade-e2e-sub-links || { if base64 -d /run/xray-cascade-e2e-sub-body > /run/xray-cascade-e2e-sub-links 2>/dev/null; then :; else cp /run/xray-cascade-e2e-sub-body /run/xray-cascade-e2e-sub-links; fi; }
    grpc_links=$(grep -c 'type=grpc' /run/xray-cascade-e2e-sub-links || true)
    if [ "$grpc_links" -lt 1 ]; then
      echo "3XUI_GRPC_SUBSCRIPTION_FAILED grpc=$grpc_links" >&2
      exit 1
    fi
    echo "3XUI_GRPC_SUBSCRIPTION_READY grpc=$grpc_links"
  fi
  if [ "$hysteria2_port" -gt 0 ]; then
    test -s /run/xray-cascade-e2e-sub-links || { if base64 -d /run/xray-cascade-e2e-sub-body > /run/xray-cascade-e2e-sub-links 2>/dev/null; then :; else cp /run/xray-cascade-e2e-sub-body /run/xray-cascade-e2e-sub-links; fi; }
    hysteria2_links=$(grep -c '^hysteria2://' /run/xray-cascade-e2e-sub-links || true)
    if [ "$hysteria2_links" -lt 1 ]; then
      echo "3XUI_HYSTERIA2_SUBSCRIPTION_FAILED hysteria2=$hysteria2_links" >&2
      exit 1
    fi
    echo "3XUI_HYSTERIA2_SUBSCRIPTION_READY hysteria2=$hysteria2_links"
  fi
  echo "3XUI_ROSCOMVPN_SUBSCRIPTION_READY http=$subscription_code checksum=verified"
fi
`, nil
}

// FailoverE2EScript proves the IPv4-primary policy at the network boundary.
// It rejects only the managed interserver destination/port, verifies IPv6
// fallback, then rejects both paths to prove that Xray fails closed instead of
// leaking client traffic through a direct outbound.
func FailoverE2EScript(inv inventory.Inventory) (string, error) {
	if inv.Transport.PreferInterserver != "ipv4" {
		return "", errors.New("failover E2E requires prefer_interserver: ipv4")
	}
	exitIPv4, err := netip.ParseAddr(inv.Exit.CascadeAddress)
	if err != nil || !exitIPv4.Is4() || !exitIPv4.IsPrivate() {
		return "", errors.New("failover E2E requires a private exit cascade IPv4 address")
	}
	exitIPv6, err := netip.ParseAddr(inv.Exit.PublicIPv6)
	if err != nil || !exitIPv6.Is6() || !exitIPv6.IsPrivate() {
		return "", errors.New("failover E2E requires a private exit IPv6 address")
	}
	raw, err := json.Marshal(map[string]any{
		"entryAddress":         inv.Entry.CascadeAddress,
		"clientPort":           inv.Transport.ClientPort,
		"interserverPort":      inv.Transport.InterserverPort,
		"interserverXhttpPort": inv.InterserverAlternativePort("reality-xhttp"),
		"exitIPv4":             exitIPv4.String(),
		"exitIPv6":             exitIPv6.String(),
	})
	if err != nil {
		return "", fmt.Errorf("encode failover E2E input: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(raw)
	return `set -eu
umask 077
cd /usr/local/x-ui
printf '%s' '` + payload + `' | base64 -d > /run/xray-cascade-failover-input.json
token_name=xray-cascade-failover
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %s\n' "$token" > /run/xray-cascade-failover-header
unset token
client_pid=
v4_blocked=false
v6_blocked=false
exit_v4=$(jq -r '.exitIPv4' /run/xray-cascade-failover-input.json)
exit_v6=$(jq -r '.exitIPv6' /run/xray-cascade-failover-input.json)
hop_port=$(jq -r '.interserverPort' /run/xray-cascade-failover-input.json)
xhttp_hop_port=$(jq -r '.interserverXhttpPort' /run/xray-cascade-failover-input.json)
delete_test_token() {
  test -s /run/xray-cascade-failover-header || return 0
  curl --fail-with-body -sS -H @/run/xray-cascade-failover-header -X GET http://127.0.0.1:2053/entry/panel/api/setting/apiTokens > /run/xray-cascade-failover-tokens.json
  token_id=$(jq -r --arg name "$token_name" '.obj[]?|select(.name==$name)|.id' /run/xray-cascade-failover-tokens.json | head -n 1)
  test -n "$token_id"
  printf '{"expectedScope":"admin"}' > /run/xray-cascade-failover-delete-request.json
  curl --fail-with-body -sS -H @/run/xray-cascade-failover-header -H 'Content-Type: application/json' -X POST --data @/run/xray-cascade-failover-delete-request.json "http://127.0.0.1:2053/entry/panel/api/setting/apiTokens/delete/$token_id" > /run/xray-cascade-failover-delete.json
  jq -e '.success==true' /run/xray-cascade-failover-delete.json >/dev/null
  rm -f /run/xray-cascade-failover-header /run/xray-cascade-failover-tokens.json /run/xray-cascade-failover-delete-request.json /run/xray-cascade-failover-delete.json
}
cleanup() {
  status=$?
  if [ "$v4_blocked" = true ]; then iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT 2>/dev/null || true; fi
  if [ "$v6_blocked" = true ]; then ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT 2>/dev/null || true; fi
  if [ "$xhttp_hop_port" -gt 0 ]; then
    iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$xhttp_hop_port" -j REJECT 2>/dev/null || true
    ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$xhttp_hop_port" -j REJECT 2>/dev/null || true
  fi
  if [ -n "$client_pid" ]; then kill "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true; fi
  delete_test_token >/dev/null 2>&1 || true
  rm -f /run/xray-cascade-failover-*.json /run/xray-cascade-failover-header /run/xray-cascade-failover.log /run/xray-cascade-failover-trace
  exit "$status"
}
trap cleanup EXIT INT TERM
command -v iptables >/dev/null
command -v ip6tables >/dev/null
ip route get "$exit_v4" >/dev/null
ip -6 route get "$exit_v6" >/dev/null

curl --fail-with-body -sS -H @/run/xray-cascade-failover-header http://127.0.0.1:2053/entry/panel/api/server/getConfigJson > /run/xray-cascade-failover-runtime.json
jq -e --arg v6 "$exit_v6" --argjson xhttpPort "$xhttp_hop_port" '
  .success==true
  and (.obj.outbounds|any(.tag=="cascade-exit-ipv4"))
  and (.obj.outbounds|any(.tag=="cascade-exit-ipv6" and .settings.address==$v6))
  and ($xhttpPort==0 or (.obj.outbounds|any(.tag=="cascade-exit-xhttp-ipv4" and .settings.port==$xhttpPort and .streamSettings.network=="xhttp")))
  and ($xhttpPort==0 or (.obj.outbounds|any(.tag=="cascade-exit-xhttp-ipv6" and .settings.address==$v6 and .settings.port==$xhttpPort and .streamSettings.network=="xhttp")))
  and (.obj.routing.balancers|any(.tag=="cascade-exit" and (($xhttpPort==0 and .selector==["cascade-exit-ipv4"] and .fallbackTag=="cascade-exit-ipv6") or ($xhttpPort>0 and (.selector|length)==4 and .strategy.type=="leastPing" and .fallbackTag=="blocked"))))
  and .obj.observatory.probeInterval=="2s"
' /run/xray-cascade-failover-runtime.json >/dev/null

curl --fail-with-body -sS -H @/run/xray-cascade-failover-header http://127.0.0.1:2053/entry/panel/api/inbounds/list > /run/xray-cascade-failover-inbounds.json
settings=$(jq -r '.obj[]|select(.remark=="lab-client-entry")|.settings' /run/xray-cascade-failover-inbounds.json)
stream=$(jq -r '.obj[]|select(.remark=="lab-client-entry")|.streamSettings' /run/xray-cascade-failover-inbounds.json)
client_id=$(printf '%s' "$settings" | jq -r '.clients[0].id')
public_key=$(printf '%s' "$stream" | jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%s' "$stream" | jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%s' "$stream" | jq -r '.realitySettings.shortIds[0]')
entry_address=$(jq -r '.entryAddress' /run/xray-cascade-failover-input.json)
client_port=$(jq -r '.clientPort' /run/xray-cascade-failover-input.json)
jq -n --arg id "$client_id" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" --arg address "$entry_address" --argjson port "$client_port" '{log:{loglevel:"warning"},inbounds:[{tag:"failover-socks",listen:"127.0.0.1",port:10809,protocol:"socks",settings:{udp:false}}],outbounds:[{tag:"entry",protocol:"vless",settings:{vnext:[{address:$address,port:$port,users:[{id:$id,encryption:"none",flow:"xtls-rprx-vision"}]}]},streamSettings:{network:"tcp",security:"reality",realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}]}' > /run/xray-cascade-failover-client.json
bin=/usr/local/x-ui/bin/xray-linux-amd64
$bin run -test -config /run/xray-cascade-failover-client.json >/dev/null
$bin run -config /run/xray-cascade-failover-client.json > /run/xray-cascade-failover.log 2>&1 &
client_pid=$!
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10; do if ss -ltn | grep -q '127.0.0.1:10809'; then ready=true; break; fi; sleep 1; done
test "$ready" = true
probe() {
  rm -f /run/xray-cascade-failover-trace
  curl --fail -sS --max-time 5 --socks5-hostname 127.0.0.1:10809 -o /run/xray-cascade-failover-trace https://www.cloudflare.com/cdn-cgi/trace \
    && grep -q '^ip=' /run/xray-cascade-failover-trace
}
wait_success() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do if probe; then return 0; fi; sleep 1; done
  return 1
}

if [ "$xhttp_hop_port" -gt 0 ]; then
  # Kill both TCP address families: XHTTP must carry the cascade.
  iptables -I OUTPUT 1 -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT
  ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
  v4_blocked=true; v6_blocked=true
  wait_success
  echo 3XUI_FAILOVER_XHTTP_TRANSPORT_READY
  iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT
  ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
  v4_blocked=false; v6_blocked=false

  # Kill both XHTTP address families: the conservative TCP path must work.
  iptables -I OUTPUT 1 -d "$exit_v4" -p tcp --dport "$xhttp_hop_port" -j REJECT
  ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$xhttp_hop_port" -j REJECT
  wait_success
  echo 3XUI_FAILOVER_TCP_TRANSPORT_READY
  iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$xhttp_hop_port" -j REJECT
  ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$xhttp_hop_port" -j REJECT

  # Kill both IPv4 transports: either IPv6 transport must recover.
  iptables -I OUTPUT 1 -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT
  iptables -I OUTPUT 1 -d "$exit_v4" -p tcp --dport "$xhttp_hop_port" -j REJECT
  v4_blocked=true
  wait_success
  echo 3XUI_FAILOVER_IPV6_FALLBACK_READY

  # Kill both IPv6 transports as well: the cascade must fail closed.
  ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
  ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$xhttp_hop_port" -j REJECT
  v6_blocked=true
else
  ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
  v6_blocked=true
  wait_success
  echo 3XUI_FAILOVER_IPV4_PRIMARY_READY
  ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
  v6_blocked=false

  iptables -I OUTPUT 1 -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT
  v4_blocked=true
  wait_success
  echo 3XUI_FAILOVER_IPV6_FALLBACK_READY
  ip6tables -I OUTPUT 1 -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
  v6_blocked=true
fi
for _ in 1 2 3; do
  if probe; then echo 3XUI_FAILOVER_DIRECT_LEAK >&2; exit 1; fi
  sleep 1
done
echo 3XUI_FAILOVER_FAIL_CLOSED_READY

iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$hop_port" -j REJECT
v4_blocked=false
ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$hop_port" -j REJECT
v6_blocked=false
if [ "$xhttp_hop_port" -gt 0 ]; then
  iptables -D OUTPUT -d "$exit_v4" -p tcp --dport "$xhttp_hop_port" -j REJECT
  ip6tables -D OUTPUT -d "$exit_v6" -p tcp --dport "$xhttp_hop_port" -j REJECT
fi
wait_success
delete_test_token
echo 3XUI_FAILOVER_RECOVERY_READY
`, nil
}
