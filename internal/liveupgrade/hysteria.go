// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
)

// HysteriaOptions describes one additive Hysteria 2 client inbound on an
// existing entry. The primary VLESS inbound remains the source of the HAPP
// subscription identity; no existing inbound or interserver path is replaced.
type HysteriaOptions struct {
	PrimaryInboundTag string
	InboundTag        string
	Remark            string
	Port              int
	EntryAddress      string
	BalancerTag       string
	CertificateFile   string
	KeyFile           string
	PinCertificate    bool
	AllowPrivateEntry bool
}

func (o HysteriaOptions) validate() error {
	for name, value := range map[string]string{
		"primary inbound":  o.PrimaryInboundTag,
		"Hysteria inbound": o.InboundTag,
		"Hysteria remark":  o.Remark,
		"balancer":         o.BalancerTag,
	} {
		if !safeTag.MatchString(value) {
			return fmt.Errorf("%s tag is unsafe", name)
		}
	}
	if o.PrimaryInboundTag == o.InboundTag {
		return errors.New("Hysteria inbound tag must differ from the primary inbound tag")
	}
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("Hysteria port must be between 1 and 65535")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(o.EntryAddress))
	if err != nil || !address.IsGlobalUnicast() || (!o.AllowPrivateEntry && address.IsPrivate()) {
		return errors.New("Hysteria entry address must be a global unicast IP address")
	}
	for name, value := range map[string]string{"certificate": o.CertificateFile, "key": o.KeyFile} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("Hysteria %s path must be a clean absolute path", name)
		}
	}
	return nil
}

// HysteriaApplyScript adds one UDP+TLS Hysteria 2 inbound through the 3x-ui
// API and extends only the existing cascade catch-all rule with its tag.
func HysteriaApplyScript(panel Options, transport HysteriaOptions) (string, error) {
	if err := panel.validate(); err != nil {
		return "", err
	}
	if err := transport.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
umask 077
stage=init
work=$(mktemp -d /run/xray-cascade-hysteria-apply-XXXXXX)
cd /usr/local/x-ui
token_name=xray-cascade-hysteria-apply-$(openssl rand -hex 8)
token=$(./x-ui setting -tokenName "$token_name" -tokenScope admin -getApiToken | sed -n 's/^apiToken: //p' | tail -n 1)
test -n "$token"
printf 'Authorization: Bearer %%s\n' "$token" > "$work/header"
unset token
api=%[1]s://127.0.0.1:%[2]d%[3]sapi
delete_token() {
  test -s "$work/header" || return 0
  curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/setting/apiTokens" > "$work/tokens.json"
  token_id=$(jq -r --arg name "$token_name" '.obj[]?|select(.name==$name)|.id' "$work/tokens.json" | head -n 1)
  test -n "$token_id"
  printf '{"expectedScope":"admin"}' > "$work/delete-request.json"
  curl --fail-with-body -sS %[4]s -H @"$work/header" -H 'Content-Type: application/json' -X POST --data @"$work/delete-request.json" "$api/setting/apiTokens/delete/$token_id" > "$work/delete.json"
  jq -e '.success==true' "$work/delete.json" >/dev/null
  rm -f "$work/header"
}
cleanup() {
  status=$?
  delete_token >/dev/null 2>&1 || true
  rm -rf "$work"
  if [ "$status" -ne 0 ]; then echo "3XUI_LIVE_HYSTERIA_UPDATE_FAILED stage=$stage" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM

stage=validate-files
test -f %[10]q; test ! -L %[10]q
test -f %[11]q; test ! -L %[11]q
openssl x509 -in %[10]q -noout -checkend 3600 >/dev/null
openssl x509 -in %[10]q -pubkey -noout | openssl pkey -pubin -outform der | sha256sum | awk '{print $1}' > "$work/cert.pub"
openssl pkey -in %[11]q -pubout -outform der | sha256sum | awk '{print $1}' > "$work/key.pub"
cmp -s "$work/cert.pub" "$work/key.pub"

stage=list-inbounds
curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds.json"
jq -e '.success==true' "$work/inbounds.json" >/dev/null
stage=validate-primary
jq -e --arg primary %[5]q '
  def decoded: if type=="string" then fromjson else . end;
  ([.obj[]|select(.tag==$primary)]|length)==1
  and (.obj[]|select(.tag==$primary)|.protocol)=="vless"
  and ((.obj[]|select(.tag==$primary)|.settings|decoded|.clients)|length)==1
  and ((.obj[]|select(.tag==$primary)|.settings|decoded|.clients[0].subId//"")|length)>0
' "$work/inbounds.json" >/dev/null
existing=$(jq --arg tag %[6]q '[.obj[]|select(.tag==$tag)]|length' "$work/inbounds.json")
test "$existing" -le 1
if [ "$existing" -eq 0 ]; then
  stage=validate-port
  if ss -H -lun "sport = :%[8]d" | grep -q .; then echo 'Hysteria UDP port is already in use' >&2; exit 1; fi
  primary_settings=$(jq -r --arg primary %[5]q '.obj[]|select(.tag==$primary)|.settings' "$work/inbounds.json")
  primary_sniffing=$(jq -r --arg primary %[5]q '.obj[]|select(.tag==$primary)|.sniffing' "$work/inbounds.json")
  sub_id=$(printf '%%s' "$primary_settings" | jq -r '.clients[0].subId')
  email=$(printf '%%s' "$primary_settings" | jq -r '.clients[0].email//"client"')
  test -n "$sub_id"; test "$sub_id" != null
  auth=$(openssl rand -hex 24)
  settings=$(jq -nc --arg auth "$auth" --arg sub "$sub_id" --arg email "$email" '{version:2,clients:[{email:$email,auth:$auth,limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}]}')
  client_tls_settings='{}'
  if [ %[13]t = true ]; then
    pin=$(openssl x509 -in %[10]q -outform der | sha256sum | cut -d' ' -f1)
    test "${#pin}" -eq 64
    client_tls_settings=$(jq -nc --arg pin "$pin" '{pinnedPeerCertSha256:[$pin]}')
  fi
  stream=$(jq -nc --arg cert %[10]q --arg key %[11]q --arg sni %[9]q --argjson client "$client_tls_settings" '{network:"hysteria",security:"tls",hysteriaSettings:{version:2},tlsSettings:{serverName:$sni,alpn:["h3"],certificates:[{certificateFile:$cert,keyFile:$key}],settings:$client}}')
  jq -n --arg remark %[7]q --arg tag %[6]q --argjson port %[8]d --arg address %[9]q --arg settings "$settings" --arg stream "$stream" --arg sniffing "$primary_sniffing" '{enable:true,remark:$remark,excludeFromSub:false,subSortIndex:3,listen:"",port:$port,protocol:"hysteria",expiryTime:0,total:0,tag:$tag,shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > "$work/inbound.json"
  stage=add-inbound
  curl --fail-with-body -sS %[4]s -H @"$work/header" -H 'Content-Type: application/json' -X POST --data @"$work/inbound.json" "$api/inbounds/add" > "$work/add.json"
  jq -e '.success==true' "$work/add.json" >/dev/null
fi

stage=validate-inbound
curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds-after.json"
jq -e --arg tag %[6]q --arg remark %[7]q --arg primary %[5]q --argjson port %[8]d --arg address %[9]q --arg cert %[10]q --arg key %[11]q '
  def decoded: if type=="string" then fromjson else . end;
  ([.obj[]|select(.tag==$tag)]|length)==1
  and (.obj[]|select(.tag==$tag)|.remark)==$remark
  and (.obj[]|select(.tag==$tag)|.port)==$port
  and (.obj[]|select(.tag==$tag)|.protocol)=="hysteria"
  and (.obj[]|select(.tag==$tag)|.streamSettings|decoded|.network)=="hysteria"
  and (.obj[]|select(.tag==$tag)|.streamSettings|decoded|.security)=="tls"
  and (.obj[]|select(.tag==$tag)|.streamSettings|decoded|.tlsSettings.certificates[0].certificateFile)==$cert
  and (.obj[]|select(.tag==$tag)|.streamSettings|decoded|.tlsSettings.certificates[0].keyFile)==$key
  and (.obj[]|select(.tag==$tag)|.settings|decoded|.clients[0].subId)==(.obj[]|select(.tag==$primary)|.settings|decoded|.clients[0].subId)
  and (.obj[]|select(.tag==$tag)|.shareAddrStrategy)=="custom"
  and (.obj[]|select(.tag==$tag)|.shareAddr)==$address
' "$work/inbounds-after.json" >/dev/null

stage=read-template
curl --fail-with-body -sS %[4]s -H @"$work/header" -X POST "$api/xray/" > "$work/template-response.json"
jq -e '.success==true' "$work/template-response.json" >/dev/null
jq -r '.obj|fromjson|.xraySetting' "$work/template-response.json" > "$work/before.json"
jq -e --arg primary %[5]q --arg added %[6]q --arg bal %[12]q '(.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null)))|length)==1 and (.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($added)!=null)))|length)<=1' "$work/before.json" >/dev/null
stage=build-template
jq --arg primary %[5]q --arg added %[6]q --arg bal %[12]q '.routing.rules |= map(if .balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null) then .inboundTag=(((.inboundTag//[])+[$added])|unique) else . end)' "$work/before.json" > "$work/after.json"
stage=update-template
curl --fail-with-body -sS %[4]s -H @"$work/header" -X POST --data-urlencode xraySetting@"$work/after.json" "$api/xray/update" > "$work/update.json"
jq -e '.success==true' "$work/update.json" >/dev/null
stage=restart-xray
curl --fail-with-body -sS %[4]s -H @"$work/header" -X POST "$api/server/restartXrayService" > "$work/restart.json"
jq -e '.success==true' "$work/restart.json" >/dev/null
stage=verify-runtime
ready=false
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/server/getConfigJson" > "$work/runtime.json" 2>/dev/null \
    && jq -e --arg primary %[5]q --arg added %[6]q --arg bal %[12]q --argjson port %[8]d '.success==true and (.obj.inbounds|any(.tag==$added and .port==$port and .protocol=="hysteria" and .streamSettings.network=="hysteria" and .streamSettings.security=="tls")) and (.obj.routing.rules|any(.balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null) and ((.inboundTag//[])|index($added)!=null)))' "$work/runtime.json" >/dev/null; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
stage=delete-token
delete_token
echo 3XUI_LIVE_HYSTERIA_UPDATED
`, panel.Scheme, panel.Port, panel.BasePath, panel.CurlTLS,
		transport.PrimaryInboundTag, transport.InboundTag, transport.Remark,
		transport.Port, transport.EntryAddress, transport.CertificateFile,
		transport.KeyFile, transport.BalancerTag, transport.PinCertificate), nil
}
