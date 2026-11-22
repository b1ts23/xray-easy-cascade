// SPDX-License-Identifier: GPL-3.0-only

package liveupgrade

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// XHTTPOptions describes the single additional client transport adopted on an
// existing entry. The primary TCP inbound remains untouched and supplies the
// client identity, subscription identity, REALITY target, and SNI set.
type XHTTPOptions struct {
	PrimaryInboundTag string
	PrimaryPort       int
	InboundTag        string
	Remark            string
	Port              int
	EntryAddress      string
	BalancerTag       string
	AllowPrivateEntry bool
}

func (o XHTTPOptions) validate() error {
	for name, value := range map[string]string{
		"primary inbound": o.PrimaryInboundTag,
		"XHTTP inbound":   o.InboundTag,
		"XHTTP remark":    o.Remark,
		"balancer":        o.BalancerTag,
	} {
		if !safeTag.MatchString(value) {
			return fmt.Errorf("%s tag is unsafe", name)
		}
	}
	if o.PrimaryInboundTag == o.InboundTag {
		return errors.New("XHTTP inbound tag must differ from the primary inbound tag")
	}
	if o.PrimaryPort < 1 || o.PrimaryPort > 65535 {
		return errors.New("primary client port must be between 1 and 65535")
	}
	if o.Port < 1 || o.Port > 65535 {
		return errors.New("XHTTP port must be between 1 and 65535")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(o.EntryAddress))
	if err != nil || !address.IsGlobalUnicast() || (!o.AllowPrivateEntry && address.IsPrivate()) {
		return errors.New("XHTTP entry address must be a global unicast IP address")
	}
	return nil
}

// XHTTPApplyScript adds one VLESS + REALITY + XHTTP inbound through the
// official 3x-ui API and extends only the existing client catch-all rule with
// its tag. It deliberately does not touch the primary TCP inbound, panel,
// certificates, firewall, SSH, outbounds, balancer, or observatory.
func XHTTPApplyScript(panel Options, transport XHTTPOptions) (string, error) {
	if err := panel.validate(); err != nil {
		return "", err
	}
	if err := transport.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`set -eu
umask 077
stage=init
work=$(mktemp -d /run/xray-cascade-xhttp-apply-XXXXXX)
cd /usr/local/x-ui
token_name=xray-cascade-xhttp-apply-$(openssl rand -hex 8)
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
  if [ "$status" -ne 0 ]; then echo "3XUI_LIVE_XHTTP_UPDATE_FAILED stage=$stage" >&2; fi
  exit "$status"
}
trap cleanup EXIT INT TERM

stage=list-inbounds
curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds.json"
jq -e '.success==true' "$work/inbounds.json" >/dev/null
stage=validate-primary
if ! jq -e --arg primary %[5]q '
  def decoded: if type=="string" then fromjson else . end;
  ([.obj[]|select(.tag==$primary)]|length)==1
  and (.obj[]|select(.tag==$primary)|.protocol)=="vless"
  and ((.obj[]|select(.tag==$primary)|.settings|decoded|.clients)|length)==1
  and ((.obj[]|select(.tag==$primary)|.settings|decoded|.clients[0].id//"")|length)>0
  and ((.obj[]|select(.tag==$primary)|.settings|decoded|.clients[0].subId//"")|length)>0
' "$work/inbounds.json" >/dev/null; then
  tags=$(jq -r '[.obj[].tag]|join(",")' "$work/inbounds.json")
  matches=$(jq --arg primary %[5]q '[.obj[]|select(.tag==$primary)]|length' "$work/inbounds.json")
  clients=$(jq --arg primary %[5]q 'def decoded: if type=="string" then fromjson else . end; [.obj[]|select(.tag==$primary)|(.settings|decoded|.clients|length)]|if length==0 then 0 else .[0] end' "$work/inbounds.json")
  subid=$(jq -r --arg primary %[5]q 'def decoded: if type=="string" then fromjson else . end; [.obj[]|select(.tag==$primary)|((.settings|decoded|.clients[0].subId//"")|length>0)]|if length==0 then false else .[0] end' "$work/inbounds.json")
  echo "3XUI_LIVE_XHTTP_PRIMARY_INVALID tags=$tags matches=$matches clients=$clients subid=$subid" >&2
  exit 1
fi
stage=count-existing
existing=$(jq --arg tag %[6]q '[.obj[]|select(.tag==$tag)]|length' "$work/inbounds.json")
test "$existing" -le 1

if [ "$existing" -eq 0 ]; then
  stage=validate-port
  if ss -H -lnt "sport = :%[8]d" | grep -q .; then echo 'XHTTP port is already in use' >&2; exit 1; fi
  stage=build-inbound
  primary_settings=$(jq -r --arg primary %[5]q '.obj[]|select(.tag==$primary)|.settings' "$work/inbounds.json")
  primary_stream=$(jq -r --arg primary %[5]q '.obj[]|select(.tag==$primary)|.streamSettings' "$work/inbounds.json")
  primary_sniffing=$(jq -r --arg primary %[5]q '.obj[]|select(.tag==$primary)|.sniffing' "$work/inbounds.json")
  settings=$(printf '%%s' "$primary_settings" | jq -c '.clients=[(.clients[0]|.flow="")] | .decryption="none" | .encryption="none" | .fallbacks=[]')
  target=$(printf '%%s' "$primary_stream" | jq -r '.realitySettings.target')
  server_names=$(printf '%%s' "$primary_stream" | jq -c '.realitySettings.serverNames')
  server_name=$(printf '%%s' "$server_names" | jq -r '.[0]')
  test -n "$target"; test "$target" != null
  test -n "$server_name"; test "$server_name" != null
  curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/server/getNewX25519Cert" > "$work/x25519.json"
  private_key=$(jq -r '.obj.privateKey' "$work/x25519.json")
  public_key=$(jq -r '.obj.publicKey' "$work/x25519.json")
  test -n "$private_key"; test "$private_key" != null
  test -n "$public_key"; test "$public_key" != null
  short_id=$(openssl rand -hex 8)
  xhttp_path="/$(openssl rand -hex 8)"
  stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" --arg target "$target" --argjson names "$server_names" --arg sni "$server_name" --arg path "$xhttp_path" '{network:"xhttp",xhttpSettings:{path:$path,host:$sni,mode:"auto"},security:"reality",realitySettings:{show:false,xver:0,target:$target,serverNames:$names,privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
  jq -n --arg remark %[7]q --arg tag %[6]q --argjson port %[8]d --arg address %[9]q --arg settings "$settings" --arg stream "$stream" --arg sniffing "$primary_sniffing" '{enable:true,remark:$remark,excludeFromSub:false,subSortIndex:2,listen:"",port:$port,protocol:"vless",expiryTime:0,total:0,tag:$tag,shareAddrStrategy:"custom",shareAddr:$address,settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > "$work/inbound.json"
  stage=add-inbound
  curl --fail-with-body -sS %[4]s -H @"$work/header" -H 'Content-Type: application/json' -X POST --data @"$work/inbound.json" "$api/inbounds/add" > "$work/add.json"
  jq -e '.success==true' "$work/add.json" >/dev/null
fi

stage=validate-inbound
curl --fail-with-body -sS %[4]s -H @"$work/header" "$api/inbounds/list" > "$work/inbounds-after.json"
if ! jq -e --arg tag %[6]q --arg remark %[7]q --arg primary %[5]q --argjson port %[8]d --arg address %[9]q '
  def decoded: if type=="string" then fromjson else . end;
  ([.obj[]|select(.tag==$tag)]|length)==1
  and (.obj[]|select(.tag==$tag)|.remark)==$remark
  and (.obj[]|select(.tag==$tag)|.port)==$port
  and (.obj[]|select(.tag==$tag)|.protocol)=="vless"
  and (.obj[]|select(.tag==$tag)|.streamSettings|decoded|.network)=="xhttp"
  and (.obj[]|select(.tag==$tag)|.streamSettings|decoded|.security)=="reality"
  and ((.obj[]|select(.tag==$tag)|.settings|decoded|.clients[0].flow)//"")==""
  and (.obj[]|select(.tag==$tag)|.settings|decoded|.clients[0].id)==(.obj[]|select(.tag==$primary)|.settings|decoded|.clients[0].id)
  and (.obj[]|select(.tag==$tag)|.settings|decoded|.clients[0].subId)==(.obj[]|select(.tag==$primary)|.settings|decoded|.clients[0].subId)
  and (.obj[]|select(.tag==$tag)|.shareAddrStrategy)=="custom"
  and (.obj[]|select(.tag==$tag)|.shareAddr)==$address
' "$work/inbounds-after.json" >/dev/null; then
  jq -r --arg tag %[6]q --arg primary %[5]q 'def decoded: if type=="string" then fromjson else . end; ([.obj[]|select(.tag==$tag)]|first) as $x | ([.obj[]|select(.tag==$primary)]|first) as $p | "3XUI_LIVE_XHTTP_INBOUND_INVALID matches="+([.obj[]|select(.tag==$tag)]|length|tostring)+" port="+(($x.port//0)|tostring)+" protocol="+($x.protocol//"missing")+" network="+(($x.streamSettings|decoded|.network)//"missing")+" security="+(($x.streamSettings|decoded|.security)//"missing")+" flow="+(($x.settings|decoded|.clients[0].flow)//"missing")+" sameid="+((($x.settings|decoded|.clients[0].id)==($p.settings|decoded|.clients[0].id))|tostring)+" samesub="+((($x.settings|decoded|.clients[0].subId)==($p.settings|decoded|.clients[0].subId))|tostring)+" strategy="+($x.shareAddrStrategy//"missing")' "$work/inbounds-after.json" >&2
  exit 1
fi

stage=read-template
curl --fail-with-body -sS %[4]s -H @"$work/header" -X POST "$api/xray/" > "$work/template-response.json"
jq -e '.success==true' "$work/template-response.json" >/dev/null
jq -r '.obj|fromjson|.xraySetting' "$work/template-response.json" > "$work/before.json"
jq -e --arg primary %[5]q --arg added %[6]q --arg bal %[10]q '
  (.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null)))|length)==1
  and (.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($added)!=null)))|length)<=1
' "$work/before.json" >/dev/null
stage=build-template
jq --arg primary %[5]q --arg added %[6]q --arg bal %[10]q '
  .routing.rules |= map(if .balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null) then .inboundTag=(((.inboundTag//[])+[$added])|unique) else . end)
' "$work/before.json" > "$work/after.json"
jq -e --arg primary %[5]q --arg added %[6]q --arg bal %[10]q '
  (.routing.rules|map(select(.balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null) and ((.inboundTag//[])|index($added)!=null)))|length)==1
' "$work/after.json" >/dev/null
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
    && jq -e --arg primary %[5]q --arg added %[6]q --arg bal %[10]q --argjson port %[8]d '
      .success==true
      and (.obj.inbounds|any(.tag==$added and .port==$port and .protocol=="vless" and .streamSettings.network=="xhttp" and .streamSettings.security=="reality"))
      and (.obj.routing.rules|any(.balancerTag==$bal and ((.inboundTag//[])|index($primary)!=null) and ((.inboundTag//[])|index($added)!=null)))
    ' "$work/runtime.json" >/dev/null; then ready=true; break; fi
  sleep 1
done
test "$ready" = true
stage=delete-token
delete_token
echo 3XUI_LIVE_XHTTP_UPDATED
`, panel.Scheme, panel.Port, panel.BasePath, panel.CurlTLS,
		transport.PrimaryInboundTag, transport.InboundTag, transport.Remark,
		transport.Port, transport.EntryAddress, transport.BalancerTag), nil
}
