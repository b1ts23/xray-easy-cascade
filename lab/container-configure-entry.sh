#!/bin/sh
set -eu
umask 077
stage=init
trap 'status=$?; if [ "$status" -ne 0 ]; then echo "3XUI_ENTRY_CONFIG_FAILED stage=$stage" >&2; fi' EXIT
token=$(cat /run/lab-api-token)
printf 'Authorization: Bearer %s\n' "$token" > /run/lab-api-header
unset token
api=http://127.0.0.1:2053/entry/panel/api

api_json() {
  method=$1 path=$2 output=$3 data=${4:-}
  if [ -n "$data" ]; then
    curl --fail-with-body -sS -H @/run/lab-api-header -H 'Content-Type: application/json' -X "$method" --data @"$data" "$api$path" > "$output"
  else
    curl --fail-with-body -sS -H @/run/lab-api-header -X "$method" "$api$path" > "$output"
  fi
  if ! jq -e '.success == true' "$output" >/dev/null; then
    jq -c '{success, msg}' "$output" >&2
    return 1
  fi
}

stage=nodes
api_json GET /nodes/list /run/nodes.json
node_id=$(jq -r '.obj[]? | select(.name == "lab-exit") | .id' /run/nodes.json | head -n 1)
test -n "$node_id"
stage=list-inbounds
api_json GET /inbounds/list /run/inbounds.json

if ! jq -e '.obj[]? | select(.remark == "lab-cascade-exit")' /run/inbounds.json >/dev/null; then
  stage=create-exit-inbound
  api_json GET /server/getNewUUID /run/uuid.json
  api_json GET /server/getNewX25519Cert /run/x25519.json
  uuid=$(jq -r '.obj.uuid' /run/uuid.json)
  private_key=$(jq -r '.obj.privateKey' /run/x25519.json)
  public_key=$(jq -r '.obj.publicKey' /run/x25519.json)
  short_id=$(openssl rand -hex 8)
  settings=$(jq -nc --arg id "$uuid" '{clients:[{id:$id,email:"cascade-hop",flow:"xtls-rprx-vision",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:"cascade-hop",comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
  stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" '{network:"tcp",tcpSettings:{header:{type:"none"}},security:"reality",realitySettings:{show:false,xver:0,target:"www.microsoft.com:443",serverNames:["www.microsoft.com"],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
  sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
  jq -n --argjson node "$node_id" --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:"lab-cascade-exit",excludeFromSub:true,listen:"",port:11443,protocol:"vless",expiryTime:0,total:0,tag:"in-cascade-exit",nodeId:$node,shareAddrStrategy:"node",settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/inbound.json
  api_json POST /inbounds/add /run/inbound-response.json /run/inbound.json
fi

stage=refresh-inbounds
api_json GET /inbounds/list /run/inbounds.json
if ! jq -e '.obj[]? | select(.remark == "lab-client-entry")' /run/inbounds.json >/dev/null; then
  stage=create-entry-inbound
  api_json GET /server/getNewUUID /run/uuid.json
  api_json GET /server/getNewX25519Cert /run/x25519.json
  uuid=$(jq -r '.obj.uuid' /run/uuid.json)
  private_key=$(jq -r '.obj.privateKey' /run/x25519.json)
  public_key=$(jq -r '.obj.publicKey' /run/x25519.json)
  short_id=$(openssl rand -hex 8)
  sub_id=$(openssl rand -hex 8)
  settings=$(jq -nc --arg id "$uuid" --arg sub "$sub_id" '{clients:[{id:$id,email:"lab-client",flow:"xtls-rprx-vision",limitIp:0,totalGB:0,expiryTime:0,enable:true,tgId:0,subId:$sub,comment:"",reset:0}],decryption:"none",encryption:"none",fallbacks:[]}')
  stream=$(jq -nc --arg private "$private_key" --arg public "$public_key" --arg sid "$short_id" '{network:"tcp",tcpSettings:{header:{type:"none"}},security:"reality",realitySettings:{show:false,xver:0,target:"www.microsoft.com:443",serverNames:["www.microsoft.com"],privateKey:$private,minClientVer:"",maxClientVer:"",maxTimediff:0,shortIds:[$sid],mldsa65Seed:"",settings:{publicKey:$public,fingerprint:"chrome",serverName:"",spiderX:"/",mldsa65Verify:""}}}')
  sniffing='{"enabled":true,"destOverride":["http","tls","quic"],"metadataOnly":false,"routeOnly":true,"ipsExcluded":[],"domainsExcluded":[]}'
  jq -n --arg settings "$settings" --arg stream "$stream" --arg sniffing "$sniffing" '{enable:true,remark:"lab-client-entry",excludeFromSub:false,listen:"",port:10443,protocol:"vless",expiryTime:0,total:0,tag:"in-client-entry",shareAddrStrategy:"custom",shareAddr:"172.29.10.10",settings:$settings,streamSettings:$stream,sniffing:$sniffing}' > /run/inbound.json
  api_json POST /inbounds/add /run/inbound-response.json /run/inbound.json
fi

stage=read-inbounds
api_json GET /inbounds/list /run/inbounds.json
exit_settings=$(jq -r '.obj[] | select(.remark == "lab-cascade-exit") | .settings' /run/inbounds.json)
exit_stream=$(jq -r '.obj[] | select(.remark == "lab-cascade-exit") | .streamSettings' /run/inbounds.json)
hop_id=$(printf '%s' "$exit_settings" | jq -r '.clients[0].id')
public_key=$(printf '%s' "$exit_stream" | jq -r '.realitySettings.settings.publicKey')
server_name=$(printf '%s' "$exit_stream" | jq -r '.realitySettings.serverNames[0]')
short_id=$(printf '%s' "$exit_stream" | jq -r '.realitySettings.shortIds[0]')
outbound=$(jq -nc --arg id "$hop_id" --arg public "$public_key" --arg sni "$server_name" --arg sid "$short_id" '{tag:"cascade-exit",protocol:"vless",settings:{address:"172.29.10.11",port:11443,id:$id,encryption:"none",flow:"xtls-rprx-vision"},streamSettings:{network:"tcp",security:"reality",tcpSettings:{header:{type:"none"}},realitySettings:{serverName:$sni,fingerprint:"chrome",publicKey:$public,shortId:$sid,spiderX:"/"}}}')

stage=read-template
api_json POST /xray/ /run/template-response.json
jq -r '.obj | fromjson | .xraySetting' /run/template-response.json > /run/template.json
jq --argjson outbound "$outbound" '.outbounds=([.outbounds[]|select(.tag!="cascade-exit")]+[$outbound])|.routing.rules=([.routing.rules[]|select(.outboundTag!="cascade-exit")]+[{type:"field",network:"tcp,udp",outboundTag:"cascade-exit"}])' /run/template.json > /run/updated.json
stage=update-template
curl --fail-with-body -sS -H @/run/lab-api-header -X POST --data-urlencode xraySetting@/run/updated.json "$api/xray/update" > /run/update-response.json
jq -e '.success == true' /run/update-response.json >/dev/null
stage=restart-xray
api_json POST /server/restartXrayService /run/restart.json
stage=verify-runtime
api_json GET /server/getConfigJson /run/runtime.json
jq -e '(.obj.inbounds|any(.tag=="in-client-entry")) and (.obj.outbounds|any(.tag=="cascade-exit")) and (.obj.routing.rules|any(.outboundTag=="cascade-exit"))' /run/runtime.json >/dev/null
echo 3XUI_ENTRY_CONFIG_READY
trap - EXIT
rm -f /run/lab-api-token /run/lab-api-header /run/container-configure-entry.sh /run/*.json
