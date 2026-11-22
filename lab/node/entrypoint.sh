#!/usr/bin/env bash
set -Eeuo pipefail

test -s /run/secrets/authorized_keys
install -d -m 0700 /root/.ssh /run/sshd
install -m 0600 /run/secrets/authorized_keys /root/.ssh/authorized_keys
ssh-keygen -A
cd /usr/local/x-ui

if [[ ! -s /etc/x-ui/x-ui.db ]]; then
  umask 077
  panel_user="lab-$(openssl rand -hex 6)"
  panel_password="$(openssl rand -base64 36 | tr -d '\n')"
  printf 'username=%s\npassword=%s\n' "$panel_user" "$panel_password" > /etc/x-ui/lab-credentials
  ./x-ui setting \
    -username "$panel_user" \
    -password "$panel_password" \
    -port 2053 \
    -webBasePath "${XUI_INIT_WEB_BASE_PATH:-/}" \
    -listenIP 0.0.0.0 >/dev/null
fi

if [[ "${XUI_LAB_ROLE:-entry}" == "entry" ]]; then
  if [[ -s /etc/x-ui/exit-node-ca.crt ]]; then
    install -m 0644 /etc/x-ui/exit-node-ca.crt /usr/local/share/ca-certificates/xray-cascade-exit.crt
    update-ca-certificates >/dev/null
  fi
  if [[ ! -s /etc/x-ui/subscription.crt || ! -s /etc/x-ui/subscription.key ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
      -subj '/CN=cascade-entry-subscription' \
      -addext "subjectAltName=IP:${XUI_LAB_TLS_IP:?},DNS:cascade-entry" \
      -keyout /etc/x-ui/subscription.key -out /etc/x-ui/subscription.crt >/dev/null 2>&1
    chmod 0600 /etc/x-ui/subscription.key /etc/x-ui/subscription.crt
  fi
elif [[ "${XUI_LAB_ROLE:-entry}" == "exit" ]]; then
  if [[ ! -s /etc/x-ui/panel-ca.crt || ! -s /etc/x-ui/panel-ca.key ]]; then
    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
      -subj '/CN=xray-cascade-lab-node-ca' \
      -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' \
      -keyout /etc/x-ui/panel-ca.key -out /etc/x-ui/panel-ca.crt >/dev/null 2>&1
    openssl req -new -newkey rsa:2048 -sha256 -nodes \
      -subj '/CN=cascade-exit' \
      -keyout /etc/x-ui/panel.key -out /run/panel.csr >/dev/null 2>&1
    cat > /run/panel.ext <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:${XUI_LAB_TLS_IP:?},DNS:cascade-exit
EOF
    openssl x509 -req -sha256 -days 3650 \
      -in /run/panel.csr -CA /etc/x-ui/panel-ca.crt -CAkey /etc/x-ui/panel-ca.key \
      -CAcreateserial -extfile /run/panel.ext -out /etc/x-ui/panel.crt >/dev/null 2>&1
    rm -f /run/panel.csr /run/panel.ext /etc/x-ui/panel-ca.srl
    chmod 0600 /etc/x-ui/panel-ca.key /etc/x-ui/panel-ca.crt /etc/x-ui/panel.key /etc/x-ui/panel.crt
  fi
  ./x-ui setting -webCert /etc/x-ui/panel.crt -webCertKey /etc/x-ui/panel.key >/dev/null
fi

./x-ui >/var/log/x-ui-lab.log 2>&1 &
panel_pid=$!
printf '%s\n' "$panel_pid" > /run/x-ui.pid

/usr/sbin/sshd -D -e \
  -o PasswordAuthentication=no \
  -o PermitRootLogin=prohibit-password \
  -o AllowTcpForwarding=no \
  -o X11Forwarding=no &
sshd_pid=$!

shutdown() {
  kill -TERM "$panel_pid" "$sshd_pid" 2>/dev/null || true
  wait "$panel_pid" "$sshd_pid" 2>/dev/null || true
}
trap shutdown TERM INT EXIT

wait -n "$panel_pid" "$sshd_pid"
exit 1
