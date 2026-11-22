# Сертификаты и ключи

Проект не переиспользует один credential для разных задач.

| Роль | Где | Требование |
|---|---|---|
| SSH host key | каждый VPS | отдельный ED25519, pinned до первой мутации |
| Entry Reality | client → entry | собственная X25519-пара и short ID |
| Hop Reality | entry → exit | другая X25519-пара и short ID |
| Node server TLS | master → exit API | отдельный server certificate с trusted chain |
| Node mTLS client | master identity | отдельный client certificate от master CA |
| Subscription TLS | HAPP → entry subscription | отдельный publicly trusted certificate |
| Panel TLS | browser → entry panel | не нужен в режиме SSH tunnel; отдельный cert для public opt-in |
| API tokens | 3x-ui API | scoped, не являются TLS- или Reality-ключами |

## Лаборатория

- Exit node API имеет persistent CA-signed server certificate с IP/DNS SAN. Публичный CA
  устанавливается в system trust entry до запуска 3x-ui.
- Enrollment начинается с `pin`. Затем entry создаёт CA/client identity, exit доверяет
  этому CA, node переводится на `tlsVerifyMode=mtls`, а bootstrap token удаляется.
- Entry subscription service имеет другой self-signed certificate и отдельный private key.
- Entry admin panel доступна только на loopback, поэтому остаётся HTTP за SSH tunnel.
- E2E подтвердил, что node и subscription certificates различаются, а обе Reality-пары
  не совпадают.

Self-signed subscription certificate допустим только для lab. Production HAPP endpoint должен
использовать ACME domain/IP или заранее переданную publicly trusted пару.

## Выбранный production baseline

Read-only аудит reference-каскада 21.11.2026 подтвердил одинаковую рабочую схему на entry и exit:

- отдельный Let's Encrypt IP certificate на каждом VPS, SAN содержит только IPv4 этого узла;
- ECDSA P-256 (`ec-256`), срок действия около 160 часов;
- `acme.sh` 3.1.7, CA `https://acme-v02.api.letsencrypt.org/directory`;
- файлы `/root/cert/ip/fullchain.pem` (`0644`) и `/root/cert/ip/privkey.pem` (`0600`);
- внутри одного узла одна пара подключена и как `webCertFile/webKeyFile`, и как
  `subCertFile/subKeyFile`; между двумя VPS пары разные;
- cron запускает `acme.sh --cron` каждые 6 часов;
- deploy hook после обновления выполняет `systemctl restart x-ui`;
- постоянного listener на TCP/80 нет: standalone HTTP-01 использует его только при выпуске и
  продлении, поэтому firewall обязан разрешать TCP/80 на обоих узлах;
- VLESS + REALITY на TCP/443 не использует этот X.509 certificate: у Reality остаются отдельные
  X25519 key pair и short ID.

Эта схема выбрана default для production без домена. Entry использует свой IP certificate для
панели/подписки, exit — свой для server side node API; master mTLS client identity остаётся
отдельным credential. Панель по-прежнему не публикуется: entry доступна через SSH tunnel, а exit
API разрешён только entry. Разрешённый TCP/80 не означает постоянно работающий web server.

Let's Encrypt с 15.01.2026 общедоступно выдаёт IPv4/IPv6 certificates. Они обязательно
short-lived (160 часов), поэтому `acme-ip` допустим только с полностью автоматическим renewal,
readiness и restart/reload панели. Генератор уже закрепляет exact commit/checksum `acme.sh` 3.1.7,
отклоняет занятый TCP/80, проверяет IP SAN, соответствие certificate/key и HTTPS readiness.
Failure cleanup, повторный запуск, subscription API TLS и full install rollback прошли isolated
systemd/UFW rehearsal с локальным test CA. Guided install получает настоящий IP certificate на
каждом VPS и не фиксирует транзакцию, пока trusted HTTPS subscription и public-edge E2E не пройдут.

Источники: [Let's Encrypt GA](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability),
[Certbot IP certificates](https://letsencrypt.org/2026/03/11/shorter-certs-certbot).

## Inventory

`certificates.node_transport`, `panel_tls` и `subscription_tls` выбираются независимо.
`pending` для subscription — явный fail-closed placeholder: production deploy не должен выдавать
HTTP-подписку как готовую.
Для выбранного `acme-ip` используется штатный flow 3x-ui: Let’s Encrypt, `shortlived`, standalone
HTTP-01 и auto-renewal. Email в upstream 3x-ui опционален (`XUI_ACME_EMAIL`) и поэтому не является
обязательным полем inventory.

В `existing`-режиме `*_cert_file` и `*_key_file` — локальные файлы на машине оператора.
`vpnctl plan` до SSH-подключения отклоняет symlink, group/world-readable private key,
невалидную цепочку, несовпадающий SAN/key и сертификат с остатком менее 24 часов.
