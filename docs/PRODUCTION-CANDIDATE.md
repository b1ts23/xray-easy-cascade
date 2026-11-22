# Production candidate

Публичная команда production activation остаётся заблокированной. Внутренний controller уже
реализует clean-host bootstrap и runtime, но они не подключены к `vpnctl deploy`, пока не пройден
E2E на двух независимых публичных IP.

## Закреплённый релиз

- 3x-ui `3.11.0`;
- официальный asset `x-ui-linux-amd64.tar.gz`;
- SHA-256 `0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916`.

`vpnctl` скачивает только versioned URL, проверяет checksum, отклоняет absolute/parent paths в
архиве и требует наличие binary Xray, binary 3x-ui и официального hardened
`x-ui.service.debian`. Candidate сохраняется в `/var/lib/xray-cascade/candidates` и не копируется
в `/usr/local`, не вызывает `systemctl` и не меняет firewall.

Этот staging идемпотентно проверен в обоих Hetzner-lab контейнерах.

## Подготовка clean-VPS layout

Локально реализован fail-closed `StageInstallScript`. Он принимает только уже проверенный
candidate и отказывается работать, если целевые 3x-ui paths уже существуют. Script:

- копирует exact candidate в `/usr/local/x-ui`;
- генерирует случайные bootstrap credentials в root-only state, но не печатает их;
- настраивает entry panel на loopback, exit panel — на node interface;
- создаёт отдельные private CA/server certificate только для exit node API;
- ставит официальный hardened systemd unit/drop-in и проверяет его `systemd-analyze verify`;
- атомарно удаляет только созданные им paths при ошибке.

Этот script не вызывает `systemctl start/enable` и не трогает firewall. Отдельный activation step
требует `inactive/disabled`, выполняет `enable --now`, проверяет readiness и возвращает службу в
исходное состояние при ошибке. Entry и exit прошли этот цикл в одноразовом Ubuntu 24.04 systemd
container 21.11.2026.

## План сетевого доступа

| Узел | Порт | Источник | Назначение |
|---|---:|---|---|
| entry | SSH из inventory | existing access | сохраняется до любых firewall-изменений |
| entry | 80/tcp | public | временный standalone HTTP-01 для short-lived IP certificate |
| entry | 443/tcp | public | VLESS + REALITY клиента |
| entry | 8443/tcp | public | опциональный VLESS + XHTTP + REALITY |
| entry | 10443/tcp | public | opt-in VLESS + XHTTP + REALITY + ML-KEM |
| entry | 9443/tcp | public | opt-in legacy VLESS + gRPC + REALITY |
| entry | 443/udp | public | opt-in Hysteria 2 + TLS |
| entry | 2096/tcp | public | HAPP HTTPS subscription |
| entry | 2053/tcp | loopback | центральная панель через SSH tunnel |
| exit | SSH из inventory | existing access | сохраняется до любых firewall-изменений |
| exit | 80/tcp | public | временный standalone HTTP-01 для short-lived IP certificate |
| exit | 443/tcp | только entry IPv4/IPv6 | межсерверный VLESS + REALITY |
| exit | 8443/tcp | только entry IPv4/IPv6 | opt-in межсерверный VLESS + XHTTP + REALITY |
| exit | 2053/tcp | только entry IPv4/IPv6 | node API; далее mTLS |

Правила должны добавляться с project comments и ownership без `ufw reset` и без удаления чужих
правил. Если UFW не активен, production activation не должна включать его, пока сначала не создано
и не проверено правило текущего SSH-порта.

Генератор `FirewallScript` уже добавлен: он сначала делает root-only snapshot `user.rules`,
`user6.rules` и `/etc/default/ufw`, добавляет только rules с comments `xray-cascade:*`, включает UFW
только после SSH allow rule и восстанавливает snapshot при любой ошибке. `ufw reset`,
`ufw delete` и прямая очистка iptables запрещены тестами. Entry и exit UFW activation, snapshot и
full restore прошли в отдельном network namespace одноразового container. Script входит в
фиксированный bootstrap-порядок публичных `vpnctl install`/`deploy`.

## Production runtime controller

После успешного host bootstrap отдельный controller теперь умеет:

- создать согласованные snapshots обеих 3x-ui БД до первой runtime-мутации;
- зарегистрировать exit по scoped `node-sync` token и SHA-256 pin активного ACME leaf certificate;
- создать базовые TCP/XHTTP, включённые opt-in клиентские транспорты и межсерверные VLESS + REALITY inbounds через API 3x-ui;
- установить закреплённые RoscomVPN geo-assets, server-side direct/cascade/block правила и HAPP deeplink;
- проверить checksum deeplink до отправки на сервер;
- выпустить master/client mTLS identity, доверить master CA на exit, перевести node в `mtls` и удалить node token;
- проверить exit runtime и commit обеих транзакций;
- при любой ошибке откатить entry, затем exit из snapshot.

Production-путь использует отдельные имена ресурсов `xray-cascade-*`, запрещает private node address
и обращается к локальным панелям по HTTPS. Доверие к exit проверяется через системное CA store и
публичный Let's Encrypt IP SAN; лабораторный private CA в production не устанавливается.

Оба этапа объединены внутренним fresh-host coordinator. Если runtime ломается после успешной
установки, он сначала выполняет transaction rollback entry → exit, затем full install rollback
entry → exit и удаляет только paths/rules, перечисленные в ownership manifest. Этот coordinator
тоже пока не экспортирован через CLI.

## Operator handoff

После финального E2E пользовательская выдача должна происходить прямо в активный терминал, отдельно
для entry и exit: username, password, port, WebBasePath, локальный URL и `vpnctl panel entry|exit`.
Следом печатается одна HTTPS-подписка HAPP. Формат и атомарная recovery-копия уже реализованы и
проверены тестами. Копия имеет очевидное имя `xray-cascade-access.txt`, лежит рядом с inventory и
создаётся с правами `0600`; её можно повторно показать через `vpnctl access`. API/node tokens туда
не включаются.

## Host-level rehearsal 21.11.2026

На Hetzner создавался отдельный privileged Ubuntu 24.04 systemd container без published ports и
без рабочих volumes. Существующие app/VPN-lab containers не изменялись. Проверены обе роли:

- pinned 3x-ui candidate download/checksum и clean staging;
- comment-owned UFW rules, первый systemd start и HTTPS readiness;
- ACME failure при занятом TCP/80: восстановлены прежние web TLS paths и crontab, частичные
  `acme.sh`/certificate files удалены, 3x-ui остался рабочим;
- успешный EC P-256 IP-certificate path через локальный test CA;
- entry subscription TLS настроен только через 3x-ui API; исправлены обязательный `POST` для
  `/setting/all`, proxy bypass для loopback и base path `/entry/` перед встроенным `/panel/api`;
- повторный ACME/subscription run оставил один cron entry и состояние `ready`;
- полный rollback обеих ролей вернул UFW в `inactive`, остановил/disable 3x-ui и удалил только
  ownership-managed paths; заранее существующий ACME client сохранился;
- временные container/image удалены, все рабочие Hetzner containers остались healthy.

Реальный запрос к Let's Encrypt намеренно не выполнялся: у контейнера нет отдельного публичного IP.
Поэтому CA/network E2E остаётся отдельным production gate.

## Existing-cascade adoption 21–22.11.2026

Для действующего reference-каскада собран отдельный, ещё не публичный controller. Он не
переустанавливает 3x-ui и не меняет клиента: меняются только balancer/observatory и
порядок существующего BitTorrent block. API snapshot, independent worker, five-minute rollback
watchdog, forced rollback и commit прошли isolated lab. После двух успешных production rollback
третья RU-only transaction была подтверждена владельцем и
committed 22.11.2026. NL runtime не менялся; подробный post-commit E2E прошёл.

Подробная граница и доказательства: [`LIVE-UPGRADE-REHEARSAL.md`](LIVE-UPGRADE-REHEARSAL.md).

## Блокеры активации

- провести issuance/renewal E2E с настоящим Let's Encrypt на двух independent public IP;
- объединить уже реализованные host bootstrap и transactional runtime в публичную команду только
  после успешного реального E2E;
- повторить ACME, cascade, mTLS и encrypted backup/restore на двух independent public VPS;
- определить retention и disaster-recovery runbook.
