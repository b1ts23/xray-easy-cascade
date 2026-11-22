# Архитектура

## Топология

```text
                                  ┌─ direct ──→ назначения по политике
HAPP → entry/master 3x-ui ─┤
                                  └─ v4/v6 ──→ exit/node 3x-ui ──→ интернет
```

Клиент знает только entry и в базовом профиле получает одной подпиской TCP и XHTTP. Расширенный профиль
добавляет XHTTP+ML-KEM, gRPC legacy и Hysteria 2. Выбор direct/exit выполняет
серверный Xray на entry. Типовой, но не обязательный сценарий: entry в РФ, exit за рубежом.

## Управление

Стабильная 3x-ui 3.11.0 поддерживает remote nodes и scoped API tokens. Entry становится master, exit —
node. Центральная панель видит состояние, inbounds, клиентов и трафик обоих узлов. Для node trust
целевой режим — mTLS; bootstrap-token должен быть короткоживущим и удаляться после установления mTLS.

CLI `vpnctl` остаётся отдельным recovery plane. Даже если entry-панель недоступна, оператор может по SSH
проверить или восстановить каждый узел.

## Последовательность развёртывания

1. Локальный CLI закрепляет SSH host keys обоих VPS.
2. Read-only preflight проверяет ОС, архитектуру, порты, сеть, firewall и конфликты.
3. На exit ставится закреплённая 3x-ui, создаётся межсерверный Reality inbound.
4. Секреты inbound передаются внутри SSH-сессии CLI и не попадают в argv, логи или inventory.
5. На entry ставится master 3x-ui, создаются основной TCP inbound, опциональный XHTTP inbound и общая подписка.
6. Entry регистрирует exit как node, затем API-token заменяется mTLS trust.
7. На entry создаются отдельные outbounds для exit IPv4 и IPv6.
8. Специфичные routing-правила идут выше catch-all; block-правила не могут стоять после catch-all.
9. 3x-ui собирает runtime config, а CLI сверяет его через API и проверяет встроенным Xray до применения.
10. После staged restart CLI проверяет реальные listeners, подписку и доступные egress-пути.

mTLS CA/client identity создаётся тем же уже аутентифицированным controller-сеансом до отложенного
restart панели. Это исключает гонку, при которой CLI успевал ротировать API token в БД, пока HTTP
ещё обслуживал старый процесс. Временный token не печатается; после перехода node на mTLS bearer
удаляется.

## IPv4/IPv6

`roundRobin` без наблюдения не является fallback. Именно такая схема видна в reference-панели, но
MVP не должен повторять её без health monitor.

Выбранная сема для первого релиза:

- два outbounds с общим префиксом тега;
- при `prefer_interserver: ipv4` selector содержит только IPv4, а `fallbackTag` указывает на IPv6;
- если IPv6 отсутствует, fallback идёт в `blocked`;
- при `prefer_interserver: lowest-latency` оба пути входят в `leastPing`;
- в обоих режимах `observatory` даёт health state, а default/direct не используется как fallback;
- отдельный end-to-end probe entry → exit → интернет;
- честное состояние `DEGRADED`, если жив только один адрес.

Строгий IPv4-primary/IPv6-fallback теперь выражен декларативно. Dual-stack container lab сетевой
инъекцией отказов доказал основной IPv4, автоматический переход на ULA IPv6, fail-closed при
недоступности обоих путей без direct-утечки и последующее восстановление. Переключение между двумя
публичными стеками разных VPS остаётся production E2E до публичного обещания automatic failover.

## Панели и подписки

- Панель по умолчанию слушает loopback и открывается через `vpnctl panel`.
- Публичная панель — только opt-in, с валидным TLS, случайным base path и rate limiting.
- Node API exit разрешён только entry и recovery CLI; предпочтительно mTLS.

## Выбор клиентского маршрута

HAPP не должен принимать server-side `direct` за client-side `Direct`. В исходном RoscomVPN
`DEFAULT` публичные российские назначения обходят VPN на устройстве. Установщик проверяет
закреплённый upstream и выдаёт адаптированный профиль: client-direct разрешён только private-сетям,
весь публичный трафик приходит на entry, а там применяется `roscomvpn-default`.

Многомаршрутная подписка даёт HAPP набор альтернатив, но сама по себе не доказывает hot failover. HAPP документирует `subscription-autoconnect-type: lowestdelay` для выбора при автоподключении. Бесшовное переключение активной сессии не обещаем до отдельного E2E на Android/iOS/Desktop.
Финальный acceptance gate доказывает TCP и XHTTP через exit; XHTTP остаётся рабочим при scoped REJECT основного TCP-порта.

PQ XHTTP, Hysteria 2 и межсерверный XHTTP допускаются как opt-in транспорты и покрыты отдельными
listener/subscription/firewall проверками. gRPC исключён из default: Xray 26.10.21 печатает deprecation warning
и рекомендует XHTTP. WARP планируется только как явно включаемый outbound на exit; AWG исключён.
- Подписка — bearer credential. URL не пишется в обычные логи и отчёты.
- Безопасный HTTPS-режим подписки без домена должен быть проверен отдельно до обещания «домен не нужен».

## Источник истины

3x-ui API и её база — runtime source of truth для inbounds/clients. `vpnctl` хранит только минимальный
cluster state и желаемые инварианты. Нельзя одновременно писать активный `config.json` напрямую и
ожидать, что панель сохранит изменения. Все постоянные изменения панели выполняются через
документированный API/CLI закреплённой версии.

`vpnctl` не генерирует и не устанавливает самостоятельный Xray `config.json`. Он формирует запросы к
закреплённому API 3x-ui, затем читает собранную конфигурацию через API для проверки инвариантов.
RoscomVPN требует отдельно закреплённых geo-assets и их checksum.

Эта схема повторно доказана двумя последовательными idempotent deploy в container lab 21.11.2026:
remote node `online` по mTLS, оба inbound активны, runtime entry содержит `cascade-exit`, observatory,
fail-closed fallback и ограниченное по inbound catch-all rule, а сквозной VLESS + REALITY тест
завершился HTTPS 200. Отдельный dual-stack fault-injection E2E прошёл IPv4 primary, IPv6 fallback,
fail-closed и recovery. Это ещё не доказывает работу двух независимых public IP, публичную
provider-маршрутизацию IPv6 и host firewall на чистых VPS.

Лабораторный orchestration перенесён в `vpnctl deploy --lab`: scoped bootstrap token и параметры
передаются в stdin закреплённой SSH-сессии, не попадают в argv и не печатаются в
пользовательский output. Pin теперь только enrollment-шаг. Entry создаёт mTLS CA/client identity
через штатный API 3x-ui, exit добавляет public CA в trust, node переводится на
`tlsVerifyMode=mtls`, а API token удаляется. Production всё ещё требует trusted server certificate на exit.

## Обновление и rollback

Каждое изменение проходит:

```text
download → checksum/signature → candidate → semantic validation → xray test
         → backup → apply → readiness → end-to-end → commit snapshot
                                      └─ failure → automatic rollback
```

Обновление exit выполняется раньше entry. Совместимость версий node/master проверяется до изменения.

Container lab уже реализует базовую транзакцию: root-only ownership manifest, lock, согласованный
экспорт БД через `server/getDb`, checksum, backup управляемых geo-assets, commit только после E2E и
restore через валидирующий `server/importDB`. Намеренный post-mutation failure восстановил оба узла,
после чего повторный deploy снова прошёл E2E. Отдельный age-encrypted off-host backup покрывает
обе базы, geo-assets, certificates/keys, systemd units и UFW files. Transactional restore прошёл
cascade/subscription E2E. До production остаются retention и проверка на двух independent public VPS.
