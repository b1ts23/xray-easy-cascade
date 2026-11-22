# Xray Easy Cascade

> **Статус: lab-tested Design Preview. Production-мутации отключены и fail-closed. Не используйте текущую версию для изменения рабочих VPN-серверов.**

Xray Easy Cascade — открытый установщик двухузлового VPN на 3x-ui, VLESS и REALITY:

```text
клиент → entry → exit → интернет
              └──→ direct по выбранной политике
```

Цель проекта — позволить человеку без нейросети и ручного редактирования JSON взять два чистых VPS,
выполнить несколько команд и получить воспроизводимый каскад VLESS + REALITY с панелью управления,
подписками, IPv4/IPv6-связью, проверкой установки и безопасным откатом.

## Что уже работает

На этом этапе CLI намеренно ограничен локальными командами и read-only SSH-проверкой:

```bash
go run ./cmd/vpnctl version
go run ./cmd/vpnctl init
go run ./cmd/vpnctl init --profile extended
go run ./cmd/vpnctl plan --inventory inventory.yml
go run ./cmd/vpnctl preflight --inventory inventory.yml --known-hosts ~/.ssh/known_hosts
```

`init` атомарно создаёт inventory с правами `0600`, не хранит пароли и VPN-ключи. `plan`
лишь валидирует YAML локально. `preflight` читает состояние обоих узлов через SSH, не пишет на сервер и требует заранее закреплённые host keys.
По умолчанию `init` выбирает базовый TCP+XHTTP. `--profile extended` явно добавляет XHTTP+ML-KEM,
legacy gRPC, Hysteria 2 и скрытый interserver XHTTP; `plan` покажет все дополнительные TCP/UDP-порты до изменений.

`deploy --lab` уже работает: сам выполняет preflight, создаёт transactional snapshots и ownership
manifest, создаёт scoped bootstrap token, регистрирует node, переводит его на mTLS,
доводит оба runtime через API 3x-ui и запускает E2E.
При ошибке обе базы и управляемые geo-файлы автоматически восстанавливаются штатным import API 3x-ui.
Safety boundary принимает только
loopback SSH через jump host, private cascade IP и lab-порты. Production `deploy` без `--lab`,
а также production `verify`, `status`, `backup`, `restore`, `update`, `rollback` и `uninstall` пока
возвращают код 2. `rollback --lab` восстанавливает незавершённую lab-транзакцию,
в том числе если один узел уже откатился, а второй сохранил pending lock.

`panel` уже готов: он создаёт только loopback SSH-forward с pinned host key, включённым
`ExitOnForwardFailure` и keepalive. Панель не открывается на внешнем интерфейсе.

В лаборатории также доказан полный цикл age-зашифрованного off-host backup/restore.
Приватный ключ остаётся локально с правами `0600`; restore валидирует checksums, восстанавливает
обе базы, geo-assets, TLS/systemd/UFW state и commit только после cascade/subscription E2E.

`status --lab` выдаёт redacted human/JSON состояние обоих узлов: panel, Xray, listeners,
inbounds, node online/mTLS, отсутствие API-token и HAPP routing. `verify --lab` добавляет
полный client → entry → exit → internet и subscription-checksum E2E, затем временно и точечно
блокирует межсерверные IPv4/IPv6 пути, проверяя primary, fallback, fail-closed и recovery. Правила
снимаются cleanup trap при любом завершении. Обе команды возвращают
отдельный exit code 4 при degraded/failed проверке.

Базовый стабильный lab-профиль: две официальные 3x-ui `3.11.0` с Xray `26.10.21`,
entry регистрирует exit как `online` remote node, а клиент получает TCP + Vision и XHTTP
одной HAPP-подпиской. Расширенный opt-in профиль добавляет XHTTP+ML-KEM, legacy gRPC,
Hysteria 2 и скрытый межсерверный XHTTP. Все пять клиентских вариантов прошли
HTTPS E2E и одну HAPP-подписку в текущем lab; они допускаются строгим inventory. gRPC не является
default: Xray печатает deprecation warning и рекомендует XHTTP. Xray `config.json` напрямую не редактируется.
Весь цикл неоднократно прошёл одной командой `vpnctl deploy --lab --yes`.
Dual-stack ULA fault-injection также доказал автоматический IPv4 → IPv6 переход, отсутствие direct-
утечки при отказе обоих путей и восстановление. Публичные IPv6 двух провайдеров ещё требуют E2E на VPS.
Отдельная fault-injection заблокировала основной клиентский TCP-порт и подтвердила, что XHTTP
продолжает работать. Это доказывает доступность запасного транспорта, но не hot failover
уже открытой сессии HAPP.
SHA-256 pin используется только для enrollment. Затем controller штатным API 3x-ui создаёт master mTLS
identity, добавляет его CA в trust exit, переводит node на `tlsVerifyMode=mtls` и удаляет API token.
HTTPS-подписка использует другой сертификат. Закреплённый профиль RoscomVPN адаптируется для
каскада: HAPP не выпускает публичный трафик мимо VPN, а выбор entry/exit выполняет сервер.
Тот же официальный release asset отдельно проходит production-candidate staging: checksum,
безопасные пути архива, binary Xray/3x-ui и Debian systemd unit проверяются без активации.

Внутренний production controller уже разделён на два fail-closed этапа: clean-host bootstrap и
transactional runtime. Runtime использует активные Let's Encrypt IP certificates, отдельные
production resource names, публичный node policy, RoscomVPN/HAPP и перевод pin → mTLS с удалением
node token. Unit-тесты проверяют успешный порядок и двухузловой rollback. Публичная команда
`vpnctl deploy` остаётся выключенной до реального E2E на двух независимых публичных IP.
Внутренний fresh-host coordinator уже объединяет оба этапа и при runtime-сбое выполняет сначала
rollback обеих БД, затем ownership-scoped rollback обеих установок.

Для уже работающего reference-каскада отдельно собран narrow live-upgrade controller: он снимает
согласованный 3x-ui API snapshot, запускает worker независимо от SSH, взводит systemd rollback
watchdog и меняет только точно заданные ресурсы. Forced rollback, commit и
механика transient systemd units прошли isolated rehearsal. Этот же внутренний
controller применён к reference RU entry для routing, XHTTP и Hysteria 2; каждая
транзакция до commit оставалась под dead-man rollback. К публичному CLI он не подключён.
Для сценария без запасного интернета добавлен dead-man confirmation gate: server-side E2E не отменяет
watchdog; только явное подтверждение работы HAPP фиксирует commit, а потеря связи даёт
таймеру автоматически вернуть snapshot.

Reference Hysteria 2 adoption добавляет trusted ACME IP TLS на `443/udp`, тот же
subscription ID и существующее cascade rule. TCP/443, XHTTP/8443 и exit не заменяются.
Verifier до commit доказывает UDP/TLS cascade egress и проверяет endpoint, auth, TLS,
SNI и `h3` ALPN в `hysteria2://`. Для принудительного HAPP refresh используется
15-минутное rollback-окно. Reference-транзакция подтверждена и committed 22.11.2026.

## Локальная проверка Design Preview

```bash
go test ./...
go vet ./...
go run ./cmd/vpnctl version
go run ./cmd/vpnctl init
go run ./cmd/vpnctl plan --inventory inventory.yml
```

Публичные preview-релизы будут помечаться pre-release. Финальный Quick Start с готовым
бинарником появится только после fresh-host E2E. До этого `vpnctl deploy` без `--lab`
намеренно завершается с кодом 2 и ничего не меняет.

После успешного deploy установщик прямо в терминале показывает два отдельных блока с логином,
паролем, портом, WebBasePath и командой открытия панелей entry/exit, а затем отдельный HTTPS URL
подписки HAPP. API/node token в пользовательскую выдачу не попадает. Дополнительная recovery-копия
сохраняется не в скрытом каталоге, а рядом с `inventory.yml` как `xray-cascade-access.txt` с
правами `0600`; `vpnctl access` повторно печатает её и явно показывает полный путь.

## Что потребуется

- два VPS: entry и exit;
- страны не зашиты в архитектуру; типовой сценарий — entry в РФ и exit за рубежом;
- Ubuntu 24.04 LTS amd64 на первом поддерживаемом релизе;
- публичный IPv4 на обоих серверах;
- свободный TCP/443;
- SSH-доступ по ключу к `root` (поддержка passwordless `sudo` ещё не реализована);
- глобальный IPv6 на обоих серверах — опционально, для второго межсерверного пути;
- домен — опционально; для режима без домена выбран проверенный на reference-каскаде Let's Encrypt
  IPv4 certificate EC P-256 через `acme.sh`, с renewal каждые 6 часов и restart `x-ui`;
  systemd/UFW/ACME lifecycle прошёл isolated host-level rehearsal, но production activation
  остаётся fail-closed до E2E с настоящими independent public IP.

## Проектные ограничения MVP

- базовые клиентские входы: VLESS + REALITY через TCP + Vision и XHTTP;
- расширенные opt-in входы: XHTTP+ML-KEM, gRPC legacy и Hysteria 2; они не обещают hot failover HAPP;
- межсерверный primary — VLESS + REALITY + Vision по TCP; XHTTP можно включить как вторичный путь;
- только двухузловой каскад;
- 3x-ui 3.11.0, закреплённая по версии и checksum;
- entry — центральная панель, exit — управляемая node-панель;
- AmneziaWG/AWG не входит в проект;
- WARP остаётся отдельным неактивным модулем; AWG исключён;
- Self-SNI не входит в MVP;
- XHTTP включается явно через `client_alternatives` и публикуется одной подпиской вместе с TCP;
- никакого применения к существующей инфраструктуре без отдельного подтверждения.

## Документация проекта

- [Требования к продукту](docs/PRODUCT.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [Безопасность](docs/SECURITY.md)
- [Сертификаты и ключи](docs/CERTIFICATES.md)
- [RoscomVPN routing](docs/ROSCOMVPN.md)
- [Опциональный WARP outbound](docs/WARP.md)
- [Ownership, backup и rollback](docs/TRANSACTIONS.md)
- [Зашифрованный backup/restore](docs/BACKUP-RESTORE.md)
- [Production candidate и firewall plan](docs/PRODUCTION-CANDIDATE.md)
- [Репетиция безопасного live-upgrade](docs/LIVE-UPGRADE-REHEARSAL.md)
- [Визуальный baseline действующей 3x-ui](docs/REFERENCE-UI-2026-11-21.md)
- [Исследование Bob и Xrayebator](docs/RESEARCH.md)
- [Текущая граница и следующие шаги](docs/NEXT-STEPS.md)
- [Внешний fresh-host E2E](docs/FRESH-HOST-E2E.md)
- [Пример inventory](inventory.example.yml)

## Лицензия

GPL-3.0-only. Текущий код написан заново; код из исследованных проектов не копировался.
Полные условия указаны в [LICENSE](LICENSE).
