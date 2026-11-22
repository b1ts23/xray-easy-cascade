# Xray Easy Cascade

Xray Easy Cascade — открытый установщик каскадного VPN на двух серверах:

```text
HAPP → входной сервер → выходной сервер → интернет
```

Обычно входной сервер размещают в России, а выходной — за рубежом, но страны в проекте
не зашиты. Российские сайты можно направлять напрямую через входной сервер, а остальной
трафик — через выходной.

После установки пользователь получит:

- панели 3x-ui на обоих серверах;
- основной VLESS + REALITY через TCP/443;
- запасной VLESS + REALITY через XHTTP;
- одну HTTPS-подписку для HAPP;
- маршрутизацию RoscomVPN;
- межсерверную связь по IPv4 и, при наличии, резерв по IPv6;
- автоматический rollback, если установка не прошла проверку.

## Установка для новичка

> **Публичная установка на реальные VPS пока не включена.** Production-команда намеренно
> заблокирована до полного E2E-теста на двух чистых серверах с независимыми публичными IP.
> Текущую версию нельзя запускать для изменения рабочего VPN.

Итоговая установка будет запускаться **одной копируемой командой**. Она сама:

1. спросит адреса и SSH-ключи двух VPS;
2. проверит серверы и покажет план изменений;
3. установит и свяжет две панели 3x-ui;
4. проверит весь маршрут от клиента до выходного IP;
5. выведет доступы к обеим панелям и ссылку подписки HAPP.

Мы опубликуем эту команду здесь только после того, как именно этот сценарий пройдёт целиком.
Пока такой команды в README нет намеренно: существующие `go run`, `init`, `plan` и `preflight`
являются инструментами разработки и не устанавливают готовый VPN.

### Что потребуется для готового релиза

- два чистых VPS на Ubuntu 24.04 LTS amd64;
- публичный IPv4 на каждом сервере;
- SSH-доступ по ключу к `root`;
- свободный TCP/443;
- глобальный IPv6 на обоих серверах — необязательно, но рекомендуется для резервного пути;
- домен не требуется.

Пароли от панелей, VPN-ключи и другие секреты не будут храниться в репозитории. После
успешной установки доступы появятся в терминале и сохранятся рядом с локальным inventory
в файле `xray-cascade-access.txt` с правами `0600`.

## Что уже проверено

В изолированной лаборатории одной транзакцией разворачиваются две официальные панели
3x-ui 3.11.0 с Xray 26.10.21. Entry регистрирует exit как remote node, переводит связь
на mTLS и удаляет временный API token.

Базовый профиль содержит TCP + Vision и XHTTP. Расширенный профиль дополнительно включает
XHTTP+ML-KEM, legacy gRPC, Hysteria 2 и скрытый межсерверный XHTTP. Все пять клиентских
вариантов прошли HTTPS E2E и приехали одной подпиской HAPP. gRPC оставлен только как
совместимый legacy-вариант; Xray рекомендует XHTTP.

Также проверены:

- server-side маршрутизация RoscomVPN без прямой утечки клиентского трафика;
- IPv4 primary → IPv6 fallback → fail-closed → recovery;
- scoped firewall и SSH/Fail2ban hardening;
- согласованные snapshots обеих баз 3x-ui;
- автоматический rollback обеих ролей при ошибке;
- age-зашифрованный off-host backup и transactional restore;
- отдельные TLS-сертификаты для панелей, node mTLS и подписки;
- выдача двух блоков доступов к панелям и одной подписки HAPP.

Это подтверждает архитектуру и rollback в lab, но не заменяет последний fresh-host E2E на
двух независимых публичных VPS. Поэтому production deploy остаётся fail-closed.

---

## Для опытных пользователей и разработчиков

Ниже описан текущий Design Preview. Эти команды предназначены для изучения, разработки и
изолированной лаборатории — не для рабочих VPN-серверов.

### Сборка и локальная проверка

Нужен Go версии из [`go.mod`](go.mod).

```bash
go test ./...
go vet ./...
go run ./cmd/vpnctl version
```

### Inventory и read-only preflight

```bash
go run ./cmd/vpnctl init
go run ./cmd/vpnctl init --profile extended
go run ./cmd/vpnctl plan --inventory inventory.yml
go run ./cmd/vpnctl preflight \
  --inventory inventory.yml \
  --known-hosts ~/.ssh/known_hosts
```

`init` атомарно создаёт inventory с правами `0600` и не хранит пароли или VPN-ключи.
Базовый профиль выбирает TCP + XHTTP. `--profile extended` добавляет XHTTP+ML-KEM,
legacy gRPC, Hysteria 2 и скрытый interserver XHTTP. `plan` только валидирует YAML и
показывает будущие порты. `preflight` читает состояние узлов через SSH и требует заранее
закреплённые host keys.

### Изолированная лаборатория

```bash
go run ./cmd/vpnctl deploy \
  --lab \
  --inventory lab/inventory.yml \
  --known-hosts ~/.ssh/known_hosts \
  --proxy-jump user@lab-host \
  --yes
```

Lab safety boundary принимает только loopback SSH через jump host, private cascade IP и
лабораторные порты. Публичные SSH targets и production-порт 22 отклоняются. Инструкции по
подготовке окружения находятся в [`lab/README.md`](lab/README.md).

`deploy --lab` сам выполняет preflight, создаёт snapshots и ownership manifests, настраивает
3x-ui через API, запускает cascade/subscription E2E и откатывает обе ноды при ошибке.
`status --lab` показывает redacted-состояние, а `verify --lab` дополнительно проверяет
клиентский маршрут и fault-injection IPv4/IPv6. `rollback --lab` завершает незаконченный
двухузловой rollback.

Production `deploy`, `verify`, `status`, `backup`, `restore`, `update`, `rollback` и
`uninstall` публично заблокированы и возвращают код 2. Внутренний production controller
существует и покрыт unit-тестами, но не подключён к CLI до внешнего fresh-host E2E.

### Панели и сохранённые доступы

`vpnctl panel entry` и `vpnctl panel exit` создают только loopback SSH-forward с pinned
host key, `ExitOnForwardFailure` и keepalive. Панели не открываются на внешнем интерфейсе.
`vpnctl access` повторно печатает сохранённый operator handoff без API/node tokens.

### Архитектурные ограничения MVP

- двухузловой каскад с произвольными странами entry и exit;
- 3x-ui является единственным source of truth для Xray runtime;
- основной межсерверный транспорт — VLESS + REALITY + Vision по TCP;
- XHTTP может быть вторым межсерверным путём;
- Hysteria 2 и дополнительные клиентские транспорты включаются явно;
- запасной транспорт не означает бесшовный hot failover уже открытой сессии HAPP;
- AmneziaWG/AWG исключён;
- WARP остаётся отдельным неактивным модулем;
- Self-SNI не входит в MVP.

### Документация

- [Требования к продукту](docs/PRODUCT.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [Безопасность](docs/SECURITY.md)
- [Сертификаты и ключи](docs/CERTIFICATES.md)
- [RoscomVPN routing](docs/ROSCOMVPN.md)
- [Ownership, backup и rollback](docs/TRANSACTIONS.md)
- [Зашифрованный backup/restore](docs/BACKUP-RESTORE.md)
- [Production candidate и firewall plan](docs/PRODUCTION-CANDIDATE.md)
- [Внешний fresh-host E2E](docs/FRESH-HOST-E2E.md)
- [Текущая граница и следующие шаги](docs/NEXT-STEPS.md)
- [Исследование Bob и Xrayebator](docs/RESEARCH.md)
- [Пример inventory](inventory.example.yml)

## Лицензия

GPL-3.0-only. Код проекта написан заново; код из исследованных проектов не копировался.
Полные условия указаны в [LICENSE](LICENSE).
