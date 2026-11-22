# Требования к продукту

## Пользователь

Пользователь умеет арендовать VPS, подключаться по SSH и запускать команды из инструкции. Он не
обязан знать Xray JSON, вручную переносить UUID/REALITY-ключи между серверами, устанавливать
нейросеть или разбираться в устройстве 3x-ui.

## Результат установки

После успешного `vpnctl deploy` пользователь получает:

1. Entry с VLESS + REALITY: основным Vision/TCP и опциональным XHTTP inbound для клиентов.
2. Exit с отдельным VLESS + REALITY + Vision inbound для межсерверной связи.
3. Автоматически созданные entry → exit outbounds по IPv4 и, если доступен, IPv6.
4. Серверную маршрутизацию: `roscomvpn-default` отправляет российские назначения через entry, а остальные через exit; `cascade-all` отправляет весь трафик через exit.
5. Одну HAPP-подписку со всеми включёнными транспортами и профилем маршрутизации RoscomVPN.
6. Одну центральную 3x-ui-панель для повседневного управления.
7. Закрытую node-панель exit для управления центральной панелью и аварийного доступа.
8. Локальный root-only state с созданными идентификаторами, но без секретов в логах и argv.
9. Отчёт проверки с понятным итогом: `HEALTHY`, `DEGRADED`, `UNHEALTHY` или `UNKNOWN`.

## Команды оператора

| Команда | Назначение | Изменяет серверы |
|---|---|---|
| `vpnctl init` | Интерактивно создаёт локальный inventory | Нет |
| `vpnctl plan` | Локальная валидация inventory и план изменений | Нет |
| `vpnctl preflight` | Read-only SSH-проверка обоих узлов | Нет |
| `vpnctl deploy` | Устанавливает или доводит оба узла до желаемого состояния | Да |
| `vpnctl verify` | Проверяет оба узла и каскад; `--lab` делает временную scoped fault injection | Только `--lab`, временно |
| `vpnctl status` | Короткий статус | Нет |
| `vpnctl panel` | Открывает SSH-туннель к центральной панели | Нет |
| `vpnctl backup-keygen` | Создаёт локальную age identity | Нет |
| `vpnctl backup` | Создаёт зашифрованный переносимый backup | Да |
| `vpnctl backup-verify` | Аутентифицирует archive и проверяет checksums | Нет |
| `vpnctl restore` | Транзакционно восстанавливает оба узла | Да |
| `vpnctl update` | Обновляет по закреплённому release manifest | Да |
| `vpnctl rollback` | Возвращает последний проверенный snapshot | Да |
| `vpnctl uninstall` | Показывает план и удаляет только принадлежащие проекту файлы | Да |

Изменяющие постоянное состояние команды требуют интерактивного подтверждения либо явного `--yes`.
`plan` вообще не подключается к серверам; `preflight` и `status` только читают. Лабораторный `verify`
создаёт узкие REJECT-правила исключительно для exit IP и interserver port и гарантированно удаляет их
cleanup trap; production-вариант такого теста требует отдельного явного режима.

Промежуточный этап 20.11.2026: `vpnctl deploy --lab` неоднократно прошёл полный цикл на
изолированных 3x-ui-контейнерах. Доказаны bootstrap pin → mTLS с удалением token,
automatic rollback, encrypted off-host backup и transactional restore. Production остаётся fail-closed
до trusted subscription TLS, real systemd/UFW activation и повтора на public VPS.

Lab rollback теперь также доказан: перед каждой мутацией сохраняются обе БД и управляемые geo-assets,
commit выполняется только после E2E, а намеренно вызванный сбой автоматически восстановил оба узла.
Лабораторный restore покрывает firewall/systemd/certificates; для production нужна проверка
на реальных хостах и retention policy.

Базовый gate 22.11.2026 повторно доказал TCP/XHTTP E2E, обе ссылки в одной HAPP-подписке
и работу XHTTP при scoped блокировке основного TCP-порта. Расширенный opt-in профиль добавляет
XHTTP+ML-KEM, gRPC legacy, Hysteria 2 и межсерверный XHTTP. Автовыбор HAPP при подключении и hot failover
активной сесии — разные acceptance tests; второй пока не обещается.

## Installation UX

```text
vpnctl init [--profile base|extended]
  → адрес и SSH-доступ к entry
  → адрес и SSH-доступ к exit
  → режим панели и подписки
  → inventory.yml без паролей и VPN-ключей
  → base: TCP/Vision + XHTTP; extended: + ML-KEM, gRPC legacy, Hysteria 2, interserver XHTTP

vpnctl plan
  → строгая локальная валидация inventory
  → полный список предполагаемых изменений

vpnctl preflight
  → строгая проверка pinned SSH host keys
  → совместимость ОС и архитектуры
  → занятые порты и конфликтующие службы
  → firewall/cloud-init/apt locks
  → доступность GitHub и источников пакетов
  → read-only отчёт READY, LAB_READY или BLOCKED

vpnctl deploy
  → exit первым
  → entry вторым
  → автоматический обмен межсерверными параметрами
  → центральная панель и node trust
  → routing/subscription
  → config tests и staged restart
  → verify
```

## Поддержка существующих серверов

Роли — `entry` и `exit`, а не конкретные страны. Типовой сценарий: entry в РФ и exit за рубежом, но это не ограничение установщика.

Первый публичный релиз поддерживает только чистые VPS. Adopt существующей 3x-ui — отдельная функция,
потому что безопасное объединение чужой базы, firewall и routing нельзя обещать без транзакционной
миграции.

## Критерий готовности MVP

На двух одноразовых чистых VPS независимый пользователь по README:

- выполняет не более пяти основных команд;
- не копирует секреты между серверами вручную;
- получает рабочую подписку и панель;
- видит entry-выход для direct-назначений и exit-выход для остальных;
- переживает повторный `deploy` без смены ключей и простоя;
- после намеренно испорченного кандидата получает автоматический rollback;
- после перезагрузки обоих VPS снова получает `HEALTHY`.
