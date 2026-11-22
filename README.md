# Xray Easy Cascade

Устанавливает каскадный VPN на два чистых сервера:

```text
HAPP → входной сервер → выходной сервер → интернет
```

Типовой вариант: входной сервер в России, выходной — за рубежом. Российские ресурсы
открываются через входной сервер, остальной трафик уходит через выходной.

## Установка для новичка

Нужна только одна команда. Вставьте её в Terminal на macOS или Linux:

```bash
bash <(curl -fsSL https://github.com/b1ts23/xray-easy-cascade/releases/latest/download/install.sh)
```

Установщик сам скачает `vpnctl`, проверит SHA-256, задаст несколько вопросов и выполнит
весь сценарий. Go, Docker и ручное редактирование YAML не нужны.

### Что подготовить

- два **чистых** VPS с Ubuntu 24.04 LTS amd64;
- разные публичные IPv4-адреса;
- SSH-доступ по ключу к `root`;
- свободные TCP/443 и TCP/80 на обоих VPS;
- глобальный IPv6 на обоих VPS — желательно, но не обязательно.

### Что спросит установщик

```text
Cascade name [my-cascade]:
Entry server public IPv4:
Exit server public IPv4:
SSH private key [~/.ssh/id_ed25519]:
Trust and pin these SSH host keys? [y/N]:
Install on BOTH clean VPS? [y/N]:
```

До последнего подтверждения серверы не изменяются: выполняются только проверка SSH,
проверка свободных портов и показ точного плана. Отпечатки SSH-ключей нужно сравнить
с консолью провайдера.

### Что получится

- две панели [3x-ui](https://github.com/MHSanaei/3x-ui), доступные только через SSH-туннель;
- [VLESS](https://xtls.github.io/en/config/outbounds/vless.html) +
  [REALITY](https://xtls.github.io/en/config/transports/reality.html) на TCP/443;
- запасной [XHTTP](https://xtls.github.io/en/config/transports/xhttp.html);
- [Hysteria 2](https://xtls.github.io/en/config/transports/hysteria.html) через UDP/443;
- одна HTTPS-подписка для [HAPP](https://www.happ.su/main), содержащая все подключения;
- профиль [маршрутизации HAPP](https://www.happ.su/main/ru/dev-docs/routing) на основе
  [RoscomVPN](https://github.com/hydraponique/roscomvpn-routing);
- автоматический rollback обеих нод, если финальная проверка каскада или подписки не прошла.

В конце терминал покажет логин, пароль, порт и WebBasePath каждой панели, а затем одну
ссылку подписки HAPP. Защищённая копия сохранится в
`xray-easy-cascade-install/xray-cascade-access.txt` с правами `0600`.

## Зачем нужен IPv6

Между entry и exit создаются два независимых пути. Основным остаётся IPv4. Если Xray
через [Observatory](https://xtls.github.io/en/config/observatory.html) видит, что IPv4-путь
недоступен, новые соединения переходят на IPv6 через
[balancer fallback](https://xtls.github.io/en/config/routing.html#balancerobject).

Это помогает, если провайдер заблокировал IPv4-адрес или сломалась IPv4-маршрутизация,
но IPv6 продолжает работать. Если заблокированы оба стека, каскад закрывает соединение —
трафик не выпускается напрямую через entry. IPv6 не является гарантией против любой
блокировки: фильтрация может затронуть IPv6, оба адреса или сам протокол.

## Что проверяет установка

Перед фиксацией изменений контроллер обязательно проверяет:

1. обе панели и Xray запущены;
2. entry видит exit как управляемую mTLS-ноду;
3. реальный VLESS/TCP-клиент проходит `entry → exit → интернет`;
4. видимый внешний IP совпадает с IPv4 выходного сервера;
5. XHTTP проходит тем же каскадом;
6. HTTPS-подписка открывается и содержит TCP + XHTTP;
7. HAPP получает включённую маршрутизацию и закреплённый профиль RoscomVPN;
8. временные API-токены не попадают в пользовательскую выдачу.

Если любой пункт не прошёл, обе базы 3x-ui и созданные установщиком файлы откатываются.
Реализация и тесты: [production coordinator](internal/deployprod/deploy.go),
[E2E до commit](internal/deployprod/verify.go),
[rollback и partial-commit tests](internal/deployprod/runtime_test.go),
[lab E2E и fail-closed](internal/deploylab/deploylab_test.go).

## Используемые проекты и документация

- [HAPP — официальный сайт и загрузки](https://www.happ.su/main)
- [HAPP — официальная документация маршрутизации](https://www.happ.su/main/ru/dev-docs/routing)
- [3x-ui — официальный репозиторий](https://github.com/MHSanaei/3x-ui)
- [Закреплённый релиз 3x-ui 3.11.0](https://github.com/MHSanaei/3x-ui/releases/tag/v3.11.0)
- [Xray-core — официальный репозиторий](https://github.com/XTLS/Xray-core)
- [VLESS](https://xtls.github.io/en/config/outbounds/vless.html)
- [REALITY](https://xtls.github.io/en/config/transports/reality.html)
- [XHTTP](https://xtls.github.io/en/config/transports/xhttp.html)
- [Hysteria 2 в Xray](https://xtls.github.io/en/config/transports/hysteria.html)
- [Xray routing и balancer](https://xtls.github.io/en/config/routing.html)
- [Xray Observatory](https://xtls.github.io/en/config/observatory.html)
- [RoscomVPN routing](https://github.com/hydraponique/roscomvpn-routing)

---

## Для опытных пользователей

Одна команда выше запускает рекомендуемый `extended`-профиль. Он включает TCP, XHTTP,
XHTTP+ML-KEM, legacy gRPC, Hysteria 2 и дополнительный межсерверный XHTTP. Упрощённый
профиль можно выбрать так:

```bash
bash <(curl -fsSL https://github.com/b1ts23/xray-easy-cascade/releases/latest/download/install.sh) --profile base
```

### Ручная сборка CLI

```bash
go test ./...
go vet ./...
go build -o vpnctl ./cmd/vpnctl
```

### Ручной workflow

```bash
./vpnctl init --profile extended
./vpnctl plan --inventory inventory.yml
./vpnctl preflight --inventory inventory.yml --known-hosts ~/.ssh/known_hosts
./vpnctl deploy --inventory inventory.yml --known-hosts ~/.ssh/known_hosts
```

`init` создаёт inventory с правами `0600`. `plan` ничего не меняет. `preflight` выполняет
read-only SSH-аудит. `deploy` повторяет plan и preflight, просит подтверждение, устанавливает
обе ноды, выполняет E2E до commit и печатает operator handoff.

### Изолированная лаборатория

```bash
./vpnctl deploy \
  --lab \
  --inventory lab/inventory.yml \
  --known-hosts ~/.ssh/known_hosts \
  --proxy-jump user@lab-host \
  --yes
```

Lab принимает только loopback SSH через jump host, private cascade IP и непривилегированные
порты. Подготовка окружения: [`lab/README.md`](lab/README.md).

### Ограничения

- только двухузловой каскад;
- source of truth для runtime — API и база 3x-ui, а не ручной `config.json`;
- панели не публикуются в интернет и открываются командами `vpnctl panel entry|exit`;
- gRPC оставлен только для совместимости; официальный Xray рекомендует XHTTP;
- запасной транспорт помогает новым подключениям, но не обещает бесшовно продолжить уже
  открытую сессию;
- AmneziaWG/AWG, WARP и Self-SNI в установку не входят.

### Документация проекта

- [Требования](docs/PRODUCT.md)
- [Архитектура](docs/ARCHITECTURE.md)
- [Безопасность](docs/SECURITY.md)
- [Сертификаты](docs/CERTIFICATES.md)
- [RoscomVPN](docs/ROSCOMVPN.md)
- [Транзакции и rollback](docs/TRANSACTIONS.md)
- [Backup/restore](docs/BACKUP-RESTORE.md)
- [Fresh-host E2E](docs/FRESH-HOST-E2E.md)
- [Исследование Bob и Xrayebator](docs/RESEARCH.md)

## Лицензия

GPL-3.0-only. Код проекта написан заново; код исследованных проектов не копировался.
См. [LICENSE](LICENSE).
