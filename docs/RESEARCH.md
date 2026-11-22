# Исследование исходных проектов

Дата: 20.11.2026.

## Зафиксированные ревизии

| Проект | Commit | Лицензия | Роль |
|---|---|---|---|
| Bob Auto Xray | `0641912bb8a6f494c16e0eccac40fc0db8261cb4` | GPL-3.0 | безопасная установка 3x-ui/Xray |
| Xrayebator | `5346efe1c8b123d5604314adeee9c84e8946f12d` | MIT | каскад, подписки, transactional config |
| 3x-ui | stable `v3.11.0` | GPL-3.0 | панель, API, multi-node |

Исходники анализировались локально во временном каталоге. Живые VPN-серверы не использовались.

## Bob Auto Xray

Полезно:

- закрепление 3x-ui/Xray/GeoData и проверка SHA-256;
- non-interactive установка 3x-ui;
- работа через API панели вместо прямой правки runtime config;
- loopback panel/subscription backends за nginx;
- preflight существующей системы без `ufw reset`;
- атомарный state, resume, doctor, redacted logs;
- сильный набор unit/integration tests.

Не подходит напрямую:

- проект одноузловой;
- требует домен и ориентирован на Self-SNI;
- клиентский профиль направляет российские ресурсы напрямую с устройства;
- автоматическое обновление всей установленной ноды пока не реализовано;
- копирование кода требует GPL-3.0 для производного проекта.

Локальная проверка: запущено 586 unittest на macOS/Python 3.9. 575 прошли, 1 пропущен, 10 ошибок
относятся к среде проверки: девять loopback tests запрещены sandbox, один тест использует SSLContext
API, отсутствующий в Python 3.9. Это не VPS E2E.

## Xrayebator

Полезно:

- серверный cascade outbound и отдельная настройка exit inbound;
- импорт готовой VLESS Reality ссылки upstream;
- backup → candidate → `xray run -test` → apply → rollback;
- interrupt-safe installer и update lifecycle;
- HAPP subscription и корректное разделение client/server routing;
- много regression shell tests;
- MIT позволяет адаптацию с атрибуцией.

Не подходит напрямую:

- связь двух серверов остаётся ручной: параметры exit нужно переносить на entry;
- нет 3x-ui как основной панели;
- основной CLI — монолитный Bash-файл более чем на двадцать тысяч строк;
- в продукт включены AWG, Hysteria, WARP/PQ/GUI и другие поверхности; в нашем проекте они разделены на core, опциональные модули и исключённый AWG;
- один cascade upstream, без доказанного health-aware IPv4/IPv6 failover;
- целевые shell-тесты требуют Linux/Bash 4+, системный macOS Bash 3.2 их не запускает.

## Что берём в собственный проект

| Механизм | Источник идеи | Решение |
|---|---|---|
| Pinning/checksums | Bob, Xrayebator | Обязательно |
| UFW с сохранением SSH | Bob, Xrayebator | Реализовано: только comment-owned rules, без reset/удаления чужих правил |
| SSH Fail2ban | Bob, Xrayebator | Реализован ownership-scoped jail + `sshd -t` + reload + rollback |
| 3x-ui API integration | Bob, official 3x-ui | Обязательно |
| Multi-node/mTLS | official 3x-ui | Entry master, exit node |
| Transactional config | Xrayebator | Обязательно |
| Doctor/status contract | Bob | Обязательно |
| Cascade model | Xrayebator | Автоматизировать end-to-end |
| HAPP subscription | оба проекта + 3x-ui | Через центральную панель |
| AWG | Xrayebator/3x-ui | Исключить |
| Hysteria 2 | Xrayebator + official Xray/3x-ui | Опциональный UDP+TLS-вход; cascade/subscription E2E прошёл 22.11.2026 |
| Self-SNI | Bob/Xrayebator | Отложить |
| Electron GUI | Xrayebator | Не брать в MVP |
| VLESS Encryption ML-KEM | Xrayebator + official Xray/3x-ui | Отдельный opt-in XHTTP inbound; cascade/subscription E2E прошёл 22.11.2026 |
| WARP | official 3x-ui | Планируемый opt-in outbound на exit; не регистровать Cloudflare device без явного согласия |

Не всё из двух upstream-проектов должно входить в первый release. Управление expiry/traffic limits, Telegram-алерты,
DNS-01, четыре формата подписки и SNI probe полезны, но это отдельные operator features, а не основа каскада. Self-SNI,
AWG и автоматическая WARP-регистрация сознательно не переносятся.

## Что означают «7 маршрутов» Xrayebator

Xrayebator публикует семь клиентских вариантов, но это не семь независимых
протоколов. После сверки README и генератора inbound/link принято такое решение:

| Вариант Xrayebator | Серверное отличие | Решение xray-cascade |
|---|---|---|
| `tcp-vision` | TCP + REALITY + Vision | Основной transport, lab E2E |
| `xhttp-legacy` | XHTTP + REALITY, `decryption=none` | Opt-in, lab E2E |
| `xhttp-pq` | отдельный XHTTP inbound с ML-KEM `decryption` | Opt-in `reality-xhttp-pq`, lab E2E; обычный XHTTP не заменяет |
| `grpc` | gRPC + REALITY | Opt-in, lab E2E; Xray 26.10.21 печатает deprecation warning, поэтому не default |
| `tcp-mux` | TCP + REALITY без Vision | Отложен: нужен отдельный порт, а отдельный anti-blocking эффект не доказан |
| `tcp-utls-firefox` | тот же TCP/Vision inbound; иной client fingerprint | Не создавать дублирующий inbound только ради link-parameter |
| `tcp-xudp` | тот же TCP/Vision inbound; `packetEncoding=xudp` в link | Планировать как client-link alias после HAPP E2E, а не как новый серверный transport |

Лабораторный controller доказал пять клиентских входов и одну HAPP-подписку. TCP/Vision + XHTTP
остаются базовым профилем, а XHTTP+ML-KEM, gRPC и Hysteria 2 включаются явно. Межсерверный XHTTP
также допускается как вторичный скрытый путь. gRPC остаётся legacy: Xray печатает deprecation warning.

## Дополнительные официальные возможности

- 3x-ui 3.11.0 имеет REST API, scoped tokens и multi-node управление.
- 3x-ui умеет remote routing sources и geodata presets.
- Xray поддерживает `leastPing` с `observatory` и `leastLoad` с `burstObservatory`.
- Xray 26.10.21 требует TLS для Hysteria 2 и удалил `allowInsecure`; lab использует certificate pin, production — trusted ACME certificate.
- Эти механизмы требуют отдельного E2E: green status не доказывает реальный путь entry → exit → интернет.

## Предварительный технологический выбор

Публичный controller — статически собранный Go CLI. Пользователь скачивает готовый release binary и
вводит команды; Go toolchain на его машине не нужен. На VPS постоянным control daemon остаётся только
3x-ui/Xray. CLI доставляет временный проверенный payload через SSH и удаляет staging после применения.

Этот выбор предпочтительнее большого Bash-скрипта: один бинарник одинаково работает на Linux/macOS,
может безопасно разбирать YAML/JSON, управлять SSH host keys, скрывать секреты из argv и тестироваться
без реальных VPS. Windows планируется через нативный бинарник; WSL остаётся запасным вариантом.
