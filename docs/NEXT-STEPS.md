# Текущая граница и следующие шаги

Дата: 22.11.2026.

## Доказано

- два 3x-ui 3.11.0 в изолированном Hetzner lab;
- entry master → exit node с pin-enrollment, затем mTLS и удаление API token;
- базовый профиль TCP/Vision + XHTTP и расширенный opt-in профиль XHTTP+ML-KEM/gRPC/Hysteria 2 через один каскад и одну HAPP-подписку;
- опциональный скрытый interserver XHTTP с ограничением firewall только entry IPv4/IPv6;
- ownership-scoped UFW и SSH/Fail2ban protection с rollback без смены порта или способа входа;
- RoscomVPN client metadata и server-side block/direct/cascade routing;
- IPv4 primary, IPv6 fallback, fail-closed и recovery;
- transactional backup/rollback, повторный idempotent deploy;
- redacted status: entry/exit `READY`; TCP/XHTTP/XHTTP+ML-KEM/gRPC/Hysteria 2 listeners активны.
- guarded reference adoption: IPv4 primary/IPv6 fallback, XHTTP/8443 и Hysteria 2/UDP443
  committed только после server E2E и ручного подтверждения HAPP;
- SSH/Fail2ban hardening на reference RU прошёл config tests, новый SSH login и commit;
- публичный GitHub-репозиторий создан; добавлены checksum-verified bootstrap, `vpnctl install`,
  production E2E до commit и terminal handoff.

## Почему работа не переходит автоматически дальше

Следующие acceptance gates создают внешнее состояние или затрагивают реальную сеть:

1. **WARP E2E** — регистрирует Cloudflare device и создаёт credential. Нужно явное согласие.
2. **Дополнительные provider reports** — независимо повторять installer на чистых VPS и собирать
   только redacted pass/fail evidence.
3. **Lifecycle UX** — подключить production backup/restore/update/uninstall с теми же ownership gates.

Каждая fresh-host установка сама выполняет public-edge TCP/XHTTP, expected exit-IP и HAPP
subscription E2E до commit. При сбое controller откатывает runtime и owned host install обеих ролей.
