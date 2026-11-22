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
- публичный GitHub-репозиторий создан; production `deploy` по-прежнему fail-closed.

## Почему работа не переходит автоматически дальше

Следующие acceptance gates создают внешнее состояние или затрагивают реальную сеть:

1. **WARP E2E** — регистрирует Cloudflare device и создаёт credential. Нужно явное согласие.
2. **Production clean-host E2E** — нужны два независимых публичных IP для ACME, UFW, systemd и provider IPv6.
3. **Public production UX** — упаковать внутренний fresh-host controller в безопасную
   `vpnctl deploy`; reference adopt не заменяет clean-host E2E.

До прохождения clean-host E2E публичная production-мутация остаётся fail-closed. Это не мешает
дальше улучшать код и тесты, но не позволяет честно объявить установщик production-ready.

Два новых VPS не нужны для публикации кода. Fresh-host gate может позже выполнить контрибьютор на одноразовых хостах; до этого проект честно остаётся Design Preview.
