# Ownership, backup and rollback

Каждая управляемая мутация должна выполняться внутри двухузловой транзакции.

## Протокол

1. `vpnctl` создаёт случайный 128-bit transaction ID.
2. На exit и entry атомарно создаётся lock в `/var/lib/xray-cascade/lock`.
3. Root-only `ownership.json` проверяет cluster/role и перечисляет только управляемые файлы
   и логические ресурсы 3x-ui.
4. Штатный API 3x-ui `server/getDb` создаёт согласованный snapshot базы; SHA-256 записывается
   в metadata. Отдельно с признаком наличия сохраняются RoscomVPN geo-файлы, разные TLS-сертификаты
   entry/exit, официальный systemd unit/drop-in и текущие UFW rule files.
   Root-only bootstrap panel credentials также входят в encrypted portable backup и rollback snapshot.
5. После изменений выполняются runtime и end-to-end проверки.
6. Только после успешного E2E обе транзакции получают состояние `committed`, затем lock снимается.
7. При любой ошибке `vpnctl` вызывает `server/importDB`, который валидирует SQLite, сохраняет
   собственный fallback и перезапускает Xray/панель. Затем восстанавливаются только файлы из manifest.

Если процесс оператора был прерван и lock остался, lab восстанавливается командой:

```bash
vpnctl rollback --lab --yes \
  --inventory lab/inventory.example.yml \
  --known-hosts lab/.state/known_hosts \
  --proxy-jump root@DOCKER_HOST:22
```

Команда требует одинаковый pending transaction ID на обоих узлах и не принимает public targets.

## Что уже доказано

В Hetzner-lab намеренный сбой после изменения entry автоматически восстановил обе базы и защищаемые
файлы. Fingerprints разных entry/exit сертификатов до и после rollback совпали. Следующий обычный
deploy снова прошёл полный cascade и subscription E2E.

Отдельный portable backup также реализован для lab. `vpnctl backup` потоково получает
согласованную БД и managed files каждого узла, добавляет checksums и шифрует общий archive
на age X25519 recipient. `vpnctl restore` валидирует архив до мутации, открывает новую
двухузловую rollback-транзакцию и commit только после cascade/subscription E2E.
Первый restore выявил гонку отложенного restart 3x-ui и автоматически откатил оба узла;
после двухфазной проверки down/up повторный restore завершился успешно.

Для принятия уже работающего каскада добавлен отдельный internal live-upgrade protocol.
Он делает согласованный API export, запускает worker независимо от SSH и до
мутации взводит transient systemd rollback timer. В isolated lab прошли как forced
rollback, так и commit; механика отмены/срабатывания watchdog дополнительно
проверена на настоящем systemd. Детали: [`LIVE-UPGRADE-REHEARSAL.md`](LIVE-UPGRADE-REHEARSAL.md).
Для reference-каскада commit дополнительно закрыт manual confirmation gate: после server-side E2E
watchdog остаётся взведённым. Без явного подтверждения работы HAPP срабатывает rollback.

## Границы

До production остаются:

- retention и очистка старых committed snapshots;
- аутентификация ownership manifest для `uninstall`;
- репетиция после потери всего independent public VPS;
- повторение full systemd/UFW activation и rollback на двух independent public VPS.

Production `install`/`deploy` подключены к этому coordinator. Отдельные production-команды
`backup`, `restore` и ручной `rollback` пока остаются fail-closed.
