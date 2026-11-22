# Optional Cloudflare WARP outbound

WARP не входит в core-каскад и не заменяет exit. Если модуль будет включён, топология
остаётся такой:

```text
клиент → entry → exit → direct → интернет
                       └─→ WARP ─→ интернет  (только явно выбранные назначения)
```

## Почему на exit

- entry должен сохранять свой обычный direct egress для RoscomVPN RU-назначений;
- все пути до WARP должны проходить через оба VPS, иначе модуль размывает каскад;
- сбой WARP не должен переключать трафик на entry direct. Безопасный fallback — обычный exit direct
  либо `blocked`, в зависимости от явной политики.

## Что подтверждено в 3x-ui 3.11.0

Закреплённая версия 3x-ui имеет API `/panel/api/xray/warp/{action}`. Доступны регистрация,
чтение/удаление credentials, смена IP, license, interval и MASQUE. Штатный service обращается к
Cloudflare registration API, хранит device/token/private key в settings панели и заполняет
WireGuard outbound с тегом `warp`.

Xrayebator не является источником этой реализации; прежнее утверждение «WARP есть в обоих
репозиториях» исправлено после проверки исходников.

## Safety gate

Реальный WARP E2E не запускается автономно, потому что registration:

- создаёт внешнее device/account state в Cloudflare;
- принимает ToS timestamp;
- добавляет новый долгоживущий credential в backup/restore/rotation lifecycle.

До явного согласия владельца разрешены только local design, mock API tests и генерация plan.
После согласия acceptance должен доказать:

1. обычный cascade egress до и после включения;
2. отдельный WARP egress только для test destination;
3. отсутствие WARP на entry;
4. явный fallback/fail-closed при отказе Cloudflare endpoint;
5. redacted status, encrypted backup/restore и ownership-scoped uninstall credentials.
