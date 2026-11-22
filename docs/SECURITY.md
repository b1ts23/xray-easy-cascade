# Модель безопасности

## Защищаемые данные

- SSH private keys и passphrases;
- 3x-ui credentials и scoped API tokens;
- VLESS UUID и subscription IDs;
- REALITY private keys и short IDs;
- URL подписок;
- backups базы 3x-ui.

## Базовые правила

1. Секреты не передаются аргументами процессов и не пишутся в shell history.
2. Inventory не содержит паролей, VPN-ключей и subscription URL.
3. Локальный state имеет права `0700/0600`; для переносимого backup требуется шифрование.
4. SSH host key закрепляется до первой мутации. `StrictHostKeyChecking=no` запрещён.
5. Скачиваемые release assets закреплены версией и SHA-256; `main` не исполняется на сервере.
6. API-токены имеют минимальный scope и срок; bootstrap token удаляется после настройки mTLS.
7. Панели и subscription backend не открываются наружу без необходимости.
8. Firewall меняется добавлением узких правил, без `ufw reset` и удаления чужих правил.
9. Uninstall удаляет только пути из подписанного ownership manifest.
10. Логи и диагностические JSON проходят redaction и не содержат bearer credentials.

Lab transaction snapshots имеют режим `0600`, остаются на соответствующем узле, проверяются по
SHA-256 и восстанавливаются штатным import API 3x-ui. Для потери VPS отдельно реализован
age-encrypted off-host backup. Его private identity хранится только у оператора; production
disaster recovery остаётся fail-closed до public-VPS rehearsal.

## Threat model MVP

| Угроза | Базовая защита |
|---|---|
| MITM при первом SSH | Подтверждение fingerprint, сохранение known host |
| Подмена GitHub asset | Версионный URL + опубликованный checksum |
| Утечка секрета через `ps` | stdin/0600-файл, не argv |
| Компрометация публичной панели | SSH tunnel по умолчанию, TLS/rate limit для opt-in |
| Компрометация node token | scoped token, expiry, mTLS, удаление bootstrap token |
| Поломка Xray новым JSON | 3x-ui API candidate + встроенная проверка Xray + rollback |
| Блокировка одного адреса exit | наблюдение IPv4/IPv6 и health-aware выбор |
| Утечка subscription URL | redaction, no-referrer/noindex, rotation |
| Повторный deploy меняет ключи | идемпотентный state и стабильные identifiers |

## Не обещаем в MVP

- анонимность от владельцев VPS и глобального наблюдателя;
- неуязвимость к активному DPI;
- безопасный adopt произвольного существующего сервера;
- zero-downtime upgrade без E2E-доказательства;
- защиту секретов от `root` на уже скомпрометированном VPS.
