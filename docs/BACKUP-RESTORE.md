# Encrypted backup and restore

`vpnctl` реализует полный цикл пока только для isolated lab. Production-команды остаются
fail-closed до репетиции на двух disposable public VPS.

## Ключи

`backup-keygen` создаёт age X25519 identity с правами `0600` и печатает только public recipient.
Приватную identity нужно скопировать в offline storage. Она не попадает в inventory и не
отправляется на сервер. Её потеря делает backup невосстановимым.

## Состав backup

Каждый node export содержит согласованную БД из штатного 3x-ui `server/getDb`, SHA-256 manifest,
ownership metadata, node key state, root-only bootstrap panel credentials, раздельные TLS certificate/key pairs,
trust anchor, RoscomVPN
geo-assets, systemd unit/drop-in и UFW rule files, если они есть. Entry и exit заворачиваются в один
age-encrypted tar со вторым manifest.

Plaintext node archives на диск оператора не пишутся. При restore они появляются только в
root-only `/run` на целевом узле и удаляются cleanup trap.

## Безопасность restore

До мутации controller проверяет все outer members, checksums и cluster identity. Затем создаётся
обычная two-node rollback-транзакция. Exit восстанавливается первым. Tar отклоняет любые
неизвестные path, БД импортируется через `server/importDB`, а readiness обязан увидеть и
отложенную остановку, и новый старт панели.

Commit происходит только после HTTPS 200 через VLESS + REALITY cascade и совпадения HAPP
routing checksum. Любая ошибка вызывает automatic rollback обоих узлов.
