# Reference 3x-ui configuration — 21.11.2026

Источник — скриншоты действующей entry-панели владельца. Это визуальный baseline для публичного
установщика, а не разрешение изменять живые RU/NL-серверы. Client IDs, subscription IDs, deeplink и
другие bearer credentials из изображений здесь намеренно не воспроизводятся.

## Что подтверждено

### Client ingress

- один включённый VLESS + TCP + REALITY inbound на `443/tcp`;
- один активный клиент, привязанный к этому inbound;
- quota и expiry не заданы;
- inbound и клиент видны в обычных разделах 3x-ui, а не только в сыром JSON.

### Inter-server egress

- отдельный VLESS + TCP + REALITY outbound на exit IPv4;
- отдельный VLESS + TCP + REALITY outbound на exit IPv6;
- стандартные `direct` (`freedom`) и `blocked` (`blackhole`);
- оба exit outbound входят в один balancer со стратегией `roundRobin`;
- на скриншоте текущей целью balancer был IPv4.

Reference-конфигурация использовала `roundRobin` без доказанного health-aware fallback. Более того,
два selector в `roundRobin` чередуют IPv4/IPv6 в обычном режиме, а не используют IPv6 только
как резерв. Поэтому установщик оставляет оба outbound видимыми, но при `prefer_interserver: ipv4`
включает только IPv4 в selector, а IPv6 задаёт как `fallbackTag`. Observatory определяет недоступность
основного пути. Если IPv6 нет, fallback остаётся `blocked`.

### Server-side routing

Порядок и смысл видимых правил:

1. служебный API inbound → `api`;
2. RoscomVPN GeoIP RU → `direct`;
3. RoscomVPN GeoSite RU/allow-list категории → `direct`;
4. `geoip:private` → `blocked`;
5. клиентский inbound TCP/UDP → balancer exit IPv4/IPv6;
6. BitTorrent → `blocked`.

В таком экранном порядке BitTorrent-rule стоит после более общего client TCP/UDP-rule и потому может
быть недостижим: Xray применяет первое совпавшее правило. Установщик исправляет порядок и ставит
BitTorrent/block до client catch-all.

В installer-managed варианте block-правила ставятся перед direct/catch-all, а каскадное правило
ограничивается тегом клиентского inbound. Служебный API rule 3x-ui сохраняется.

### HAPP subscription

- автоопределение HAPP включено;
- маршрутизация включена;
- в поле правил находится RoscomVPN deeplink;
- шифрование subscription link выключено;
- HAPP No-Limit выключен;
- dropdown preset показывает `Iran Bypass`, но он не является источником истины: установщик передаёт
  закреплённый и проверенный RoscomVPN deeplink напрямую через settings API.

## Отдельно от reference

Remote node в публичном установщике — дополнительный management plane. Он не заменяет видимые
IPv4/IPv6 outbounds и balancer. В главной панели должны одновременно присутствовать:

- управляемый exit в разделе Nodes;
- оба транспортных пути в Outbounds;
- balancer и observatory;
- обычные Inbounds, Clients и Routing rules.

## Результат сверки с документацией

Скриншоты подтвердили правильную общую модель: один client inbound, два межсерверных outbound,
один balancer, server-side direct для выбранных российских назначений и один HAPP subscription.
Но установщик намеренно не копирует три детали reference-конфигурации:

1. BitTorrent/block не остаётся ниже общего TCP/UDP catch-all: правила Xray применяются сверху вниз,
   и первое совпадение завершает выбор маршрута.
2. IPv4-primary не имитируется `roundRobin` из двух путей: добавлен top-level `observatory`,
   IPv4 оставлен в selector, IPv6 стал fallback. Режим `lowest-latency` отдельно использует
   `leastPing` с обоими путями. Ни один режим не имеет fallback в `direct`.
3. Общий catch-all ограничен `inboundTag` клиентского входа. Node API, внутренние проверки панели и
   другой служебный трафик не должны случайно попадать в каскад.

`geoip:private → blocked` на entry также сохранён осознанно. В оригинальном клиентском RoscomVPN
private-сети идут Direct, но на сервере это открыло бы VPN-клиенту доступ к loopback/RFC1918-сетям
самого VPS. Client-side private Direct и server-side private Block — разные уровни политики.

21.11.2026 исправленная схема дважды подряд прошла idempotent container-lab deploy: node остался
`online` в mTLS, cascade E2E вернул HTTP 200, HAPP subscription вернула routing header с ожидаемым
checksum, а повторный запуск не оставил API token у node. После перевода lab bridge на dual-stack
отдельно прошли IPv4-primary, IPv6-fallback, fail-closed без direct-утечки и recovery.
