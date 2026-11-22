# RoscomVPN routing

В проекте два независимых слоя:

1. `subscription.happ_routing` доставляет адаптированный HAPP-профиль через HTTPS-подписку.
2. `cluster.routing_profile` определяет server-side routing entry: block → entry direct → exit.

Один слой не заменяет другой. Наличие профиля в HAPP не доказывает серверный
выход, а server-side rules не могут передать profile metadata одиночной `vless://`-ссылке.

Оригинальный `DEFAULT` отправляет `category-ru`, `geoip:direct` и ряд публичных сервисов
в client-side `Direct`. Для каскада это недопустимо: сайт увидел бы обычный IP устройства,
а не entry или exit. Поэтому `vpnctl` сначала проверяет точный checksum оригинала, затем строит
профиль `RoscomVPN Cascade`: client-direct остаётся только для `private`, блокировки и закреплённые
geo-assets сохраняются, а весь публичный разрешённый трафик идёт в entry. Уже entry решает,
выпустить соединение напрямую или передать на exit.

## Закреплённая ревизия

- Repository: `hydraponique/roscomvpn-routing`.
- Commit: `bbc59bc58d44f7b39d63ea78cc14f04b87c302a2` (20.11.2026).
- `HAPP/DEFAULT.DEEPLINK` SHA-256:
  `47f637abe2091d64091f7e9b5c6cbac5caf2478a51a779410f2409a99ffe57e0`.
- `HAPP/DEFAULT.JSON` SHA-256:
  `c5edd1adbd9cea81f1265724ab24b4aa7acf7044b9e13534d9af88927f5c0091`.
- GeoIP tag `202611201128`, SHA-256
  `97b323419502b2793e978e92902bbf4a84eb5513cc4f43058c66875d3365b956`.
- GeoSite tag `202610120948`, SHA-256
  `95f15c43e6f3356c51e14a444bc9d99a5e4810640070089b7ba46b31d6cdf001`.

`vpnctl` не скачивает `main`: URL содержит commit/tag, а каждый upstream asset проходит checksum.
Обновление этих констант должно быть отдельным reviewable change, а не фоновой подменой.

## Серверный порядок

1. Штатный API rule 3x-ui сохраняется.
2. `geoip:private`, BitTorrent и RoscomVPN `win-spy`/`torrent`/`category-ads` → `blocked`.
3. RU/BY, whitelist и выбранные сервисы → entry `direct`.
4. GeoIP `direct` → entry `direct`.
5. TCP/UDP только клиентского inbound → balancer `cascade-exit`.

Balancer использует видимые `cascade-exit-ipv4` и, при наличии global IPv6 на обоих VPS,
`cascade-exit-ipv6`. В штатном IPv4-primary режиме IPv4 входит в selector, IPv6 указан как fallback;
без IPv6 fallback равен `blocked`. Опция lowest-latency переводит оба пути в `leastPing`.
`observatory` нужен обоим схемам; default/direct outbound не служит fallback.

В lab runtime фактический порядок подтверждён как `blocked, direct, direct, cascade-exit`.
Сетевой тест с точечными REJECT доказал IPv4 primary, ULA IPv6 fallback, fail-closed без direct-утечки
и recovery. Реальные разные egress IP и public-provider IPv6 на одном Docker host доказать нельзя;
это остаётся production E2E.

## HAPP verification

`vpnctl deploy --lab` проверяет реальный subscription response с User-Agent HAPP:

- HTTP 200 по HTTPS;
- `Routing-Enable: true`;
- наличие `Routing`;
- SHA-256 заголовка совпадает с детерминированно адаптированным deeplink текущего deploy.
- subscription body содержит TCP и XHTTP для одного `subId`; исследовательские PQ/gRPC/Hysteria в released subscription не публикуются.

Секретный subscription URL, `subId` и сам header в output не печатаются.
