# Разбор Happ 4.3.0 и INCY 3.8.8 — архитектура и что стоит перенять (2026-09-29)

**Статус:** статический анализ установленных артефактов на этом хосте.
Happ — rpm `/opt/happ` (Qt6/QML GUI + root-демон + бандлированные ядра).
INCY — Compose Multiplatform (Kotlin/JVM) JAR, декомпилирован CFR 0.152
(`/tmp/incy-src` — временно); Linux-установка на хосте удалена, анализ по
Windows-пакету `Program Files/INCY` + легacy-конфигам в `~/.config/incy`.

## Happ (`happ-4.3.0-318`)

### Состав
- `bin/Happ` — Qt6/QML GUI (13 МБ, stripped). QML-импорты в `lib/qml`.
  Диплинки `happ://connect|disconnect|toggle|routing|routing/add/…` и
  `happ://crypt/`…`crypt5/` — **пять уровней шифрованных подписочных
  ссылок** для провайдеров.
- `bin/happd` — root-демон (не stripped, символы читаются), systemd
  `Restart=always`. IPC — unix-сокет `/tmp/happd.sock`.
- `bin/core/xray` 26.7.28 + geoip/geosite + `routing/` (каталоги профилей
  роутинга: `~/.local/share/Happ/routing/<subId>/<name>/{geoip,geosite}.dat` —
  per-profile geo-ассеты, как у нас).
- `bin/tun/sing-box` 1.12.12 и `bin/tun2/{libtun2proxy.so,tun2proxy-bin,
  udpgw-server}` — **несколько TUN-движков**: `tun-type` meta-параметр
  принимает `singbox|tun2proxy|default|xray` (xray tun inbound тоже есть).
- `bin/antifilter` — вендорный **byedpi** (CLI-сигнатура `-K proto,
  -H hosts, -j ipset, -V ports, -M mod-http hcsmix/dcsmix/rmspace`) —
  DPI-desync без VPN вообще.
- `happ-diag`, `happ-tcping` — диагностика и TCP-ping (не прокси-ping).

### Демон `happd` (символы)
- `CommunicationServer`/`ClientConnection` — мультиклиентский сокет.
- `HappDaemon`: `onSystemSuspend/onSystemResume`, `isInWakeGrace`
  (grace-окно после пробуждения), `armPendingSessionCleanup`
  (отложенная уборка при смерти GUI — туннель не падает мгновенно),
  `broadcastProcessEvent`.
- `ManagedProcess`/`ProcessManager`: спавнит xray/sing-box по JSON-спеке
  от GUI (`setupProcess`, `buildEnvironment`, `parseArguments`),
  `attemptRestart`, stdout/stderr назад клиенту.
- `ProcessExplorerService/Worker` — **per-app разведка**: список процессов
  + кэш иконок (`pruneIconCache`) → сплит-туннелирование по приложениям.
- `PushService` + `McsClient` + `mcs_proto` (protobuf) — живой FCM/MCS-канал
  к `mtalk.google.com:5228`, heartbeat + reconnect, `HappStateStore`
  (sqlite `/var/lib/happd/state.db`) — пуши от Happ-инфраструктуры.
- `Components::ApplyProxySettings/ClearProxySettings` — системный прокси.
- pkexec-фолбэк: полиси `com.happ.singbox.policy`,
  `com.happ.tun2proxy.policy`, хелперы `happ-kill-singbox`,
  `happ-tun2proxy-wrapper` в `/usr/local/bin`.

### Модель данных
- GUI собирает конфиги сам (`[CONFIG BUILDER] Building VLESS_gRPC_*`),
  демон лишь запускает процессы — **демон = тонкий привилегированный
  process-manager**, вся логика в GUI.
- `routing.json`: профили привязаны к `subscriptionId`
  (`subConfigs[].subscriptionId`, `providerRoutingDisabled`,
  `ignoreProfile`) — отсюда наш баг с неприменённым профилем.
- Подписки: `subs.db` + HWID-параметры (`subsSendHWID`,
  `subsAlternativeHWID`, `subsReadOnlyHWID`), `heartbeat-%1` —
  heartbeat-воркер к провайдеру, `subscription-userinfo` парсинг.
- `happ::TDnsttClient`/`DnsttStats` + `dnstt-probe.json` — **DNSTT**
  (DNS-туннель) клиент для глухих блокировок.
- `premium-fallback.bin` — офлайн-фолбэк премиум-проверки.

## INCY (`incy-desktop-3.8.8.jar`)

### Стек
- Kotlin/JVM + Compose Desktop (JBR), Koin DI, kotlinx-serialization,
  sqlite (`~/.local/share/incy/incy.db`: `servers`, `subscriptions`),
  JNA для libc (`LinuxTun` — прямой `ioctl(TUNSETIFF)`), JBR-runtime в
  комплекте. URL-схемы `incy:`, `awg:`, `amneziawg:` (AmneziaWG!).
- `SingleInstance` — unix-socket IPC: второй запуск форвардит URL в живое
  окно + file-lock.
- `linux/incy-tray.py` — AppIndicator/StatusNotifier мост (stdin/stdout
  JSON) — java.awt.SystemTray мёртв на Wayland, они притащили Python-
  хелпер. Аккуратное решение той же проблемы, что у нас.

### Привилегии и TUN
- `platform/f` — эскалатор: `pkexec --disable-internal-agent` → sudo →
  doas; учитывает `FLATPAK_ID`/`APPIMAGE`, `/etc/os-release` (SteamOS!).
- `service/H` (`XrayHelperRuntime`): ставит `incy-helper-linux.sh` в
  `/usr/lib/incy/` + polkit-экшн `cc.incy.vpn.policy`. Команды хелпера:
  `standalone-up <tun> <uid> <mtu>`, `standalone-apply <cidr> <dnsCsv>
  <routesCsv>`, `standalone-down`, `dns-restore`, `route-cleanup`,
  `stop-xray-tun`. xray под `/var/tmp/incy-xray/` (pid, xray.log,
  config.json), geo-ассеты стейджатся (`stageGeoAssets`).
- macOS-вариант хелпера (`incy-helper.sh`, whitelist команд): TUN через
  **hev-socks5-tunnel** (не xray!), поиск `utun*` по адресу, и главное —
  `route-setup` явно обходит `8.8.8.8/1.1.1.1/9.9.9.9…` через физический
  шлюз: «иначе DNS xray попадает в TUN → петля резолва → CPU storm».
- Windows (`service/D`, WinTun): ждёт регистрации адаптера 30с, ставит
  `0.0.0.0/1`+`128.0.0.0/1` через gw `198.18.0.1` (split-default, не
  трогает дефолт), `Set-NetConnectionProfile Private`, DNS snapshot через
  netsh → restore, `/32`-маршрут сервера через физшлюз, `ipconfig
  /flushdns`, orphan-sweep на останове.
- Kill switch Linux (`platform/o`): iptables-цепь `INCY_KILLSWITCH` —
  RETURN для lo/127/8, `mark 8888` (fwmark самого xray!), `198.18.0.0/15`
  (FakeDNS), multicast/broadcast, dport 53 → `REJECT
  icmp-admin-prohibited`; вешается `iptables -I OUTPUT 1`.

### Движок и фичи
- Движок **только xray** (`tun_incy`, `xray_ping_*.json`). Пинг —
  `pingProtocol: incy`: на каждый сервер поднимается реальный xray с
  временным конфигом и меряется HTTP-задержка через локальный SOCKS —
  честный e2e-ping вместо tcping.
- `xray api statsquery --server=127.0.0.1:10813` — счётчики трафика
  через встроенный API xray.
- preferences.json: `useMux`/`muxConcurrency`/`muxXudpConcurrency`
  (XUDP!), `useFragmentation` (`tlshello`, длина/интервал пакетов),
  `useNoises` (rand-паддинг), `enableFakeDNS` (198.18/15), `remoteDNS`
  DoH `https://1.1.1.1/dns-query` + `domesticDNS`, `captureSystemDns`,
  `killSwitch`, `allowLanConnections/Hotspot/ViaProxy`,
  `bypassPrivateIPs`, `geoTrimEnabled` (тримминг dat под выбранные
  категории!), `routingProfilesEnabled`, `providerTheme`, sendHWID,
  `customUserAgent`, `preferredIPType`.
- Модели (`domain/model`, не обфусцированы): `XrayFullConfig`,
  `RoutingConfig`, `DnsConfig`, `InboundConfig`, `OutboundConfig`,
  `NoiseConfig`, `SniffingConfig`, `SubscriptionConfig.PremiumSettings`,
  `XrayRoutingRule`, `BurstObservatory` (xray observatory для
  url-test/balancer), `ProfileDnsTransport` (per-profile DNS-транспорт).

## Что перенять нам (приоритеты)

1. **Bypass-маршрут сервера `/32` через физический шлюз** — есть и у Happ,
   и у Incy; у нас server-IP без явного маршрута (заложник чужих
   туннелей — реальный инцидент с happ-xray).
2. **Bypass-маршруты публичных DNS** (8.8.8.8/1.1.1.1/9.9.9.9 + custom
   remoteDNS) через физшлюз — Incy прямо называет причину: DNS-петля в
   TUN → CPU storm. У нас DNS на линке — проверить этот сценарий.
3. **Split-default `0.0.0.0/1`+`128.0.0.0/1`** вместо/рядом с `0.0.0.0/0` —
   альтернатива нашему `suppress_prefix_length`-подходу, совместимее с
   чужими туннелями.
4. **Grace-очистка при смерти клиента** (`armPendingSessionCleanup`) и
   wake-grace (`onSystemResume`) — у нас disconnect жёсткий; suspend/resume
   в AGENTS-мишени ещё не покрыт.
5. **stderr xray в лог** — Incy/Happ пишут `xray.log`; у нас `Stdio::null`
   (реальный провал диагностики в этом инциденте).
6. **`xray api statsquery`** для live-счётчиков rx/tx — проще, чем парсинг
   /proc/net/dev по интерфейсу.
7. **E2E-ping через временный xray** (`xray_ping_*.json` + SOCKS на
   loopback) — точнее tcping; переиспользует уже генерируемый конфиг.
8. **Kill switch** — готовый паттерн iptables-цепи (mark-исключение +
   FakeDNS-диапазон + DNS-исключение + REJECT).
9. **FCM/MCS push и DNSTT** — провайдер-фичи, нам не нужны сейчас.
10. **fwmark 8888** у Incy — аналог нашего `transportMark`; проверить, что
    kill-switch/правила учитывают нашу метку так же.
11. Tray на Linux через AppIndicator-пайтон — альтернатива, если статусный
    значок понадобится до поддержки в Tauri.

## Прочие находки

- Happ `tun-type` принимает meta-параметр из подписки — провайдер может
  выбирать движок TUN клиенту (singbox/tun2proxy/xray/default).
- `happ://cryptN/` — шифрованные ссылки подписок; формат не раскрыт
  (строки показывают только схему).
- INCY хранит серверы/подписки в sqlite; Happ — `subs.db` + JSON-конфиги.

## Перенесено в net_manager

Из находок Incy реализовано (на нашей модели `Profile` + `domain_policies`,
без заведения отдельной Happ-сущности):

- **`routing.domainStrategy` / `domainMatcher`** — поля `xrayDomainStrategy`
  (`asIs`/`ipIfNonMatch`/`ipOnDemand`) и `xrayDomainMatcher`
  (`mph`/`hybrid`/`linear`) на `Profile`, эмитятся в `apply_profile_routing`.
- **Split-DNS по Incy** — `profile.xrayDns`: `servers[]` (udp/tcp/tls/
  https/https+local/quic+local/localhost/fakedns, `port`, `domains`,
  `skipFallback`), `route: proxy|direct` пинает адрес резолвера через
  соответствующий outbound (remote-через-прокси / domestic-напрямую);
  пустой `domains` у маршрутизируемого сервера автопривязывается к
  доменам своей группы политик; если все записи доменные — дублируется
  голый catch-all. Правило `port:53 → dns-out` + `dns`-outbound.
- **FakeDNS** — `fakeDns` → секция `fakedns` (`198.18.0.0/16`) +
  `sniffing.destOverride += "fakedns"` на всех inbound, включая TUN.
- **DNS-null для block-доменов** — литеральные block-селекторы
  (`domain:`/`full:`/plain) дополнительно уходят в `dns.hosts → 127.0.0.1`;
  явные `hosts` побеждают.
- **Multicast → block** (`224.0.0.0/4`, `ff00::/8`) при активных правилах.
- **`geosite:cat@attr`** — валидатор теперь пропускает один `@attr`
  (`*`-wildcards разрешены).
- **Geo-кэш по паре URL** — `geoassets/<sha256(geoip+geosite)[:16]>/`,
  профили с одинаковыми URL делят одну копию; при снятых URL кэш не
  трогаем (общий).
- **`.sha256`-sidecar** — перед скачиванием пробуется `<url>.sha256`;
  совпадение с записанным digest пропускает ~20 МБ даунлоада, мисматч
  держит старую копию (или ошибка, если кэша нет).
- **Маскирование логов** — `core::log_sanitize` маскирует публичные
  IPv4/IPv6/домены (`203.0.113.7 → 203.0.x.x`, `api.x.com → *.x.com`),
  сохраняя приватные/локальные адреса и имена файлов; встроено в
  `redact_runtime_log` (log tails) и в `xray log:`-ошибку демона.
- **Импорт Happ-роутинг-профилей** — `core::happ_routing` принимает
  экспорт Happ/Incy (сырой JSON, base64/base64url, `happ://routing/…`
  и `incy://routing/…` диплинки), нормализует регистр ключей и
  lenient-формы (строковые bool, строки вместо массивов) и маппит на
  нашу модель: `DirectSites/ProxySites/BlockSites`+`*Ip` →
  `domain_policies` в порядке `RouteOrder`, `Remote*/Domestic*DNS` →
  `xrayDns.servers` с `route: proxy|direct`, `DnsHosts` → `hosts`,
  `FakeDNS` → `fakeDns`, `DomainStrategy`/`domainMatcher` → поля
  профиля, `Geoipurl`/`Geositeurl` → geo-URL, `bypassPrivateIPs` →
  `privateLanDirect`. UI — «Import Happ routing profile» на вкладке
  маршрутизации формы профиля (команда `parse_happ_routing`,
  превью-заполнение, дальше обычный save). Проигнорированные поля
  (`remoteDnsAddresses`, `GlobalProxy:false`, хеши) возвращаются
  предупреждениями, а не проглатываются.
- **Bypass-маршруты сервера и резолверов** — `add_xray_bypass_routes`
  ставит `/32`/`/128` на IP upstream-сервера и на `dns_bypass`-хосты
  (`XrayConnectParams.dns_bypass`: все `xrayDns`-резолверы с
  `route != proxy` — proxy-резолвер обязан быть достижим внутри туннеля —
  плюс 1.1.1.1/8.8.8.8/9.9.9.9 при full-capture) через физический шлюз;
  имена резолвятся best-effort в демоне, записи журналируются и
  перестраиваются `reconcile_network` при смене uplink-гейтвея.
  Семейный фильтр: резолвер байпасится, только если его family полностью
  захвачена туннелем.
- **Split-default как опция профиля** — `xraySplitDefault` (UI-чекбокс на
  Linux TUN): вместо `0.0.0.0/0` ставятся `0.0.0.0/1`+`128.0.0.0/1`;
  `prepare_xray`/`is_full_route`/`full_coverage` считают каноническую пару
  полным покрытием (та же tunnel-table + policy-rules семантика, `/2` и
  прочие неканонические разбиения по-прежнему отвергаются).
- **Lifetime системных подключений** — первоначальная grace-очистка по
  смерти последнего клиента отменена контрактом
  `ARCHITECTURE_CONTRACT.md` (2026-11-08). Подключения принадлежат демону;
  выход CLI/GUI не отключает их и не требует пользовательского keeper.
  Явное отключение, shutdown и recovery сохраняют очистку ресурсов.
- **Wake на resume** — `watch_suspend_resume` слушает logind
  `PrepareForSleep` по system D-Bus: после пробуждения 2-секундный settle,
  затем общий reconcile (маршруты/DNS/links/bypass-гейтвеи/cond-правила).
  Без D-Bus фича молча выключена — остаются netlink-watch и 10-с тик.
- **Xray statsquery** — в генерируемый TUN-конфиг инжектятся
  `stats`/`api`/`policy.system` + loopback-only `api-in` dokodemo-door на
  детерминированном порту `xray_api_port(mark)` и routing-правило
  `api-in → api`; `XrayProcessRunner::query_stats` дергает
  `xray api statsquery` и парсит `inbound>>>tun-in` downlink/uplink в
  `XrayStatusResult.rxBytes/txBytes` (None при недоступном API —
  например, устаревший staged-конфиг), счётчики доезжают до
  `ProtocolHealth` диагностики.

Не перенесено (осознанно): нативный тримминг `.dat` и MPH-кэш через
`incycore` (у Incy — закрытая Go-библиотека; стоковый Xray сам строит mph),
балансеры/`burstObservatory` (нужна инфраструктура ping/observatory),
`routeOrder` как перечисление (порядок уже выражается порядком политик),
`autorouting`-заголовки подписок (канал пуша правил от провайдера —
спорная фича, у Happ работала нестабильно).
