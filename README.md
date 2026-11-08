# podkop-user-lists

Личные списки доменов/подсетей для роутинга через Podkop (sing-box).

- `data/own_domains.lst` — свои домены (правится руками), по одному на строку
- `data/own_subnets.lst` — свои подсети (CIDR), по одной на строку

Пустые строки и всё после `#` игнорируются. Некорректная строка не роняет
сборку: она пропускается, а в лог Action попадает предупреждение с привязкой
к номеру строки. Отдельно проверяется перевод строки в конце файла — без него
дописывание в конец склеивает новую запись с последней.

GitHub Actions (`.github/workflows/build.yml`) каждый день, а также при пуше в
`data/`, скачивает актуальные списки [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains)
(cloudflare, cloudfront, digitalocean, meta, discord, google_ai, hetzner,
hodca, ovh, roblox, russia_inside, telegram, google_play) и `google.srs` от
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat),
сливает их со своими списками, чистит дубли/битые записи и публикует
`domains.srs` + `subnets.srs` (sing-box) и `domains.trs` + `subnets.trs`
(формат tachyon-core, грузится быстрее) в [Release `latest`](../../releases/latest).

Отдельно собираются `russia-domains` и `russia-subnets` (.srs и .trs) — российские
адреса для bypass-секции: geoip RU, белые списки runetfreedom и Tachyon, свои
`data/own_ru_subnets.lst`. Эти же подсети вычитаются из `subnets`, чтобы
российские сервисы с IP из реестров блокировок не уходили в туннель.

`russia-domains` — это отдельные российские домены (roscomvpn category-ru и whitelist,
Tachyon geosite_ru, ru_only_inside, ru_whitelist) плюс зоны .ru/.su/.рф и другие
российские TLD целиком. Зоны и широкие домены вроде ucoz.com матчатся логическим
правилом «суффикс И НЕ домен из `domains` И адрес НЕ из `subnets`», так что
заблокированные сайты в этих зонах по-прежнему уходят в туннель.

## Использование в Podkop

```
remote_domain_lists: https://github.com/<owner>/podkop-user-lists/releases/latest/download/domains.srs
remote_subnet_lists: https://github.com/<owner>/podkop-user-lists/releases/latest/download/subnets.srs
```

Для Tachyon с ядром tachyon-core те же списки в `.trs`:

```
https://raw.githubusercontent.com/<owner>/podkop-user-lists/master/dist/domains.trs
https://raw.githubusercontent.com/<owner>/podkop-user-lists/master/dist/subnets.trs
```
