# podkop-user-lists

Личные списки доменов/подсетей для роутинга через Podkop (sing-box).

- `data/own_domains.lst` — свои домены (правится руками), по одному на строку
- `data/own_subnets.lst` — свои подсети (CIDR), по одной на строку

GitHub Actions (`.github/workflows/build.yml`) каждый день, а также при пуше в
`data/`, скачивает актуальные списки [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains)
(cloudflare, cloudfront, digitalocean, meta, discord, google_ai, hetzner,
hodca, ovh, roblox, russia_inside, telegram, google_play) и `google.srs` от
[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat),
сливает их со своими списками, чистит дубли/битые записи и публикует
`domains.srs` + `subnets.srs` в [Release `latest`](../../releases/latest).

## Использование в Podkop

```
remote_domain_lists: https://github.com/<owner>/podkop-user-lists/releases/latest/download/domains.srs
remote_subnet_lists: https://github.com/<owner>/podkop-user-lists/releases/latest/download/subnets.srs
```
