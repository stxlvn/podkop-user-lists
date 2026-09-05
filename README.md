# podkop-user-lists

Личные списки доменов/подсетей для роутинга через Podkop (sing-box), не покрытые готовыми community-списками ([itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains), [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)).

- `data/domains.lst` — домены, по одному на строку
- `data/subnets.lst` — подсети (CIDR), по одной на строку

При каждом пуше в `data/` GitHub Actions собирает `domains.srs` и `subnets.srs` (формат sing-box rule-set) и публикует их в [Release `latest`](../../releases/latest).

## Использование в Podkop

```
remote_domain_lists: https://github.com/<owner>/podkop-user-lists/releases/latest/download/domains.srs
remote_subnet_lists: https://github.com/<owner>/podkop-user-lists/releases/latest/download/subnets.srs
```
