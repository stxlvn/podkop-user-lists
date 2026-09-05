#!/usr/bin/env python3
"""Скачивает enabled-списки itdoginfo + отдельные экстра-источники, декомпилирует
через sing-box, сливает с data/own_domains.lst и data/own_subnets.lst,
пишет итог в domains.json / subnets.json (source-формат для sing-box compile).

ВАЖНО про размер subnets: помимо попадания в rule_set самого sing-box,
subnets.srs ЕЩЁ парсится Podkop'ом и КАЖДЫЙ элемент добавляется в nftables-сет
podkop_subnets (шлюз перехвата пакетов по IP — нужен для прямых IP-подключений
вроде Telegram MTProto, которые идут в обход DNS/fakeip). На слабом роутере
десятки тысяч элементов эту операцию не тянут — сет остаётся пустым, и такие
подключения тихо перестают тоннелироваться. Поэтому в subnets держим только
itdoginfo-списки + свои — компактно и быстро добавляется в nft. Домены
ограничения на размер не имеют (fakeip/sniff, не nftables-сет), поэтому туда
можно смело подмешивать что угодно."""
import ipaddress
import json
import subprocess
import urllib.request

ITDOG_LISTS = [
    "cloudflare", "cloudfront", "digitalocean", "meta", "discord",
    "google_ai", "hetzner", "hodca", "ovh", "roblox", "russia_inside",
    "telegram", "google_play",
]
ITDOG_URL = "https://github.com/itdoginfo/allow-domains/releases/latest/download/{}.srs"

# домены — сюда можно тащить сколько угодно, ограничений нет
DOMAIN_ONLY_EXTRA_URLS = [
    "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/spotify.srs",
]

# подсети — НЕ добавляем сюда всё подряд (google.srs 8k+, all-in-one 20k+
# записей) — см. пояснение в начале файла. Если понадобится точечно —
# добавлять руками в data/own_subnets.lst, не сюда.
SUBNET_ONLY_EXTRA_URLS = []


def fetch(url, dest):
    urllib.request.urlretrieve(url, dest)


def decompile(srs_path, json_path):
    subprocess.run(["sing-box", "rule-set", "decompile", srs_path, "-o", json_path],
                    check=True, capture_output=True)


def extract_domains(json_path, domains):
    data = json.load(open(json_path))
    for rule in data.get("rules", []):
        for d in rule.get("domain", []):
            domains.add(d)
        for d in rule.get("domain_suffix", []):
            domains.add(d)


def extract_subnets(json_path, subnets):
    data = json.load(open(json_path))
    for rule in data.get("rules", []):
        for c in rule.get("ip_cidr", []):
            try:
                ipaddress.ip_network(c, strict=False)
                subnets.add(c)
            except ValueError:
                pass  # битые фрагменты в апстриме — пропускаем


def main():
    domains, subnets = set(), set()

    for name in ITDOG_LISTS:
        srs, js = f"/tmp/{name}.srs", f"/tmp/{name}.json"
        fetch(ITDOG_URL.format(name), srs)
        decompile(srs, js)
        extract_domains(js, domains)
        extract_subnets(js, subnets)

    for i, url in enumerate(DOMAIN_ONLY_EXTRA_URLS):
        srs, js = f"/tmp/dextra{i}.srs", f"/tmp/dextra{i}.json"
        fetch(url, srs)
        decompile(srs, js)
        extract_domains(js, domains)

    for i, url in enumerate(SUBNET_ONLY_EXTRA_URLS):
        srs, js = f"/tmp/sextra{i}.srs", f"/tmp/sextra{i}.json"
        fetch(url, srs)
        decompile(srs, js)
        extract_subnets(js, subnets)

    domains.update(l.strip() for l in open("data/own_domains.lst") if l.strip())
    subnets.update(l.strip() for l in open("data/own_subnets.lst") if l.strip())

    print(f"итого: {len(domains)} доменов, {len(subnets)} подсетей")

    json.dump({"version": 3, "rules": [{"domain_suffix": sorted(domains)}]},
              open("domains.json", "w"))
    json.dump({"version": 3, "rules": [{"ip_cidr": sorted(subnets, key=lambda x: (":" in x, x))}]},
              open("subnets.json", "w"))


if __name__ == "__main__":
    main()
