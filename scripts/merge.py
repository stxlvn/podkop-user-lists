#!/usr/bin/env python3
"""Скачивает enabled-списки itdoginfo + google.srs от MetaCubeX, декомпилирует
через sing-box, сливает с data/own_domains.lst и data/own_subnets.lst,
пишет итог в domains.json / subnets.json (source-формат для sing-box compile)."""
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
METACUBE_URL = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/sing/geo/geoip/google.srs"


def fetch(url, dest):
    urllib.request.urlretrieve(url, dest)


def decompile(srs_path, json_path):
    subprocess.run(["sing-box", "rule-set", "decompile", srs_path, "-o", json_path],
                    check=True, capture_output=True)


def extract(json_path, domains, subnets):
    data = json.load(open(json_path))
    for rule in data.get("rules", []):
        for d in rule.get("domain", []):
            domains.add(d)
        for d in rule.get("domain_suffix", []):
            domains.add(d)
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
        extract(js, domains, subnets)

    fetch(METACUBE_URL, "/tmp/google_meta.srs")
    decompile("/tmp/google_meta.srs", "/tmp/google_meta.json")
    extract("/tmp/google_meta.json", domains, subnets)

    domains.update(l.strip() for l in open("data/own_domains.lst") if l.strip())
    subnets.update(l.strip() for l in open("data/own_subnets.lst") if l.strip())

    print(f"итого: {len(domains)} доменов, {len(subnets)} подсетей")

    json.dump({"version": 3, "rules": [{"domain_suffix": sorted(domains)}]},
              open("domains.json", "w"))
    json.dump({"version": 3, "rules": [{"ip_cidr": sorted(subnets, key=lambda x: (":" in x, x))}]},
              open("subnets.json", "w"))


if __name__ == "__main__":
    main()
