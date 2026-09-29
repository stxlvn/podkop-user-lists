#!/usr/bin/env python3
"""Скачивает enabled-списки itdoginfo + отдельные экстра-источники, декомпилирует
через sing-box, сливает с data/own_domains.lst и data/own_subnets.lst,
пишет итог в domains.json / subnets.json (source-формат для sing-box compile).

Подсети перед записью схлопываются: podkop добавляет каждую строку subnets.srs
в nftables-сет podkop_subnets построчно, с форком на строку, так что время
старта роутера линейно зависит от числа строк."""
import ipaddress
import json
import re
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
    "https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box/rule-set-geosite/geosite-ru-blocked.srs",
    "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/microsoft.srs",
    "https://github.com/MetaCubeX/meta-rules-dat/raw/refs/heads/sing/geo/geosite/google.srs",
]

SUBNET_ONLY_EXTRA_URLS = [
    "https://raw.githubusercontent.com/mudachyo/IP-Ranger/main/ip-lists/ALL-IN-ONE/all-in-one.srs",
]


DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def warn(path, num, line):
    print(f"::warning file={path},line={num}::пропущена некорректная строка: {line.strip()}")


def check_trailing_newline(path):
    with open(path, "rb") as f:
        data = f.read()
    if data and not data.endswith(b"\n"):
        print(f"::warning file={path}::файл не заканчивается переводом строки — "
              f"дописывание в конец склеит новую запись с последней")


def read_own_domains(path):
    check_trailing_newline(path)
    out, skipped = set(), 0
    for num, line in enumerate(open(path), 1):
        s = line.split("#", 1)[0].strip().lower()
        if not s:
            continue
        if DOMAIN_RE.match(s) and all(len(p) <= 63 for p in s.split(".")):
            out.add(s)
        else:
            warn(path, num, line)
            skipped += 1
    if skipped:
        print(f"  {path}: пропущено строк: {skipped}")
    return out


def read_own_subnets(path):
    check_trailing_newline(path)
    out, skipped = set(), 0
    for num, line in enumerate(open(path), 1):
        s = line.split("#", 1)[0].strip()
        if not s:
            continue
        try:
            out.add(str(ipaddress.ip_network(s, strict=False)))
        except ValueError:
            warn(path, num, line)
            skipped += 1
    if skipped:
        print(f"  {path}: пропущено строк: {skipped}")
    return out


def source_label(url):
    parts = url.split("/")
    return f"{parts[3]}/{parts[-1]}" if len(parts) > 4 else url


def fetch(url, dest):
    urllib.request.urlretrieve(url, dest)


def decompile(srs_path, json_path):
    subprocess.run(["sing-box", "rule-set", "decompile", srs_path, "-o", json_path],
                    check=True, capture_output=True)


def extract_domains(json_path):
    data = json.load(open(json_path))
    found = set()
    for rule in data.get("rules", []):
        found.update(rule.get("domain", []))
        found.update(rule.get("domain_suffix", []))
    return found


def extract_subnets(json_path):
    data = json.load(open(json_path))
    found = set()
    for rule in data.get("rules", []):
        for c in rule.get("ip_cidr", []):
            try:
                ipaddress.ip_network(c, strict=False)
                found.add(c)
            except ValueError:
                pass  # битые фрагменты в апстриме — пропускаем
    return found


def merge(label, found, target, report):
    """Складывает найденное в target и запоминает вклад источника."""
    new = found - target
    target |= found
    report.append((label, len(found), len(new), len(found) - len(new)))
    return new


def print_report(title, report, total):
    print(f"\n{title}")
    print(f"  {'источник':<34}{'всего':>8}{'новых':>8}{'дублей':>8}")
    for label, got, new, dup in report:
        print(f"  {label:<34}{got:>8}{new:>8}{dup:>8}")
    print(f"  {'ИТОГО уникальных':<34}{total:>8}")


def drop_covered_subdomains(domains):
    """Убирает поддомены, уже покрытые родительским доменом: при сопоставлении
    по суффиксу example.com и так матчит sub.example.com."""
    kept = set()
    for d in domains:
        parts = d.split(".")
        if any(".".join(parts[i:]) in domains for i in range(1, len(parts) - 1)):
            continue
        kept.add(d)
    return kept


def collapse(subnets):
    out = []
    for version in (4, 6):
        nets = [n for n in (ipaddress.ip_network(c) for c in subnets)
                if n.version == version]
        out += [str(n) for n in ipaddress.collapse_addresses(nets)]
    return set(out)


def main():
    domains, subnets = set(), set()
    domain_report, subnet_report = [], []

    for name in ITDOG_LISTS:
        srs, js = f"/tmp/{name}.srs", f"/tmp/{name}.json"
        fetch(ITDOG_URL.format(name), srs)
        decompile(srs, js)
        merge(f"itdoginfo/{name}", extract_domains(js), domains, domain_report)
        merge(f"itdoginfo/{name}", extract_subnets(js), subnets, subnet_report)

    for i, url in enumerate(DOMAIN_ONLY_EXTRA_URLS):
        srs, js = f"/tmp/dextra{i}.srs", f"/tmp/dextra{i}.json"
        fetch(url, srs)
        decompile(srs, js)
        merge(source_label(url), extract_domains(js), domains, domain_report)

    for i, url in enumerate(SUBNET_ONLY_EXTRA_URLS):
        srs, js = f"/tmp/sextra{i}.srs", f"/tmp/sextra{i}.json"
        fetch(url, srs)
        decompile(srs, js)
        merge(source_label(url), extract_subnets(js), subnets, subnet_report)

    merge("data/own_domains.lst", read_own_domains("data/own_domains.lst"),
          domains, domain_report)
    merge("data/own_subnets.lst", read_own_subnets("data/own_subnets.lst"),
          subnets, subnet_report)

    print_report("ДОМЕНЫ", domain_report, len(domains))
    before_subdomains = len(domains)
    domains = drop_covered_subdomains(domains)
    print(f"  свёрнуто поддоменов (покрыты родительским): "
          f"{before_subdomains - len(domains)} -> остаётся {len(domains)}")

    print_report("ПОДСЕТИ", subnet_report, len(subnets))
    before_collapse = len(subnets)
    subnets = collapse(subnets)
    print(f"  схлопнуто смежных/вложенных: {before_collapse - len(subnets)} "
          f"-> остаётся {len(subnets)}")

    print(f"\nитого: {len(domains)} доменов, {len(subnets)} подсетей")

    json.dump({"version": 3, "rules": [{"domain_suffix": sorted(domains)}]},
              open("domains.json", "w"))
    json.dump({"version": 3, "rules": [{"ip_cidr": sorted(subnets, key=lambda x: (":" in x, x))}]},
              open("subnets.json", "w"))


if __name__ == "__main__":
    main()
