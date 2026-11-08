#!/usr/bin/env python3
"""Скачивает enabled-списки itdoginfo + отдельные экстра-источники, декомпилирует
через sing-box, сливает с data/own_domains.lst и data/own_subnets.lst,
пишет итог в domains.json / subnets.json (source-формат для sing-box compile).

Подсети перед записью схлопываются: podkop добавляет каждую строку subnets.srs
в nftables-сет podkop_subnets построчно, с форком на строку, так что время
старта роутера линейно зависит от числа строк."""
import bisect
import ipaddress
import os
import json
import re
import subprocess
import time
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
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/sing-box/geoblock.srs",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/sing-box/ai_all.srs",
]

SUBNET_ONLY_EXTRA_URLS = [
    "https://raw.githubusercontent.com/mudachyo/IP-Ranger/main/ip-lists/ALL-IN-ONE/all-in-one.srs",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/sing-box/twitter.srs",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/sing-box/telegram.srs",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/sing-box/meta.srs",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/sing-box/discord.srs",
]

# в .srs этих списков подсетей нет, они лежат только плоскими .lst
SUBNET_LST_URLS = [
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/subnets/ru_blocked.lst",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/subnets/refilter.lst",
]

# «Россия напрямую» (как в форке fuyriz/podkop-user-lists): эти подсети
# вычитаются из proxy-подсетей и публикуются отдельно для bypass-секции
RU_DOMAIN_SRS_URLS = [
    "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite/release/sing-box/category-ru.srs",
    "https://cdn.jsdelivr.net/gh/hydraponique/roscomvpn-geosite/release/sing-box/whitelist.srs",
]
RU_DOMAIN_LST_URLS = [
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/domains/geosite_ru.lst",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/domains/ru_only_inside.lst",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/domains/ru_whitelist.lst",
]
RU_TLDS = {"ru", "su", "xn--p1ai"}
RU_SUBNET_SRS_URLS = [
    "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/srs/ru.srs",
]
RU_SUBNET_LST_URLS = [
    "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/ru.txt",
    # это российские адреса из «белого списка» на время отключений, а не исключения
    "https://raw.githubusercontent.com/runetfreedom/russia-blocked-geoip/release/text/ru-whitelist.txt",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/subnets/ru_whitelist.lst",
    "https://raw.githubusercontent.com/Dushnilin/tachyon-lists/main/release/subnets/ru_domains.lst",
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


RELEASE_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/releases/(?:latest/download|download/([^/]+))/([^/]+)$")
RAW_RE = re.compile(r"^https://github\.com/([^/]+/[^/]+)/raw/(?:refs/heads/)?(.+)$")
_releases = {}


def github_asset_url(url):
    """Ссылку на файл релиза переводит на API-адрес ассета: веб-редирект
    github.com/.../releases/... периодически отдаёт 504, а API — нет."""
    raw = RAW_RE.match(url)
    if raw:
        return f"https://raw.githubusercontent.com/{raw.group(1)}/{raw.group(2)}", {}
    m = RELEASE_RE.match(url)
    if not m:
        return url, {}
    repo, tag, name = m.groups()
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    key = (repo, tag)
    if key not in _releases:
        api = f"https://api.github.com/repos/{repo}/releases/" + (f"tags/{tag}" if tag else "latest")
        with urllib.request.urlopen(urllib.request.Request(api, headers=headers), timeout=60) as r:
            _releases[key] = {a["name"]: a["url"] for a in json.load(r)["assets"]}
    return _releases[key][name], dict(headers, Accept="application/octet-stream")


def fetch(url, dest, attempts=12):
    for n in range(attempts):
        try:
            real, headers = github_asset_url(url)
            req = urllib.request.Request(real, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:
                f.write(r.read())
            return
        except OSError as e:
            if n == attempts - 1:
                raise
            print(f"  {url}: {e}, повтор через {min(5 * (n + 1), 30)} с")
            time.sleep(min(5 * (n + 1), 30))


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


def read_domain_lst(path):
    found = set()
    for line in open(path, encoding="utf-8"):
        s = line.split("#", 1)[0].strip().lower().lstrip(".")
        if not s:
            continue
        try:
            s = s.encode("idna").decode()
        except UnicodeError:
            continue
        if "." not in s or (DOMAIN_RE.match(s) and all(len(p) <= 63 for p in s.split("."))):
            found.add(s)
    return found


def read_subnet_lst(path):
    found = set()
    for line in open(path):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            found.add(str(ipaddress.ip_network(line, strict=False)))
        except ValueError:
            pass
    return found


def subtract(subnets, removed):
    """subnets минус removed по диапазонам адресов, результат снова в CIDR."""
    out = set()
    for version in (4, 6):
        cut = sorted((int(n.network_address), int(n.broadcast_address))
                     for n in (ipaddress.ip_network(c) for c in removed)
                     if n.version == version)
        merged = []
        for lo, hi in cut:
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        starts = [lo for lo, _ in merged]
        addr = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        for c in subnets:
            n = ipaddress.ip_network(c)
            if n.version != version:
                continue
            lo, hi = int(n.network_address), int(n.broadcast_address)
            i = max(bisect.bisect_right(starts, lo) - 1, 0)
            cur = lo
            while i < len(merged) and merged[i][0] <= hi:
                clo, chi = merged[i]
                if chi >= cur:
                    if clo > cur:
                        out.update(str(x) for x in ipaddress.summarize_address_range(addr(cur), addr(clo - 1)))
                    cur = max(cur, chi + 1)
                i += 1
            if cur <= hi:
                out.update(str(x) for x in ipaddress.summarize_address_range(addr(cur), addr(hi)))
    return out


def build_russia(domain_report, subnet_report):
    domains, subnets = set(), set()
    for i, url in enumerate(RU_DOMAIN_SRS_URLS):
        srs, js = f"/tmp/rud{i}.srs", f"/tmp/rud{i}.json"
        fetch(url, srs)
        decompile(srs, js)
        merge(source_label(url), extract_domains(js), domains, domain_report)
    for i, url in enumerate(RU_DOMAIN_LST_URLS):
        lst = f"/tmp/rudl{i}.lst"
        fetch(url, lst)
        merge(source_label(url), read_domain_lst(lst), domains, domain_report)
    for i, url in enumerate(RU_SUBNET_SRS_URLS):
        srs, js = f"/tmp/rus{i}.srs", f"/tmp/rus{i}.json"
        fetch(url, srs)
        decompile(srs, js)
        merge(source_label(url), extract_subnets(js), subnets, subnet_report)
    for i, url in enumerate(RU_SUBNET_LST_URLS):
        lst = f"/tmp/rul{i}.lst"
        fetch(url, lst)
        merge(source_label(url), read_subnet_lst(lst), subnets, subnet_report)
    merge("data/own_ru_subnets.lst", read_own_subnets("data/own_ru_subnets.lst"),
          subnets, subnet_report)
    tlds = RU_TLDS | {d for d in domains if "." not in d}
    domains = {d for d in domains if "." in d}
    return drop_covered_subdomains(domains), tlds, collapse(subnets)


def russia_domain_rules(ru_domains, tlds, proxy_domains, proxy_subnets):
    """Российские зоны и домены напрямую, но всё, что есть в proxy-списке,
    остаётся в туннеле: зоны (.ru/.su/.рф…) и широкие домены вроде ucoz.com,
    под которыми лежат заблокированные сайты, идут логическим правилом
    «суффикс И НЕ proxy-домен И адрес НЕ из proxy-подсетей» (сайты, которые
    уходят в туннель только по IP, получают от DNS настоящий адрес). Отдельный домен, уже покрытый зоной и не
    задевающий proxy-список, выкидывается как лишний."""
    def ancestors(d):
        parts = d.split(".")
        return {".".join(parts[i:]) for i in range(1, len(parts))}

    proxy_ancestors = set().union(*(ancestors(p) for p in proxy_domains))
    broad = {d for d in ru_domains if d in proxy_ancestors and d not in proxy_domains}
    plain = {d for d in ru_domains - broad
             if d.rsplit(".", 1)[-1] not in tlds
             or d in proxy_domains or ancestors(d) & proxy_domains}
    group = tlds | broad
    excl = {p for p in proxy_domains if ancestors(p) & group}
    rules = [{"domain_suffix": sorted(plain)}]
    zone = {"domain_suffix": sorted(group)}
    zone = {"type": "logical", "mode": "and", "rules": [zone]}
    if excl:
        zone["rules"].append({"domain_suffix": sorted(excl), "invert": True})
    zone["rules"].append({"ip_cidr": sorted(proxy_subnets, key=lambda x: (":" in x, x)),
                          "invert": True})
    rules.append(zone)
    return rules, plain | broad, excl


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

    for i, url in enumerate(SUBNET_LST_URLS):
        lst = f"/tmp/slst{i}.lst"
        fetch(url, lst)
        merge(source_label(url), read_subnet_lst(lst), subnets, subnet_report)

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

    ru_domain_report, ru_subnet_report = [], []
    ru_domains, ru_tlds, ru_subnets = build_russia(ru_domain_report, ru_subnet_report)
    print_report("РОССИЯ НАПРЯМУЮ: ДОМЕНЫ", ru_domain_report, len(ru_domains))
    print_report("РОССИЯ НАПРЯМУЮ: ПОДСЕТИ", ru_subnet_report, len(ru_subnets))
    before_ru = len(subnets)
    subnets = collapse(subtract(subnets, ru_subnets))
    print(f"  proxy-подсети после вычитания российских: {before_ru} -> {len(subnets)}")

    ru_rules, ru_specific, ru_excl = russia_domain_rules(ru_domains, ru_tlds, domains, subnets)
    print(f"  зоны напрямую: {', '.join(sorted(ru_tlds))}; исключений из proxy-списка: {len(ru_excl)}; "
          f"отдельных российских доменов: {len(ru_domains)} -> {len(ru_specific)}")

    print(f"\nитого: {len(domains)} доменов, {len(subnets)} подсетей; "
          f"россия: {len(ru_specific)} доменов + {len(ru_tlds)} зон, {len(ru_subnets)} подсетей")

    json.dump({"version": 3, "rules": [{"domain_suffix": sorted(domains)}]},
              open("domains.json", "w"))
    json.dump({"version": 3, "rules": [{"ip_cidr": sorted(subnets, key=lambda x: (":" in x, x))}]},
              open("subnets.json", "w"))
    json.dump({"version": 3, "rules": ru_rules},
              open("russia-domains.json", "w"))
    json.dump({"version": 3, "rules": [{"ip_cidr": sorted(ru_subnets, key=lambda x: (":" in x, x))}]},
              open("russia-subnets.json", "w"))


if __name__ == "__main__":
    main()
