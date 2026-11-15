#!/usr/bin/env python3
"""ScopeLens: passive IP scope-attribution helper.

Default mode only queries public registry/intelligence APIs. It never opens a
connection to an investigated IP. Optional Shodan/Censys lookups use their
stored datasets and require API credentials. Optional DNS checks are separate
and use dig/nslookup against the machine's configured resolver.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen


USER_AGENT = "ScopeLens/0.3"
TIMEOUT = 8
RIPESTAT_BASE = "https://stat.ripe.net/data"
BOOTSTRAP_URLS = {
    4: "https://data.iana.org/rdap/ipv4.json",
    6: "https://data.iana.org/rdap/ipv6.json",
}

UI = {
    "ru": {
        "passive_notice": "ScopeLens | напрямую к проверяемым IP не подключается",
        "disclosure": "IP передаются RDAP и RIPEstat; Censys/Shodan — только по флагам.",
        "keywords_prompt": "Ключевые слова или домен (через запятую; Enter — пропустить): ",
        "target_prompt": "Введи один IP-адрес или путь к файлу со списком IP: ",
        "invalid_ip": "Пропущены строки, которые не являются IP-адресами: ",
        "no_valid_ip": "Не найдено корректных IP-адресов.",
        "input_error": "Ошибка ввода",
        "direct": "ЕСТЬ ПРЯМОЕ СОВПАДЕНИЕ — проверить; это не доказательство владения",
        "provider": "СОВПАЛ ТОЛЬКО ПРОВАЙДЕР — связь с организацией не установлена",
        "none": "СОВПАДЕНИЙ НЕТ",
        "not_assessed": "НЕ ОЦЕНЕНО",
        "rdap": "Реестр",
        "bgp": "BGP",
        "hostnames": "Имена хостов",
        "matches": "совпавшие слова",
        "not_found": "не найдено",
        "no_name": "имя не указано",
        "range_unknown": "диапазон неизвестен",
        "country_unknown": "страна неизвестна",
        "none_value": "нет",
        "active_method": "dig и nslookup",
        "active_note": "Только DNS-запросы; скрипт не выполнял HTTP, TCP, TLS, ping, traceroute или сканирование портов.",
        "waiting": "запрос…",
        "lookup_failed": "ошибка запроса",
        "assessment_direct": "Совпало: {terms} ({fields}).",
        "assessment_provider": "Совпали только данные провайдера: {terms}.",
        "assessment_none": "Совпадений с ключевыми словами нет.",
        "assessment_not_set": "Ключевые слова не заданы.",
        "source_label": "Данные",
        "reports_saved": "Отчёты сохранены: {count} JSON-файлов",
        "reports_folder": "Папка",
        "skipped_key": "пропущен: ключ не задан",
        "not_run": "Не запускалась.",
        "report": "  Отчёт",
        "final_labels": "Метки основаны на совпадениях ключевых слов и не подтверждают владение или разрешение на тестирование.",
        "final_network": "Скрипт не отправляет HTTP, TCP, TLS, ping, traceroute или запросы к портам проверяемого IP.",
        "censys_key_prompt": "Введи Censys Personal Access Token (ввод скрыт; Enter — пропустить): ",
        "shodan_key_prompt": "Введи Shodan API key (ввод скрыт; Enter — пропустить): ",
        "censys_skipped": "Censys пропущен: API-токен не указан.",
        "shodan_skipped": "Shodan пропущен: API-ключ не указан.",
        "not_assessed_note": "Ключевые слова не заданы.",
        "direct_note": "Название реестровой записи или имя хоста совпало с ключевым словом; это признак связи, а не доказательство юридического владения или разрешения на тест.",
        "provider_note": "Совпало только поле сети/провайдера; связь с организацией не установлена.",
        "none_note": "В возвращённых полях нет совпадений с заданными словами; это не определяет связь хоста с организацией.",
        "limitation_registry": "Данные реестра описывают регистрацию/назначение адреса, но не обязательно текущего конечного пользователя.",
        "limitation_bgp": "Origin ASN показывает сеть, объявляющую маршрут, а не обязательно клиента, использующего IP.",
        "limitation_observations": "PTR, Censys и Shodan дают признаки связи; данные могут отсутствовать или устареть.",
        "limitation_no_match": "Отсутствие результата или совпадения не доказывает, что организация не связана с хостом.",
        "limitation_authorization": "Этот отчёт не является разрешением на тестирование хоста.",
        "missing_censys": "Censys пропущен: не задан CENSYS_PAT.",
        "missing_shodan": "Shodan пропущен: не задан SHODAN_API_KEY.",
        "query_rdap": "Запрашиваю RDAP…",
        "query_ripestat": "Запрашиваю RIPEstat: BGP и PTR…",
        "query_asn": "Проверяю ASN AS{asn}…",
        "query_censys": "Запрашиваю индекс Censys…",
        "query_shodan": "Запрашиваю индекс Shodan…",
        "host_progress": "Хост {current}/{total}: {ip}",
        "interrupted": "Остановлено пользователем. Уже сохранённые отчёты оставлены на диске.",
        "active_notice": "\nОбе утилиты отправляют DNS-запросы настроенному резолверу.",
        "active_note": "Только DNS-запросы; скрипт не выполнял HTTP, TCP, TLS, ping, traceroute или сканирование портов.",
        "active_host": "DNS для {ip}:",
        "active_ptr": "  PTR: {value}",
        "active_forward": "  {name} — A: {a}; AAAA: {aaaa}",
        "active_tool": "  {tool}:",
        "tool_unavailable": "утилита не установлена",
        "active_only_notice": "ScopeLens | режим только DNS; опрос RDAP, RIPEstat, Censys и Shodan отключён",
        "ptr_label": "PTR",
        "summary_label": "Итог",
        "names_label": "имена",
        "ports_label": "порты",
        "cli_description": "ScopeLens: проверка IP по публичным данным и отдельный режим DNS-проверки.",
        "ip_help": "Один IPv4- или IPv6-адрес",
        "file_help": "Файл со списком IP, по одному адресу в строке",
        "outdir_help": "Папка для JSON-отчётов",
        "censys_help": "Запросить данные Censys; при необходимости запросить токен",
        "shodan_help": "Запросить данные Shodan; при необходимости запросить ключ",
        "active_dns_help": "Выполнить только DNS-проверки через dig и nslookup",
        "lang_help": "Язык вывода",
        "dns_mode_exclusive": "--active-dns запускает только DNS. Не сочетай его с --censys или --shodan.",
        "field_names": {
            "RDAP name": "имя сети в RDAP",
            "RDAP entities and remarks": "организация и примечания RDAP",
            "RIPEstat PTR": "PTR в RIPEstat",
            "Censys hostnames": "имена хостов Censys",
            "Shodan hostnames/domains": "имена и домены Shodan",
        },
    },
    "en": {
        "passive_notice": "ScopeLens | does not connect directly to the investigated IP",
        "disclosure": "Queried IPs are disclosed to the selected RDAP registry and RIPEstat; Censys/Shodan receive them only when enabled.",
        "keywords_prompt": "Organization keywords/domains, comma-separated (Enter to skip): ",
        "target_prompt": "Enter one IP address or a path to a line-by-line IP file: ",
        "invalid_ip": "Skipped entries that are not IP addresses: ",
        "no_valid_ip": "No valid IP addresses were supplied.",
        "input_error": "Input error",
        "direct": "DIRECT MATCH FOUND — review; not ownership proof",
        "provider": "PROVIDER MATCH ONLY — organization link not established",
        "none": "NO MATCH FOUND — unrelated status not established",
        "not_assessed": "NOT ASSESSED",
        "rdap": "RDAP",
        "bgp": "BGP",
        "hostnames": "Hostnames",
        "matches": "keyword matches",
        "not_found": "not found",
        "no_name": "no name",
        "range_unknown": "range unavailable",
        "country_unknown": "country unknown",
        "none_value": "none",
        "active_notice": "\nBoth utilities send DNS queries to the configured resolver.",
        "active_method": "dig and nslookup",
        "active_note": "DNS queries only; no HTTP, TCP, TLS, ping, traceroute, or port scan was run by this script.",
        "waiting": "querying…",
        "lookup_failed": "request failed",
        "assessment_direct": "Matched: {terms} ({fields}).",
        "assessment_provider": "Only provider data matched: {terms}.",
        "assessment_none": "No keyword matches.",
        "assessment_not_set": "No keywords supplied.",
        "source_label": "Evidence",
        "reports_saved": "Reports saved: {count} JSON files",
        "reports_folder": "Folder",
        "skipped_key": "skipped: no key provided",
        "not_run": "Not run.",
        "report": "  Report",
        "final_labels": "Assessment labels are keyword-match indicators, not ownership or authorization decisions.",
        "final_network": "No HTTP, TCP, TLS, ping, traceroute, or port-scan traffic to the target IP is generated by this script.",
        "censys_key_prompt": "Enter Censys Personal Access Token (input hidden; Enter to skip): ",
        "shodan_key_prompt": "Enter Shodan API key (input hidden; Enter to skip): ",
        "censys_skipped": "Censys skipped: no API token provided.",
        "shodan_skipped": "Shodan skipped: no API key provided.",
        "not_assessed_note": "No keywords supplied.",
        "direct_note": "A registry label or hostname matches a keyword; this is evidence of association, not proof of legal ownership or test authorization.",
        "provider_note": "Only a network/provider field matches; this does not establish an organization link.",
        "none_note": "No supplied keyword matched the returned fields; this does not determine whether the host is associated with the organization.",
        "limitation_registry": "Registry data describes address registration/assignment, not necessarily the current end user.",
        "limitation_bgp": "BGP origin ASN identifies the announcing network, not necessarily the organization using the IP.",
        "limitation_observations": "PTR, Censys, and Shodan observations are association evidence and may be missing or stale.",
        "limitation_no_match": "No result or keyword mismatch is not proof that an organization is unrelated.",
        "limitation_authorization": "This report does not grant authorization to test the host.",
        "missing_censys": "Censys skipped: CENSYS_PAT is not set.",
        "missing_shodan": "Shodan skipped: SHODAN_API_KEY is not set.",
        "query_rdap": "Querying RDAP…",
        "query_ripestat": "Querying RIPEstat: BGP and PTR…",
        "query_asn": "Looking up ASN AS{asn}…",
        "query_censys": "Querying the Censys index…",
        "query_shodan": "Querying the Shodan index…",
        "host_progress": "Host {current}/{total}: {ip}",
        "interrupted": "Interrupted by user. Reports already saved remain on disk.",
        "active_host": "DNS for {ip}:",
        "active_ptr": "  PTR: {value}",
        "active_forward": "  {name} — A: {a}; AAAA: {aaaa}",
        "active_tool": "  {tool}:",
        "tool_unavailable": "utility not installed",
        "active_only_notice": "ScopeLens | DNS-only mode; RDAP, RIPEstat, Censys, and Shodan lookups are disabled",
        "ptr_label": "PTR",
        "summary_label": "Result",
        "names_label": "names",
        "ports_label": "ports",
        "cli_description": "ScopeLens: IP attribution from public data, with a separate DNS-only mode.",
        "ip_help": "One IPv4 or IPv6 address",
        "file_help": "File with one IP address per line",
        "outdir_help": "Directory for JSON reports",
        "censys_help": "Query Censys data; prompt for a token if needed",
        "shodan_help": "Query Shodan data; prompt for a key if needed",
        "active_dns_help": "Run DNS checks only, using both dig and nslookup",
        "lang_help": "Output language",
        "dns_mode_exclusive": "--active-dns runs DNS checks only. Do not combine it with --censys or --shodan.",
        "field_names": {},
    },
}


def fetch_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = TIMEOUT,
) -> dict[str, Any]:
    request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            return json.loads(body)
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {"_error": f"{type(exc).__name__}: {exc}", "_url": url}


def fetch_text(url: str, headers: dict[str, str] | None = None) -> str:
    request_headers = {"User-Agent": USER_AGENT}
    if headers:
        request_headers.update(headers)
    request = Request(url, headers=request_headers)
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            return response.read().decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"{type(exc).__name__}: {exc}") from exc


_BOOTSTRAP_CACHE: dict[int, dict[str, Any]] = {}


def rdap_url_for(ip: ipaddress._BaseAddress) -> str:
    family = ip.version
    if family not in _BOOTSTRAP_CACHE:
        _BOOTSTRAP_CACHE[family] = fetch_json(BOOTSTRAP_URLS[family])
    bootstrap = _BOOTSTRAP_CACHE[family]
    if "_error" in bootstrap:
        raise RuntimeError(bootstrap["_error"])

    matches: list[tuple[int, str]] = []
    for prefixes, urls in bootstrap.get("services", []):
        if not urls:
            continue
        for prefix in prefixes:
            try:
                network = ipaddress.ip_network(prefix, strict=False)
            except ValueError:
                continue
            if ip in network:
                matches.append((network.prefixlen, urls[0]))
    if not matches:
        raise RuntimeError("No RDAP service found in the IANA bootstrap data")
    _, base_url = max(matches, key=lambda item: item[0])
    return f"{base_url.rstrip('/')}/ip/{quote(str(ip), safe=':')}"


def rdap_lookup(ip: ipaddress._BaseAddress) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        url = rdap_url_for(ip)
    except RuntimeError as exc:
        return {"_error": str(exc)}, {}
    raw = fetch_json(url)
    if "_error" in raw:
        return raw, {}

    remarks: list[str] = []
    for item in raw.get("remarks", []) or []:
        remarks.extend(str(x) for x in item.get("description", []) or [])

    entities: list[str] = []
    def walk_entities(items: list[dict[str, Any]]) -> None:
        for entity in items or []:
            vcard = entity.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if len(field) >= 4 and field[0] in ("fn", "org"):
                        value = field[3]
                        if isinstance(value, list):
                            value = " ".join(str(part) for part in value if part)
                        if value:
                            entities.append(str(value))
            walk_entities(entity.get("entities", []) or [])

    walk_entities(raw.get("entities", []) or [])
    cidrs = raw.get("cidr0_cidrs", []) or []
    cidr_text = [
        f"{item.get('v4prefix') or item.get('v6prefix')}/{item.get('length')}"
        for item in cidrs
    ]
    summary = {
        "name": raw.get("name"),
        "handle": raw.get("handle"),
        "range": (
            f"{raw.get('startAddress')} - {raw.get('endAddress')}"
            if raw.get("startAddress") or raw.get("endAddress")
            else None
        ),
        "cidrs": cidr_text,
        "country": raw.get("country"),
        "type": raw.get("type"),
        "status": raw.get("status"),
        "entities": sorted(set(entities)),
        "remarks": remarks,
        "rdap_url": url,
    }
    return raw, summary


def ripestat_lookup(endpoint: str, resource: str) -> dict[str, Any]:
    query = urlencode({"resource": resource})
    return fetch_json(f"{RIPESTAT_BASE}/{endpoint}/data.json?{query}")


_ASN_OVERVIEW_CACHE: dict[str, dict[str, Any]] = {}


def ripestat_as_overview(asn: str) -> dict[str, Any]:
    key = str(asn).removeprefix("AS")
    if key not in _ASN_OVERVIEW_CACHE:
        _ASN_OVERVIEW_CACHE[key] = ripestat_lookup("as-overview", f"AS{key}")
    return _ASN_OVERVIEW_CACHE[key]


def ripestat_summary(
    network_raw: dict[str, Any],
    ptr_raw: dict[str, Any],
    asn_overviews: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    network_data = network_raw.get("data", {}) if isinstance(network_raw, dict) else {}
    asn_items = network_data.get("asns", []) or []
    asn_overviews = asn_overviews or {}
    asns = []
    for item in asn_items:
        asn = item.get("asn") if isinstance(item, dict) else item
        overview = asn_overviews.get(str(asn), {})
        overview_data = overview.get("data", {}) if isinstance(overview, dict) else {}
        if isinstance(item, dict):
            asns.append({
                "asn": asn,
                "holder": item.get("holder") or item.get("name") or overview_data.get("holder"),
            })
        else:
            asns.append({"asn": asn, "holder": overview_data.get("holder")})
    ptr_data = ptr_raw.get("data", {}) if isinstance(ptr_raw, dict) else {}
    raw_ptrs = ptr_data.get("result")
    if isinstance(raw_ptrs, str):
        raw_ptrs = [raw_ptrs]
    if not isinstance(raw_ptrs, list):
        raw_ptrs = []
    ptrs = unique_names([value for value in raw_ptrs if isinstance(value, str)])
    return {
        "prefix": network_data.get("prefix"),
        "asns": asns,
        "ptr": ptrs[0] if len(ptrs) == 1 else None,
        "ptrs": ptrs,
        "ptr_error": ptr_data.get("error") or ptr_raw.get("_error"),
    }


def collect_censys(ip: str, token: str) -> dict[str, Any]:
    url = f"https://api.platform.censys.io/v3/global/asset/host/{quote(ip, safe=':')}"
    raw = fetch_json(
        url,
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        },
        timeout=8,
    )
    if "_error" in raw:
        return {"raw": raw, "summary": {"error": raw["_error"], "url": url}}
    result = raw.get("result", raw)
    resource = result.get("resource", result) if isinstance(result, dict) else {}
    dns = resource.get("dns", {}) or {}
    services = resource.get("services", []) or []
    names = dns.get("names", []) or []
    if isinstance(names, str):
        names = [names]
    service_ports = sorted({s.get("port") for s in services if isinstance(s, dict) and s.get("port") is not None})
    network = resource.get("autonomous_system", {}) or {}
    return {
        "raw": raw,
        "summary": {
            "found": True,
            "hostnames": names,
            "service_count": len(services),
            "ports": service_ports,
            "asn": network.get("asn"),
            "as_name": network.get("name") or network.get("description"),
            "url": url,
        },
    }


def collect_shodan(ip: str, api_key: str) -> dict[str, Any]:
    query = urlencode({"key": api_key})
    url = f"https://api.shodan.io/shodan/host/{quote(ip, safe=':')}?{query}"
    raw = fetch_json(url, timeout=8)
    if "_error" in raw or raw.get("error"):
        error = raw.get("_error") or raw.get("error")
        if "_url" in raw:
            raw["_url"] = "https://api.shodan.io/shodan/host/{ip}"
        return {"raw": raw, "summary": {"error": error, "url": "https://api.shodan.io/shodan/host/{ip}"}}
    banners = raw.get("data", []) or []
    return {
        "raw": raw,
        "summary": {
            "found": True,
            "hostnames": raw.get("hostnames", []) or [],
            "domains": raw.get("domains", []) or [],
            "org": raw.get("org"),
            "isp": raw.get("isp"),
            "asn": raw.get("asn"),
            "country": raw.get("country_name"),
            "ports": raw.get("ports", []) or [],
            "banner_count": len(banners),
            "url": "https://api.shodan.io/shodan/host/{ip}",
        },
    }


def unique_names(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        name = value.strip().rstrip(".").lower()
        if not name or name in seen or " " in name or len(name) > 253:
            continue
        if not re.fullmatch(r"[a-z0-9._-]+", name):
            continue
        seen.add(name)
        result.append(name)
    return result


def source_hostnames(report: dict[str, Any]) -> list[str]:
    names: list[Any] = []
    ripe = report.get("ripestat", {}).get("summary", {})
    names.extend(ripe.get("ptrs", []) or [])
    ptr = ripe.get("ptr")
    if ptr:
        names.append(ptr)
    censys = report.get("censys", {}).get("summary", {})
    names.extend(censys.get("hostnames", []) or [])
    shodan = report.get("shodan", {}).get("summary", {})
    names.extend(shodan.get("hostnames", []) or [])
    return unique_names(names)


def keyword_assessment(report: dict[str, Any], keywords: list[str], lang: str) -> dict[str, Any]:
    ui = UI[lang]
    if not keywords:
        return {"label": "NOT_ASSESSED", "matches": [], "note": ui["not_assessed_note"]}

    rdap = report.get("rdap", {}).get("summary", {})
    ripe = report.get("ripestat", {}).get("summary", {})
    censys = report.get("censys", {}).get("summary", {})
    shodan = report.get("shodan", {}).get("summary", {})

    strong_fields: dict[str, str] = {
        "RDAP name": str(rdap.get("name") or ""),
        "RDAP entities and remarks": " ".join(rdap.get("entities", []) + rdap.get("remarks", [])),
        "RIPEstat PTR": " ".join(ripe.get("ptrs", []) or []) + " " + str(ripe.get("ptr") or ""),
        "Censys hostnames": " ".join(censys.get("hostnames", []) or []),
        "Shodan hostnames/domains": " ".join((shodan.get("hostnames", []) or []) + (shodan.get("domains", []) or [])),
    }
    weak_fields: dict[str, str] = {
        "RIPEstat ASN holders": " ".join(str(a.get("holder") or "") for a in ripe.get("asns", [])),
        "Censys ASN name": str(censys.get("as_name") or ""),
        "Shodan organization/ISP": " ".join(str(shodan.get(k) or "") for k in ("org", "isp")),
    }

    matches: list[dict[str, str]] = []
    for keyword in keywords:
        needle = keyword.casefold().strip()
        if not needle:
            continue
        for field_name, value in strong_fields.items():
            if needle in value.casefold():
                matches.append({"keyword": keyword, "field": field_name, "strength": "direct-text-match"})
        for field_name, value in weak_fields.items():
            if needle in value.casefold():
                matches.append({"keyword": keyword, "field": field_name, "strength": "network-provider-match"})

    if any(match["strength"] == "direct-text-match" for match in matches):
        label = "DIRECT_MATCH_REVIEW"
        note = ui["direct_note"]
    elif matches:
        label = "PROVIDER_MATCH_ONLY"
        note = ui["provider_note"]
    else:
        label = "NO_KEYWORD_MATCH"
        note = ui["none_note"]
    return {"label": label, "matches": matches, "note": note}


def enrich_ip(
    ip_text: str,
    keywords: list[str],
    censys_token: str | None,
    shodan_key: str | None,
    lang: str,
) -> dict[str, Any]:
    ui = UI[lang]
    ip = ipaddress.ip_address(ip_text)
    print(f"  {ui['query_rdap']}", flush=True)
    rdap_raw, rdap_summary = rdap_lookup(ip)
    print(f"  {ui['query_ripestat']}", flush=True)
    network_raw = ripestat_lookup("network-info", ip_text)
    network_data = network_raw.get("data", {}) if isinstance(network_raw, dict) else {}
    asn_overviews: dict[str, dict[str, Any]] = {}
    for asn in network_data.get("asns", []) or []:
        asn_value = asn.get("asn") if isinstance(asn, dict) else asn
        if asn_value is not None:
            asn_value = str(asn_value).removeprefix("AS")
            if asn_value not in _ASN_OVERVIEW_CACHE:
                print(f"  {ui['query_asn'].format(asn=asn_value)}", flush=True)
            asn_overviews[asn_value] = ripestat_as_overview(asn_value)
    ptr_raw = ripestat_lookup("reverse-dns-ip", ip_text)

    report: dict[str, Any] = {
        "input_ip": ip_text,
        "queried_at_utc": datetime.now(timezone.utc).isoformat(),
        "rdap": {
            "summary": rdap_summary,
            "raw": rdap_raw,
        },
        "ripestat": {
            "summary": ripestat_summary(network_raw, ptr_raw, asn_overviews),
            "raw_network_info": network_raw,
            "raw_as_overviews": asn_overviews,
            "raw_reverse_dns_ip": ptr_raw,
        },
        "optional_sources": {},
        "active_dns": {"ran": False, "note": ui["not_run"]},
        "limitations": [
            ui["limitation_registry"],
            ui["limitation_bgp"],
            ui["limitation_observations"],
            ui["limitation_no_match"],
            ui["limitation_authorization"],
        ],
        "report_language": lang,
    }

    if censys_token:
        print(f"  {ui['query_censys']}", flush=True)
        report["censys"] = collect_censys(ip_text, censys_token)
        report["optional_sources"]["censys"] = "queried"
    elif censys_token == "":
        report["censys"] = {
            "summary": {"status": "skipped_missing_api_key", "message": ui["missing_censys"]}, "raw": {}
        }
        report["optional_sources"]["censys"] = "skipped_missing_api_key"
    if shodan_key:
        print(f"  {ui['query_shodan']}", flush=True)
        report["shodan"] = collect_shodan(ip_text, shodan_key)
        report["optional_sources"]["shodan"] = "queried"
    elif shodan_key == "":
        report["shodan"] = {
            "summary": {"status": "skipped_missing_api_key", "message": ui["missing_shodan"]}, "raw": {}
        }
        report["optional_sources"]["shodan"] = "skipped_missing_api_key"

    report["keyword_assessment"] = keyword_assessment(report, keywords, lang)
    report["passive_hostnames"] = source_hostnames(report)
    return report


def run_dns_tool(tool: str, query_name: str, record_type: str, reverse: bool = False) -> list[str]:
    executable = shutil.which(tool)
    if not executable:
        return []
    kind = "PTR" if reverse else record_type
    if tool == "dig":
        command = [executable, "+time=2", "+tries=1", "+short"]
        command += ["-x", query_name] if reverse else [kind, query_name]
    else:
        command = [executable, f"-type={kind}", query_name]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return []

    results: list[str] = []
    after_name = False
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if tool == "dig":
            value = stripped.rstrip(".")
            if kind != "PTR":
                try:
                    address = ipaddress.ip_address(value)
                    if address.version == (4 if kind == "A" else 6):
                        results.append(str(address))
                except ValueError:
                    continue
            elif value:
                results.append(value)
            continue

        if kind == "PTR":
            match = re.search(r"(?:name\s*=|^Name:\s*)(\S+)", stripped, re.IGNORECASE)
            if match:
                results.append(match.group(1).rstrip("."))
        elif re.match(r"^Name:\s*", stripped, re.IGNORECASE):
            after_name = True
        elif after_name and re.match(r"^Address(?:es)?:\s*", stripped, re.IGNORECASE):
            value = stripped.split(":", 1)[1].strip().split("#", 1)[0]
            try:
                address = ipaddress.ip_address(value)
                if address.version == (4 if kind == "A" else 6):
                    results.append(str(address))
            except ValueError:
                pass
    return list(dict.fromkeys(results))


def active_dns_checks(reports: list[dict[str, Any]], lang: str) -> None:
    ui = UI[lang]
    print(ui["active_notice"])
    tools = ("dig", "nslookup")
    installed = {tool: shutil.which(tool) is not None for tool in tools}
    for report in reports:
        ip_text = report["input_ip"]
        print(f"\n{ui['active_host'].format(ip=ip_text)}", flush=True)
        ptr_by_tool = {
            tool: run_dns_tool(tool, ip_text, "PTR", reverse=True) if installed[tool] else []
            for tool in tools
        }
        names = unique_names(
            report.get("passive_hostnames", [])
            + [name for answers in ptr_by_tool.values() for name in answers]
        )
        dns_results: dict[str, dict[str, Any]] = {}
        for tool in tools:
            print(ui["active_tool"].format(tool=tool))
            if not installed[tool]:
                print(f"    {ui['tool_unavailable']}")
                dns_results[tool] = {"available": False, "ptr_answers": [], "forward_answers_by_hostname": {}}
                continue
            print(ui["active_ptr"].format(value=", ".join(ptr_by_tool[tool]) or ui["not_found"]))
            forward: dict[str, dict[str, list[str]]] = {}
            for name in names:
                forward[name] = {
                    "A": run_dns_tool(tool, name, "A"),
                    "AAAA": run_dns_tool(tool, name, "AAAA"),
                }
                print(ui["active_forward"].format(
                    name=name,
                    a=", ".join(forward[name]["A"]) or ui["not_found"],
                    aaaa=", ".join(forward[name]["AAAA"]) or ui["not_found"],
                ))
                time.sleep(0.1)
            dns_results[tool] = {
                "available": True,
                "ptr_answers": ptr_by_tool[tool],
                "forward_answers_by_hostname": forward,
            }
        report["active_dns"] = {
            "ran": True,
            "method": ui["active_method"],
            "note": ui["active_note"],
            "results_by_tool": dns_results,
        }


def parse_keywords(text: str) -> list[str]:
    keywords: list[str] = []
    seen: set[str] = set()
    for item in re.split(r"[,;\n]", text):
        value = item.strip()
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            keywords.append(value)
    return keywords


def load_targets(args: argparse.Namespace, lang: str) -> list[str]:
    ui = UI[lang]
    if args.ip:
        raw_lines = [args.ip]
    elif args.file:
        raw_lines = Path(args.file).read_text(encoding="utf-8-sig").splitlines()
    else:
        entered = input(ui["target_prompt"]).strip()
        candidate = Path(entered.strip('"'))
        if candidate.is_file():
            raw_lines = candidate.read_text(encoding="utf-8-sig").splitlines()
        else:
            raw_lines = [entered]

    targets: list[str] = []
    invalid: list[str] = []
    seen: set[str] = set()
    for line in raw_lines:
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            normalized = str(ipaddress.ip_address(value))
        except ValueError:
            invalid.append(value)
            continue
        if normalized not in seen:
            seen.add(normalized)
            targets.append(normalized)
    if invalid:
        print(ui["invalid_ip"] + ", ".join(invalid), file=sys.stderr)
    if not targets:
        raise ValueError(ui["no_valid_ip"])
    return targets


def print_summary(report: dict[str, Any], lang: str) -> None:
    ui = UI[lang]
    assessment = report.get("keyword_assessment", {})
    label = assessment.get("label", "NOT_ASSESSED")
    if label == "DIRECT_MATCH_REVIEW":
        matches = assessment.get("matches", [])
        terms = ", ".join(sorted({m["keyword"] for m in matches}))
        fields = ", ".join(sorted({ui["field_names"].get(m["field"], m["field"]) for m in matches}))
        conclusion = ui["assessment_direct"].format(terms=terms, fields=fields)
    elif label == "PROVIDER_MATCH_ONLY":
        terms = ", ".join(sorted({m["keyword"] for m in assessment.get("matches", [])}))
        conclusion = ui["assessment_provider"].format(terms=terms)
    elif label == "NO_KEYWORD_MATCH":
        conclusion = ui["assessment_none"]
    else:
        conclusion = ui["assessment_not_set"]

    rdap = report.get("rdap", {}).get("summary", {})
    rdap_raw = report.get("rdap", {}).get("raw", {})
    ripe = report.get("ripestat", {}).get("summary", {})
    network_raw = report.get("ripestat", {}).get("raw_network_info", {})
    names = report.get("passive_hostnames", [])
    asn_text = ", ".join(
        f"AS{item['asn']} {item.get('holder') or ''}".strip()
        for item in ripe.get("asns", [])
        if item.get("asn") is not None
    ) or ui["not_found"]
    rdap_error = rdap_raw.get("_error")
    bgp_error = network_raw.get("_error")
    rdap_value = (
        f"{rdap.get('name')} | {rdap.get('range')} | {rdap.get('country')}"
        if rdap.get("name") or rdap.get("range")
        else f"{ui['lookup_failed']}: {rdap_error or ui['not_found']}"
    )
    bgp_value = (
        f"{ripe.get('prefix') or ui['not_found']} | {asn_text}"
        if ripe.get("prefix") or ripe.get("asns")
        else f"{ui['lookup_failed']}: {bgp_error or ui['not_found']}"
    )

    print(f"  {ui['rdap']}: {rdap_value}")
    print(f"  {ui['bgp']}: {bgp_value}")
    print(f"  {ui['ptr_label']}: {', '.join(names) if names else ui['not_found']}")
    for service in ("censys", "shodan"):
        if service in report:
            summary = report[service].get("summary", {})
            if summary.get("error"):
                print(f"  {service.title()}: {summary['error']}")
            elif summary.get("status") == "skipped_missing_api_key":
                print(f"  {service.title()}: {ui['skipped_key']}")
            else:
                hosts = summary.get("hostnames", []) or summary.get("domains", []) or []
                ports = summary.get("ports", [])
                print(f"  {service.title()}: {ui['names_label']}={', '.join(hosts) or ui['not_found']}; {ui['ports_label']}={ports or ui['not_found']}")
    print(f"  {ui['summary_label']}: {conclusion}")


def get_optional_key(enabled: bool, env_name: str, prompt_key: str, lang: str) -> str | None:
    if not enabled:
        return None
    token = os.environ.get(env_name, "").strip()
    if token:
        return token
    if sys.stdin.isatty():
        token = getpass.getpass(UI[lang][prompt_key]).strip()
        return token
    return ""


def save_report(report: dict[str, Any], run_dir: Path) -> Path:
    filename = report["input_ip"].replace(":", "_") + ".json"
    path = run_dir / filename
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def main() -> int:
    language_parser = argparse.ArgumentParser(add_help=False)
    language_parser.add_argument("--lang", choices=("ru", "en"), default="ru")
    language_args, _ = language_parser.parse_known_args()
    ui = UI[language_args.lang]

    parser = argparse.ArgumentParser(description=ui["cli_description"])
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--ip", help=ui["ip_help"])
    source.add_argument("--file", help=ui["file_help"])
    parser.add_argument("--outdir", default="scopelens_reports", help=ui["outdir_help"])
    parser.add_argument("--censys", action="store_true", help=ui["censys_help"])
    parser.add_argument("--shodan", action="store_true", help=ui["shodan_help"])
    parser.add_argument("--active-dns", action="store_true", help=ui["active_dns_help"])
    parser.add_argument("--lang", choices=("ru", "en"), default=language_args.lang, help=ui["lang_help"])
    args = parser.parse_args()

    if args.active_dns and (args.censys or args.shodan):
        parser.error(ui["dns_mode_exclusive"])

    try:
        targets = load_targets(args, args.lang)
    except (OSError, ValueError) as exc:
        print(f"{ui['input_error']}: {exc}", file=sys.stderr)
        return 2

    run_dir = Path(args.outdir) / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir.mkdir(parents=True, exist_ok=True)
    reports: list[dict[str, Any]] = []
    interrupted = False

    if args.active_dns:
        print(ui["active_only_notice"])
        reports = [
            {
                "input_ip": ip_text,
                "queried_at_utc": datetime.now(timezone.utc).isoformat(),
                "passive_hostnames": [],
                "active_dns": {"ran": False, "note": ui["not_run"]},
                "report_language": args.lang,
            }
            for ip_text in targets
        ]
        try:
            active_dns_checks(reports, args.lang)
        except KeyboardInterrupt:
            print(f"\n{ui['interrupted']}")
            interrupted = True
    else:
        print(ui["passive_notice"])
        print(ui["disclosure"])
        keywords = parse_keywords(input(ui["keywords_prompt"]))

        censys_token = get_optional_key(args.censys, "CENSYS_PAT", "censys_key_prompt", args.lang)
        shodan_key = get_optional_key(args.shodan, "SHODAN_API_KEY", "shodan_key_prompt", args.lang)
        if args.censys and not censys_token:
            print(ui["censys_skipped"])
        if args.shodan and not shodan_key:
            print(ui["shodan_skipped"])

        for index, ip_text in enumerate(targets):
            if index:
                print()
            print(ui["host_progress"].format(current=index + 1, total=len(targets), ip=ip_text), flush=True)
            try:
                report = enrich_ip(ip_text, keywords, censys_token, shodan_key, args.lang)
            except KeyboardInterrupt:
                print(f"\n{ui['interrupted']}")
                interrupted = True
                break
            except Exception as exc:  # keep the batch going if one source fails unexpectedly
                report = {
                    "input_ip": ip_text,
                    "queried_at_utc": datetime.now(timezone.utc).isoformat(),
                    "error": f"{type(exc).__name__}: {exc}",
                    "keyword_assessment": {"label": "NOT_ASSESSED", "matches": []},
                    "passive_hostnames": [],
                    "active_dns": {"ran": False, "note": ui["not_run"]},
                    "report_language": args.lang,
                }
            reports.append(report)
            print_summary(report, args.lang)
            save_report(report, run_dir)
            time.sleep(0.35)

    for report in reports:
        save_report(report, run_dir)
    if reports:
        print(f"\n{ui['reports_saved'].format(count=len(reports))}")
        print(f"{ui['reports_folder']}: {run_dir}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
