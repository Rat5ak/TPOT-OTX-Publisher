#!/usr/bin/env python3
import argparse
import json
import logging
import sys
import ipaddress
import os
import re
import time
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Tuple, Optional, List
from urllib.parse import urlparse

import requests

BASE = "https://otx.alienvault.com/api/v1"

# Pin pulse IDs here (shared across all scripts)
PULSE_REGISTRY = "/opt/otx-publisher/pulses.json"

# OTX tuning
OTX_TIMEOUT_GET = 45
OTX_TIMEOUT_CREATE = 180
OTX_TIMEOUT_PATCH = 180
OTX_RETRIES = 3
OTX_RETRY_SLEEP = 3

# Publishing tuning
# IMPORTANT: OTX rejects creates with zero indicators (400: "Can't create pulse without indicators")
CREATE_WITH_EMPTY_INDICATORS = False

# Enrichment tuning
ENRICH_MAX_WINDOW_HOURS = 72  # skip enriched composite agg on big backfills


# ---------------- config / logging ----------------
def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def setup_logger(log_path: Optional[str]):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_path:
        handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("otx-tpot-rolling")


# ---------------- pulse registry helpers ----------------
def load_pulse_id(feed: str) -> Optional[str]:
    try:
        with open(PULSE_REGISTRY, "r") as f:
            data = json.load(f) or {}
        pid = data.get(feed)
        if isinstance(pid, str) and pid.strip():
            return pid.strip()
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def save_pulse_id(feed: str, pulse_id: str) -> None:
    os.makedirs(os.path.dirname(PULSE_REGISTRY), exist_ok=True)
    data = {}
    try:
        if os.path.exists(PULSE_REGISTRY):
            with open(PULSE_REGISTRY, "r") as f:
                data = json.load(f) or {}
    except Exception:
        data = {}
    data[feed] = pulse_id
    tmp = PULSE_REGISTRY + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, PULSE_REGISTRY)


# ---------------- ES helpers ----------------
def _utc_iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()


def es_health(es_host: str, timeout: int) -> bool:
    try:
        r = requests.get(f"{es_host}/_cluster/health", timeout=timeout)
        r.raise_for_status()
        return r.json().get("status") in ("yellow", "green")
    except Exception:
        return False


def es_search(es_host: str, index: str, body: dict, timeout: int):
    url = f"{es_host}/{index}/_search"
    return requests.post(
        url,
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=timeout,
    )


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


def get_local_ipv4s() -> Set[str]:
    """
    Most generic + stable: use local interface IPv4s as "self" IPs.
    This avoids the previous "top dest_ip counts" heuristic which can be wrong
    (eg Suricata flows showing remote public IPs as dest_ip).
    """
    ips: Set[str] = {"127.0.0.1"}
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip_cidr = parts[3]
                ip = ip_cidr.split("/", 1)[0]
                try:
                    ipaddress.ip_address(ip)
                    ips.add(ip)
                except Exception:
                    pass
    except Exception:
        pass
    return ips


# ---------------- URL host helpers ----------------
def _url_host(u: str) -> Optional[str]:
    try:
        netloc = urlparse(u).netloc
        if not netloc:
            return None
        host = netloc.split("@")[-1].split(":")[0].strip("[]")
        return host.lower()
    except Exception:
        return None


def _is_self_url(u: str, local_ips: Set[str]) -> bool:
    host = _url_host(u)
    if not host:
        return False
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        if str(ipaddress.ip_address(host)) in local_ips:
            return True
    except Exception:
        pass

    first = host.split(".")[0]
    if re.fullmatch(r"(?:\d{1,3}-){3}\d{1,3}", first):
        maybe = first.replace("-", ".")
        try:
            if str(ipaddress.ip_address(maybe)) in local_ips:
                return True
        except Exception:
            pass

    try:
        import socket
        addrs = set()
        for _, _, _, _, sockaddr in socket.getaddrinfo(host, None):
            ip = sockaddr[0]
            try:
                ip = str(ipaddress.ip_address(ip))
                addrs.add(ip)
            except Exception:
                pass
        if addrs & local_ips:
            return True
    except Exception:
        pass
    return False


def _suricata_alert_or_not_suricata_filter() -> dict:
    """
    Exclude Suricata flow events everywhere (they create junk like 1.1.1.1/1.0.0.1 from DNS flows),
    but keep Suricata alert events and keep all other sensors unchanged.
    """
    return {
        "bool": {
            "should": [
                {"bool": {"must_not": [{"term": {"type.keyword": "Suricata"}}]}},
                {"bool": {"must": [
                    {"term": {"type.keyword": "Suricata"}},
                    {"term": {"event_type.keyword": "alert"}}
                ]}},
            ],
            "minimum_should_match": 1,
        }
    }


# ---------- enrichment helpers ----------
def es_iter_enriched_ips(
    es_host: str,
    idx_pattern: str,
    ip_field: str,
    start_iso: str,
    end_iso: str,
    timeout: int,
    logger,
):
    after = None
    seen_any = False
    while True:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                        {"exists": {"field": ip_field}},
                        _suricata_alert_or_not_suricata_filter(),
                    ]
                }
            },
            "aggs": {
                "by": {
                    "composite": {
                        "size": 1000,
                        "sources": [{"ip": {"terms": {"field": ip_field}}}],
                        **({"after": after} if after else {}),
                    },
                    "aggs": {
                        "dst_port": {"terms": {"field": "dest_port", "size": 10}},
                        "cc": {"terms": {"field": "geoip.country_code2.keyword", "size": 5}},
                        "proto": {"terms": {"field": "protocol.keyword", "size": 5}},
                        "sensors": {"terms": {"field": "type.keyword", "size": 50}},
                    },
                }
            },
        }
        try:
            r = es_search(es_host, idx_pattern, body, timeout)
            if r.status_code != 200:
                logger.warning(f"enriched agg status={r.status_code} body={r.text[:200]}")
                break
            ag = r.json().get("aggregations", {}).get("by", {})
            buckets = ag.get("buckets", [])
            if buckets:
                seen_any = True
            for b in buckets:
                ip = b.get("key", {}).get("ip")
                if not isinstance(ip, str):
                    continue
                doc_count = int(b.get("doc_count", 0) or 0)
                ports = [int(x.get("key")) for x in b.get("dst_port", {}).get("buckets", [])]
                ccs = [str(x.get("key")) for x in b.get("cc", {}).get("buckets", [])]
                protos = [str(x.get("key")) for x in b.get("proto", {}).get("buckets", [])]
                sensors = [
                    str(x.get("key", "")).lower()
                    for x in b.get("sensors", {}).get("buckets", [])
                    if x.get("key")
                ]
                yield ip, doc_count, ports, ccs, protos, sensors
            after = ag.get("after_key")
            if not after:
                break
        except Exception as e:
            logger.warning(f"enriched agg failed: {e}")
            break
    if not seen_any:
        logger.warning("No IPs via enriched path, falling back to plain IP aggregation.")


# ---------------- IOC collection ----------------
def collect_iocs(cfg: dict, logger: logging.Logger) -> Tuple[Dict[str, Set[str]], dict]:
    es = cfg["elasticsearch"]
    es_host, es_timeout = es["host"], int(es.get("timeout", 15))

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=cfg["pulse"]["time_window_hours"])
    start_iso, end_iso = _utc_iso(start_time), _utc_iso(end_time)

    indices = cfg["indices"]
    idx_pattern = ",".join(indices) if isinstance(indices, list) else str(indices)

    max_indicators = int(cfg["limits"].get("max_indicators", 0))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", True))
    min_events = int(cfg["pulse"].get("min_event_count", 1))

    iocs = {"ipv4": set(), "urls": set(), "hashes": set()}
    meta = {"ipv4": {}, "urls": {}, "hashes": {}, "ipv4_enrich": {}}

    time_query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                _suricata_alert_or_not_suricata_filter(),
            ]
        }
    }

    def composite_iter(idx: str, field: str, key_name: str):
        after = None
        while True:
            body = {
                "size": 0,
                "query": time_query,
                "aggs": {
                    "by": {
                        "composite": {
                            "size": 1000,
                            "sources": [{key_name: {"terms": {"field": field}}}],
                        },
                        "aggs": {"sensors": {"terms": {"field": "type.keyword", "size": 50}}},
                    }
                },
            }
            if after:
                body["aggs"]["by"]["composite"]["after"] = after
            try:
                r = es_search(es_host, idx, body, es_timeout)
                if r.status_code != 200:
                    break
                ag = r.json().get("aggregations", {}).get("by", {})
                for b in ag.get("buckets", []):
                    key = b.get("key", {}).get(key_name)
                    if key is None:
                        continue
                    yield key, int(b.get("doc_count", 0)), [
                        sb.get("key", "").lower()
                        for sb in b.get("sensors", {}).get("buckets", [])
                        if sb.get("key")
                    ]
                after = ag.get("after_key")
                if not after:
                    break
            except Exception as e:
                logger.warning(f"composite agg failed for {idx} field {field}: {e}")
                break

    def norm_ip(val: str) -> Optional[str]:
        if not isinstance(val, str):
            return None
        s = val.strip()
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:\d+$", s):
            s = s.split(":", 1)[0]
        try:
            ip = ipaddress.ip_address(s)
            if ip.is_unspecified:
                return None
            return str(ip)
        except Exception:
            return None

    # self IPs from interfaces (stable, prevents bad "top dest_ip" inference)
    local_ips: Set[str] = get_local_ipv4s()
    logger.info(f"Local/self IPv4s from interfaces: {sorted(local_ips)}")

    # enriched IP path (skip on huge windows)
    ip_counts: Dict[str, int] = {}
    used_enriched = False
    window_hours = int(cfg["pulse"].get("time_window_hours", 1))
    if window_hours <= ENRICH_MAX_WINDOW_HOURS:
        try:
            ip_field = "src_ip.keyword"
            enriched_seen = 0
            for ip, cnt, ports, ccs, protos, sensors in es_iter_enriched_ips(
                es_host, idx_pattern, ip_field, start_iso, end_iso, es_timeout, logger
            ):
                if cnt < min_events:
                    continue
                if exclude_private and is_private_ip(ip):
                    continue
                if ip in local_ips:
                    continue

                ip_counts[ip] = ip_counts.get(ip, 0) + cnt
                iocs["ipv4"].add(ip)
                if sensors:
                    meta["ipv4"].setdefault(ip, set()).update(sensors)
                else:
                    meta["ipv4"].setdefault(ip, set())

                def _take(xs, n):
                    return [str(x) for x in xs[:n] if (x or x == 0)]

                ports_s = ",".join(_take(sorted(set(ports)), 5))
                ccs_s = ",".join(_take(ccs, 5))
                protos_s = ",".join(_take(protos, 5))

                parts = []
                if ccs_s:
                    parts.append(f"geo={ccs_s}")
                if ports_s:
                    parts.append(f"ports={ports_s}")
                if protos_s:
                    parts.append(f"proto={protos_s}")
                if parts:
                    meta["ipv4_enrich"][ip] = "; ".join(parts)

                enriched_seen += 1

            if enriched_seen:
                used_enriched = True
            else:
                logger.warning("No IPs via enriched path, falling back to plain IP aggregation.")
        except Exception as e:
            logger.warning(f"Enriched IP path errored: {e}. Falling back to plain IP aggregation.")
    else:
        logger.info(f"Skipping enriched IP path for large window ({window_hours}h)")

    # fallback plain IP aggregation
    if not used_enriched:
        src_fields = ["src_ip.keyword", "source_ip.keyword", "client_ip.keyword"]
        for idx in indices:
            for fld in src_fields:
                try:
                    for ip_raw, cnt, sensors in composite_iter(idx, fld, "ip"):
                        ip = norm_ip(ip_raw)
                        if not ip or cnt < min_events:
                            continue
                        if exclude_private and is_private_ip(ip):
                            continue
                        if ip in local_ips:
                            continue
                        ip_counts[ip] = ip_counts.get(ip, 0) + cnt
                        iocs["ipv4"].add(ip)
                        if sensors:
                            meta["ipv4"].setdefault(ip, set()).update(sensors)
                        else:
                            meta["ipv4"].setdefault(ip, set())
                except Exception as e:
                    logger.warning(f"IP agg iterate failed for {idx} {fld}: {e}")

    # URLs
    url_fields = [
        "url.keyword", "http.url.keyword", "request.url.keyword",
        "url", "http.url", "request.url",
    ]
    for idx in indices:
        for fld in url_fields:
            try:
                for u, _, sensors in composite_iter(idx, fld, "u"):
                    if not isinstance(u, str):
                        continue
                    if not (u.startswith("http://") or u.startswith("https://")):
                        continue
                    if _is_self_url(u, local_ips):
                        continue
                    iocs["urls"].add(u)
                    if sensors:
                        meta["urls"].setdefault(u, set()).update(sensors)
                    else:
                        meta["urls"].setdefault(u, set())
            except Exception:
                continue

    # Hashes
    hash_fields = [
        "sha256.keyword", "fileinfo.sha256.keyword", "files.sha256.keyword",
        "sha256", "fileinfo.sha256", "files.sha256",
    ]
    for idx in indices:
        for fld in hash_fields:
            try:
                for hv, _, sensors in composite_iter(idx, fld, "h"):
                    if not isinstance(hv, str) or len(hv) not in (32, 40, 64, 128):
                        continue
                    hv = hv.lower()
                    iocs["hashes"].add(hv)
                    if sensors:
                        meta["hashes"].setdefault(hv, set()).update(sensors)
                    else:
                        meta["hashes"].setdefault(hv, set())
            except Exception:
                continue

    # Hashes from shasum for download/upload events
    download_eids = [
        "cowrie.session.file_download",
        "adbhoney.session.file_download",
        "cowrie.session.file_upload",
        "adbhoney.session.file_upload",
    ]
    for idx in indices:
        after = None
        while True:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}},
                            {"terms": {"eventid.keyword": download_eids}},
                            _suricata_alert_or_not_suricata_filter(),
                        ]
                    }
                },
                "aggs": {
                    "by": {
                        "composite": {
                            "size": 1000,
                            "sources": [{"h": {"terms": {"field": "shasum.keyword"}}}],
                            **({"after": after} if after else {}),
                        },
                        "aggs": {"sensors": {"terms": {"field": "type.keyword", "size": 50}}},
                    }
                },
            }
            try:
                r = es_search(es_host, idx, body, es_timeout)
                if r.status_code != 200:
                    break
                ag = r.json().get("aggregations", {}).get("by", {})
                for b in ag.get("buckets", []):
                    hv = b.get("key", {}).get("h")
                    if not isinstance(hv, str) or len(hv) not in (32, 40, 64, 128):
                        continue
                    hv = hv.lower()
                    iocs["hashes"].add(hv)
                    sensors = [
                        sb.get("key", "").lower()
                        for sb in b.get("sensors", {}).get("buckets", [])
                        if sb.get("key")
                    ]
                    if sensors:
                        meta["hashes"].setdefault(hv, set()).update(sensors)
                    else:
                        meta["hashes"].setdefault(hv, set())
                after = ag.get("after_key")
                if not after:
                    break
            except Exception:
                break

    # respect max_indicators but keep URLs/Hashes
    if max_indicators > 0:
        non_ip = len(iocs["urls"]) + len(iocs["hashes"])
        room_for_ips = max(0, max_indicators - non_ip)
        if len(iocs["ipv4"]) > room_for_ips:
            sorted_ips = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)
            keep = set(ip for ip, _ in sorted_ips[:room_for_ips])
            iocs["ipv4"] = keep
            meta["ipv4"] = {k: v for k, v in meta["ipv4"].items() if k in keep}
            meta["ipv4_enrich"] = {k: v for k, v in meta.get("ipv4_enrich", {}).items() if k in keep}
            logging.getLogger("otx-tpot-rolling").warning(
                f"trimmed IPv4s to {room_for_ips} due to max_indicators"
            )

    return iocs, meta


# ---------------- OTX helpers ----------------
def otx_headers(api_key: str) -> dict:
    return {
        "X-OTX-API-KEY": api_key,
        "User-Agent": "otx-tpot-rolling/1.0",
        "Content-Type": "application/json",
    }


def req_with_retries(method: str, url: str, headers: dict, data: Optional[str], timeout: int, logger):
    last_err = None
    for attempt in range(1, OTX_RETRIES + 1):
        try:
            if method == "GET":
                return requests.get(url, headers=headers, timeout=timeout)
            if method == "POST":
                return requests.post(url, headers=headers, data=data, timeout=timeout)
            if method == "PATCH":
                return requests.patch(url, headers=headers, data=data, timeout=timeout)
            raise ValueError("unsupported method")
        except Exception as e:
            last_err = e
            logger.warning(f"OTX {method} failed attempt {attempt}/{OTX_RETRIES}: {e}")
            if attempt < OTX_RETRIES:
                time.sleep(OTX_RETRY_SLEEP)
    raise last_err


def test_otx(api_key: str, logger) -> bool:
    try:
        r = req_with_retries(
            "GET",
            f"{BASE}/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": "otx-tpot-rolling/1.0"},
            data=None,
            timeout=10,
            logger=logger,
        )
        ok = r.status_code == 200
        if not ok:
            logger.error(f"OTX auth failed: {r.status_code} {r.text[:200]}")
        return ok
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False


def get_pulse(api_key: str, pulse_id: str, logger) -> Optional[dict]:
    headers = otx_headers(api_key)
    try:
        r = req_with_retries(
            "GET",
            f"{BASE}/pulses/{pulse_id}",
            headers=headers,
            data=None,
            timeout=OTX_TIMEOUT_GET,
            logger=logger,
        )
        if r.status_code != 200:
            logger.error(f"OTX get pulse {pulse_id} failed: {r.status_code} {r.text[:300]}")
            return None
        return r.json()
    except Exception as e:
        logger.error(f"OTX get pulse {pulse_id} exception: {e}")
        return None


def create_pulse(
    api_key: str,
    name: str,
    description: str,
    tlp: str,
    tags: List[str],
    indicators: List[dict],
    public: bool,
    logger,
    dry_run: bool,
) -> Optional[str]:
    headers = otx_headers(api_key)

    body = {
        "name": name,
        "description": description,
        "public": public,
        "TLP": tlp,
        "tags": tags,
        "indicators": indicators,  # MUST NOT be empty or OTX returns 400
    }

    if dry_run:
        logger.info(f"[DRY-RUN] Would CREATE monthly T-Pot pulse '{name}' with {len(indicators)} indicators")
        return None

    try:
        r = req_with_retries(
            "POST",
            f"{BASE}/pulses/create",
            headers=headers,
            data=json.dumps(body),
            timeout=OTX_TIMEOUT_CREATE,
            logger=logger,
        )
    except Exception as e:
        logger.error(f"Create pulse request failed: {e}")
        return None

    if r.status_code >= 400:
        logger.error(f"Create pulse failed {r.status_code}: {r.text[:500]}")
        return None

    created = r.json()
    pid = created.get("id")
    logger.info(
        f"Created monthly T-Pot pulse '{created.get('name','(no name)')}' (id={pid}) "
        f"with {len(indicators)} indicators"
    )
    return pid


def add_indicators(
    api_key: str,
    pulse_id: str,
    to_add: List[dict],
    logger,
    dry_run: bool,
) -> bool:
    if not to_add:
        logger.info("No new indicators to add to monthly T-Pot pulse.")
        return True

    headers = otx_headers(api_key)

    ipv4s = sum(1 for i in to_add if i.get("type") == "IPv4")
    urls = sum(1 for i in to_add if i.get("type") == "URL")
    hashes = sum(1 for i in to_add if str(i.get("type", "")).startswith("FileHash"))

    logger.info(
        f"Monthly T-Pot pulse {pulse_id}: adding {len(to_add)} indicators "
        f"({ipv4s} IPv4s, {urls} URLs, {hashes} hashes)"
    )

    if dry_run:
        logger.info(f"[DRY-RUN] Would PATCH pulse {pulse_id} adding {len(to_add)} indicators")
        return True

    body = {"indicators": {"add": to_add}}

    try:
        r = req_with_retries(
            "PATCH",
            f"{BASE}/pulses/{pulse_id}",
            headers=headers,
            data=json.dumps(body),
            timeout=OTX_TIMEOUT_PATCH,
            logger=logger,
        )
    except Exception as e:
        logger.error(f"OTX patch failed: {e}")
        return False

    if r.status_code >= 400:
        logger.error(f"OTX update error {r.status_code}: {r.text[:2000]}")
        return False

    logger.info(f"Patched pulse {pulse_id} with {len(to_add)} indicators")
    return True


# ---------------- role + indicator building ----------------
def _role_for(ioc_type: str, sensors: Set[str]) -> str:
    s = {str(x).lower() for x in (sensors or [])}
    t = (ioc_type or "").upper()
    if t == "URL":
        return "malware_hosting"
    if t in ("IPV4", "IPV6"):
        if {"cowrie", "honeytrap"} & s:
            return "scanning_host"
        return "unknown"
    return "unknown"


def build_indicators(cfg: dict, iocs: Dict[str, Set[str]], meta: dict) -> List[dict]:
    window = int(cfg["pulse"].get("time_window_hours", 1))
    me = int((cfg.get("pulse", {}) or {}).get("min_event_count", 1))
    loc = str((cfg.get("pulse", {}) or {}).get("location_label", "")).strip()
    include_title = bool((cfg.get("pulse", {}) or {}).get("include_sensor_in_title", True))

    def _clean_tags(tags):
        t = sorted(set(tags))
        return [x for x in t if x != "unknown"] or ["unknown"]

    def title_with(sensors: List[str], base: str) -> str:
        if not include_title:
            return base
        visible = [t for t in sensors if not (isinstance(t, str) and str(t).startswith("role:"))]
        ss = ", ".join(sorted(set(visible))) if visible else "unknown"
        return f"{base} • {ss}"

    def desc_for(sensors: List[str], indicator: Optional[str] = None) -> str:
        s = (
            ", ".join(sorted(set([t for t in sensors if not str(t).startswith("role:")])))
            or "unknown"
        )
        base = f"Observed on T-Pot within last {window}h; sensors={s}; threshold≥{me}; private IPs excluded."
        if indicator and indicator in meta.get("ipv4_enrich", {}):
            base += f" {meta['ipv4_enrich'][indicator]}"
        if loc:
            base += f" Location={loc}."
        return base

    indicators: List[dict] = []

    for ip in sorted(iocs.get("ipv4", [])):
        sensors = sorted(meta["ipv4"].get(ip, set())) or ["unknown"]
        tags = _clean_tags(sensors)
        indicators.append(
            {
                "indicator": ip,
                "type": "IPv4",
                "title": title_with(tags, "Attacker IP"),
                "description": desc_for(tags, indicator=ip),
                "tags": tags,
                "role": _role_for("IPv4", set(sensors)),
            }
        )

    for u in sorted(iocs.get("urls", [])):
        sensors = sorted(meta["urls"].get(u, set())) or ["unknown"]
        tags = _clean_tags(sensors)
        indicators.append(
            {
                "indicator": u,
                "type": "URL",
                "title": title_with(tags, "Payload URL"),
                "description": desc_for(tags),
                "tags": tags,
                "role": _role_for("URL", set(sensors)),
            }
        )

    for h in sorted(iocs.get("hashes", [])):
        itype = "FileHash-SHA256" if len(h) == 64 else ("FileHash-MD5" if len(h) == 32 else "FileHash")
        sensors = sorted(meta["hashes"].get(h, set())) or ["unknown"]
        tags = _clean_tags(sensors)
        indicators.append(
            {
                "indicator": h,
                "type": itype,
                "title": title_with(tags, "Dropped File Hash"),
                "description": desc_for(tags),
                "tags": tags,
            }
        )

    return indicators


# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--window-hours", type=int, help="override window hours (lookback for ES)")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.window_hours:
        cfg.setdefault("pulse", {})["time_window_hours"] = int(args.window_hours)

    logger = setup_logger(cfg.get("log_path"))

    es_host = cfg["elasticsearch"]["host"]
    es_timeout = int(cfg["elasticsearch"].get("timeout", 15))

    if not es_health(es_host, es_timeout):
        logger.error("Elasticsearch unhealthy/unreachable")
        return
    if not test_otx(cfg["otx_api_key"], logger):
        return

    iocs, meta = collect_iocs(cfg, logger)
    total = sum(len(v) for v in iocs.values())
    logger.info(
        f"[rolling] Collected IOCs total={total} (IPs={len(iocs['ipv4'])}, URLs={len(iocs['urls'])}, Hashes={len(iocs['hashes'])})"
    )
    if total == 0:
        logger.warning("No IOCs found in window; skipping")
        return

    indicators = build_indicators(cfg, iocs, meta)
    if not indicators:
        logger.warning("No indicators built; skipping")
        return

    tlp = str(cfg["pulse"].get("tlp", "green")).upper()
    prefix = cfg["pulse"].get("name_prefix", "Honeypot Data - T-Pot")
    loc = str(cfg["pulse"].get("location_label", "")).strip()
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")

    # Month-aware feed key so January rolls over automatically
    feed_key = f"tpot_monthly_{now.strftime('%Y-%m')}"

    if loc:
        name = f"{prefix} - {loc} - {month_label}"
    else:
        name = f"{prefix} - {month_label}"

    desc = (
        f"Rolling monthly view for {month_label} of indicators observed by T-Pot CE honeypots. "
        f"Each run looks back the last {hours}h and appends newly seen indicators for this month. "
        f"Signals are deduped and filtered (min event count threshold; private IPs excluded). "
        f"Intended for defensive use; infrastructure may be compromised or spoofed. Sensor: T-Pot CE."
    )
    if loc:
        desc += f" Location: {loc}."

    tags = cfg.get("pulse", {}).get("tags") or [
        "tpot", "honeypot", "sensor-tagged", "cowrie", "suricata", "dionaea",
        "honeytrap", "p0f", "fatt", "mailoney", "tanner", "sentrypeer"
    ]
    public = tlp == "GREEN"
    api_key = cfg["otx_api_key"]

    logger.info(f"T-Pot monthly window has {len(indicators)} indicators for {month_label}")

    pulse_id = load_pulse_id(feed_key)

    if not pulse_id:
        pulse_id = create_pulse(
            api_key, name, desc, tlp, tags, indicators, public, logger, args.dry_run
        )
        if pulse_id and not args.dry_run:
            save_pulse_id(feed_key, pulse_id)
            logger.info(f"Pinned pulse id for {feed_key} -> {pulse_id} in {PULSE_REGISTRY}")
        return

    existing = get_pulse(api_key, pulse_id, logger)
    if existing is None:
        logger.error(f"Could not fetch existing T-Pot monthly pulse {pulse_id}; aborting patch.")
        return

    pname = existing.get("name", "")
    if not isinstance(pname, str) or (prefix not in pname):
        logger.error(
            "Pulse ID safety check failed. "
            f"Expected pulse name to contain '{prefix}', got '{pname}'. "
            "Refusing to publish."
        )
        return

    existing_inds = existing.get("indicators") or []
    existing_keys = {
        (i.get("indicator"), i.get("type"))
        for i in existing_inds
        if isinstance(i, dict)
    }

    to_add: List[dict] = []
    for ind in indicators:
        key = (ind.get("indicator"), ind.get("type"))
        if key not in existing_keys:
            to_add.append(ind)

    logger.info(
        f"T-Pot monthly pulse {pulse_id}: {len(indicators)} indicators in this window, "
        f"{len(to_add)} are new after dedupe"
    )

    add_indicators(api_key, pulse_id, to_add, logger, args.dry_run)


if __name__ == "__main__":
    main()
