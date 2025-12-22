#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, re, os
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Set, Optional, List
import requests

BASE = "https://otx.alienvault.com/api/v1"

PULSE_REGISTRY = "/opt/otx-publisher/pulses.json"

# ---- pulse registry (minimal) ----
def load_pulse_id(key: str) -> Optional[str]:
    try:
        with open(PULSE_REGISTRY, "r") as f:
            data = json.load(f)
        v = data.get(key)
        return v if isinstance(v, str) and v else None
    except Exception:
        return None


def save_pulse_id(key: str, pid: str) -> None:
    data = {}
    try:
        if os.path.exists(PULSE_REGISTRY):
            with open(PULSE_REGISTRY, "r") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                data = {}
    except Exception:
        data = {}

    data[key] = pid
    with open(PULSE_REGISTRY, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)


# -------- helpers --------
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
    return logging.getLogger("otx-ciscoasa-rolling")

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
    return requests.post(
        f"{es_host}/{index}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=timeout,
    )

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def _clean_payload(s: str) -> str:
    """Collapse whitespace and strip outer quotes; do NOT truncate."""
    if not isinstance(s, str):
        return ""
    s = re.sub(r"\s+", " ", s).strip()
    s = s.strip('"').strip("'")
    return s

# -------- CiscoASA collection --------
ASA_SHOULD = [
    {"term": {"type.keyword": "Ciscoasa"}},
    {"term": {"type.keyword": "ciscoasa"}},
    {"term": {"event.dataset.keyword": "cisco.asa"}},
    {"term": {"program.keyword": "ciscoasa"}},
    {"term": {"service.name.keyword": "ciscoasa"}},
]

SRC_FIELDS = [
    "src_ip.keyword",
    "source_ip.keyword",
    "client_ip.keyword",
    "source.ip",
    "client.ip",
    "source.address.keyword",
]

PAYLOAD_FIELD = "payload_printable.keyword"
GEO_CC_FIELD = "geoip.country_code2.keyword"
GEO_ASN_FIELD = "geoip.asn"
GEO_ASORG_FIELD = "geoip.as_org.keyword"

def collect_ciscoasa_ips_and_enrichment(
    cfg: dict, logger
) -> Tuple[Set[str], Dict[str, str], Dict[str, Dict[str, str]]]:
    """
    Returns:
      ips           : set of IPv4s
      payload_by_ip : ip -> payload_printable (sanitized, full)
      geo_by_ip     : ip -> {cc, asn, as_org} (strings where present)
    """
    es = cfg["elasticsearch"]
    es_host = es["host"]
    es_timeout = int(es.get("timeout", 15))
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    indices = cfg.get("indices", ["logstash-*"])
    min_events = int(cfg["pulse"].get("min_event_count", 1))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", True))

    counts: Dict[str, int] = {}
    payload_by_ip: Dict[str, str] = {}
    geo_by_ip: Dict[str, Dict[str, str]] = {}

    # ---- Pass 1: count unique src IPs (any CiscoASA doc)
    for idx in indices:
        for field in SRC_FIELDS:
            after = None
            while True:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": _utc_iso(start),
                                            "lte": _utc_iso(end),
                                        }
                                    }
                                }
                            ],
                            "should": ASA_SHOULD,
                            "minimum_should_match": 1,
                        }
                    },
                    "aggs": {
                        "by": {
                            "composite": {
                                "size": 1000,
                                "sources": [{"ip": {"terms": {"field": field}}}],
                            }
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
                        raw = b.get("key", {}).get("ip")
                        if not isinstance(raw, str):
                            continue
                        val = raw.split(":", 1)[0]  # strip ":port" if present
                        try:
                            ip = str(ipaddress.ip_address(val))
                        except Exception:
                            continue
                        if exclude_private and is_private_ip(ip):
                            continue
                        counts[ip] = counts.get(ip, 0) + int(b.get("doc_count", 0))
                    after = ag.get("after_key")
                    if not after:
                        break
                except Exception:
                    break

    ips = {ip for ip, c in counts.items() if c >= min_events}
    logger.info(f"CiscoASA IPv4s in window: {len(ips)}")
    if not ips:
        return set(), {}, {}

    # ---- Pass 2: per-IP payload example (only where payload exists)
    for idx in indices:
        for field in SRC_FIELDS:
            after = None
            while True:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": _utc_iso(start),
                                            "lte": _utc_iso(end),
                                        }
                                    }
                                },
                                {"exists": {"field": field}},
                                {"exists": {"field": PAYLOAD_FIELD}},
                            ],
                            "should": ASA_SHOULD,
                            "minimum_should_match": 1,
                        }
                    },
                    "aggs": {
                        "by": {
                            "composite": {
                                "size": 1000,
                                "sources": [{"ip": {"terms": {"field": field}}}],
                            },
                            "aggs": {
                                "pp": {
                                    "terms": {
                                        "field": PAYLOAD_FIELD,
                                        "size": 1,
                                        "order": {"_count": "desc"},
                                    }
                                }
                            },
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
                        ip_raw = b.get("key", {}).get("ip")
                        if not isinstance(ip_raw, str):
                            continue
                        ip_val = ip_raw.split(":", 1)[0]
                        try:
                            ip = str(ipaddress.ip_address(ip_val))
                        except Exception:
                            continue
                        if ip not in ips:
                            continue
                        buckets = (b.get("pp", {}) or {}).get("buckets", [])
                        if buckets:
                            sample = buckets[0].get("key")
                            if isinstance(sample, str) and sample:
                                payload_by_ip.setdefault(ip, _clean_payload(sample))
                    after = ag.get("after_key")
                    if not after:
                        break
                except Exception:
                    break
    logger.info(
        f"Enriched payloads attached: {len(payload_by_ip)} of {len(ips)} IPs"
    )

    # ---- Pass 3: per-IP geo (CC/ASN/AS_ORG)
    for idx in indices:
        for field in SRC_FIELDS:
            after = None
            while True:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {
                                    "range": {
                                        "@timestamp": {
                                            "gte": _utc_iso(start),
                                            "lte": _utc_iso(end),
                                        }
                                    }
                                },
                                {"exists": {"field": field}},
                                {
                                    "bool": {
                                        "should": [
                                            {"exists": {"field": GEO_CC_FIELD}},
                                            {"exists": {"field": GEO_ASN_FIELD}},
                                            {"exists": {"field": GEO_ASORG_FIELD}},
                                        ],
                                        "minimum_should_match": 1,
                                    }
                                },
                            ],
                            "should": ASA_SHOULD,
                            "minimum_should_match": 1,
                        }
                    },
                    "aggs": {
                        "by": {
                            "composite": {
                                "size": 1000,
                                "sources": [{"ip": {"terms": {"field": field}}}],
                            },
                            "aggs": {
                                "cc": {
                                    "terms": {
                                        "field": GEO_CC_FIELD,
                                        "size": 1,
                                        "order": {"_count": "desc"},
                                    }
                                },
                                "asn": {
                                    "terms": {
                                        "field": GEO_ASN_FIELD,
                                        "size": 1,
                                        "order": {"_count": "desc"},
                                    }
                                },
                                "asorg": {
                                    "terms": {
                                        "field": GEO_ASORG_FIELD,
                                        "size": 1,
                                        "order": {"_count": "desc"},
                                    }
                                },
                            },
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
                        ip_raw = b.get("key", {}).get("ip")
                        if not isinstance(ip_raw, str):
                            continue
                        ip_val = ip_raw.split(":", 1)[0]
                        try:
                            ip = str(ipaddress.ip_address(ip_val))
                        except Exception:
                            continue
                        if ip not in ips:
                            continue
                        entry = geo_by_ip.setdefault(ip, {})
                        cc_b = (b.get("cc", {}) or {}).get("buckets", [])
                        asn_b = (b.get("asn", {}) or {}).get("buckets", [])
                        org_b = (b.get("asorg", {}) or {}).get("buckets", [])
                        if cc_b:
                            entry["cc"] = str(cc_b[0].get("key"))
                        if asn_b:
                            entry["asn"] = str(asn_b[0].get("key"))
                        if org_b:
                            entry["as_org"] = str(org_b[0].get("key"))
                    after = ag.get("after_key")
                    if not after:
                        break
                except Exception:
                    break
    logger.info(f"Enriched geo attached: {len(geo_by_ip)} of {len(ips)} IPs")

    return ips, payload_by_ip, geo_by_ip

# -------- pulse builders --------
def build_indicators(
    ips: Set[str], payloads: Dict[str, str], geos: Dict[str, Dict[str, str]]
) -> List[dict]:
    indicators: List[dict] = []
    for ip in sorted(ips):
        parts = ["Seen in CiscoASA honeypot logs within the configured window."]
        if ip in payloads:
            parts.append(f"request: {payloads[ip]}")
        g = geos.get(ip, {})
        geo_bits = []
        if g.get("cc"):
            geo_bits.append(g["cc"])
        if g.get("asn"):
            if g.get("as_org"):
                geo_bits.append(f'ASN {g["asn"]} ({g["as_org"]})')
            else:
                geo_bits.append(f"ASN {g['asn']}")
        if geo_bits:
            parts.append("geo: " + "; ".join(geo_bits))
        indicators.append(
            {
                "indicator": ip,
                "type": "IPv4",
                "title": "Attacker IP \u2022 CiscoASA",
                "description": " ".join(parts),
                "tags": ["ciscoasa", "tpot", "honeypot"],
            }
        )
    return indicators

def build_monthly_pulse_base(cfg: dict, indicators: List[dict]) -> dict:
    tlp = str(cfg["pulse"].get("tlp", "green")).upper()
    prefix = cfg["pulse"].get("name_prefix", "CiscoASA \u2013 T-Pot")
    loc = str(cfg["pulse"].get("location_label", "")).strip()

    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")
    base_name = f"{prefix} \u2013 {loc}" if loc else prefix
    name = f"{base_name} \u2013 {month_label}"

    desc = (
        "IPv4 addresses observed by CiscoASA honeypot events on T-Pot, "
        "aggregated for this calendar month. "
        "Deduped to unique sources; private IPs excluded. "
        + (f"Location: {loc}. " if loc else "")
        + "Caveat: request lines alone cannot distinguish scan vs successful exploit; "
          "device memory inspection is required to confirm compromise."
    )

    return {
        "name": name,
        "description": desc,
        "public": (tlp == "GREEN"),
        # include both keys just to be safe with OTX
        "tlp": tlp,
        "TLP": tlp,
        "tags": ["tpot", "honeypot", "ciscoasa", "monthly"],
        "indicators": indicators,
    }

# -------- OTX helpers (ADB-style) --------
def otx_headers(api_key: str) -> dict:
    return {
        "X-OTX-API-KEY": api_key,
        "User-Agent": "otx-ciscoasa-rolling/1.0",
        "Content-Type": "application/json",
    }

def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get(f"{BASE}/users/me", headers=otx_headers(api_key), timeout=10)
        ok = r.status_code == 200
        if not ok:
            logger.error(f"OTX auth failed: {r.status_code} {r.text[:200]}")
        return ok
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False

def find_monthly_pulse(api_key: str, name: str, logger) -> Optional[str]:
    """
    Look for an existing pulse with the exact given name under /pulses/my.
    Returns pulse id or None.
    """
    headers = otx_headers(api_key)
    page = 1
    while page <= 5:
        try:
            r = requests.get(
                f"{BASE}/pulses/my",
                headers=headers,
                params={"page": page},
                timeout=30,
            )
            if r.status_code != 200:
                logger.error(
                    f"OTX list pulses failed page={page}: {r.status_code} {r.text[:300]}"
                )
                return None
            data = r.json()
            results = data.get("results") or data.get("pulses") or data
            if not results:
                break
            for p in results:
                if isinstance(p, dict) and p.get("name") == name:
                    return p.get("id")
            page += 1
        except Exception as e:
            logger.error(f"OTX list pulses exception page={page}: {e}")
            return None
    return None

def get_pulse(api_key: str, pulse_id: str, logger) -> Optional[dict]:
    headers = otx_headers(api_key)
    try:
        r = requests.get(f"{BASE}/pulses/{pulse_id}", headers=headers, timeout=30)
        if r.status_code != 200:
            logger.error(
                f"OTX get pulse {pulse_id} failed: {r.status_code} {r.text[:300]}"
            )
            return None
        return r.json()
    except Exception as e:
        logger.error(f"OTX get pulse {pulse_id} exception: {e}")
        return None

def create_pulse(api_key: str, pulse: dict, logger, dry_run: bool) -> Optional[str]:
    headers = otx_headers(api_key)
    if dry_run:
        inds = pulse.get("indicators") or []
        logger.info(
            f"[DRY-RUN] Would CREATE CiscoASA monthly pulse '{pulse.get('name')}' "
            f"with {len(inds)} indicators"
        )
        return None
    r = requests.post(
        f"{BASE}/pulses/create",
        headers=headers,
        data=json.dumps(pulse),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"Create pulse failed {r.status_code}: {r.text[:500]}")
        return None
    created = r.json()
    pid = created.get("id")
    logger.info(
        f"Created CiscoASA monthly pulse: {created.get('name','(no name)')} (id={pid})"
    )
    return pid

def add_indicators(
    api_key: str, pulse_id: str, to_add: List[dict], logger, dry_run: bool
) -> bool:
    if not to_add:
        logger.info("No new indicators to add to CiscoASA monthly pulse.")
        return True
    headers = otx_headers(api_key)
    body = {"indicators": {"add": to_add}}
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would PATCH CiscoASA pulse {pulse_id} adding {len(to_add)} indicators"
        )
        return True
    r = requests.patch(
        f"{BASE}/pulses/{pulse_id}",
        headers=headers,
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"OTX update error {r.status_code}: {r.text[:500]}")
        return False
    logger.info(
        f"Successfully patched CiscoASA monthly pulse {pulse_id} with {len(to_add)} new indicators"
    )
    return True

# -------- main --------
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

    ips, payloads, geos = collect_ciscoasa_ips_and_enrichment(cfg, logger)
    if not ips:
        logger.warning("No CiscoASA IPs found in window; skipping")
        return

    hour_inds = build_indicators(ips, payloads, geos)
    if not hour_inds:
        logger.warning("No indicators built from CiscoASA window; skipping")
        return

    base_pulse = build_monthly_pulse_base(cfg, hour_inds)
    pulse_name = base_pulse["name"]
    api_key = cfg["otx_api_key"]

    # 1) find existing monthly pulse by name
    now = datetime.now(timezone.utc)
    reg_key = f"ciscoasa_{now.strftime('%Y-%m')}"

    pulse_id = load_pulse_id(reg_key)
    if not pulse_id:
        pulse_id = find_monthly_pulse(api_key, pulse_name, logger)
        if pulse_id:
            save_pulse_id(reg_key, pulse_id)

    if not pulse_id:
        # no existing pulse for this month: create it with current indicators
        pid = create_pulse(api_key, base_pulse, logger, args.dry_run)
        if pid and not args.dry_run:
            save_pulse_id(reg_key, pid)
        if not pid and not args.dry_run:
            logger.error("Failed to create CiscoASA monthly pulse; aborting.")
            return
        return

    # 2) existing pulse: fetch and add only new indicators
    existing = get_pulse(api_key, pulse_id, logger)
    if existing is None:
        logger.error("Could not fetch existing CiscoASA monthly pulse; aborting.")
        return

    existing_inds = existing.get("indicators") or []
    existing_keys = {
        (i.get("indicator"), i.get("type"))
        for i in existing_inds
        if isinstance(i, dict)
    }

    to_add: List[dict] = []
    for ind in hour_inds:
        key = (ind.get("indicator"), ind.get("type"))
        if key not in existing_keys:
            to_add.append(ind)

    logger.info(
        f"CiscoASA monthly pulse {pulse_id}: {len(hour_inds)} in this window, "
        f"{len(to_add)} are new after dedupe"
    )

    add_indicators(api_key, pulse_id, to_add, logger, args.dry_run)

if __name__ == "__main__":
    main()
