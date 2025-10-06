import argparse, json, logging, sys, ipaddress, re
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Set
import requests

# -------- helpers --------
def load_config(path: str) -> dict:
    with open(path, "r") as f: return json.load(f)

def setup_logger(log_path: str|None):
    handlers=[logging.StreamHandler(sys.stdout)]
    if log_path: handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers)
    return logging.getLogger("otx-ciscoasa")

def _utc_iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()

def es_health(es_host: str, timeout: int) -> bool:
    try:
        r = requests.get(f"{es_host}/_cluster/health", timeout=timeout)
        r.raise_for_status()
        return r.json().get("status") in ("yellow","green")
    except Exception:
        return False

def es_search(es_host: str, index: str, body: dict, timeout: int):
    return requests.post(f"{es_host}/{index}/_search",
                         headers={"Content-Type":"application/json"},
                         data=json.dumps(body), timeout=timeout)

def is_private_ip(ip: str) -> bool:
    try: return ipaddress.ip_address(ip).is_private
    except Exception: return True

def _clean_payload(s: str) -> str:
    """Collapse whitespace and strip outer quotes; do NOT truncate."""
    if not isinstance(s, str): return ""
    s = re.sub(r'\s+', ' ', s).strip()
    s = s.strip('"').strip("'")
    return s

# -------- main bits --------
ASA_SHOULD = [
    {"term": {"type.keyword": "Ciscoasa"}},
    {"term": {"type.keyword": "ciscoasa"}},
    {"term": {"event.dataset.keyword": "cisco.asa"}},
    {"term": {"program.keyword": "ciscoasa"}},
    {"term": {"service.name.keyword": "ciscoasa"}},
]

SRC_FIELDS = [
    "src_ip.keyword", "source_ip.keyword", "client_ip.keyword",
    "source.ip", "client.ip", "source.address.keyword"
]

PAYLOAD_FIELD = "payload_printable.keyword"
GEO_CC_FIELD  = "geoip.country_code2.keyword"
GEO_ASN_FIELD = "geoip.asn"
GEO_ASORG_FIELD = "geoip.as_org.keyword"

def collect_ciscoasa_ips_and_enrichment(cfg: dict, logger) -> Tuple[Set[str], Dict[str,str], Dict[str,Dict[str,str]]]:
    """
    Returns:
      ips                : set of IPv4s
      payload_by_ip      : ip -> payload_printable (sanitized, full)
      geo_by_ip          : ip -> {cc, asn, as_org} (strings where present)
    """
    es = cfg["elasticsearch"]; es_host, es_timeout = es["host"], es["timeout"]
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc); start = end - timedelta(hours=hours)
    indices = cfg.get("indices", ["logstash-*"])
    min_events = int(cfg["pulse"].get("min_event_count", 1))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", True))

    counts: Dict[str,int] = {}
    payload_by_ip: Dict[str,str] = {}
    geo_by_ip: Dict[str,Dict[str,str]] = {}

    # ---- Pass 1: count unique src IPs (any CiscoASA doc)
    for idx in indices:
        for field in SRC_FIELDS:
            after = None
            while True:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [{"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}}],
                            "should": ASA_SHOULD,
                            "minimum_should_match": 1
                        }
                    },
                    "aggs": {
                        "by": {
                            "composite": {"size": 1000, "sources": [{"ip":{"terms":{"field": field}}}]}
                        }
                    }
                }
                if after: body["aggs"]["by"]["composite"]["after"] = after
                try:
                    r = es_search(es_host, idx, body, es_timeout)
                    if r.status_code != 200: break
                    ag = r.json().get("aggregations",{}).get("by",{})
                    for b in ag.get("buckets", []):
                        raw = b.get("key",{}).get("ip")
                        if not isinstance(raw, str): continue
                        val = raw.split(":",1)[0]  # strip ":port" if present
                        try:
                            ip = str(ipaddress.ip_address(val))
                        except Exception:
                            continue
                        if exclude_private and is_private_ip(ip): continue
                        counts[ip] = counts.get(ip, 0) + int(b.get("doc_count",0))
                    after = ag.get("after_key")
                    if not after: break
                except Exception:
                    break

    ips = {ip for ip,c in counts.items() if c >= min_events}
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
                                {"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}},
                                {"exists":{"field": field}},
                                {"exists":{"field": PAYLOAD_FIELD}}
                            ],
                            "should": ASA_SHOULD,
                            "minimum_should_match": 1
                        }
                    },
                    "aggs": {
                        "by": {
                            "composite": {"size": 1000, "sources": [{"ip":{"terms":{"field": field}}}]},
                            "aggs": {
                                "pp": {"terms":{"field": PAYLOAD_FIELD, "size": 1, "order":{"_count":"desc"}}}
                            }
                        }
                    }
                }
                if after: body["aggs"]["by"]["composite"]["after"] = after
                try:
                    r = es_search(es_host, idx, body, es_timeout)
                    if r.status_code != 200: break
                    ag = r.json().get("aggregations",{}).get("by",{})
                    for b in ag.get("buckets", []):
                        ip_raw = b.get("key",{}).get("ip")
                        if not isinstance(ip_raw, str): continue
                        ip_val = ip_raw.split(":",1)[0]
                        try:
                            ip = str(ipaddress.ip_address(ip_val))
                        except Exception:
                            continue
                        if ip not in ips:  # only enrich ones we intend to publish
                            continue
                        buckets = (b.get("pp",{}) or {}).get("buckets",[])
                        if buckets:
                            sample = buckets[0].get("key")
                            if isinstance(sample, str) and sample:
                                payload_by_ip.setdefault(ip, _clean_payload(sample))
                    after = ag.get("after_key")
                    if not after: break
                except Exception:
                    break
    logger.info(f"Enriched payloads attached: {len(payload_by_ip)} of {len(ips)} IPs")

    # ---- Pass 3: per-IP geo (CC/ASN/AS_ORG) — collect most common values
    for idx in indices:
        for field in SRC_FIELDS:
            after = None
            while True:
                body = {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}},
                                {"exists":{"field": field}},
                                {"bool":{"should":[
                                    {"exists":{"field": GEO_CC_FIELD}},
                                    {"exists":{"field": GEO_ASN_FIELD}},
                                    {"exists":{"field": GEO_ASORG_FIELD}}
                                ], "minimum_should_match": 1}}
                            ],
                            "should": ASA_SHOULD,
                            "minimum_should_match": 1
                        }
                    },
                    "aggs": {
                        "by": {
                            "composite": {"size": 1000, "sources": [{"ip":{"terms":{"field": field}}}]},
                            "aggs": {
                                "cc":    {"terms":{"field": GEO_CC_FIELD, "size": 1, "order":{"_count":"desc"}}},
                                "asn":   {"terms":{"field": GEO_ASN_FIELD, "size": 1, "order":{"_count":"desc"}}},
                                "asorg": {"terms":{"field": GEO_ASORG_FIELD, "size": 1, "order":{"_count":"desc"}}}
                            }
                        }
                    }
                }
                if after: body["aggs"]["by"]["composite"]["after"] = after
                try:
                    r = es_search(es_host, idx, body, es_timeout)
                    if r.status_code != 200: break
                    ag = r.json().get("aggregations",{}).get("by",{})
                    for b in ag.get("buckets", []):
                        ip_raw = b.get("key",{}).get("ip")
                        if not isinstance(ip_raw, str): continue
                        ip_val = ip_raw.split(":",1)[0]
                        try:
                            ip = str(ipaddress.ip_address(ip_val))
                        except Exception:
                            continue
                        if ip not in ips:
                            continue
                        entry = geo_by_ip.setdefault(ip, {})
                        cc_b  = (b.get("cc",{}) or {}).get("buckets",[])
                        asn_b = (b.get("asn",{}) or {}).get("buckets",[])
                        org_b = (b.get("asorg",{}) or {}).get("buckets",[])
                        if cc_b:
                            entry["cc"] = str(cc_b[0].get("key"))
                        if asn_b:
                            entry["asn"] = str(asn_b[0].get("key"))
                        if org_b:
                            entry["as_org"] = str(org_b[0].get("key"))
                    after = ag.get("after_key")
                    if not after: break
                except Exception:
                    break
    logger.info(f"Enriched geo attached: {len(geo_by_ip)} of {len(ips)} IPs")

    return ips, payload_by_ip, geo_by_ip

def build_pulse(cfg: dict, ips: Set[str], payloads: Dict[str,str], geos: Dict[str,Dict[str,str]]) -> dict:
    tlp = str(cfg["pulse"].get("tlp","green")).upper()
    prefix = cfg["pulse"].get("name_prefix","CiscoASA – T-Pot")
    window = int(cfg["pulse"].get("time_window_hours",1))
    loc = str(cfg["pulse"].get("location_label","")).strip()
    name = f"{prefix} – {loc} – last {window}h" if loc else f"{prefix} – last {window}h"

    desc = ("IPv4 addresses observed by CiscoASA honeypot events within the last "
            f"{window}h on T-Pot. Deduped to unique sources; private IPs excluded. "
            + (f"Location: {loc}. " if loc else "")
            + "Caveat: request lines alone cannot distinguish scan vs successful exploit; device memory inspection is required to confirm compromise.")

    indicators = []
    for ip in sorted(ips):
        parts = ["Seen in CiscoASA honeypot logs within the configured window."]
        if ip in payloads:
            parts.append(f'request: {payloads[ip]}')
        g = geos.get(ip, {})
        geo_bits = []
        if g.get("cc"): geo_bits.append(g["cc"])
        if g.get("asn"):
            if g.get("as_org"):
                geo_bits.append(f'ASN {g["asn"]} ({g["as_org"]})')
            else:
                geo_bits.append(f'ASN {g["asn"]}')
        if geo_bits:
            parts.append("geo: " + "; ".join(geo_bits))
        indicators.append({
            "indicator": ip,
            "type": "IPv4",
            "title": "Attacker IP • CiscoASA",
            "description": " ".join(parts),
            "tags": ["ciscoasa","tpot","honeypot"]
        })

    return {
        "name": name,
        "description": desc,
        "public": (tlp == "GREEN"),
        "tlp": tlp,
        "tags": ["tpot","honeypot","ciscoasa"],
        "indicators": indicators
    }

def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get("https://otx.alienvault.com/api/v1/users/me",
                         headers={"X-OTX-API-KEY": api_key, "User-Agent":"otx-ciscoasa/1.2"},
                         timeout=10)
        ok = (r.status_code == 200)
        if not ok: logger.error(f"OTX auth failed: {r.status_code} {r.text}")
        return ok
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False

def publish(api_key: str, pulse: dict, dry_run: bool, logger):
    if dry_run:
        logger.info(f"[DRY-RUN] Would publish pulse with {len(pulse['indicators'])} IPv4s")
        return
    r = requests.post("https://otx.alienvault.com/api/v1/pulses/create/",
                      headers={"X-OTX-API-KEY": api_key,
                               "User-Agent":"otx-ciscoasa/1.2",
                               "Content-Type":"application/json"},
                      data=json.dumps(pulse), timeout=60)
    if r.status_code >= 400:
        logger.error(f"OTX error {r.status_code}: {r.text[:2000]}")
    r.raise_for_status()
    created = r.json()
    logger.info(f"Published pulse: {created.get('name','(no name)')} (id={created.get('id','?')})")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    cfg = load_config(args.config)
    logger = setup_logger(cfg.get("log_path"))

    if not es_health(cfg["elasticsearch"]["host"], cfg["elasticsearch"]["timeout"]):
        logger.error("Elasticsearch unhealthy/unreachable"); return
    if not test_otx(cfg["otx_api_key"], logger): return

    ips, payloads, geos = collect_ciscoasa_ips_and_enrichment(cfg, logger)
    if not ips:
        logger.warning("No CiscoASA IPs found in window; skipping")
        return

    pulse = build_pulse(cfg, ips, payloads, geos)
    publish(cfg["otx_api_key"], pulse, args.dry_run, logger)

if __name__ == "__main__":
    main()
