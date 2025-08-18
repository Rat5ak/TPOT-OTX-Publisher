#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, hashlib, os
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, List
import requests

# ------------------------------- config + logging -------------------------------

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

def setup_logger(log_path: str | None):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_path:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers
    )
    return logging.getLogger("otx-publisher")

# ----------------------------------- helpers -----------------------------------

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def utc_iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()

def es_health(es_host: str, timeout: int) -> bool:
    try:
        r = requests.get(f"{es_host}/_cluster/health", timeout=timeout)
        r.raise_for_status()
        status = r.json().get("status", "unknown")
        return status in ("yellow", "green")
    except Exception:
        return False

def es_search(es_host: str, index: str, body: dict, timeout: int):
    url = f"{es_host}/{index}/_search"
    return requests.post(url,
                         headers={"Content-Type": "application/json"},
                         data=json.dumps(body),
                         timeout=timeout)

# --------------- dedupe fingerprint (stable across identical data) --------------

def indicators_fingerprint(iocs: dict) -> str:
    items: List[str] = []
    for v in sorted(iocs.get("ipv4", [])):
        items.append(f"ip:{v}")
    for v in sorted(iocs.get("urls", [])):
        items.append(f"url:{v}")
    for v in sorted(iocs.get("hashes", [])):
        items.append(f"hash:{v}")
    blob = "\n".join(items).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()

def load_state(state_path: str) -> dict:
    try:
        with open(state_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state_path: str, state: dict):
    with open(state_path, "w") as f:
        json.dump(state, f, indent=2)

# --------------------------------- collection ----------------------------------

def collect_iocs(cfg: dict, logger: logging.Logger) -> Dict[str, Set[str]]:
    es = cfg["elasticsearch"]
    es_host, es_timeout = es["host"], es.get("timeout", 30)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=cfg["pulse"]["time_window_hours"])

    indices = cfg["indices"]
    max_indicators = cfg["limits"].get("max_indicators", 5000)
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", True))
    min_event_count = int(cfg["pulse"].get("min_event_count", 3))

    iocs = {"ipv4": set(), "urls": set(), "hashes": set()}

    # Fields to try across different index mappings
    ip_fields_agg = ["src_ip.keyword", "source_ip.keyword", "client_ip.keyword", "source.ip", "client.ip"]
    ip_fields_src = ["src_ip", "source_ip", "client_ip", "source.ip", "client.ip"]
    url_fields = ["url", "http.url", "request.url", "url.full", "url.original"]
    hash_fields = ["sha256", "fileinfo.sha256", "files.sha256", "shasum", "sha1", "md5"]

    base_query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": utc_iso(start_time), "lte": utc_iso(end_time)}}}
                ]
            }
        },
        "size": 10000,
        "_source": list(set(ip_fields_src + url_fields + hash_fields + ["eventid", "event_type"]))
    }

    # Build a hot list of IPs with at least N events (noise control)
    hot_ips: Set[str] = set()
    for idx in indices:
        for ipagg in ip_fields_agg:
            agg_query = {
                "size": 0,
                "query": base_query["query"],
                "aggs": {"ips": {"terms": {"field": ipagg, "size": 20000}}}
            }
            try:
                r = es_search(es_host, idx, agg_query, es_timeout)
                if r.status_code != 200:
                    continue
                buckets = r.json().get("aggregations", {}).get("ips", {}).get("buckets", [])
                for b in buckets:
                    if b.get("doc_count", 0) >= min_event_count:
                        k = b.get("key")
                        if k:
                            hot_ips.add(k)
            except Exception as e:
                logger.debug(f"agg pass failed for {idx}:{ipagg}: {e}")

    # Pull docs and extract indicators
    for idx in indices:
        try:
            r = es_search(es_host, idx, base_query, es_timeout)
            if r.status_code != 200:
                logger.warning(f"search {idx} -> {r.status_code}")
                continue
            hits = r.json().get("hits", {}).get("hits", [])
            for h in hits:
                src = h.get("_source", {})

                # IPs
                for fld in ip_fields_src:
                    ip = src.get(fld)
                    if not ip:
                        continue
                    if exclude_private and is_private_ip(ip):
                        continue
                    # only accept IPs that made the hot list
                    if ip in hot_ips:
                        iocs["ipv4"].add(ip)

                # URLs
                for uf in url_fields:
                    u = src.get(uf)
                    if isinstance(u, str) and (u.startswith("http://") or u.startswith("https://")):
                        iocs["urls"].add(u)

                # Hashes (detect type by length; accept md5/sha1/sha256)
                for hf in hash_fields:
                    hv = src.get(hf)
                    if not isinstance(hv, str):
                        continue
                    hv = hv.strip().lower()
                    if len(hv) in (32, 40, 64):  # md5/sha1/sha256
                        iocs["hashes"].add(hv)

                # Stop if getting too big
                if sum(len(v) for v in iocs.values()) >= max_indicators:
                    logger.warning("hit max_indicators cap; truncating")
                    return iocs

        except Exception as e:
            logger.warning(f"doc pass failed for {idx}: {e}")

    return iocs

# ----------------------------------- OTX ---------------------------------------

def test_otx_connection(api_key: str, logger: logging.Logger) -> bool:
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": "otx-publisher/1.0"},
            timeout=10
        )
        if r.status_code == 200:
            return True
        logger.error(f"OTX auth check failed: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        logger.error(f"OTX connectivity init failed: {e}")
        return False

def build_pulse(cfg: dict, iocs: Dict[str, Set[str]]) -> dict:
    tlp = cfg["pulse"]["tlp"].upper()
    prefix = cfg["pulse"]["name_prefix"]
    window = cfg["pulse"]["time_window_hours"]

    name = f"{prefix} – last {window}h"
    desc = (
        "Indicators observed by T-Pot CE honeypots. "
        "Signals are deduped and filtered (min event count threshold; private IPs excluded). "
        "Intended for defensive use; infrastructure may be compromised or spoofed. "
        "Sensor: T-Pot CE via Elasticsearch over SSH tunnel."
    )

    # OTX expects type strings like: IPv4, URL, FileHash-SHA256, FileHash-MD5, FileHash-SHA1
    def hash_type(h: str) -> str:
        if len(h) == 64:
            return "FileHash-SHA256"
        if len(h) == 40:
            return "FileHash-SHA1"
        return "FileHash-MD5"

    indicators = []
    for ip in sorted(iocs["ipv4"]):
        indicators.append({"indicator": ip, "type": "IPv4", "title": "Attacker IP"})
    for u in sorted(iocs["urls"]):
        indicators.append({"indicator": u, "type": "URL", "title": "Payload URL"})
    for h in sorted(iocs["hashes"]):
        indicators.append({"indicator": h, "type": hash_type(h), "title": "Dropped File Hash"})

    return {
        "name": name,
        "description": desc,
        "public": (tlp == "GREEN"),   # public for GREEN; set False for AMBER/RED
        "tlp": tlp,
        "tags": ["tpot", "cowrie", "honeytrap", "suricata", "dionaea", "honeypot", "ssh", "malicious"],
        "indicators": indicators
    }

def publish_pulse_rest(api_key: str, pulse: dict, dry_run: bool, logger: logging.Logger) -> dict | None:
    # count safely even if types were altered
    ip_cnt   = sum(1 for i in pulse["indicators"] if str(i.get("type","")).lower() in ("ipv4","ip","ipaddress"))
    url_cnt  = sum(1 for i in pulse["indicators"] if str(i.get("type","")).lower() == "url")
    hash_cnt = sum(1 for i in pulse["indicators"] if str(i.get("type","")).lower().startswith("filehash"))

    logger.info(f"Pulse indicators: IPs={ip_cnt}, URLs={url_cnt}, Hashes={hash_cnt}")
    if dry_run:
        logger.info("DRY-RUN: not publishing to OTX")
        return None

    try:
        r = requests.post(
            "https://otx.alienvault.com/api/v1/pulses/create",
            headers={"X-OTX-API-KEY": api_key, "Content-Type": "application/json", "User-Agent": "otx-publisher/1.0"},
            json=pulse,
            timeout=20
        )
        if not r.ok:
            raise RuntimeError(f"OTX publish failed: {r.status_code} {r.text[:400]}")
        created = r.json()
        logger.info(f"Published pulse: {created.get('name','(no name)')} (id={created.get('id','?')})")
        return created
    except Exception as e:
        logger.error(f"OTX REST publish exception: {e}")
        return None

# ------------------------------------ main -------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Publish T-Pot IOCs to OTX with dedupe.")
    ap.add_argument("--config", default="config.json", help="Path to config.json")
    ap.add_argument("--dry-run", action="store_true", help="Collect only; do not publish or write state")
    ap.add_argument("--force", action="store_true", help="Ignore dedupe fingerprint and publish anyway")
    args = ap.parse_args()

    cfg = load_config(args.config)
    logger = setup_logger(cfg.get("log_path"))

    # Health checks
    if not es_health(cfg["elasticsearch"]["host"], cfg["elasticsearch"].get("timeout", 30)):
        logger.error("Elasticsearch unhealthy/unreachable over the tunnel")
        sys.exit(2)
    if not test_otx_connection(cfg["otx_api_key"], logger):
        sys.exit(3)

    # Collect
    iocs = collect_iocs(cfg, logger)
    total = sum(len(v) for v in iocs.values())

    # Pre-publish dedupe
    state_path = cfg.get("state_path", "/opt/otx-publisher/state.json")
    os.makedirs(os.path.dirname(state_path), exist_ok=True)
    fp = indicators_fingerprint(iocs)
    state = load_state(state_path)

    if total == 0:
        logger.info("No IOCs collected in the window; nothing to do.")
        return

    if not args.force and state.get("last_fingerprint") == fp:
        logger.info("Indicators unchanged since last publish (fingerprint match) — skipping.")
        return

    # Build + publish
    pulse = build_pulse(cfg, iocs)
    created = publish_pulse_rest(cfg["otx_api_key"], pulse, args.dry_run, logger)

    # Persist state if actually published
    if not args.dry_run and created is not None:
        new_state = {
            "last_run_utc": datetime.now(timezone.utc).isoformat(),
            "last_fingerprint": fp,
            "last_total": total,
            "counts": {"ips": len(iocs["ipv4"]), "urls": len(iocs["urls"]), "hashes": len(iocs["hashes"])},
            "pulse_name": pulse.get("name")
        }
        save_state(state_path, new_state)

if __name__ == "__main__":
    main()
