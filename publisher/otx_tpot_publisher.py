#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, os, hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Tuple
import requests

# ---------------- config / logging ----------------
def load_config(path: str) -> dict:
    with open(path, "r") as f: return json.load(f)

def setup_logger(log_path: str):
    handlers=[logging.StreamHandler(sys.stdout)]
    if log_path: handlers.append(logging.FileHandler(log_path))
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers)
    return logging.getLogger("otx-publisher")

# ---------------- ES helpers ----------------
def _utc_iso(dt: datetime) -> str: return dt.replace(tzinfo=timezone.utc).isoformat()

def es_health(es_host: str, timeout: int) -> bool:
    try:
        r = requests.get(f"{es_host}/_cluster/health", timeout=timeout)
        r.raise_for_status()
        return r.json().get("status") in ("yellow","green")
    except Exception:
        return False

def es_search(es_host: str, index: str, body: dict, timeout: int):
    url = f"{es_host}/{index}/_search"
    return requests.post(url, headers={"Content-Type":"application/json"},
                         data=json.dumps(body), timeout=timeout)

def is_private_ip(ip: str) -> bool:
    try: return ipaddress.ip_address(ip).is_private
    except Exception: return True

# ---------------- sensor detection ----------------
def detect_sensor(src: dict, index_name: str|None=None) -> str:
    """
    Best-effort sensor name from common fields, path hints, or index name.
    Returns lowercase: 'cowrie','suricata','dionaea','honeytrap','tpot','unknown'
    """
    cand = []

    # Direct fields present in your sample docs
    for k in ("type", "eventid", "path", "t-pot_hostname"):
        v = src.get(k)
        if isinstance(v, str) and v:
            cand.append(v.lower())

    # Elastic common fields (keep as fallback if they ever appear)
    for k in ("event.module","event.dataset","service.name","program","agent.type","agent.name"):
        v = src.get(k)
        if isinstance(v, str) and v:
            cand.append(v.lower())
    for k in ("event", "service", "agent"):
        sub = src.get(k, {})
        if isinstance(sub, dict):
            for kk in ("module","dataset","name","type"):
                vv = sub.get(kk)
                if isinstance(vv, str) and vv:
                    cand.append(vv.lower())

    # index name can carry hints in some stacks (yours is logstash-YYYY.MM.DD)
    if index_name:
        cand.append(str(index_name).lower())

    blob = " ".join(cand)

    # strong direct checks
    if "cowrie" in blob:     return "cowrie"
    if "suricata" in blob:   return "suricata"
    if "dionaea" in blob:    return "dionaea"
    if "honeytrap" in blob or "honey" in blob: return "honeytrap"
    # p0f fingerprint sensor
    if "p0f" in blob or "/p0f/" in blob: return "p0f"

    # path-based hints
    if "/cowrie/" in blob:   return "cowrie"
    if "/suricata/" in blob: return "suricata"
    if "/dionaea/" in blob:  return "dionaea"
    if "/honey" in blob:     return "honeytrap"

    # weak fallbacks
    if "tpot" in blob:       return "tpot"
    return "unknown"

# ---------------- IOC collection ----------------
def collect_iocs(cfg: dict, logger: logging.Logger) -> Tuple[Dict[str, Set[str]], dict]:
    es=cfg["elasticsearch"]; es_host, es_timeout = es["host"], es["timeout"]
    end_time=datetime.now(timezone.utc)
    start_time=end_time - timedelta(hours=cfg["pulse"]["time_window_hours"])

    indices = cfg["indices"]
    max_indicators = cfg["limits"]["max_indicators"]
    exclude_private = cfg["pulse"]["exclude_private_ips"]

    iocs = {"ipv4": set(), "urls": set(), "hashes": set()}
    meta = {"ipv4": {}, "urls": {}, "hashes": {}}  # indicator -> set(sensors)

    base_query = {
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": _utc_iso(start_time), "lte": _utc_iso(end_time)}}}
                ]
            }
        },
        "size": 10000,
        "_source": [
            "src_ip","source_ip","client_ip",
            "url","http.url","request.url",
            "sha256","shasum","fileinfo.sha256","files.sha256",
            "event","event.module","event.dataset",
            "service","service.name","program","agent","agent.name","agent.type",
            "type","eventid","path","t-pot_hostname","event","event.module","event.dataset",
            "service","service.name","program","agent","agent.name","agent.type"
        ]
    }

    agg_query = {
        "size": 0,
        "query": base_query["query"],
        "aggs": { "ips": {"terms": {"field": "src_ip.keyword", "size": 20000}} }
    }

    # pass 1: hot IPs
    hot_ips=set()
    for idx in indices:
        try:
            r = es_search(es_host, idx, agg_query, es_timeout)
            if r.status_code != 200: continue
            for b in r.json().get("aggregations",{}).get("ips",{}).get("buckets",[]):
                if b.get("doc_count",0) >= cfg["pulse"]["min_event_count"]:
                    key = b.get("key")
                    if key: hot_ips.add(key)
        except Exception as e:
            logger.warning(f"agg pass failed for {idx}: {e}")

    # pass 2: docs
    for idx in indices:
        try:
            r = es_search(es_host, idx, base_query, es_timeout)
            if r.status_code != 200: continue
            for h in r.json().get("hits",{}).get("hits",[]):
                src = h.get("_source",{})
                sensor = detect_sensor(src, idx)

                # IPs
                for fld in ("src_ip","source_ip","client_ip"):
                    ip = src.get(fld)
                    if not ip: continue
                    if exclude_private and is_private_ip(ip): continue
                    if ip in hot_ips:
                        iocs["ipv4"].add(ip)
                        meta["ipv4"].setdefault(ip, set()).add(sensor)

                # URLs
                for uf in ("url","http.url","request.url"):
                    u = src.get(uf)
                    if u and isinstance(u,str) and (u.startswith("http://") or u.startswith("https://")):
                        iocs["urls"].add(u)
                        meta["urls"].setdefault(u, set()).add(sensor)

                # Hashes
                for hf in ("sha256","fileinfo.sha256","files.sha256","shasum"):
                    hv = src.get(hf)
                    if hv and isinstance(hv,str) and len(hv) >= 32:
                        hv = hv.lower()
                        iocs["hashes"].add(hv)
                        meta["hashes"].setdefault(hv, set()).add(sensor)

                if sum(len(v) for v in iocs.values()) >= max_indicators:
                    logger.warning("hit max_indicators cap; truncating")
                    return iocs, meta
        except Exception as e:
            logger.warning(f"doc pass failed for {idx}: {e}")
    return iocs, meta

# ---------------- dedupe state ----------------
def indicators_fingerprint(iocs: dict, meta: dict|None=None, include_sensor: bool=False) -> str:
    items=[]
    if include_sensor and meta:
        for v in sorted(iocs.get("ipv4", [])):
            sensors = ",".join(sorted(meta.get("ipv4",{}).get(v, set()))) or "unknown"
            items.append(f"ip:{v}|{sensors}")
        for v in sorted(iocs.get("urls", [])):
            sensors = ",".join(sorted(meta.get("urls",{}).get(v, set()))) or "unknown"
            items.append(f"url:{v}|{sensors}")
        for v in sorted(iocs.get("hashes", [])):
            sensors = ",".join(sorted(meta.get("hashes",{}).get(v, set()))) or "unknown"
            items.append(f"hash:{v}|{sensors}")
    else:
        for v in sorted(iocs.get("ipv4", [])):  items.append(f"ip:{v}")
        for v in sorted(iocs.get("urls", [])):  items.append(f"url:{v}")
        for v in sorted(iocs.get("hashes", [])):items.append(f"hash:{v}")
    return hashlib.sha256("\n".join(items).encode("utf-8")).hexdigest()

def load_state(state_path: str) -> dict:
    try:
        with open(state_path,"r") as f: return json.load(f)
    except Exception:
        return {}

def save_state(state_path: str, state: dict):
    tmp = state_path + ".tmp"
    with open(tmp,"w") as f: json.dump(state,f,indent=2)
    os.replace(tmp, state_path)

def should_run_daily_only(cfg: dict, state_path: str, logger):
    # Return True if it's time to publish again based on time only.
    # Ignores indicator fingerprints entirely.
    pub = cfg.get("publish", {}) if isinstance(cfg.get("publish", {}), dict) else {}
    # Default to 1440 mins (24h) if not set
    min_mins = int(pub.get("min_interval_minutes", 1440) or 1440)

    st = load_state(state_path)
    last_iso = st.get("last_run_utc")
    last = None
    if last_iso:
        try:
            last = datetime.fromisoformat(last_iso)
        except Exception:
            last = None

    now = datetime.now(timezone.utc)
    if last and (now - last) < timedelta(minutes=min_mins):
        logger.info("Daily mode: ran recently — skipping.")
        return False
    return True

def should_publish(iocs: dict, cfg: dict, state_path: str, logger, meta: dict|None=None):
    pub = cfg.get("publish",{}) if isinstance(cfg.get("publish",{}), dict) else {}
    include_sensor = bool(pub.get("fingerprint_include_sensor", False))
    fp = indicators_fingerprint(iocs, meta=meta, include_sensor=include_sensor)
    st = load_state(state_path)
    if st.get("last_fingerprint") == fp:
        mins = int(pub.get("min_interval_minutes", 0) or 0)
        if mins:
            try: last = datetime.fromisoformat(st.get("last_run_utc"))
            except Exception: last = None
            if last and (datetime.now(timezone.utc) - last < timedelta(minutes=mins)):
                logger.info("Indicators unchanged and within cool-off — skipping.")
                return False, fp
        logger.info("Indicators unchanged since last publish (fingerprint match) — skipping.")
        return False, fp
    return True, fp

# ---------------- OTX ----------------
def test_otx_connection(api_key: str, logger: logging.Logger) -> bool:
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent":"otx-publisher/1.0"},
            timeout=10
        )
        if r.status_code == 200: return True
        logger.error(f"OTX auth check failed: {r.status_code} {r.text[:200]}")
        return False
    except Exception as e:
        logger.error(f"OTX connectivity init failed: {e}")
        return False

def build_pulse(cfg: dict, iocs: Dict[str, Set[str]], meta: dict) -> dict:
    tlp=cfg["pulse"]["tlp"].upper(); prefix=cfg["pulse"]["name_prefix"]; window=cfg["pulse"]["time_window_hours"]
    name=f"{prefix} – last {window}h"
    desc=("Indicators observed by T-Pot CE honeypots. "
          "Signals are deduped and filtered (min event count threshold; private IPs excluded). "
          "Indicators carry per-sensor tags (e.g., cowrie/suricata/dionaea/honeytrap). "
          "Intended for defensive use; infrastructure may be compromised or spoofed. "
          "Sensor: T-Pot CE.")
    indicators=[]
    include_title = bool(cfg.get("pulse",{}).get("include_sensor_in_title", True))
    def _clean_tags(tags):
        t = sorted(set(tags))
        return [x for x in t if x != "unknown"] or ["unknown"]

    # Attach per-indicator tags from meta (sensor names) + show in title
    def title_with(sensors: list[str], base: str) -> str:
        if not include_title: return base
        ss = ", ".join(sensors) if sensors else "unknown"
        return f"{base} • {ss}"

    for ip in sorted(iocs["ipv4"]):
        tags = _clean_tags(sorted(meta["ipv4"].get(ip, set())) or ["unknown"])
        indicators.append({"indicator": ip, "type": "IPv4", "title": title_with(tags, "Attacker IP"), "tags": tags})
    for u in sorted(iocs["urls"]):
        tags = _clean_tags(sorted(meta["urls"].get(u, set())) or ["unknown"])
        indicators.append({"indicator": u, "type": "URL", "title": title_with(tags, "Payload URL"), "tags": tags})
    for h in sorted(iocs["hashes"]):
        itype = "FileHash-SHA256" if len(h)==64 else "FileHash-MD5"
        tags = _clean_tags(sorted(meta["hashes"].get(h, set())) or ["unknown"])
        indicators.append({"indicator": h, "type": itype, "title": title_with(tags, "Dropped File Hash"), "tags": tags})
    return {"name":name,"description":desc,"public":(tlp=="GREEN"),"tlp":tlp,
            "tags":["tpot","cowrie","honeytrap","suricata","dionaea","honeypot","ssh","malicious","sensor-tagged"],
            "indicators":indicators}

def publish_pulse(api_key: str, pulse: dict, dry_run: bool, logger: logging.Logger):
    ip_cnt  = sum(1 for i in pulse["indicators"] if i["type"]=="IPv4")
    url_cnt = sum(1 for i in pulse["indicators"] if i["type"]=="URL")
    hash_cnt= sum(1 for i in pulse["indicators"] if i["type"].startswith("FileHash"))
    logger.info(f"Pulse indicators: IPs={ip_cnt}, URLs={url_cnt}, Hashes={hash_cnt}")
    if dry_run:
        logger.info("DRY-RUN: not publishing to OTX")
        return None
    try:
        r = requests.post(
            "https://otx.alienvault.com/api/v1/pulses/create/",
            headers={"X-OTX-API-KEY": api_key, "User-Agent":"otx-publisher/1.0",
                     "Content-Type":"application/json"},
            data=json.dumps(pulse), timeout=30
        )
        r.raise_for_status()
        created = r.json()
        logger.info(f"Published pulse: {created.get('name','(no name)')} (id={created.get('id','?')})")
        return created
    except Exception as e:
        logger.error(f"OTX publish failed: {e}")
        raise

# ---------------- main ----------------
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--config", default="config.json")
    p.add_argument("--dry-run", action="store_true")
    args=p.parse_args()

    cfg=load_config(args.config)
    logger=setup_logger(cfg.get("log_path"))

    if not es_health(cfg["elasticsearch"]["host"], cfg["elasticsearch"]["timeout"]):
        logger.error("Elasticsearch unhealthy/unreachable"); return
    if not test_otx_connection(cfg["otx_api_key"], logger): return

    iocs, meta = collect_iocs(cfg, logger)
    total = sum(len(v) for v in iocs.values())
    logger.info(f"Collected IOCs total={total} (IPs={len(iocs['ipv4'])}, URLs={len(iocs['urls'])}, Hashes={len(iocs['hashes'])})")
    if total==0:
        logger.warning("No IOCs found in window; skipping publish"); return

    state_path = cfg.get("state_path", "/opt/otx-publisher/state.json")

    # --- Daily only check ---
    pub = cfg.get("publish", {}) if isinstance(cfg.get("publish", {}), dict) else {}
    min_mins = int(pub.get("min_interval_minutes", 1440) or 1440)
    st = load_state(state_path)
    last_iso = st.get("last_run_utc")
    last = None
    if last_iso:
        try:
            last = datetime.fromisoformat(last_iso)
        except Exception:
            last = None
    now = datetime.now(timezone.utc)
    if last and (now - last) < timedelta(minutes=min_mins):
        logger.info("Daily-only mode: ran recently — skipping.")
        return

    pulse = build_pulse(cfg, iocs, meta)
    created = publish_pulse(cfg["otx_api_key"], pulse, args.dry_run, logger)

    if not args.dry_run:
        new_state = {
            "last_run_utc": datetime.now(timezone.utc).isoformat(),
            "last_total": total,
            "counts": {"ips": len(iocs["ipv4"]), "urls": len(iocs["urls"]), "hashes": len(iocs["hashes"])},
            "pulse_name": pulse.get("name")
        }
        save_state(state_path, new_state)

if __name__ == "__main__":
    main()
