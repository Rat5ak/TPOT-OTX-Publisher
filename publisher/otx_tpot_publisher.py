#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, os, hashlib, re
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Tuple
from urllib.parse import urlparse
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

# ---------------- sensor detection (fallback) ----------------
def detect_sensor(src: dict, index_name: str|None=None) -> str:
    cand=[]
    for k in ("type","eventid","path","t-pot_hostname"):
        v=src.get(k);
        if isinstance(v,str) and v: cand.append(v.lower())
    for k in ("event.module","event.dataset","service.name","program","agent.type","agent.name"):
        v=src.get(k);
        if isinstance(v,str) and v: cand.append(v.lower())
    for k in ("event","service","agent"):
        sub=src.get(k,{})
        if isinstance(sub,dict):
            for kk in ("module","dataset","name","type"):
                vv=sub.get(kk)
                if isinstance(vv,str) and vv: cand.append(vv.lower())
    if index_name: cand.append(str(index_name).lower())
    blob=" ".join(cand)
    for kw,canon in (("cowrie","cowrie"),("suricata","suricata"),("dionaea","dionaea"),
                     ("honeytrap","honeytrap"),("h0neytr4p","honeytrap"),("p0f","p0f")):
        if kw in blob: return canon
    if "tpot" in blob: return "tpot"
    return "unknown"

# ---------------- URL host helpers ----------------
def _url_host(u: str) -> str|None:
    try:
        netloc = urlparse(u).netloc
        if not netloc: return None
        host = netloc.split('@')[-1].split(':')[0].strip('[]')
        return host.lower()
    except Exception:
        return None

def _is_self_url(u: str, local_ips: Set[str]) -> bool:
    host = _url_host(u)
    if not host: return False
    if host in ("localhost","127.0.0.1","::1"): return True
    # direct IP host only (we DO NOT treat dash-hostnames as self)
    try:
        if str(ipaddress.ip_address(host)) in local_ips:
            return True
    except Exception:
        pass
    return False

# ---------------- IOC collection (composite aggs; refined self-IP) ----------------
def collect_iocs(cfg: dict, logger: logging.Logger) -> Tuple[Dict[str, Set[str]], dict]:
    es=cfg["elasticsearch"]; es_host, es_timeout = es["host"], es["timeout"]
    end_time=datetime.now(timezone.utc)
    start_time=end_time - timedelta(hours=cfg["pulse"]["time_window_hours"])

    indices = cfg["indices"]
    max_indicators = int(cfg["limits"]["max_indicators"])
    exclude_private = bool(cfg["pulse"]["exclude_private_ips"])
    min_events = int(cfg["pulse"]["min_event_count"])

    iocs = {"ipv4": set(), "urls": set(), "hashes": set()}
    meta = {"ipv4": {}, "urls": {}, "hashes": {}}  # indicator -> set(sensors)

    time_query = {"bool":{"filter":[{"range":{"@timestamp":{"gte":_utc_iso(start_time), "lte":_utc_iso(end_time)}}}]}}

    def composite_iter(idx: str, field: str, key_name: str):
        after=None
        while True:
            body={
                "size":0,
                "query": time_query,
                "aggs":{
                    "by":{
                        "composite":{"size":1000,"sources":[{key_name:{"terms":{"field":field}}}]},
                        "aggs":{"sensors":{"terms":{"field":"type.keyword","size":50}}}
                    }
                }
            }
            if after: body["aggs"]["by"]["composite"]["after"]=after
            try:
                r=es_search(es_host, idx, body, es_timeout)
                if r.status_code!=200: break
                ag=r.json().get("aggregations",{}).get("by",{})
                for b in ag.get("buckets",[]):
                    key=b.get("key",{}).get(key_name)
                    if key is None: continue
                    yield key, int(b.get("doc_count",0)), [sb.get("key","").lower() for sb in b.get("sensors",{}).get("buckets",[]) if sb.get("key")]
                after=ag.get("after_key")
                if not after: break
            except Exception as e:
                logger.warning(f"composite agg failed for {idx} field {field}: {e}")
                break

    # Normalize a value to a clean IP string, or return None
    def norm_ip(val: str) -> str|None:
        if not isinstance(val, str): return None
        s = val.strip()
        # Strip ":port" for IPv4 "A.B.C.D:port"
        if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:\d+$', s):
            s = s.split(':',1)[0]
        try:
            ip = ipaddress.ip_address(s)
            # exclude unspecified/bogus
            if ip.is_unspecified: return None
            return str(ip)
        except Exception:
            return None

    # ---- Collect destination IP counts to infer local self IP(s)
    dst_fields = ["dest_ip.keyword","dest_ip","destination.ip","server.ip","host.ip","server.address","destination.address"]
    dest_counts: Dict[str,int] = {}
    for idx in indices:
        for fld in dst_fields:
            try:
                for raw, cnt, _ in composite_iter(idx, fld, "ip"):
                    ip = norm_ip(raw)
                    if not ip: continue
                    dest_counts[ip] = dest_counts.get(ip, 0) + cnt
            except Exception:
                continue

    # pick top few dest IPs by volume as local (heuristic)
    local_ips: Set[str] = set()
    if dest_counts:
        top = sorted(dest_counts.items(), key=lambda kv: kv[1], reverse=True)
        # keep up to 3 with a simple minimum volume guard (>= 1% of top)
        top1 = top[0][1]
        for ip, c in top[:3]:
            if c >= max(10, int(0.01*top1)):
                local_ips.add(ip)
        logger.info(f"Self-IP candidates (top dest by count): {[(ip, dest_counts[ip]) for ip in list(local_ips)[:3]]}{' ...' if len(local_ips)>3 else ''}")

    # ---- IPs (union across src fields) with sensor tags from type.keyword
    ip_counts: Dict[str,int] = {}
    src_fields = ["src_ip.keyword","source_ip.keyword","client_ip.keyword"]
    for idx in indices:
        for fld in src_fields:
            try:
                for ip_raw, cnt, sensors in composite_iter(idx, fld, "ip"):
                    ip = norm_ip(ip_raw)
                    if not ip or cnt < min_events: continue
                    if exclude_private and is_private_ip(ip): continue
                    ip_counts[ip]=ip_counts.get(ip,0)+cnt
                    if sensors: meta["ipv4"].setdefault(ip, set()).update(sensors)
                    else: meta["ipv4"].setdefault(ip, set())
            except Exception as e:
                logger.warning(f"IP agg iterate failed for {idx} {fld}: {e}")
    for ip in ip_counts.keys():
        iocs["ipv4"].add(ip)

    # ---- URLs (aggregate + drop only explicit self IP/localhost hosts)
    url_fields = ["url.keyword","http.url.keyword","request.url.keyword","url","http.url","request.url"]
    for idx in indices:
        for fld in url_fields:
            try:
                for u, cnt, sensors in composite_iter(idx, fld, "u"):
                    if not isinstance(u,str): continue
                    if not (u.startswith("http://") or u.startswith("https://")): continue
                    if _is_self_url(u, local_ips):
                        continue
                    iocs["urls"].add(u)
                    if sensors: meta["urls"].setdefault(u,set()).update(sensors)
                    else: meta["urls"].setdefault(u,set())
            except Exception:
                continue

    # ---- Hashes (aggregate)
    hash_fields = ["sha256.keyword","fileinfo.sha256.keyword","files.sha256.keyword","shasum.keyword","sha256","fileinfo.sha256","files.sha256","shasum"]
    for idx in indices:
        for fld in hash_fields:
            try:
                for hv, cnt, sensors in composite_iter(idx, fld, "h"):
                    if not isinstance(hv,str) or len(hv)<32: continue
                    hv = hv.lower()
                    iocs["hashes"].add(hv)
                    if sensors: meta["hashes"].setdefault(hv,set()).update(sensors)
                    else: meta["hashes"].setdefault(hv,set())
            except Exception:
                continue

    # ---- final trim: respect max_indicators but KEEP URLs/Hashes
    if max_indicators > 0:
        non_ip = len(iocs["urls"]) + len(iocs["hashes"])
        room_for_ips = max(0, max_indicators - non_ip)
        if len(iocs["ipv4"]) > room_for_ips:
            sorted_ips = sorted(ip_counts.items(), key=lambda kv: kv[1], reverse=True)
            keep = set(ip for ip,_ in sorted_ips[:room_for_ips])
            iocs["ipv4"] = keep
            meta["ipv4"] = {k:v for k,v in meta["ipv4"].items() if k in keep}
            logging.getLogger("otx-publisher").warning(
                f"trimmed IPv4s to {room_for_ips} due to max_indicators")

    return iocs, meta

# ---------------- dedupe state ----------------
def indicators_fingerprint(iocs: dict, meta: dict|None=None, include_sensor: bool=False) -> str:
    items=[]
    if include_sensor and meta:
        for v in sorted(iocs.get("ipv4", [])):
            sensors=",".join(sorted(meta.get("ipv4",{}).get(v, set()))) or "unknown"
            items.append(f"ip:{v}|{sensors}")
        for v in sorted(iocs.get("urls", [])):
            sensors=",".join(sorted(meta.get("urls",{}).get(v, set()))) or "unknown"
            items.append(f"url:{v}|{sensors}")
        for v in sorted(iocs.get("hashes", [])):
            sensors=",".join(sorted(meta.get("hashes",{}).get(v, set()))) or "unknown"
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
    pub = cfg.get("publish", {}) if isinstance(cfg.get("publish", {}), dict) else {}
    min_mins = int(pub.get("min_interval_minutes", 1440) or 1440)
    st = load_state(state_path)
    last_iso = st.get("last_run_utc")
    last=None
    if last_iso:
        try: last = datetime.fromisoformat(last_iso)
        except Exception: last=None
    now = datetime.now(timezone.utc)
    if last and (now - last) < timedelta(minutes=min_mins):
        logger.info("Daily-only mode: ran recently — skipping.")
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
            except Exception: last=None
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
          "Indicators carry per-sensor tags derived from event 'type'. "
          "Intended for defensive use; infrastructure may be compromised or spoofed. "
          "Sensor: T-Pot CE.")
    indicators=[]
    include_title = bool(cfg.get("pulse",{}).get("include_sensor_in_title", True))
    def _clean_tags(tags):
        t = sorted(set(tags))
        return [x for x in t if x != "unknown"] or ["unknown"]
    def title_with(sensors: list[str], base: str) -> str:
        if not include_title: return base
        ss = ", ".join(sorted(set(sensors))) if sensors else "unknown"
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
            "tags":["tpot","honeypot","sensor-tagged","cowrie","suricata","dionaea","honeytrap","p0f","fatt","mailoney","tanner","sentrypeer"],
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
            data=json.dumps(pulse), timeout=60
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
    pub = cfg.get("publish", {}) if isinstance(cfg.get("publish", {}), dict) else {}
    min_mins = int(pub.get("min_interval_minutes", 1440) or 1440)
    st = load_state(state_path)
    last_iso = st.get("last_run_utc")
    last=None
    if last_iso:
        try: last = datetime.fromisoformat(last_iso)
        except Exception: last=None
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