#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Set
import requests

BASE = "https://otx.alienvault.com/api/v1"

# --------------- helpers ---------------
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
    return logging.getLogger("otx-ssh-rolling")

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
    return requests.post(
        f"{es_host}/{index}/_search",
        headers={"Content-Type":"application/json"},
        data=json.dumps(body),
        timeout=timeout,
    )

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def mask_token(s: str) -> str:
    if not isinstance(s, str) or not s:
        return ""
    s = s.strip()
    # mask email-style usernames
    if "@" in s and "." in s.split("@")[-1]:
        local, dom = s.split("@", 1)
        if len(local) <= 2:
            m = "*" * len(local)
        else:
            m = local[0] + ("*" * (len(local)-2)) + local[-1]
        return f"{m}@{dom}"
    # mask non-email usernames / passwords
    if len(s) <= 3:
        return "*" * len(s)
    return s[0] + ("*" * (len(s)-2)) + s[-1]

def top_keys(buckets: list, k="key", n=5) -> List[str]:
    out=[]
    for b in (buckets or [])[:n]:
        v=b.get(k)
        if isinstance(v,str):
            out.append(v)
        elif isinstance(v,(int,float)):
            out.append(str(v))
    return out

# --------------- query setup ---------------
SSH_SHOULD = [
    {"term":{"type.keyword":"cowrie"}},{"term":{"type.keyword":"Cowrie"}},
    {"term":{"type.keyword":"heralding"}},{"term":{"type.keyword":"Heralding"}},
    {"term":{"protocol.keyword":"ssh"}},
    {"term":{"event.dataset.keyword":"cowrie"}},
    {"term":{"event.dataset.keyword":"heralding"}},
]

IP_FIELDS     = ["src_ip.keyword","source_ip.keyword","client_ip.keyword","source.ip","client.ip","source.address.keyword"]
PORT_FIELDS   = ["dest_port","destination.port","server.port"]
CC_FIELDS     = ["geoip.country_code2.keyword","geoip.country_iso_code","geoip.country_name.keyword"]
ASN_FIELDS    = ["geoip.asn"]
ASORG_FIELDS  = ["geoip.as_org.keyword"]
USER_FIELDS   = ["username.keyword","user.name.keyword","ssh.username.keyword","cowrie.username.keyword"]
PASS_FIELDS   = ["password.keyword","ssh.password.keyword","cowrie.password.keyword"]
CLIENT_FIELDS = ["ssh.client.keyword","ssh.client","ssh.client_version.keyword","client.keyword","network.user_agent.original.keyword"]

# destination-like fields for self-IP auto-detection
DEST_CANDIDATES = [
    "destination.ip","dest_ip","server.ip","host.ip","server.address","destination.address",
]

# --- self/service IP detection via runtime field over destination-like paths
def detect_self_ips(es_host: str, indices: List[str], timeout: int,
                    start: datetime, end: datetime, logger) -> List[str]:
    rm = {
        "dst_rt": {
            "type": "keyword",
            "script": {
                "source": """
                def fields = params.f;
                for (def k : fields) {
                  if (doc.containsKey(k) && !doc[k].empty) {
                    def v = doc[k].value;
                    if (v != null) { emit(v.toString()); return; }
                  }
                }
                """,
                "params": {"f": DEST_CANDIDATES},
            },
        },
    }
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": {"gte": _utc_iso(start), "lte": _utc_iso(end)}}},
                ],
                "should": SSH_SHOULD,
                "minimum_should_match": 1,
            }
        },
        "runtime_mappings": rm,
        "aggs": {"dst": {"terms": {"field": "dst_rt", "size": 10}}},
    }
    top: List[str] = []
    for idx in indices:
        try:
            r = es_search(es_host, idx, body, timeout)
            if r.status_code != 200:
                continue
            buckets = r.json().get("aggregations", {}).get("dst", {}).get("buckets", [])
            for b in buckets[:3]:
                k = b.get("key")
                if not isinstance(k, str):
                    continue
                k = k.split(":", 1)[0]
                try:
                    ipstr = str(ipaddress.ip_address(k))
                    if ipstr not in top:
                        top.append(ipstr)
                except Exception:
                    continue
            if top:
                break
        except Exception as e:
            logger.warning(f"self-ip detect failed: {e}")
            break
    if top:
        logger.info(f"Self IPs (top dest): {top}")
    else:
        logger.info("Self IPs not detected (dest runtime path empty).")
    return top

# pick a field, but AVOID candidates whose top value is in avoid list (self IPs, etc.)
def pick_field(es_host: str, indices: List[str], timeout: int, candidates: List[str],
               start: datetime, end: datetime, avoid: List[str]) -> Optional[str]:
    avoid_set = set(avoid or [])
    for idx in indices:
        for f in candidates:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": _utc_iso(start), "lte": _utc_iso(end)}}},
                            {"exists": {"field": f}},
                        ],
                        "should": SSH_SHOULD,
                        "minimum_should_match": 1,
                    }
                },
                "aggs": {"t": {"terms": {"field": f, "size": 1}}},
            }
            try:
                r = es_search(es_host, idx, body, timeout)
                if r.status_code != 200:
                    continue
                ag = r.json().get("aggregations", {}).get("t", {})
                buckets = ag.get("buckets") or []
                if not buckets:
                    continue
                top = str(buckets[0].get("key", "")).split(":", 1)[0]
                if top in avoid_set:
                    # this field is probably pointing at our own address; skip it
                    continue
                return f
            except Exception:
                pass
    return None

# --------------- collection ---------------
def collect_ssh(cfg: dict, logger) -> Tuple[Dict[str,int], Dict[str,dict]]:
    es = cfg["elasticsearch"]
    es_host = es["host"]
    es_timeout = int(es.get("timeout", 15))
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    indices = cfg.get("indices", ["logstash-*"])
    min_events = int(cfg["pulse"].get("min_event_count", 1))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", False))

    # detect self IPs first (auto) and union with config
    detected_self = detect_self_ips(es_host, indices, es_timeout, start, end, logger)
    cfg_self = list(map(str, (cfg.get("self_ips") or []))) if isinstance(cfg.get("self_ips"), list) else []
    self_ips: Set[str] = set(detected_self) | set(cfg_self)
    if self_ips:
        logger.info(f"Using self IPs (detected ∪ config): {sorted(self_ips)}")

    # field discovery; avoid picking an IP field whose top value equals a self IP
    ipf   = pick_field(es_host, indices, es_timeout, IP_FIELDS, start, end, list(self_ips))
    portf = pick_field(es_host, indices, es_timeout, PORT_FIELDS, start, end, [])
    ccf   = pick_field(es_host, indices, es_timeout, CC_FIELDS, start, end, [])
    asnf  = pick_field(es_host, indices, es_timeout, ASN_FIELDS, start, end, [])
    asorg = pick_field(es_host, indices, es_timeout, ASORG_FIELDS, start, end, [])
    userf = pick_field(es_host, indices, es_timeout, USER_FIELDS, start, end, [])
    passf = pick_field(es_host, indices, es_timeout, PASS_FIELDS, start, end, [])
    clientf = pick_field(es_host, indices, es_timeout, CLIENT_FIELDS, start, end, [])

    if not ipf:
        logger.error("No aggregatable IP field found for SSH docs; aborting.")
        return {}, {}

    logger.info(
        "Using fields "
        f"ip={ipf} port={portf} cc={ccf} asn={asnf} org={asorg} "
        f"user={userf} pass={passf} client={clientf}"
    )

    counts: Dict[str,int] = {}
    enrich: Dict[str,dict] = {}

    def sub_aggs():
        a = {"sensors":{"terms":{"field":"type.keyword","size":10}}}
        if portf:  a["ports"]   = {"terms":{"field":portf,"size":5}}
        if ccf:    a["cc"]      = {"terms":{"field":ccf,"size":3}}
        if asnf:   a["asn"]     = {"terms":{"field":asnf,"size":3}}
        if asorg:  a["asn_org"] = {"terms":{"field":asorg,"size":3}}
        if userf:  a["user"]    = {"terms":{"field":userf,"size":5}}
        if passf:  a["pass"]    = {"terms":{"field":passf,"size":5}}
        if clientf:a["client"]  = {"terms":{"field":clientf,"size":5}}
        return a

    for idx in indices:
        after=None
        while True:
            body = {
                "size": 0,
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"@timestamp": {"gte": _utc_iso(start), "lte": _utc_iso(end)}}},
                            {"exists": {"field": ipf}},
                        ],
                        "should": SSH_SHOULD,
                        "minimum_should_match": 1,
                    }
                },
                "aggs": {
                    "by": {
                        "composite":{"size":1000,"sources":[{"ip":{"terms":{"field": ipf}}}]},
                        "aggs": sub_aggs(),
                    }
                },
            }
            if after:
                body["aggs"]["by"]["composite"]["after"] = after
            try:
                r = es_search(es_host, idx, body, es_timeout)
                if r.status_code != 200:
                    break
                ag = r.json().get("aggregations",{}).get("by",{})
                for b in ag.get("buckets", []):
                    raw = b.get("key",{}).get("ip")
                    if not isinstance(raw, str):
                        continue
                    ipval = raw.split(":",1)[0]
                    try:
                        ip = str(ipaddress.ip_address(ipval))
                    except Exception:
                        continue
                    if ip in self_ips:           # skip self/service IPs
                        continue
                    if exclude_private and is_private_ip(ip):
                        continue
                    c = int(b.get("doc_count",0))
                    counts[ip] = counts.get(ip,0) + c

                    e = enrich.setdefault(ip, {"sensors": set()})
                    if "ports" in b:   e["ports"]  = top_keys(b["ports"].get("buckets",[]), n=5)
                    if "cc" in b:      e["cc"]     = top_keys(b["cc"].get("buckets",[]), n=3)
                    if "asn" in b:     e["asn"]    = top_keys(b["asn"].get("buckets",[]), n=3)
                    if "asn_org" in b: e["org"]    = top_keys(b["asn_org"].get("buckets",[]), n=3)
                    if "user" in b:    e["users"]  = [mask_token(x) for x in top_keys(b["user"].get("buckets",[]), n=5)]
                    if "pass" in b:    e["passes"] = [mask_token(x) for x in top_keys(b["pass"].get("buckets",[]), n=5)]
                    if "client" in b:  e["client"] = top_keys(b["client"].get("buckets",[]), n=5)
                    for sb in (b.get("sensors",{}).get("buckets",[]) or []):
                        sk = sb.get("key")
                        if isinstance(sk,str) and sk:
                            e["sensors"].add(sk)
                after = ag.get("after_key")
                if not after:
                    break
            except Exception:
                break

    # drop IPs below min_events
    for ip in list(enrich.keys()):
        if counts.get(ip,0) < min_events:
            enrich.pop(ip, None)
    counts = {k:v for k,v in counts.items() if v >= min_events}

    logger.info(f"SSH IPv4s in window: {len(counts)}")
    return counts, enrich

# --------------- indicator builder ---------------
def build_ip_indicators(cfg: dict, counts: Dict[str,int], enrich: Dict[str,dict]) -> List[dict]:
    indicators: List[dict] = []
    for ip in sorted(counts.keys()):
        e = enrich.get(ip, {})
        sensors = sorted(e.get("sensors", set())) or ["unknown"]
        parts = [
            f"seen in SSH honeypot; events={counts[ip]}",
            f"sensors={','.join(sensors)}",
        ]
        if e.get("ports"):  parts.append(f"ports={','.join(map(str,e['ports']))}")
        if e.get("cc"):     parts.append(f"cc={','.join(e['cc'])}")
        if e.get("asn"):    parts.append(f"asn={','.join(e['asn'])}")
        if e.get("org"):    parts.append(f"asn_org={','.join(e['org'])}")
        if e.get("client"): parts.append(f"client={','.join(e['client'])}")
        if e.get("users"):  parts.append(f"user(top)={','.join(e['users'])}")
        if e.get("passes"): parts.append(f"pass(top)={','.join(e['passes'])}")

        indicators.append({
            "indicator": ip,
            "type": "IPv4",
            "title": "Attacker IP \u2022 SSH",
            "description": "; ".join(parts),
            "tags": ["ssh","cowrie","heralding","tpot","honeypot","bruteforce"],
            "role": "bruteforce",
        })
    return indicators

# --------------- OTX helpers ---------------
def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get(
            f"{BASE}/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent":"otx-ssh-rolling/1.0"},
            timeout=10,
        )
        ok = (r.status_code == 200)
        if not ok:
            logger.error(f"OTX auth failed: {r.status_code} {r.text[:200]}")
        return ok
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False

def otx_headers(api_key: str) -> dict:
    return {
        "X-OTX-API-KEY": api_key,
        "User-Agent": "otx-ssh-rolling/1.0",
        "Content-Type": "application/json",
    }

def find_monthly_pulse(api_key: str, name: str, logger) -> Optional[str]:
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
                logger.error(f"OTX list pulses failed page={page}: {r.status_code} {r.text[:300]}")
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
            logger.error(f"OTX get pulse {pulse_id} failed: {r.status_code} {r.text[:300]}")
            return None
        return r.json()
    except Exception as e:
        logger.error(f"OTX get pulse {pulse_id} exception: {e}")
        return None

def create_pulse(api_key: str, name: str, description: str, tlp: str,
                 tags: List[str], indicators: List[dict], public: bool,
                 logger, dry_run: bool) -> Optional[str]:
    headers = otx_headers(api_key)
    body = {
        "name": name,
        "description": description,
        "public": public,
        "TLP": tlp,
        "tags": tags,
        "indicators": indicators,
    }
    ipv4_count = len([i for i in indicators if i.get("type") == "IPv4"])
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would CREATE monthly SSH pulse '{name}' "
            f"with {ipv4_count} IPv4s"
        )
        return None
    r = requests.post(f"{BASE}/pulses/create", headers=headers, data=json.dumps(body), timeout=60)
    if r.status_code >= 400:
        logger.error(f"Create SSH pulse failed {r.status_code}: {r.text[:500]}")
        return None
    created = r.json()
    pid = created.get("id")
    logger.info(f"Created new SSH monthly pulse: {created.get('name','(no name)')} (id={pid})")
    return pid

def add_indicators(api_key: str, pulse_id: str, to_add: List[dict], logger, dry_run: bool) -> bool:
    if not to_add:
        logger.info("No new SSH indicators to add to monthly pulse.")
        return True
    headers = otx_headers(api_key)
    body = {
        "indicators": {
            "add": to_add,
        }
    }
    ipv4_count = len([i for i in to_add if i.get("type") == "IPv4"])
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would PATCH SSH pulse id={pulse_id} adding {len(to_add)} indicators "
            f"({ipv4_count} IPv4s)"
        )
        return True
    r = requests.patch(
        f"{BASE}/pulses/{pulse_id}",
        headers=headers,
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"OTX SSH update error {r.status_code}: {r.text[:500]}")
        return False
    logger.info(f"Successfully patched SSH pulse {pulse_id} with {len(to_add)} new indicators")
    return True

# --------------- main ---------------
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

    counts, enrich = collect_ssh(cfg, logger)
    if not counts:
        logger.warning("No SSH IPs found in window; skipping")
        return

    hours = int(cfg["pulse"].get("time_window_hours", 1))
    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")

    tlp = str(cfg["pulse"].get("tlp","green")).upper()
    prefix = cfg["pulse"].get("name_prefix","SSH \u2192 Attacker IPs")
    loc = str(cfg["pulse"].get("location_label","")).strip()
    if loc:
        name = f"{prefix} \u2013 {loc} \u2013 {month_label}"
    else:
        name = f"{prefix} \u2013 {month_label}"

    desc = (
        f"Rolling monthly view for {month_label} of SSH brute-force source IPv4 addresses "
        f"observed by Cowrie/Heralding on a T-Pot honeypot. Each run looks back the last "
        f"{hours}h and appends newly seen IPs for this month."
    )
    if loc:
        desc += f" Location: {loc}."

    tags = cfg.get("pulse", {}).get("tags") or ["tpot","honeypot","ssh","cowrie","heralding","bruteforce"]
    public = (tlp == "GREEN")

    ip_indicators = build_ip_indicators(cfg, counts, enrich)
    all_new = ip_indicators

    if not all_new:
        logger.warning("No SSH indicators built from this window; skipping.")
        return

    api_key = cfg["otx_api_key"]

    # look up or create the monthly pulse
    pulse_id = find_monthly_pulse(api_key, name, logger)

    if not pulse_id:
        pulse_id = create_pulse(api_key, name, desc, tlp, tags, all_new, public, logger, args.dry_run)
        if not pulse_id and not args.dry_run:
            logger.error("Failed to create SSH monthly pulse; aborting.")
        return

    # fetch existing indicators and append only new ones
    existing = get_pulse(api_key, pulse_id, logger)
    if existing is None:
        logger.error("Could not fetch existing SSH monthly pulse; aborting.")
        return

    existing_inds = existing.get("indicators") or []
    existing_keys = {(i.get("indicator"), i.get("type")) for i in existing_inds if isinstance(i, dict)}

    to_add: List[dict] = []
    for ind in all_new:
        key = (ind.get("indicator"), ind.get("type"))
        if key not in existing_keys:
            to_add.append(ind)

    add_indicators(api_key, pulse_id, to_add, logger, args.dry_run)

if __name__ == "__main__":
    main()