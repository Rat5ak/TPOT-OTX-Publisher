#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, re, unicodedata as _U, os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional, Set
import requests

# --- OTX-accepted roles (allow-list) ---
ROLE_OK = {
    "scanning_host",
    "bruteforce",
    "malware_hosting",
    "malware_distribution",
    "command_and_control",
    "c2_server",
}

BASE = "https://otx.alienvault.com/api/v1"

# ---------------- pulse registry (month-aware) ----------------
PULSE_REGISTRY = "/opt/otx-publisher/pulses.json"


def load_pulse_id(key: str) -> Optional[str]:
    try:
        if os.path.exists(PULSE_REGISTRY):
            with open(PULSE_REGISTRY, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                v = data.get(key)
                return str(v) if v else None
    except Exception:
        return None
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


# ---------------- config helpers ----------------
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
    return logging.getLogger("otx-adb-rolling")

def _utc_iso(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat()

# ---------------- ES helpers ----------------
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

# ---------------- field selection ----------------
IP_FIELDS  = [
    "src_ip.keyword","source_ip.keyword","client_ip.keyword",
    "source.ip","client.ip","source.address.keyword"
]
PORT_FIELDS= ["dest_port","destination.port","server.port"]
CC_FIELDS  = ["geoip.country_code2.keyword","geoip.country_iso_code","geoip.country_name.keyword"]
ASN_FIELDS = ["geoip.asn"]
ASORG_FIELDS=["geoip.as_org.keyword"]

ADB_SHOULD = [
    {"term":{"type.keyword":"adbhoney"}},
    {"term":{"type.keyword":"Adbhoney"}},
    {"term":{"event.dataset.keyword":"adbhoney"}},
    {"term":{"program.keyword":"adbhoney"}},
    {"term":{"service.name.keyword":"adbhoney"}},
    {"term":{"dest_port":5555}},
    {"term":{"destination.port":5555}},
]
SURI_SHOULD = [
    {"term":{"type.keyword":"Suricata"}},
    {"term":{"event.dataset.keyword":"suricata"}},
    {"term":{"event_type.keyword":"alert"}},
    {"term":{"event_type":"alert"}},
]

CMD_Q = r'("pm install" OR "am start" OR ".apk" OR "/data/local/tmp/" OR nohup OR wget OR curl OR miner OR trinity OR "chmod 0755" OR "pm path" OR "start -n" OR "sh -c")'

def pick_field(es_host: str, indices: List[str], timeout: int, candidates: List[str],
               start: datetime, end: datetime) -> Optional[str]:
    for idx in indices:
        for f in candidates:
            body = {
                "size": 0,
                "query": {"bool":{
                    "filter":[
                        {"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}},
                        {"exists":{"field": f}}
                    ],
                    "should": ADB_SHOULD, "minimum_should_match": 1
                }},
                "aggs": {"t":{"terms":{"field": f, "size": 1}}}
            }
            try:
                r = es_search(es_host, idx, body, timeout)
                if r.status_code != 200:
                    continue
                ag = r.json().get("aggregations",{}).get("t",{})
                if (ag.get("buckets") or []):
                    return f
            except Exception:
                pass
    return None

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def top_keys(buckets: list, k="key", n=5) -> List[str]:
    out=[]
    for b in (buckets or [])[:n]:
        v=b.get(k)
        if isinstance(v,str): out.append(v)
        elif isinstance(v,(int,float)): out.append(str(v))
    return out

# --------- runtime fallback aggregator for attacker IPs ----------
def collect_adb_runtime(cfg: dict, logger) -> Tuple[Dict[str,int], Dict[str,dict], str, Optional[str], Optional[str], Optional[str], Optional[str]]:
    es = cfg["elasticsearch"]; es_host = es["host"]; es_timeout = int(es.get("timeout", 15))
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc); start = end - timedelta(hours=hours)
    indices = cfg.get("indices", ["logstash-*"])
    min_events = int(cfg["pulse"].get("min_event_count", 1))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", True))

    counts: Dict[str,int] = {}
    enrich: Dict[str,dict] = {}

    idx_pattern = ",".join(indices)
    body = {
        "size": 0,
        "query": {"bool":{
            "filter":[
                {"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}}
            ],
            "should": ADB_SHOULD, "minimum_should_match": 1
        }},
        "runtime_mappings": {
            "ip_rt": {
                "type": "keyword",
                "script": {
                    "source": """
                        def cands = new String[] {
                          'src_ip','source_ip','client_ip','source.ip','client.ip','source.address'
                        };
                        for (def f : cands) {
                          if (params._source.containsKey(f) && params._source[f] != null) {
                            def v = params._source[f];
                            if (v != null) { emit(v.toString()); return; }
                          }
                        }
                    """
                }
            }
        },
        "aggs": {
            "by": {
                "composite":{"size":1000,"sources":[{"ip":{"terms":{"field":"ip_rt"}}}]}
            }
        }
    }

    after=None
    try:
        while True:
            if after:
                body["aggs"]["by"]["composite"]["after"] = after
            r = es_search(es_host, idx_pattern, body, es_timeout)
            if r.status_code != 200:
                logger.warning(f"runtime ip agg status={r.status_code} body={r.text[:200]}")
                break
            ag = r.json().get("aggregations",{}).get("by",{})
            for b in ag.get("buckets", []):
                raw = b.get("key",{}).get("ip")
                if not isinstance(raw, str): continue
                ipval = raw.split(":",1)[0]
                try: ip = str(ipaddress.ip_address(ipval))
                except Exception: continue
                if exclude_private and is_private_ip(ip): continue
                c = int(b.get("doc_count",0) or 0)
                if c < min_events: continue
                counts[ip] = counts.get(ip,0) + c
                enrich.setdefault(ip, {})
            after = ag.get("after_key")
            if not after: break
    except Exception as e:
        logger.warning(f"runtime ip agg failed: {e}")

    logger.info(f"[runtime] ADBHoney IPv4s in window: {len(counts)}")
    return counts, enrich, "ip_rt", None, None, None, None

# ---------------- collection: base IPs ----------------
def collect_adb(cfg: dict, logger) -> Tuple[Dict[str,int], Dict[str,dict], str, Optional[str], Optional[str], Optional[str], Optional[str]]:
    es = cfg["elasticsearch"]; es_host = es["host"]; es_timeout = int(es.get("timeout", 15))
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc); start = end - timedelta(hours=hours)
    indices = cfg.get("indices", ["logstash-*"])
    min_events = int(cfg["pulse"].get("min_event_count", 1))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", True))

    ipf   = pick_field(es_host, indices, es_timeout, IP_FIELDS, start, end)
    portf = pick_field(es_host, indices, es_timeout, PORT_FIELDS, start, end)
    ccf   = pick_field(es_host, indices, es_timeout, CC_FIELDS, start, end)
    asnf  = pick_field(es_host, indices, es_timeout, ASN_FIELDS, start, end)
    asorg = pick_field(es_host, indices, es_timeout, ASORG_FIELDS, start, end)

    if not ipf:
        logger.warning("No aggregatable IP field found; switching to runtime fallback.")
        return collect_adb_runtime(cfg, logger)

    logger.info(f"Using fields ip={ipf} port={portf} cc={ccf} asn={asnf} org={asorg}")

    counts: Dict[str,int] = {}
    enrich: Dict[str,dict] = {}

    def sub_aggs():
        a={}
        if portf:  a["ports"]   = {"terms":{"field":portf,"size":5}}
        if ccf:    a["cc"]      = {"terms":{"field":ccf,"size":3}}
        if asnf:   a["asn"]     = {"terms":{"field":asnf,"size":3}}
        if asorg:  a["asn_org"] = {"terms":{"field":asorg,"size":3}}
        return a

    for idx in indices:
        after=None
        while True:
            body = {
                "size": 0,
                "query": {"bool":{
                    "filter":[
                        {"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}},
                        {"exists":{"field": ipf}}
                    ],
                    "should": ADB_SHOULD, "minimum_should_match": 1
                }},
                "aggs": {
                    "by": {
                        "composite":{"size":1000,"sources":[{"ip":{"terms":{"field": ipf}}}]},
                        "aggs": sub_aggs()
                    }
                }
            }
            if after: body["aggs"]["by"]["composite"]["after"]=after
            try:
                r = es_search(es_host, idx, body, es_timeout)
                if r.status_code != 200: break
                ag = r.json().get("aggregations",{}).get("by",{})
                for b in ag.get("buckets", []):
                    raw = b.get("key",{}).get("ip")
                    if not isinstance(raw, str): continue
                    ipval = raw.split(":",1)[0]
                    try:
                        ip = str(ipaddress.ip_address(ipval))
                    except Exception:
                        continue
                    if exclude_private and is_private_ip(ip): continue
                    c = int(b.get("doc_count",0))
                    counts[ip] = counts.get(ip,0) + c

                    e = enrich.setdefault(ip, {})
                    if "ports" in b:  e["ports"]  = top_keys(b["ports"].get("buckets",[]), n=5)
                    if "cc" in b:     e["cc"]     = top_keys(b["cc"].get("buckets",[]), n=3)
                    if "asn" in b:    e["asn"]    = top_keys(b["asn"].get("buckets",[]), n=3)
                    if "asn_org" in b:e["org"]    = top_keys(b["asn_org"].get("buckets",[]), n=3)
                after = ag.get("after_key")
                if not after: break
            except Exception:
                break

    if not counts:
        logger.warning("Standard IP agg returned 0 IPs; retrying with runtime fallback.")
        return collect_adb_runtime(cfg, logger)

    for ip in list(enrich.keys()):
        if counts.get(ip,0) < min_events:
            enrich.pop(ip, None)
            counts.pop(ip, None)

    logger.info(f"ADBHoney IPv4s in window: {len(counts)}")
    return counts, enrich, ipf, portf, ccf, asnf, asorg

# ---------------- evidence: Suricata cats ----------------
def gather_suricata_cats(es_host: str, indices: List[str], timeout: int,
                         ipf: str, ips: List[str], start: datetime, end: datetime) -> Dict[str, List[str]]:
    if not ips: return {}
    body = {
        "size": 0,
        "query": {"bool":{
            "filter":[
                {"range":{"@timestamp":{"gte":_utc_iso(start),"lte":_utc_iso(end)}}},
                {"terms":{ipf: ips}}
            ],
            "should": SURI_SHOULD, "minimum_should_match": 1
        }},
        "aggs":{"by":{
            "terms":{"field": ipf, "size": min(10000, max(10, len(ips)) )},
            "aggs":{"cats":{"terms":{"field":"alert.category.keyword","size":50}}}
        }}
    }
    out: Dict[str,List[str]] = {}
    for idx in indices:
        try:
            r = es_search(es_host, idx, body, timeout)
            if r.status_code != 200: continue
            for b in r.json().get("aggregations",{}).get("by",{}).get("buckets",[]):
                ip = b.get("key")
                if not ip: continue
                cats = top_keys(b.get("cats",{}).get("buckets",[]), n=50)
                if cats: out[ip] = cats
        except Exception:
            pass
    return out

# ---------------- evidence: ADB command hits + preview ----------------
def gather_adb_cmd_hits(es_host: str, indices: list, timeout: int,
                        ipf: str, ips: list, start, end) -> dict:
    import json as _json
    if not ips:
        return {}
    out = {}

    body_hits = {
        "size": 0,
        "query": {"bool":{
            "filter":[
                {"range":{"@timestamp":{"gte": _utc_iso(start), "lte": _utc_iso(end)}}},
                {"terms":{ipf: ips}}
            ],
            "must":[ {"query_string":{"query": CMD_Q, "default_field":"*"}} ],
            "should":[
                {"term":{"type.keyword":"Suricata"}},
                {"term":{"event.dataset.keyword":"suricata"}},
                {"term":{"type.keyword":"adbhoney"}},
                {"term":{"type.keyword":"Adbhoney"}},
                {"term":{"event.dataset.keyword":"adbhoney"}},
                {"term":{"dest_port":5555}},
                {"term":{"destination.port":5555}}
            ],
            "minimum_should_match": 1
        }},
        "aggs":{"by":{"terms":{"field": ipf, "size": min(10000, max(10, len(ips)))}}}
    }
    for idx in indices:
        try:
            r = es_search(es_host, idx, body_hits, timeout)
            if r.status_code != 200: continue
            for b in r.json().get("aggregations",{}).get("by",{}).get("buckets",[]):
                ip = b.get("key")
                if not ip: continue
                d = out.setdefault(ip, {})
                d["hits"] = int(b.get("doc_count",0))
        except Exception:
            pass

    body_prev = {
        "size": 0,
        "query": {"bool":{
            "filter":[
                {"range":{"@timestamp":{"gte": _utc_iso(start), "lte": _utc_iso(end)}}},
                {"terms":{ipf: ips}}
            ],
            "must":[ {"simple_query_string":{
                "query": CMD_Q,
                "fields": ["input","input.keyword","request","payload_printable","message","event.original"],
                "default_operator": "OR"
            }} ],
            "should":[
                {"term":{"type.keyword":"Adbhoney"}},
                {"term":{"type.keyword":"adbhoney"}},
                {"term":{"event.dataset.keyword":"adbhoney"}}
            ],
            "minimum_should_match": 1
        }},
        "aggs":{"by":{
            "terms":{"field": ipf, "size": min(10000, max(10, len(ips)))},
            "aggs":{"ex":{"top_hits":{
                "size":1,
                "_source":{"includes":["input","request","payload_printable","message","event.original"]},
                "sort":[{"@timestamp":{"order":"desc"}}]
            }}}}}
    }
    for idx in indices:
        try:
            r = es_search(es_host, idx, body_prev, timeout)
            if r.status_code != 200: continue
            for b in r.json().get("aggregations",{}).get("by",{}).get("buckets",[]):
                ip = b.get("key")
                if not ip: continue
                d = out.setdefault(ip, {})
                doc = (b.get("ex",{}).get("hits",{}).get("hits") or [])
                preview = ""
                if doc:
                    src = doc[0].get("_source",{}) or {}
                    preview = (src.get("input") or src.get("request") or
                               src.get("payload_printable") or src.get("message") or
                               (src.get("event",{}) or {}).get("original","") or "")
                    if isinstance(preview, dict):
                        preview = _json.dumps(preview)
                d["preview"] = (preview or "").replace("\r"," ").replace("\n"," ")[:300]
        except Exception:
            pass

    return out

# ---------------- role helpers ----------------
def _sanitize_role(role: str) -> str:
    if not role: return "scanning_host"
    r = str(role).strip().lower().replace("-", "_")
    alias = {
        "scanner":"scanning_host",
        "c2":"command_and_control",
        "c2_server":"command_and_control",
        "malware_distribution": "malware_hosting",
        "malware-distribution": "malware_hosting",
        "distribution": "malware_hosting",
    }
    r = alias.get(r, r)
    return r if r in ROLE_OK else "scanning_host"

def _classify_role(e: dict) -> str:
    cats_l = [c.lower() for c in e.get("cats", []) if isinstance(c, str)]
    c2_terms  = ("c2","command and control","command & control","c&c","botnet")
    mal_terms = ("malware","trojan","worm","backdoor","exploit",
                 "attempted administrator privilege gain","attempted user privilege gain")
    if any(any(t in c for t in c2_terms) for c in cats_l):
        return "command_and_control"
    if any(any(t in c for t in mal_terms) for c in cats_l):
        return "malware_distribution"
    hits = int(e.get("adb_cmd_hits", 0) or 0)
    if hits > 0:
        prev = e.get("preview","") or ""
        m = re.search(r'https?://(\d{1,3}(?:\.\d{1,3}){3})', prev)
        if m and m.group(1) == e.get("ip"):
            return "malware_hosting"
        return "malware_distribution"
    return "scanning_host"

# ---------------- Hash indicators (ENRICHED via outfile + src_ip + src_url + previews) ----------------
def collect_hash_indicators(es_host: str, indices: List[str], start: datetime, end: datetime,
                            timeout: int, window_hours: int, max_docs: int = 400,
                            self_ips: Optional[Set[str]] = None) -> Tuple[List[dict], Set[str], Set[str]]:
    session = requests.Session()
    idx_pattern = ",".join(indices)

    def es_s(body):
        try:
            r = session.post(
                f"{es_host}/{idx_pattern}/_search",
                headers={"Content-Type":"application/json"},
                data=json.dumps(body),
                timeout=timeout,
            )
            if r.status_code >= 400:
                return None
            return r.json()
        except Exception:
            return None

    # 1) Aggregate by outfile.keyword
    body_outfile = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": [
                    { "range": { "@timestamp": { "gte": _utc_iso(start), "lte": _utc_iso(end) } } },
                    { "exists": { "field": "outfile" } },
                ],
                "should": ADB_SHOULD,
                "minimum_should_match": 1,
            }
        },
        "aggs": {
            "by_outfile": {
                "terms": {
                    "field": "outfile.keyword",
                    "size": 2000,
                },
                "aggs": {
                    "last_seen": { "max": { "field": "@timestamp" } },
                    "by_src": { "terms": { "field": "src_ip.keyword", "size": 5 } },
                    "by_cc":  { "terms": { "field": "geoip.country_code2.keyword", "size": 5 } },
                }
            }
        },
    }

    res = es_s(body_outfile)
    buckets = (res or {}).get("aggregations",{}).get("by_outfile",{}).get("buckets",[]) if res else []

    sha_re = re.compile(r"([0-9a-fA-F]{64})")

    # helper: newest doc for this outfile with URL-ish + text fields
    CMD_FIELDS = ["input","request","payload_printable","message","event.original"]
    def one_download_doc(outfile):
        body = {
            "size": 1,
            "sort": [{"@timestamp":{"order":"desc"}}],
            "_source": {
                "includes": [
                    "@timestamp","outfile","src_ip","src.ip","source.ip",
                    "geoip.country_code2","geoip.country_code2.keyword",
                    "adbhoney.session.url","url.full"
                ] + CMD_FIELDS
            },
            "query": {
                "bool": {
                    "filter": [
                        { "range": { "@timestamp": { "gte": _utc_iso(start), "lte": _utc_iso(end) } } },
                        { "term":  { "outfile.keyword": outfile } },
                    ],
                    "should": ADB_SHOULD,
                    "minimum_should_match": 1,
                }
            },
        }
        r = es_s(body)
        hits = (r or {}).get("hits",{}).get("hits",[]) if r else []
        return hits[0] if hits else None

    def get_cmd_previews(src_ip, limit=3):
        if not src_ip:
            return []
        must_should = [{"exists":{"field": f}} for f in CMD_FIELDS]
        ip_should = [
            {"term":{"src_ip": src_ip}},
            {"term":{"src.ip": src_ip}},
            {"term":{"source.ip": src_ip}},
        ]
        body = {
            "size": limit,
            "sort": [{"@timestamp":{"order":"desc"}}],
            "_source": {"includes": ["@timestamp","src_ip","src.ip","source.ip"] + CMD_FIELDS},
            "query": {
                "bool": {
                    "filter": [
                        { "range": { "@timestamp": { "gte": _utc_iso(start), "lte": _utc_iso(end) } } }
                    ],
                    "must": [{ "bool": { "should": must_should, "minimum_should_match": 1 }}],
                    "should": ADB_SHOULD + ip_should,
                    "minimum_should_match": 1,
                }
            },
        }
        r = es_s(body)
        hits = (r or {}).get("hits",{}).get("hits",[]) if r else []
        out = []
        for h in hits:
            s = h.get("_source",{}) or {}
            v = next((s.get(f) for f in CMD_FIELDS if s.get(f)), "")
            if isinstance(v, dict):
                try: v = json.dumps(v)
                except Exception: v = str(v)
            v = (v or "").replace("\r"," ").replace("\n"," ").strip()
            if v:
                out.append(v)
        return out

    def get_src_ip(src):
        for k in ("src_ip","src.ip","source.ip"):
            if src.get(k): return str(src[k])
        return None

    out: List[dict] = []
    extra_ips: Set[str] = set()
    scanner_ips: Set[str] = set()
    self_ips = self_ips or set()

    def tags_from_cmds(cmds: List[str]) -> List[str]:
        t = set(["tpot","honeypot","adb","android","dropper","sample"])
        c_all = " ".join(cmds).lower()
        if "trinity" in c_all: t.add("trinity")
        if "mirai"   in c_all: t.add("mirai")
        if "mozi"    in c_all: t.add("mozi")
        if "miner"   in c_all or "xmrig" in c_all: t.add("miner")
        return sorted(t)

    for b in buckets:
        outfile = b.get("key") or ""
        m = sha_re.search(outfile)
        if not m:
            continue
        sha256 = m.group(1).lower()
        last_seen = (b.get("last_seen",{}) or {}).get("value_as_string")

        top_src = [x.get("key") for x in (b.get("by_src",{}) or {}).get("buckets",[]) if x.get("key")]
        top_cc  = [x.get("key") for x in (b.get("by_cc",{})  or {}).get("buckets",[]) if x.get("key")]

        dl = one_download_doc(outfile)
        src_ip = get_src_ip(dl.get("_source",{})) if dl else None

        # Find a src_url from structured fields or scrape from text
        src_url = None
        if dl:
            _s = dl.get("_source", {}) or {}
            src_url = _s.get("adbhoney.session.url") or _s.get("url.full")
            if not src_url:
                text = " ".join(str(_s.get(k, "")) for k in CMD_FIELDS)
                m2 = re.search(r'https?://\S+', text)
                if m2:
                    src_url = m2.group(0)

        if src_ip:
            try:
                norm_ip = str(ipaddress.ip_address(src_ip))
            except Exception:
                norm_ip = None
            if norm_ip and not is_private_ip(norm_ip) and norm_ip not in self_ips:
                extra_ips.add(norm_ip)
            if norm_ip and norm_ip not in top_src:
                top_src = [norm_ip] + top_src

        cmd_previews = get_cmd_previews(src_ip, limit=3) if src_ip else []

        parts = [
            f"Captured within last {window_hours}h by ADBHoney",
            f"outfile={outfile}",
        ]
        if src_ip:
            parts.append(f"src_ip={src_ip}")
        if src_url:
            parts.append(f"src_url={src_url}")
        if top_src:
            parts.append("src_ips=" + ",".join(top_src[:5]))
        if top_cc:
            parts.append("cc=" + ",".join(top_cc[:5]))
        if last_seen:
            parts.append(f"last_seen={last_seen}")
        if cmd_previews:
            preview_str = " | ".join(p[:120] for p in cmd_previews[:3])
            parts.append(f"cmds=[{preview_str}]")

        indicator = {
            "indicator": sha256,
            "type": "FileHash-SHA256",
            "title": "ADB dropper sample",
            "description": "; ".join(parts),
            "tags": tags_from_cmds(cmd_previews),
        }
        out.append(indicator)

    return out, extra_ips, scanner_ips

# ---------------- IP indicator builder ----------------
def build_ip_indicators(cfg: dict, counts: Dict[str,int], enrich: Dict[str,dict],
                        cats: Dict[str, List[str]], cmd: Dict[str,dict]) -> List[dict]:
    indicators: List[dict] = []
    for ip in sorted(counts.keys()):
        e = dict(enrich.get(ip, {}))
        e["ip"] = ip
        e["cats"] = cats.get(ip, [])
        cmd_e = cmd.get(ip, {})
        e["adb_cmd_hits"] = int(cmd_e.get("hits",0) or 0)
        e["preview"] = cmd_e.get("preview","") or ""

        parts=[f"seen in ADBHoney; events={counts[ip]}"]
        if e.get("ports"):  parts.append(f"ports={','.join(map(str,e['ports']))}")
        if e.get("cc"):     parts.append(f"cc={','.join(e['cc'])}")
        if e.get("asn"):    parts.append(f"asn={','.join(e['asn'])}")
        if e.get("org"):    parts.append(f"asn_org={','.join(e['org'])}")
        if e.get("cats"):   parts.append(f"cats={','.join(e['cats'])}")
        parts.append(f"adb_cmd_hits={e['adb_cmd_hits']}")
        if e["preview"] and e["preview"].strip():
            p = e["preview"].replace("\n"," ").replace("\r"," ")
            parts.append(f'cmd="{p[:160]}"')

        if "force_role" in e and e["force_role"]:
            role = _sanitize_role(e["force_role"])
        else:
            role = _sanitize_role(_classify_role(e))

        indicators.append({
            "indicator": ip,
            "type": "IPv4",
            "title": "Attacker IP \u2022 ADB",
            "description": "; ".join(parts),
            "tags": ["adb","android","tpot","honeypot","scanner","mozi","mirai","botnet","dropper"],
            "role": role
        })
    return indicators

# ---------------- OTX helpers ----------------
def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get(
            f"{BASE}/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent":"otx-adb-rolling/1.0"},
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
        "User-Agent": "otx-adb-rolling/1.0",
        "Content-Type": "application/json",
    }

def _norm_name(s: str) -> str:
    # tolerant comparer: normalize unicode, unify arrows/dashes, collapse whitespace, lowercase
    s = _U.normalize("NFKC", s or "")
    s = s.replace("->", "→")
    s = s.replace("—", "–").replace("-", "–")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s

def find_monthly_pulse(api_key: str, name: str, logger) -> Optional[str]:
    want = _norm_name(name)
    headers = otx_headers(api_key)

    # Page through "my pulses"
    page = 1
    while page <= 10:
        try:
            r = requests.get(f"{BASE}/pulses/my", headers=headers, params={"page": page}, timeout=30)
            if r.status_code != 200:
                logger.error(f"OTX list pulses failed page={page}: {r.status_code} {r.text[:300]}")
                return None
            data = r.json()
            results = data.get("results") or data.get("pulses") or []
            if not results:
                break
            for p in results:
                if _norm_name(p.get("name","")) == want:
                    return p.get("id")
            page += 1
        except Exception as e:
            logger.error(f"OTX list pulses exception page={page}: {e}")
            return None

    # Fallback to search API in case pagination missed it
    try:
        left = name.split("–")[0].strip()
        s = requests.get(f"{BASE}/search/pulses", headers=headers, params={"q": left}, timeout=30)
        if s.status_code == 200:
            for p in s.json().get("results", []):
                if _norm_name(p.get("name","")) == want:
                    return p.get("id")
    except Exception:
        pass
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
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would CREATE monthly pulse '{name}' "
            f"with {len([i for i in indicators if i.get('type')=='IPv4'])} IPv4s "
            f"and {len([i for i in indicators if i.get('type','').startswith('FileHash-')])} hashes"
        )
        return None
    r = requests.post(f"{BASE}/pulses/create", headers=headers, data=json.dumps(body), timeout=60)
    if r.status_code >= 400:
        logger.error(f"Create pulse failed {r.status_code}: {r.text[:500]}")
        return None
    created = r.json()
    pid = created.get("id")
    logger.info(f"Created new monthly pulse: {created.get('name','(no name)')} (id={pid})")
    return pid

def add_indicators(api_key: str, pulse_id: str, to_add: List[dict], logger, dry_run: bool) -> bool:
    if not to_add:
        logger.info("No new indicators to add to monthly pulse.")
        return True
    headers = otx_headers(api_key)
    body = { "indicators": { "add": to_add } }
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would PATCH pulse id={pulse_id} adding {len(to_add)} indicators "
            f"({len([i for i in to_add if i.get('type')=='IPv4'])} IPv4s, "
            f"{len([i for i in to_add if i.get('type','').startswith('FileHash-')])} hashes)"
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
    logger.info(f"Successfully patched pulse {pulse_id} with {len(to_add)} new indicators")
    return True

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
    indices = cfg.get("indices", ["logstash-*"])

    if not es_health(es_host, es_timeout):
        logger.error("Elasticsearch unhealthy/unreachable"); return
    if not test_otx(cfg["otx_api_key"], logger): return

    # self IPs: from config + hard-coded box IPs
    cfg_self = set(str(x) for x in (cfg.get("self_ips") or []) if x)
    hardcoded_self = {"172.105.186.117", "194.195.124.195"}
    self_ips = cfg_self | hardcoded_self
    logger.info(f"Using self IPs (config only + hard-coded): {sorted(self_ips) if self_ips else []}")

    counts, enrich, ipf, portf, ccf, asnf, asorg = collect_adb(cfg, logger)
    if not counts:
        logger.warning("No ADBHoney IPs found in window; skipping")
        return

    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc); start = end - timedelta(hours=hours)

    # Hash indicators + extra attacker IPs from hash logs (outfile-based)
    hash_inds, extra_ips, scanner_ips = collect_hash_indicators(
        es_host, indices, start, end, es_timeout, hours, self_ips=self_ips
    )

    # merge extra IPs into counts/enrich so they also become IPv4 IOCs
    for ip in extra_ips:
        if ip not in counts:
            counts[ip] = 1
        enrich.setdefault(ip, {})

    # mark research/scanner IPs (reserved for future)
    for ip in scanner_ips:
        e = enrich.setdefault(ip, {})
        e.setdefault("force_role", "scanning_host")

    ips = sorted(counts.keys())
    cats = gather_suricata_cats(es_host, indices, es_timeout, ipf, ips, start, end)
    cmd  = gather_adb_cmd_hits(es_host, indices, es_timeout, ipf, ips, start, end)

    ip_indicators = build_ip_indicators(cfg, counts, enrich, cats, cmd)
    all_new_from_window = ip_indicators + hash_inds

    if not all_new_from_window:
        logger.warning("No indicators (IP or hash) built from this window; skipping.")
        return

    # Build monthly name/description (e.g. "ADBHoney → Attacker IPs – Australia – November 2025")
    tlp = str(cfg["pulse"].get("tlp","green")).upper()
    prefix = cfg["pulse"].get("name_prefix","ADBHoney \u2192 Attacker IPs")
    loc = str(cfg["pulse"].get("location_label","")).strip()
    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")
    name = f"{prefix} \u2013 {loc} \u2013 {month_label}" if loc else f"{prefix} \u2013 {month_label}"

    desc = (
        f"Rolling monthly view for {month_label} of IPv4 addresses and file hashes observed by "
        f"ADBHoney on a T-Pot honeypot. Each run looks back the last {hours}h and appends newly "
        f"seen indicators for this month."
    )
    if loc:
        desc += f" Location: {loc}."

    tags = cfg.get("pulse", {}).get("tags") or ["tpot","honeypot","adb","android","botnet","scanner","dropper"]
    public = (tlp == "GREEN")

    api_key = cfg["otx_api_key"]

    # 1) see if monthly pulse already exists (tolerant)
    reg_key = f"adbhoney_{now.strftime('%Y-%m')}"

    pulse_id = load_pulse_id(reg_key)
    if not pulse_id:
        pulse_id = find_monthly_pulse(api_key, name, logger)
        if pulse_id:
            save_pulse_id(reg_key, pulse_id)

    if not pulse_id:
        # Create fresh monthly pulse with everything we have in this window
        pulse_id = create_pulse(api_key, name, desc, tlp, tags, all_new_from_window, public, logger, args.dry_run)
        if pulse_id and not args.dry_run:
            save_pulse_id(reg_key, pulse_id)
        if not pulse_id and not args.dry_run:
            logger.error("Failed to create monthly pulse; aborting.")
        return

    # 2) If it exists, GET it to figure out which indicators are already present
    existing = get_pulse(api_key, pulse_id, logger)
    if existing is None:
        logger.error("Could not fetch existing monthly pulse; aborting.")
        return

    existing_inds = existing.get("indicators") or []
    existing_keys = {(i.get("indicator"), i.get("type")) for i in existing_inds if isinstance(i, dict)}

    to_add: List[dict] = []
    for ind in all_new_from_window:
        key = (ind.get("indicator"), ind.get("type"))
        if key not in existing_keys:
            to_add.append(ind)

    add_indicators(api_key, pulse_id, to_add, logger, args.dry_run)

if __name__ == "__main__":
    main()
