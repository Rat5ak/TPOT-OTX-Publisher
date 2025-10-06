# /opt/otx-publisher/otx_ssh_ips.py
#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, re
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Tuple, Optional
import requests

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
    return logging.getLogger("otx-ssh")

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

def mask_token(s: str) -> str:
    if not isinstance(s, str) or not s:
        return ""
    s = s.strip()
    # crude email detection => mask local-part
    if "@" in s and "." in s.split("@")[-1]:
        local, dom = s.split("@", 1)
        m = ("*" * len(local)) if len(local) <= 2 else (local[0] + ("*" * (len(local) - 2)) + local[-1])
        return f"{m}@{dom}"
    if len(s) <= 3:
        return "*" * len(s)
    return s[0] + ("*" * (len(s) - 2)) + s[-1]

def top_keys(buckets: list, k: str = "key", n: int = 5) -> List[str]:
    out: List[str] = []
    for b in (buckets or [])[:n]:
        v = b.get(k)
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (int, float)):
            out.append(str(v))
    return out

# --------------- query setup ---------------
SSH_SHOULD = [
    {"term": {"type.keyword": "cowrie"}}, {"term": {"type.keyword": "Cowrie"}},
    {"term": {"type.keyword": "heralding"}}, {"term": {"type.keyword": "Heralding"}},
    {"term": {"protocol.keyword": "ssh"}},
    {"term": {"event.dataset.keyword": "cowrie"}},
    {"term": {"event.dataset.keyword": "heralding"}},
]

IP_FIELDS   = ["src_ip.keyword", "source_ip.keyword", "client_ip.keyword", "source.ip", "client.ip", "source.address.keyword"]
PORT_FIELDS = ["dest_port", "destination.port", "server.port"]
CC_FIELDS   = ["geoip.country_code2.keyword", "geoip.country_iso_code", "geoip.country_name.keyword"]
ASN_FIELDS  = ["geoip.asn"]
ASORG_FIELDS= ["geoip.as_org.keyword"]
USER_FIELDS = ["username.keyword", "user.name.keyword", "ssh.username.keyword", "cowrie.username.keyword"]
PASS_FIELDS = ["password.keyword", "ssh.password.keyword", "cowrie.password.keyword"]
CLIENT_FIELDS = ["ssh.client.keyword", "ssh.client", "ssh.client_version.keyword", "client.keyword", "network.user_agent.original.keyword"]

def pick_field(es_host: str, indices: List[str], timeout: int, candidates: List[str],
               start: datetime, end: datetime) -> Optional[str]:
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
                if (ag.get("buckets") or []):
                    return f
            except Exception:
                pass
    return None

# --------------- collection ---------------
def collect_ssh(cfg: dict, logger) -> Tuple[Dict[str, int], Dict[str, dict]]:
    es = cfg["elasticsearch"]; es_host, es_timeout = es["host"], es["timeout"]
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    end = datetime.now(timezone.utc); start = end - timedelta(hours=hours)
    indices = cfg.get("indices", ["logstash-*"])
    min_events = int(cfg["pulse"].get("min_event_count", 1))
    exclude_private = bool(cfg["pulse"].get("exclude_private_ips", False))  # you asked to include privs, default False

    ipf   = pick_field(es_host, indices, es_timeout, IP_FIELDS, start, end)
    portf = pick_field(es_host, indices, es_timeout, PORT_FIELDS, start, end)
    ccf   = pick_field(es_host, indices, es_timeout, CC_FIELDS, start, end)
    asnf  = pick_field(es_host, indices, es_timeout, ASN_FIELDS, start, end)
    asorg = pick_field(es_host, indices, es_timeout, ASORG_FIELDS, start, end)
    userf = pick_field(es_host, indices, es_timeout, USER_FIELDS, start, end)
    passf = pick_field(es_host, indices, es_timeout, PASS_FIELDS, start, end)
    clientf = pick_field(es_host, indices, es_timeout, CLIENT_FIELDS, start, end)

    if not ipf:
        logger.error("No aggregatable IP field found for SSH docs; aborting.")
        return {}, {}

    logger.info(f"Using fields ip={ipf} port={portf} cc={ccf} asn={asnf} org={asorg} user={userf} pass={passf} client={clientf}")

    counts: Dict[str, int] = {}
    enrich: Dict[str, dict] = {}

    def sub_aggs():
        a = {"sensors": {"terms": {"field": "type.keyword", "size": 10}}}
        if portf:   a["ports"]   = {"terms": {"field": portf,   "size": 5}}
        if ccf:     a["cc"]      = {"terms": {"field": ccf,     "size": 3}}
        if asnf:    a["asn"]     = {"terms": {"field": asnf,    "size": 3}}
        if asorg:   a["asn_org"] = {"terms": {"field": asorg,   "size": 3}}
        if userf:   a["user"]    = {"terms": {"field": userf,   "size": 5}}
        if passf:   a["pass"]    = {"terms": {"field": passf,   "size": 5}}
        if clientf: a["client"]  = {"terms": {"field": clientf, "size": 5}}
        return a

    for idx in indices:
        after = None
        while True:
            body = {
                "size": 0,
                "query": {"bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": _utc_iso(start), "lte": _utc_iso(end)}}},
                        {"exists": {"field": ipf}},
                    ],
                    "should": SSH_SHOULD,
                    "minimum_should_match": 1,
                }},
                "aggs": {
                    "by": {
                        "composite": {"size": 1000, "sources": [{"ip": {"terms": {"field": ipf}}}]},
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
                ag = r.json().get("aggregations", {}).get("by", {})
                for b in ag.get("buckets", []):
                    raw = b.get("key", {}).get("ip")
                    if not isinstance(raw, str):
                        continue
                    ipval = raw.split(":", 1)[0]
                    try:
                        ip = str(ipaddress.ip_address(ipval))
                    except Exception:
                        continue
                    if exclude_private and is_private_ip(ip):
                        continue
                    c = int(b.get("doc_count", 0))
                    counts[ip] = counts.get(ip, 0) + c

                    e = enrich.setdefault(ip, {"sensors": set()})
                    if "ports"   in b: e["ports"]  = top_keys(b["ports"].get("buckets", []), n=5)
                    if "cc"      in b: e["cc"]     = top_keys(b["cc"].get("buckets", []),    n=3)
                    if "asn"     in b: e["asn"]    = top_keys(b["asn"].get("buckets", []),   n=3)
                    if "asn_org" in b: e["org"]    = top_keys(b["asn_org"].get("buckets", []), n=3)
                    if "user"    in b: e["users"]  = [mask_token(x) for x in top_keys(b["user"].get("buckets", []), n=5)]
                    if "pass"    in b: e["passes"] = [mask_token(x) for x in top_keys(b["pass"].get("buckets", []), n=5)]
                    if "client"  in b: e["client"] = top_keys(b["client"].get("buckets", []), n=5)
                    for sb in (b.get("sensors", {}).get("buckets", []) or []):
                        sk = sb.get("key")
                        if isinstance(sk, str) and sk:
                            e["sensors"].add(sk)
                after = ag.get("after_key")
                if not after:
                    break
            except Exception:
                break

    for ip in list(enrich.keys()):
        if counts.get(ip, 0) < min_events:
            enrich.pop(ip, None)
            counts.pop(ip, None)

    logger.info(f"SSH IPv4s in window: {len(counts)}")
    return counts, enrich

# --------------- pulse ---------------
def build_pulse(cfg: dict, counts: Dict[str, int], enrich: Dict[str, dict]) -> dict:
    tlp = str(cfg["pulse"].get("tlp", "green")).upper()
    prefix = cfg["pulse"].get("name_prefix", "SSH → Attacker IPs")
    window = int(cfg["pulse"].get("time_window_hours", 1))
    loc = str(cfg["pulse"].get("location_label", "")).strip()
    name = f"{prefix} – {loc} – last {window}h" if loc else f"{prefix} – last {window}h"

    desc = (f"IPv4 addresses observed by SSH honeypot (Cowrie/Heralding) within the last {window}h on T-Pot. "
            f"Deduped to unique sources. " + (f"Location: {loc}. " if loc else ""))

    indicators: List[dict] = []
    for ip in sorted(counts.keys()):
        e = enrich.get(ip, {})
        sensors = sorted(e.get("sensors", set())) or ["unknown"]
        parts = [
            f"seen in SSH honeypot; events={counts[ip]}",
            f"sensors={','.join(sensors)}",
        ]
        if e.get("ports"):  parts.append(f"ports={','.join(map(str, e['ports']))}")
        if e.get("cc"):     parts.append(f"cc={','.join(e['cc'])}")
        if e.get("asn"):    parts.append(f"asn={','.join(e['asn'])}")
        if e.get("org"):    parts.append(f"asn_org={','.join(e['org'])}")
        if e.get("client"): parts.append(f"client={','.join(e['client'])}")
        if e.get("users"):  parts.append(f"user(top)={','.join(e['users'])}")
        if e.get("passes"): parts.append(f"pass(top)={','.join(e['passes'])}")

        indicators.append({
            "indicator": ip,
            "type": "IPv4",
            "title": "Attacker IP • SSH",
            "description": "; ".join(parts),
            "tags": ["ssh", "cowrie", "heralding", "tpot", "honeypot", "bruteforce"],
            "role": "bruteforce",
        })

    return {
        "name": name,
        "description": desc,
        "public": (tlp == "GREEN"),
        "tlp": tlp,
        "tags": ["tpot", "honeypot", "ssh", "cowrie", "heralding", "bruteforce"],
        "indicators": indicators,
    }

# --------------- OTX ---------------
def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get(
            "https://otx.alienvault.com/api/v1/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": "otx-ssh/1.0"},
            timeout=10,
        )
        ok = (r.status_code == 200)
        if not ok:
            logger.error(f"OTX auth failed: {r.status_code} {r.text[:200]}")
        return ok
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False

def publish(api_key: str, pulse: dict, dry_run: bool, logger):
    if dry_run:
        logger.info(f"[DRY-RUN] Would publish pulse with {len(pulse['indicators'])} IPv4s")
        return
    r = requests.post(
        "https://otx.alienvault.com/api/v1/pulses/create/",
        headers={"X-OTX-API-KEY": api_key,
                 "User-Agent": "otx-ssh/1.0",
                 "Content-Type": "application/json"},
        data=json.dumps(pulse),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"OTX error {r.status_code}: {r.text[:2000]}")
    r.raise_for_status()
    created = r.json()
    logger.info(f"Published pulse: {created.get('name','(no name)')} (id={created.get('id','?')})")

# --------------- main ---------------
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

    counts, enrich = collect_ssh(cfg, logger)
    if not counts:
        logger.warning("No SSH IPs found in window; skipping")
        return

    pulse = build_pulse(cfg, counts, enrich)
    publish(cfg["otx_api_key"], pulse, args.dry_run, logger)

if __name__ == "__main__":
    main()
