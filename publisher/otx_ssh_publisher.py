#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, os, subprocess
from datetime import datetime, timedelta, timezone
from typing import Dict, Set, Optional
import requests

BASE = "https://otx.alienvault.com/api/v1"
PULSE_REGISTRY = "/opt/otx-publisher/pulses.json"

# ---------------- logging ----------------
def load_config(p):
    with open(p) as f:
        return json.load(f)

def setup_logger():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    return logging.getLogger("otx-ssh-telnet")

# ---------------- helpers ----------------
def _utc(dt):
    return dt.replace(tzinfo=timezone.utc).isoformat()

def _norm_ip(s):
    if not isinstance(s, str):
        return None
    s = s.strip()
    if ":" in s and s.count(".") == 3:
        s = s.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(s))
    except Exception:
        return None

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True

def mask_token(s: str) -> str:
    if not s:
        return ""
    s = str(s)
    if "@" in s and "." in s.split("@")[-1]:
        local, dom = s.split("@", 1)
        if len(local) <= 2:
            m = "*" * len(local)
        else:
            m = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{m}@{dom}"
    return s[0] + "*" * (len(s) - 2) + s[-1] if len(s) > 3 else "*" * len(s)

# ---------------- self IP detection ----------------
def get_self_ips(cfg, log):
    out = set()
    for x in cfg.get("self_ips", []):
        ip = _norm_ip(str(x))
        if ip:
            out.add(ip)

    try:
        p = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True)
        for l in p.stdout.splitlines():
            if " inet " in l:
                ip = _norm_ip(l.split("inet")[1].split("/")[0])
                if ip:
                    out.add(ip)
    except Exception:
        pass

    for u in ("https://api.ipify.org", "https://ifconfig.co/ip"):
        try:
            r = requests.get(u, timeout=3)
            ip = _norm_ip(r.text)
            if ip and not is_private(ip):
                out.add(ip)
                break
        except Exception:
            pass

    out.add("127.0.0.1")
    log.info(f"Self IPs: {sorted(out)}")
    return out

# ---------------- Elasticsearch ----------------
def es_post(es, index, body, timeout=30):
    return requests.post(
        f"{es}/{index}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=timeout,
    )

# ---------------- pulse registry ----------------
def load_pulse_id(key):
    try:
        with open(PULSE_REGISTRY) as f:
            return json.load(f).get(key)
    except Exception:
        return None

def save_pulse_id(key, pid):
    data = {}
    if os.path.exists(PULSE_REGISTRY):
        with open(PULSE_REGISTRY) as f:
            data = json.load(f)
    data[key] = pid
    with open(PULSE_REGISTRY, "w") as f:
        json.dump(data, f, indent=2)

# ---------------- field discovery ----------------
USER_FIELDS = [
    "ssh.username.keyword",
    "username.keyword",
    "user.name.keyword",
    "cowrie.username.keyword",
]

PASS_FIELDS = [
    "ssh.password.keyword",
    "password.keyword",
    "cowrie.password.keyword",
]

CLIENT_FIELDS = [
    "ssh.client.keyword",
    "ssh.client",
    "client.keyword",
    "ssh.client_version.keyword",
]

def pick_field(es, index, start, end, candidates) -> Optional[str]:
    for f in candidates:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": _utc(start), "lte": _utc(end)}}},
                        {"exists": {"field": f}},
                    ]
                }
            },
            "aggs": {"t": {"terms": {"field": f, "size": 1}}},
        }
        try:
            r = es_post(es, index, body)
            if r.status_code == 200 and r.json().get("aggregations", {}).get("t", {}).get("buckets"):
                return f
        except Exception:
            pass
    return None

# ---------------- collection ----------------
def collect(cfg, log):
    es = cfg["elasticsearch"]["host"]
    hours = int(cfg["pulse"].get("time_window_hours", 1))
    start = datetime.now(timezone.utc) - timedelta(hours=hours)
    end = datetime.now(timezone.utc)

    self_ips = get_self_ips(cfg, log)

    userf = pick_field(es, "logstash-*", start, end, USER_FIELDS) or "ssh.username.keyword"
    passf = pick_field(es, "logstash-*", start, end, PASS_FIELDS) or "ssh.password.keyword"
    clientf = pick_field(es, "logstash-*", start, end, CLIENT_FIELDS) or "ssh.client.keyword"

    log.info(f"Using fields: user={userf} pass={passf} client={clientf}")

    counts: Dict[str, int] = {}
    enrich: Dict[str, dict] = {}
    protos: Dict[str, Set[str]] = {}

    query = {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": _utc(start), "lte": _utc(end)}}},
                {"exists": {"field": "src_ip.keyword"}},
            ],
            "should": [
                {"terms": {"type.keyword": ["cowrie", "Cowrie", "heralding", "Heralding"]}},
                {"terms": {"protocol.keyword": ["ssh", "telnet"]}},
            ],
            "minimum_should_match": 1,
        }
    }

    aggs = {
        "by": {
            "composite": {
                "size": 1000,
                "sources": [{"ip": {"terms": {"field": "src_ip.keyword"}}}],
            },
            "aggs": {
                "proto": {"terms": {"field": "protocol.keyword", "size": 2}},
                "ports": {"terms": {"field": "dest_port", "size": 5}},
                "cc": {"terms": {"field": "geoip.country_code2.keyword", "size": 3}},
                "asn": {"terms": {"field": "geoip.asn", "size": 3}},
                "org": {"terms": {"field": "geoip.as_org.keyword", "size": 3}},
                "user": {"terms": {"field": userf, "size": 5}},
                "pass": {"terms": {"field": passf, "size": 5}},
                "client": {"terms": {"field": clientf, "size": 5}},
                "sensor": {"terms": {"field": "type.keyword", "size": 5}},
            },
        }
    }

    after = None
    while True:
        body = {"size": 0, "query": query, "aggs": aggs}
        if after:
            body["aggs"]["by"]["composite"]["after"] = after

        r = es_post(es, "logstash-*", body)
        if r.status_code != 200:
            break

        data = r.json()["aggregations"]["by"]
        for b in data["buckets"]:
            ip = _norm_ip(b["key"]["ip"])
            if not ip or ip in self_ips:
                continue

            counts[ip] = counts.get(ip, 0) + b["doc_count"]
            protos.setdefault(ip, set()).update(x["key"] for x in b["proto"]["buckets"])

            e = enrich.setdefault(ip, {})
            e["ports"] = [str(x["key"]) for x in b["ports"]["buckets"]]
            e["cc"] = [x["key"] for x in b["cc"]["buckets"]]
            e["asn"] = [str(x["key"]) for x in b["asn"]["buckets"]]
            e["org"] = [x["key"] for x in b["org"]["buckets"]]
            e["users"] = [mask_token(x["key"]) for x in b["user"]["buckets"]]
            e["passes"] = [mask_token(x["key"]) for x in b["pass"]["buckets"]]
            e["client"] = [x["key"] for x in b["client"]["buckets"]]
            e["sensors"] = [x["key"] for x in b["sensor"]["buckets"]]

        after = data.get("after_key")
        if not after:
            break

    return counts, enrich, protos, start, end

# ---------------- indicators ----------------
def build_indicators(cfg, counts, enrich, protos):
    location = cfg["pulse"].get("location_label", "Unknown")
    out = []

    for ip, c in counts.items():
        p = protos.get(ip, set())

        if {"ssh", "telnet"} <= p:
            title = "Attacker IP - SSH & Telnet"
        elif "telnet" in p:
            title = "Attacker IP - Telnet"
        else:
            title = "Attacker IP - SSH"

        e = enrich[ip]
        desc = [
            f"Observed authentication attempts via {', '.join(sorted(p)) or 'unknown'} against Cowrie/Heralding honeypots in {location}.",
            f"Total events observed: {c}.",
            f"Sensors involved: {', '.join(e['sensors'])}.",
        ]
        if e.get("ports"): desc.append(f"Target ports: {', '.join(e['ports'])}.")
        if e.get("cc"): desc.append(f"Source country: {', '.join(e['cc'])}.")
        if e.get("asn"): desc.append(f"ASN(s): {', '.join(e['asn'])}.")
        if e.get("org"): desc.append(f"Organisation(s): {', '.join(e['org'])}.")
        if e.get("users"): desc.append(f"Usernames observed (masked): {', '.join(e['users'])}.")
        if e.get("passes"): desc.append(f"Passwords observed (masked): {', '.join(e['passes'])}.")
        if e.get("client"): desc.append(f"Client banners: {', '.join(e['client'])}.")

        out.append({
            "indicator": ip,
            "type": "IPv4",
            "title": title,
            "description": " ".join(desc),
            "role": "bruteforce",
            "tags": ["ssh", "telnet", "cowrie", "heralding", "tpot", "honeypot"],
        })

    return out

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--window-hours", type=int)
    a = ap.parse_args()

    cfg = load_config(a.config)
    if a.window_hours:
        cfg.setdefault("pulse", {})["time_window_hours"] = a.window_hours

    log = setup_logger()
    counts, enrich, protos, start, end = collect(cfg, log)
    if not counts:
        log.info("No indicators found.")
        return

    inds = build_indicators(cfg, counts, enrich, protos)

    now = datetime.now(timezone.utc)
    month = now.strftime("%B %Y")
    pulse = cfg["pulse"]
    key = f"ssh_telnet_{now.strftime('%Y-%m')}"

    name = f"{pulse['name_prefix']} - {pulse.get('location_label','')} - {month}"
    desc = (
        f"Rolling monthly view of attacker IPv4 addresses observed via SSH and Telnet "
        f"authentication attempts against Cowrie and Heralding honeypots on a T-Pot CE instance. "
        f"Each run looks back the last {pulse.get('time_window_hours',1)}h and appends newly seen "
        f"indicators for this calendar month. Signals are deduplicated to unique sources; "
        f"private IPs may be included depending on configuration. "
        f"Intended for defensive use; source infrastructure may be compromised, misattributed, "
        f"or spoofed. Location: {pulse.get('location_label','Unknown')}.")

    headers = {
        "X-OTX-API-KEY": cfg["otx_api_key"],
        "Content-Type": "application/json",
    }

    pid = load_pulse_id(key)
    if not pid:
        r = requests.post(
            f"{BASE}/pulses/create",
            headers=headers,
            json={
                "name": name,
                "description": desc,
                "public": True,
                "TLP": pulse.get("tlp", "GREEN"),
                "tags": ["ssh", "telnet", "honeypot", "tpot"],
                "indicators": inds,
            },
        )
        save_pulse_id(key, r.json()["id"])
        return

    r = requests.get(f"{BASE}/pulses/{pid}", headers=headers).json()
    existing = {(i["indicator"], i["type"]) for i in r.get("indicators", [])}
    add = [i for i in inds if (i["indicator"], i["type"]) not in existing]

    if add:
        requests.patch(
            f"{BASE}/pulses/{pid}",
            headers=headers,
            json={"indicators": {"add": add}},
        )

if __name__ == "__main__":
    main()
