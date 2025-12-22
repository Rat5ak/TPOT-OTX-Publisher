#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, os
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import requests

BASE = "https://otx.alienvault.com/api/v1"
UA   = "otx-dionaea-rolling/1.0"
PULSE_REGISTRY = "/opt/otx-publisher/pulses.json"

# ---------------- helpers ----------------
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
    return logging.getLogger("otx-dionaea-rolling")

def es_search(es_host: str, index: str, body: dict, timeout: int):
    return requests.post(
        f"{es_host}/{index}/_search",
        headers={"Content-Type": "application/json"},
        data=json.dumps(body),
        timeout=timeout,
    )

def mask_token(s: str) -> str:
    if not isinstance(s, str) or not s:
        return ""
    s = s.strip()
    # crude email vs token masking – just so passwords/usernames don't leak fully
    if "@" in s and "." in s.split("@")[-1]:
        local, dom = s.split("@", 1)
        if len(local) <= 2:
            m = "*" * len(local)
        else:
            m = local[0] + ("*" * (len(local) - 2)) + local[-1]
        return f"{m}@{dom}"
    if len(s) <= 3:
        return "*" * len(s)
    return s[0] + ("*" * (len(s) - 2)) + s[-1]

# ---------------- pulse registry (add-back) ----------------
def load_pulse_id(key: str) -> Optional[str]:
    try:
        with open(PULSE_REGISTRY) as f:
            data = json.load(f) or {}
        return data.get(key)
    except Exception:
        return None

def save_pulse_id(key: str, pid: str) -> None:
    data = {}
    try:
        if os.path.exists(PULSE_REGISTRY):
            with open(PULSE_REGISTRY) as f:
                data = json.load(f) or {}
    except Exception:
        data = {}
    data[key] = pid
    with open(PULSE_REGISTRY, "w") as f:
        json.dump(data, f, indent=2)

# ---------------- OTX helpers ----------------
def otx_headers(api_key: str) -> dict:
    return {
        "X-OTX-API-KEY": api_key,
        "User-Agent": UA,
        "Content-Type": "application/json",
    }

def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get(f"{BASE}/users/me", headers=otx_headers(api_key), timeout=10)
        if r.status_code != 200:
            logger.error(f"OTX auth failed: {r.status_code} {r.text[:200]}")
            return False
        return True
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False

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
                logger.error(
                    f"OTX list pulses failed page={page}: "
                    f"{r.status_code} {r.text[:300]}"
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

def create_pulse(
    api_key: str,
    name: str,
    description: str,
    tlp: str,
    tags: list,
    indicators: list,
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
        "indicators": indicators,
    }
    ipv4_count = len([i for i in indicators if i.get("type") == "IPv4"])
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would CREATE Dionaea pulse '{name}' with {ipv4_count} IPv4s"
        )
        return None
    r = requests.post(
        f"{BASE}/pulses/create",
        headers=headers,
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"Create Dionaea pulse failed {r.status_code}: {r.text[:500]}")
        return None
    created = r.json()
    pid = created.get("id")
    logger.info(
        f"Created new Dionaea pulse: {created.get('name', '(no name)')} (id={pid})"
    )
    return pid

def add_indicators(api_key: str, pulse_id: str, to_add: list, logger, dry_run: bool) -> bool:
    if not to_add:
        logger.info("No new Dionaea indicators to add to pulse.")
        return True
    headers = otx_headers(api_key)
    body = {"indicators": {"add": to_add}}
    ipv4_count = len([i for i in to_add if i.get("type") == "IPv4"])
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would PATCH Dionaea pulse id={pulse_id} adding "
            f"{len(to_add)} indicators ({ipv4_count} IPv4s)"
        )
        return True
    r = requests.patch(
        f"{BASE}/pulses/{pulse_id}",
        headers=headers,
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"OTX Dionaea update error {r.status_code}: {r.text[:500]}")
        return False
    logger.info(
        f"Successfully patched Dionaea pulse {pulse_id} with {len(to_add)} new indicators"
    )
    return True

# ---------------- Dionaea collection ----------------
def collect_dionaea(cfg: dict, logger, window_hours: int) -> Tuple[Dict[str, int], Dict[str, dict]]:
    es = cfg["elasticsearch"]
    es_host = es["host"]
    es_timeout = int(es.get("timeout", 15))

    logger.info(f"Collecting Dionaea docs from last {window_hours}h")

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{window_hours}h",
                                "lte": "now",
                            }
                        }
                    },
                    {"term": {"path.keyword": "/data/dionaea/log/dionaea.json"}},
                    {"exists": {"field": "src_ip"}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "src_ip.keyword", "size": 10000},
                "aggs": {
                    "sample": {
                        "top_hits": {
                            "size": 1,
                            "_source": {
                                "includes": [
                                    "dest_port",
                                    "connection.protocol",
                                    "geoip.country_code2",
                                    "geoip.asn",
                                    "geoip.as_org",
                                    "username",
                                    "password",
                                ]
                            },
                        }
                    }
                },
            }
        },
    }

    try:
        r = es_search(es_host, "logstash-*", body, es_timeout)
    except Exception as e:
        logger.error(f"ES request failed: {e}")
        return {}, {}

    if r.status_code != 200:
        logger.error(f"ES search failed: {r.status_code} {r.text[:300]}")
        return {}, {}

    data = r.json()
    buckets = data.get("aggregations", {}).get("by_ip", {}).get("buckets", [])
    logger.info(f"ES returned {len(buckets)} Dionaea IP buckets")

    counts: Dict[str, int] = {}
    enrich: Dict[str, dict] = {}

    for b in buckets:
        ip = b.get("key")
        if not isinstance(ip, str):
            continue
        try:
            ip = str(ipaddress.ip_address(ip))
        except Exception:
            continue

        c = int(b.get("doc_count", 0))
        counts[ip] = c

        src = (
            (b.get("sample", {}) or {})
            .get("hits", {})
            .get("hits", [{}])[0]
            .get("_source", {})
        )

        e: Dict[str, object] = {}
        proto = ((src.get("connection") or {}).get("protocol")) or "unknown"
        port = src.get("dest_port")
        if isinstance(port, int):
            e["ports"] = [str(port)]
        else:
            e["ports"] = []
        e["services"] = [str(proto)]

        geo = src.get("geoip") or {}
        cc = geo.get("country_code2")
        if cc:
            e["cc"] = [str(cc)]
        else:
            e["cc"] = []
        asn = geo.get("asn")
        if asn is not None:
            e["asn"] = [str(asn)]
        else:
            e["asn"] = []
        org = geo.get("as_org")
        if org:
            e["org"] = [str(org)]
        else:
            e["org"] = []

        user = src.get("username")
        pwd = src.get("password")
        e["users"] = [mask_token(str(user))] if user else []
        e["passes"] = [mask_token(str(pwd))] if pwd else []

        enrich[ip] = e

    logger.info(f"Dionaea IPv4s in window: {len(counts)}")
    return counts, enrich

# ---------------- indicator builder ----------------
def build_ip_indicators(cfg: dict, counts: Dict[str, int], enrich: Dict[str, dict]) -> list:
    indicators: list = []
    for ip in sorted(counts.keys()):
        e = enrich.get(ip, {})
        services = e.get("services") or ["unknown"]
        ports    = e.get("ports") or []
        cc       = e.get("cc") or []
        asn      = e.get("asn") or []
        org      = e.get("org") or []
        users    = e.get("users") or []
        passes   = e.get("passes") or []

        parts = [
            f"seen in Dionaea honeypot logs; events={counts[ip]}",
            f"services={','.join(services)}",
        ]
        if ports:
            parts.append(f"ports={','.join(map(str, ports))}")
        if cc:
            parts.append(f"cc={','.join(cc)}")
        if asn:
            parts.append(f"asn={','.join(asn)}")
        if org:
            parts.append(f"asn_org={','.join(org)}")
        if users:
            parts.append(f"user(top)={','.join(users)}")
        if passes:
            parts.append(f"pass(top)={','.join(passes)}")

        indicators.append(
            {
                "indicator": ip,
                "type": "IPv4",
                "title": "Attacker IP \u2022 Dionaea",
                "description": "; ".join(parts),
                "tags": ["dionaea", "tpot", "honeypot", "bruteforce"],
                "role": "bruteforce",
            }
        )
    return indicators

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--window-hours", type=int, help="lookback window in hours")
    args = ap.parse_args()

    cfg = load_config(args.config)
    window_hours = int(args.window_hours or cfg.get("pulse", {}).get("time_window_hours", 1))

    logger = setup_logger(cfg.get("log_path"))

    if not test_otx(cfg["otx_api_key"], logger):
        return

    counts, enrich = collect_dionaea(cfg, logger, window_hours)
    if not counts:
        logger.warning("No Dionaea IPs found in window; skipping")
        return

    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")
    month_key = now.strftime("%Y-%m")

    pulse_cfg = cfg.get("pulse", {})
    tlp = str(pulse_cfg.get("tlp", "GREEN")).upper()
    prefix = pulse_cfg.get("name_prefix", "Dionaea \u2192 Attacker IPs")
    loc = str(pulse_cfg.get("location_label", "")).strip()

    if loc:
        name = f"{prefix} – {loc} – {month_label}"
    else:
        name = f"{prefix} – {month_label}"

    desc = pulse_cfg.get(
        "description",
        (
            f"Rolling monthly view for {month_label} of attacker IPv4 addresses "
            f"seen in Dionaea honeypot logs on a T-Pot instance. Each run looks back "
            f"the last {window_hours}h and appends newly seen IPs for this month."
        ),
    )

    tags = pulse_cfg.get("tags") or ["tpot", "honeypot", "dionaea", "bruteforce"]
    public = tlp == "GREEN"

    ip_indicators = build_ip_indicators(cfg, counts, enrich)
    if not ip_indicators:
        logger.warning("No Dionaea indicators built from this window; skipping.")
        return

    api_key = cfg["otx_api_key"]

    # ---------------- pulse id resolution (registry-first) ----------------
    reg_key = f"dionaea_{month_key}"
    pulse_id = load_pulse_id(reg_key)

    if not pulse_id:
        pulse_id = find_monthly_pulse(api_key, name, logger)
        if pulse_id:
            save_pulse_id(reg_key, pulse_id)

    if not pulse_id:
        pulse_id = create_pulse(
            api_key, name, desc, tlp, tags, ip_indicators, public, logger, args.dry_run
        )
        if pulse_id and not args.dry_run:
            save_pulse_id(reg_key, pulse_id)
        if not pulse_id and not args.dry_run:
            logger.error("Failed to create Dionaea pulse; aborting.")
        return

    existing = get_pulse(api_key, pulse_id, logger)
    if existing is None:
        logger.error("Could not fetch existing Dionaea pulse; aborting.")
        return

    existing_inds = existing.get("indicators") or []
    existing_keys = {(i.get("indicator"), i.get("type"))
                     for i in existing_inds if isinstance(i, dict)}

    to_add: list = []
    for ind in ip_indicators:
        key = (ind.get("indicator"), ind.get("type"))
        if key not in existing_keys:
            to_add.append(ind)

    add_indicators(api_key, pulse_id, to_add, logger, args.dry_run)

if __name__ == "__main__":
    main()
