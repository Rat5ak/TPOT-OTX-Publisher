#!/usr/bin/env python3
import argparse, json, logging, sys, ipaddress, os
from datetime import datetime, timezone
from typing import Dict, List, Tuple, Optional
import requests

BASE = "https://otx.alienvault.com/api/v1"
BASE_HEADERS_UA = "otx-suricata-rolling/1.0"

# --- add: pulse registry (minimal) ---
PULSE_REGISTRY = "/opt/otx-publisher/pulses.json"

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
        # fail-open: if pulses.json is busted, we just rebuild it clean
        data = {}

    data[key] = pid
    with open(PULSE_REGISTRY, "w") as f:
        json.dump(data, f, indent=2, sort_keys=True)

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
    return logging.getLogger("otx-suricata-rolling")

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

def top_keys(buckets: list, n: int = 5) -> List[str]:
    out: List[str] = []
    for b in (buckets or [])[:n]:
        v = b.get("key")
        if isinstance(v, str):
            out.append(v)
        elif isinstance(v, (int, float)):
            out.append(str(v))
    return out

# ---------------- OTX helpers ----------------
def test_otx(api_key: str, logger) -> bool:
    try:
        r = requests.get(
            f"{BASE}/users/me",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": BASE_HEADERS_UA},
            timeout=10,
        )
        if r.status_code != 200:
            logger.error(f"OTX auth failed: {r.status_code} {r.text[:200]}")
            return False
        return True
    except Exception as e:
        logger.error(f"OTX connectivity failed: {e}")
        return False

def otx_headers(api_key: str) -> dict:
    return {
        "X-OTX-API-KEY": api_key,
        "User-Agent": BASE_HEADERS_UA,
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
                f"OTX get pulse {pulse_id} failed: "
                f"{r.status_code} {r.text[:300]}"
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
    tags: List[str],
    indicators: List[dict],
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
            f"[DRY-RUN] Would CREATE Suricata pulse '{name}' "
            f"with {ipv4_count} IPv4s"
        )
        return None
    r = requests.post(
        f"{BASE}/pulses/create",
        headers=headers,
        data=json.dumps(body),
        timeout=60,
    )
    if r.status_code >= 400:
        logger.error(f"Create Suricata pulse failed {r.status_code}: {r.text[:500]}")
        return None
    created = r.json()
    pid = created.get("id")
    logger.info(
        f"Created new Suricata pulse: {created.get('name', '(no name)')} (id={pid})"
    )
    return pid

def add_indicators(api_key: str, pulse_id: str, to_add: List[dict], logger, dry_run: bool) -> bool:
    if not to_add:
        logger.info("No new Suricata indicators to add to pulse.")
        return True
    headers = otx_headers(api_key)
    body = {"indicators": {"add": to_add}}
    ipv4_count = len([i for i in to_add if i.get("type") == "IPv4"])
    if dry_run:
        logger.info(
            f"[DRY-RUN] Would PATCH Suricata pulse id={pulse_id} adding "
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
        logger.error(f"OTX Suricata update error {r.status_code}: {r.text[:500]}")
        return False
    logger.info(
        f"Successfully patched Suricata pulse {pulse_id} with "
        f"{len(to_add)} new indicators"
    )
    return True

# ---------------- Suricata collection ----------------
def collect_suricata(cfg: dict, logger, window_hours: int) -> Tuple[Dict[str, int], Dict[str, dict]]:
    es = cfg["elasticsearch"]
    es_host = es["host"]
    es_timeout = int(es.get("timeout", 15))

    fields = cfg.get("fields", {})
    ip_field   = fields.get("ip_field",   "src_ip.keyword")
    port_field = fields.get("port_field", "dest_port")
    cc_field   = fields.get("cc_field",   "geoip.country_code2.keyword")
    asn_field  = fields.get("asn_field",  "geoip.asn")
    org_field  = fields.get("org_field",  "geoip.as_org.keyword")
    cat_field  = fields.get("category_field", "alert.category.keyword")
    sig_field  = fields.get("sig_field", "alert.signature.keyword")

    severity_mode = str(cfg.get("severity_mode", "sev_lte2")).strip() or "sev_lte2"

    logger.info(
        f"Collecting Suricata docs from last {window_hours}h "
        f"(severity_mode={severity_mode})"
    )
    logger.info(
        "Using fields "
        f"ip={ip_field} port={port_field} cc={cc_field} asn={asn_field} "
        f"org={org_field} category={cat_field} sig={sig_field}"
    )

    # Decide the severity filter
    if severity_mode == "sev1":
        sev_filter = { "term": { "alert.severity": 1 } }
    elif severity_mode == "sev_lte2":
        sev_filter = { "range": { "alert.severity": { "lte": 2 } } }
    else:
        # fallback
        sev_filter = { "range": { "alert.severity": { "lte": 3 } } }

    counts: Dict[str, int] = {}
    enrich: Dict[str, dict] = {}

    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": f"now-{window_hours}h",
                                "lte": "now"
                            }
                        }
                    },
                    { "term":  { "event_type.keyword": "alert" } },
                    sev_filter,
                    { "exists": { "field": "src_ip" } },
                    { "term":  { "path.keyword": "/data/suricata/log/eve.json" } }
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": { "field": ip_field, "size": 10000 },
                "aggs": {
                    "ports": {
                        "terms": { "field": port_field, "size": 10 }
                    },
                    "categories": {
                        "terms": { "field": cat_field, "size": 10 }
                    },
                    "sigs": {
                        "terms": { "field": sig_field, "size": 10 }
                    },
                    "cc": {
                        "terms": { "field": cc_field, "size": 5 }
                    },
                    "asn": {
                        "terms": { "field": asn_field, "size": 5 }
                    },
                    "asn_org": {
                        "terms": { "field": org_field, "size": 5 }
                    }
                }
            }
        }
    }

    try:
        r = es_search(es_host, "logstash-*", body, es_timeout)
    except Exception as e:
        logger.error(f"ES request failed: {e}")
        return counts, enrich

    if r.status_code != 200:
        logger.error(f"ES search failed: {r.status_code} {r.text[:300]}")
        return counts, enrich

    data = r.json()
    buckets = data.get("aggregations", {}).get("by_ip", {}).get("buckets", [])

    for b in buckets:
        ip = b.get("key")
        if not isinstance(ip, str):
            continue
        try:
            ip = str(ipaddress.ip_address(ip))
        except Exception:
            continue

        c = int(b.get("doc_count", 0))
        counts[ip] = counts.get(ip, 0) + c

        e = enrich.setdefault(ip, {})
        e["ports"]      = top_keys(b.get("ports", {}).get("buckets", []), n=10)
        e["categories"] = top_keys(b.get("categories", {}).get("buckets", []), n=10)
        e["sigs"]       = top_keys(b.get("sigs", {}).get("buckets", []), n=10)
        e["cc"]         = top_keys(b.get("cc", {}).get("buckets", []), n=5)
        e["asn"]        = top_keys(b.get("asn", {}).get("buckets", []), n=5)
        e["org"]        = top_keys(b.get("asn_org", {}).get("buckets", []), n=5)

    logger.info(f"Suricata IPv4s in window: {len(counts)}")
    return counts, enrich

# ---------------- role heuristic ----------------
def infer_suricata_role(categories: List[str], sigs: List[str]) -> str:
    """Infer an OTX IP role from Suricata categories + signatures."""
    cats = {c.lower() for c in (categories or []) if c}
    sigset = {s.lower() for s in (sigs or []) if s}

    if not cats and not sigset:
        return "scanning_host"

    combo = cats | sigset

    # --- C2-ish / beaconing ---
    for x in combo:
        if any(w in x for w in (
            " c2", "command and control", "callback", "beacon",
            "remote access trojan", "rat ", " rat-", "botnet"
        )):
            return "command_and_control"

    # --- Brute-force / auth abuse ---
    for x in combo:
        if any(w in x for w in (
            "bruteforce", "brute force", "login attempt",
            "password guess", "dictionary attack"
        )):
            return "bruteforce"

    # --- Exploit / malware hosting ---
    for x in combo:
        if any(w in x for w in (
            "malware", "exploit", "ransomware", "shellcode",
            "overflow", "command injection", "sql injection",
            "xss", "trojan"
        )):
            return "malware_hosting"

    return "scanning_host"  # default / noisy scans

# ---------------- indicator builder ----------------
def build_ip_indicators(cfg: dict, counts: Dict[str, int], enrich: Dict[str, dict]) -> List[dict]:
    indicators: List[dict] = []

    sev_mode = str(cfg.get("severity_mode", "sev_lte2"))
    if "lte2" in sev_mode:
        ind_title = "High & Medium Suricata IDS Source"
        base_tags = ["tpot", "honeypot", "suricata", "ids", "sev<=2"]
    else:
        ind_title = "High-Signal Suricata IDS Source"
        base_tags = ["tpot", "honeypot", "suricata", "ids", "sev=1"]

    for ip in sorted(counts.keys()):
        e = enrich.get(ip, {})

        ports      = e.get("ports")      or []
        categories = e.get("categories") or []
        sigs       = e.get("sigs")       or []
        cc         = e.get("cc")         or []
        asn        = e.get("asn")        or []
        org        = e.get("org")        or []

        role = infer_suricata_role(categories, sigs)

        parts = [
            f"seen in Suricata IDS alerts; events={counts[ip]}",
        ]
        if categories:
            parts.append(f"categories={','.join(categories)}")
        if sigs:
            parts.append(f"sigs(top)={'; '.join(sigs)}")
        if ports:
            parts.append(f"ports={','.join(map(str, ports))}")
        if cc:
            parts.append(f"cc={','.join(cc)}")
        if asn:
            parts.append(f"asn={','.join(asn)}")
        if org:
            parts.append(f"asn_org={','.join(org)}")

        indicators.append(
            {
                "indicator": ip,
                "type": "IPv4",
                "title": ind_title,
                "description": "; ".join(parts),
                "tags": base_tags,
                "role": role,
            }
        )

    return indicators

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--window-hours",
        type=int,
        help="lookback window in hours (overrides config.pulse.time_window_hours)",
    )
    args = ap.parse_args()

    cfg = load_config(args.config)
    window_hours = int(
        args.window_hours or cfg.get("pulse", {}).get("time_window_hours", 1)
    )

    logger = setup_logger(cfg.get("log_path"))

    if not test_otx(cfg["otx_api_key"], logger):
        return

    counts, enrich = collect_suricata(cfg, logger, window_hours)
    if not counts:
        logger.warning("No Suricata IPs found in window; skipping")
        return

    now = datetime.now(timezone.utc)
    month_label = now.strftime("%B %Y")

    tlp = str(cfg["pulse"].get("tlp", "GREEN")).upper()
    prefix = cfg["pulse"].get(
        "name_prefix",
        "Suricata \u2192 High & Medium Alert IPs",
    )
    loc = str(cfg["pulse"].get("location_label", "")).strip()
    if loc:
        name = f"{prefix} – {loc} – {month_label}"
    else:
        name = f"{prefix} – {month_label}"

    default_desc = (
        f"Rolling monthly view of source IPv4 addresses that triggered Suricata "
        f"severity 1–2 (high & medium) IDS alerts on a T-Pot honeypot. "
        f"Each run looks back the last {window_hours}h and appends newly seen "
        f"IPs for this month."
    )
    if loc:
        default_desc += f" Location: {loc}."

    desc = cfg["pulse"].get("description", default_desc)
    tags = cfg.get("pulse", {}).get("tags") or ["tpot", "honeypot", "suricata", "ids", "sev<=2"]
    public = tlp == "GREEN"

    ip_indicators = build_ip_indicators(cfg, counts, enrich)
    if not ip_indicators:
        logger.warning("No Suricata indicators built from this window; skipping.")
        return

    api_key = cfg["otx_api_key"]

    # --- add: registry-first monthly pulse id resolution ---
    reg_key = f"suricata_{now.strftime('%Y-%m')}"
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
            logger.error("Failed to create Suricata pulse; aborting.")
        return

    existing = get_pulse(api_key, pulse_id, logger)
    if existing is None:
        logger.error("Could not fetch existing Suricata pulse; aborting.")
        return

    existing_inds = existing.get("indicators") or []
    existing_keys = {
        (i.get("indicator"), i.get("type"))
        for i in existing_inds
        if isinstance(i, dict)
    }

    to_add: List[dict] = []
    for ind in ip_indicators:
        key = (ind.get("indicator"), ind.get("type"))
        if key not in existing_keys:
            to_add.append(ind)

    add_indicators(api_key, pulse_id, to_add, logger, args.dry_run)

if __name__ == "__main__":
    main()
