#!/usr/bin/env python3
import argparse
import json
import os
import textwrap
from typing import Dict, Any

import requests
from openai import OpenAI

# ------------- config -------------

OTX_API_KEY = os.environ.get("OTX_API_KEY")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

# model names (you can override with env vars if you want)
DEEP_MODEL = os.environ.get("DEEP_MODEL", "gpt-4.1")       # web + long context
GOBLIN_MODEL = os.environ.get("GOBLIN_MODEL", "gpt-4.1")   # goblin writer

client = OpenAI(api_key=OPENAI_API_KEY)

# base dir and subfolders (relative to this script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


# ------------- helpers -------------

def require_env():
    if not OPENAI_API_KEY:
        raise SystemExit("OPENAI_API_KEY env var not set")


def fetch_stix(stix_url: str) -> Dict[str, Any]:
    """
    Download STIX bundle from OTX using the given URL.

    Supports:
    - API key header style (api/v1/pulses/.../indicators/export?format=stix2)
    - Token export style (otxapi/pulses/.../export/?token=...&format=stix2.1)
    """
    headers = {}

    # only send header if we have a key and URL does not already contain a token
    if "token=" not in stix_url and OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY

    resp = requests.get(stix_url, headers=headers or None, timeout=60)
    resp.raise_for_status()
    return resp.json()


def extract_iocs_from_stix(stix_bundle: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pull out IPv4 addresses and SHA256 hashes from indicator objects.
    Tuned for OTX ADBHoney style STIX patterns.
    """
    ips = []
    hashes = []

    for obj in stix_bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "") or ""
        desc = obj.get("description", "") or ""
        labels = obj.get("labels", []) or []
        valid_from = obj.get("valid_from")

        meta = {
            "description": desc,
            "labels": labels,
            "valid_from": valid_from,
        }

        # example: [ipv4-addr:value = '1.2.3.4']
        if "ipv4-addr:value" in pattern:
            try:
                ip = pattern.split("'")[1]
            except IndexError:
                ip = None
            if ip:
                meta_ip = {"ip": ip}
                meta_ip.update(meta)
                ips.append(meta_ip)

        # example: [file:hashes.'SHA-256' = '...']
        if "SHA-256" in pattern or "sha256" in pattern.lower():
            parts = pattern.split("'")
            if len(parts) >= 4:
                h = parts[3]
                meta_h = {"sha256": h}
                meta_h.update(meta)
                hashes.append(meta_h)

    return {"ips": ips, "hashes": hashes}


def truncate(s: str, max_chars: int) -> str:
    if len(s) <= max_chars:
        return s
    return s[:max_chars] + "\n\n...[truncated]...\n"


# ------------- stage 2: deep research -------------

def run_deep_research(iocs: Dict[str, Any]) -> str:
    """
    Use a web enabled model to do big picture enrichment for the IOCs.
    """
    ioc_json = json.dumps(iocs, indent=2)

    prompt = textwrap.dedent(f"""
    You are a threat intel enrichment engine.

    Context:
    - IOCs come from an Android Debug Bridge honeypot called ADBHoney.
    - Focus on November 2025 activity for a pulse called:
      "ADBHoney -> Attacker IPs - Australia - November 2025".

    Input IOCs (JSON):
    {ioc_json}

    Tasks:
    - Group related IPs by ASN, hosting provider, country and role
      (scanner, malware hosting, C2, benign research).
    - Link file hashes and URLs to known malware families and campaigns
      using open threat intel on the internet.
    - Identify if this fits Mirai or related IoT botnets.
    - Call out bulletproof hosts and research scanners so defenders can
      tell who is actually bad.
    - Produce a narrative style report that explains what this campaign is,
      how it behaves, and what infra it relies on.

    Output:
    - A single long text report, written for a human analyst.
    - You can reference sources by name (URLhaus, JoeSandbox, OTX, etc).
    - This text will be given to another model later for funny report writing,
      so focus on accuracy and coverage, not jokes.
    """)

    response = client.responses.create(
        model=DEEP_MODEL,
        input=[{
            "role": "user",
            "content": [{"type": "input_text", "text": prompt}],
        }],
        tools=[{"type": "web_search"}],
        max_output_tokens=7000,
    )

    chunks = []
    # response.output can contain message outputs and tool outputs, only messages have .content
    for item in response.output:
        if getattr(item, "type", None) != "message":
            continue
        for c in item.content:
            if getattr(c, "type", None) == "output_text":
                chunks.append(c.text)

    return "\n".join(chunks).strip()


# ------------- stage 3: goblin report -------------

def run_goblin_report(
    stix_bundle: Dict[str, Any],
    iocs: Dict[str, Any],
    deep_research_text: str,
) -> str:
    """
    Turn raw and enriched intel into the ROBERT monthly markdown report.
    """

    stix_str = truncate(json.dumps(stix_bundle), 40000)
    ioc_str = truncate(json.dumps(iocs, indent=2), 20000)
    research_str = truncate(deep_research_text, 40000)

    system_msg = """
You are ROBERT, a slightly feral threat intel goblin.

You write monthly reports for defenders:
- Plenty of personality
- Dark humour allowed
- Still accurate enough to go in a serious SOC report
- Do not use long em dashes, just commas and normal punctuation.

Structure:
1. Executive summary
2. Key stats
3. Campaign narrative
4. Infrastructure details
5. Malware and behaviour
6. Detection and mitigation
7. Closing thoughts
"""

    user_msg = f"""
Source A: STIX bundle (truncated if huge)
{stix_str}

Source B: Extracted IOCs
{ioc_str}

Source C: Deep research enrichment
{research_str}

Write a markdown report for the pulse:
"ADBHoney -> Attacker IPs - Australia - November 2025".

Follow the structure from the system message.
Sound like a human analyst who is a bit of a goblin, but do not invent
new IOCs or campaigns that are not implied by the sources.
"""

    response = client.responses.create(
        model=GOBLIN_MODEL,
        input=[
            {
                "role": "system",
                "content": [{"type": "input_text", "text": system_msg}],
            },
            {
                "role": "user",
                "content": [{"type": "input_text", "text": user_msg}],
            },
        ],
        max_output_tokens=7000,
    )

    chunks = []
    for item in response.output:
        if getattr(item, "type", None) != "message":
            continue
        for c in item.content:
            if getattr(c, "type", None) == "output_text":
                chunks.append(c.text)

    return "\n\n".join(chunks).strip()


# ------------- cli entry -------------

def main():
    parser = argparse.ArgumentParser(
        description="ADBHoney monthly report helper, ROBERT spec"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # fetch
    p_fetch = sub.add_parser("fetch", help="fetch STIX bundle from OTX")
    p_fetch.add_argument(
        "--stix-url",
        required=True,
        help="OTX STIX export URL for the pulse",
    )
    p_fetch.add_argument(
        "--out",
        required=True,
        help="output path for stix json",
    )

    # research
    p_research = sub.add_parser(
        "research",
        help="run deep research enrichment",
    )
    p_research.add_argument("--stix-file", required=True)
    p_research.add_argument(
        "--out",
        required=True,
        help="output path for research txt",
    )

    # report
    p_report = sub.add_parser(
        "report",
        help="generate goblin report markdown",
    )
    p_report.add_argument("--stix-file", required=True)
    p_report.add_argument("--research-file", required=True)
    p_report.add_argument(
        "--out",
        required=True,
        help="output path for markdown report",
    )

    # all in one
    p_all = sub.add_parser("all", help="run all stages in one go")
    p_all.add_argument("--stix-url", required=True)
    p_all.add_argument(
        "--prefix",
        required=True,
        help="file prefix for outputs",
    )

    args = parser.parse_args()
    require_env()

    # make sure dirs exist
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    if args.cmd == "fetch":
        stix = fetch_stix(args.stix_url)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(stix, f)
        print(f"[+] wrote STIX to {args.out}")

    elif args.cmd == "research":
        with open(args.stix_file, encoding="utf-8") as f:
            stix = json.load(f)
        iocs = extract_iocs_from_stix(stix)
        research = run_deep_research(iocs)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(research)
        print(f"[+] wrote research to {args.out}")

    elif args.cmd == "report":
        with open(args.stix_file, encoding="utf-8") as f:
            stix = json.load(f)
        with open(args.research_file, encoding="utf-8") as f:
            research = f.read()
        iocs = extract_iocs_from_stix(stix)
        report = run_goblin_report(stix, iocs, research)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] wrote report to {args.out}")

    elif args.cmd == "all":
        prefix = args.prefix

        # 1 fetch
        print("[*] fetching STIX from OTX")
        stix = fetch_stix(args.stix_url)
        stix_path = os.path.join(DATA_DIR, f"{prefix}.stix.json")
        with open(stix_path, "w", encoding="utf-8") as f:
            json.dump(stix, f)
        print(f"[+] wrote {stix_path}")

        # 2 research
        print("[*] running deep research")
        iocs = extract_iocs_from_stix(stix)
        research = run_deep_research(iocs)
        research_path = os.path.join(DATA_DIR, f"{prefix}.research.txt")
        with open(research_path, "w", encoding="utf-8") as f:
            f.write(research)
        print(f"[+] wrote {research_path}")

        # 3 goblin report
        print("[*] generating goblin report")
        report = run_goblin_report(stix, iocs, research)
        report_path = os.path.join(REPORTS_DIR, f"{prefix}.report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[+] wrote {report_path}")


if __name__ == "__main__":
    main()