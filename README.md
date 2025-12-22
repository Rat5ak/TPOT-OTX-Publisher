# T-Pot → OTX Publisher

**Rolling threat intelligence from honeypots to AlienVault OTX**

This repository contains an off-box publisher that turns raw honeypot and firewall telemetry into clean, deduplicated, high-signal AlienVault OTX pulses.

It is designed to run on a **separate publisher VM**, pull data from Elasticsearch over an SSH tunnel, enrich and deduplicate indicators, and publish **rolling monthly OTX pulses** that people can actually browse, follow, and reuse.

This is not a dashboard.
This is not a SaaS.
This is a “copy config, run script, get real intel” system.

---

## Why this exists

Most honeypot → OTX tooling falls into one of two traps:

1. Firehosing thousands of indicators into throwaway pulses
2. Publishing noisy, low-context data that no one can realistically consume

This project is intentionally opinionated:

• One pulse per sensor per month
• Incremental updates instead of constant new pulses
• Conservative role assignment
• Deduplication by design
• Enough enrichment to be useful, not enough to hallucinate

The goal is **sustainable threat intelligence**, not vanity metrics.

---

## High-level flow

```text
Attackers
  ↓
T-Pot honeypots / Cisco ASA
  ↓
Elasticsearch on the sensor
  ↓ (autossh tunnel)
Publisher VM
  ↓
AlienVault OTX (rolling monthly pulses)
```

Key design choice:
**The sensor never talks to OTX.**

Your OTX API key lives only on the publisher VM.

---

## Rolling monthly pulses (core concept)

Each publisher maintains **one pulse per sensor per calendar month**.

Example:

```
CiscoASA → Attacker IPs – Australia – December 2025
```

Each run:

• Queries Elasticsearch for the last *N* hours
• Builds indicators seen in that window
• Compares against what already exists in the pulse
• Appends **only new indicators**

This avoids:

• Pulse spam
• Duplicate indicators
• Unstable URLs
• “Daily dump” fatigue

The result is a clean, cumulative monthly record of activity.

---

## Publishers included

Each publisher is independent. You can run any combination.

---

### 1) T-Pot “big boi” publisher

`publisher/otx_tpot_publisher.py`

Aggregates across **all T-Pot honeypots**.

Publishes:
• IPv4
• IPv6
• URLs
• FileHash-SHA256

Uses Suricata categories and heuristics to infer roles:
• scanning_host
• malware_hosting
• malware_distribution
• command_and_control

Best suited for:
• Daily rollups
• Monthly “everything this box saw” pulses

This is the high-volume, high-context publisher.

---

### 2) Cisco ASA attacker IP publisher

`publisher/otx_ciscoasa_ips_only.py`

Focused, IP-only publisher.

Features:
• Fast aggregation of attacker IPv4s
• Optional payload_printable snippets (cleaned + truncated)
• Minimal heuristics, minimal risk

Best suited for:
• Hourly watchlists
• Recon and scanning visibility

This is your “what is hitting the firewall right now” feed.

---

### 3) SSH brute-force publisher

`publisher/otx_ssh_ips.py`

Tracks SSH attackers via Cowrie and Heralding.

Enriches with:
• Country
• ASN / organisation
• Ports
• SSH client strings
• Top usernames/passwords (masked)

Uses OTX role: `bruteforce`.

Best suited for:
• Hourly pulses
• Credential-attack monitoring

---

### 4) ADBHoney IP + hash publisher

`otx_adbhoney_rolling.py`

Specialised Android honeypot intelligence.

Publishes:
• Attacker IPv4s (ADB / TCP 5555)
• FileHash-SHA256 droppers parsed from `outfile`

Extracts:
• Dropper hashes
• Source IPs
• Country codes
• Command previews (wget, curl, pm install, etc.)

Role assignment is conservative unless evidence is strong.

This publisher consistently produces high-quality malware intelligence.

---

## Pulse registry (`pulses.json`)

The system maintains a local registry mapping month → pulse ID.

Example:

```json
{
  "ciscoasa_2025-12": "69428baa34e26652c938ef2a",
  "ssh_telnet_2025-12": "6948b3177e210527f8afd308",
  "dionaea_2025-12": "6948bd0e9e8118474e46fa13",
  "suricata_2025-12": "6948bf8b4c9ef26d966dfcf8",
  "tpot_monthly_2025-12": "69428baa34e26652c938ef2a"
}
```

Why this exists:

• OTX search APIs are slow and fuzzy
• Pulse names are not guaranteed unique
• This guarantees idempotent updates
• Prevents duplicate pulse creation

If the registry is missing or incomplete, the scripts fall back to searching OTX by name and automatically rebuild it.

---

## Repository layout

```
publisher/
  otx_tpot_publisher.py
  otx_ciscoasa_ips_only.py
  otx_ssh_ips.py
  otx_adbhoney_rolling.py
  requirements.txt
  config.example.json
  config.ciscoasa.example.json
  config.ssh.example.json
  config.dionaea.example.json
  config.suricata.example.json

systemd/
  tpot-es-tunnel.service
  otx-publisher.service
  otx-publisher.timer
  otx-ciscoasa.service
  otx-ciscoasa.timer
  otx-ssh@.service
  otx-ssh@.timer
```

---

## Architecture & trust model

There are three trust zones:

1. **Sensor zone**
   T-Pot, Cisco ASA, raw attacker interaction.
   Semi-hostile by definition.

2. **Transport zone**
   autossh tunnel providing read-only ES access.

3. **Publisher zone**
   Holds OTX API key and performs publication.

Sensors never receive OTX credentials.

---

## Requirements

Tested on:

• Ubuntu 22.04 / 24.04
• Debian works fine

You’ll need:

• Python 3.10+
• autossh
• jq
• git
• An OTX account + API key
• SSH access from publisher → sensor

---

## Bootstrap the publisher VM

```bash
sudo apt update
sudo apt install -y python3 python3-venv autossh jq ca-certificates git

sudo mkdir -p /opt/otx-publisher
cd /opt/otx-publisher

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r publisher/requirements.txt
```

---

## Elasticsearch tunnel (autossh)

Expose sensor ES locally on the publisher.

Example service:

```ini
[Unit]
Description=autossh tunnel to T-Pot Elasticsearch
After=network-online.target
Wants=network-online.target

[Service]
User=root
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 -N \
  -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" \
  -i /root/.ssh/tpot_publisher_id \
  -L 64298:127.0.0.1:9200 tpotuser@your-sensor.example
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service
curl http://127.0.0.1:64298/_cluster/health | jq .
```

---

## Configuration handling

Rules:

• Never commit real configs
• Always `chmod 600`
• One config per publisher
• Separate log and state files

Create configs:

```bash
cp publisher/config.example.json           config.json
cp publisher/config.ciscoasa.example.json  config.ciscoasa.json
cp publisher/config.ssh.example.json       config.ssh.json
cp publisher/config.dionaea.example.json   config.dionaea.json
cp publisher/config.suricata.example.json  config.suricata.json

chmod 600 config*.json
```

---

## Running publishers manually

Always dry-run first.

```bash
source /opt/otx-publisher/venv/bin/activate
cd /opt/otx-publisher
```

SSH:

```bash
python publisher/otx_ssh_ips.py --dry-run --config config.ssh.json
python publisher/otx_ssh_ips.py --config config.ssh.json
```

Cisco ASA:

```bash
python publisher/otx_ciscoasa_ips_only.py --dry-run --config config.ciscoasa.json
python publisher/otx_ciscoasa_ips_only.py --config config.ciscoasa.json
```

T-Pot:

```bash
python publisher/otx_tpot_publisher.py --dry-run --config config.json
python publisher/otx_tpot_publisher.py --config config.json
```

ADBHoney:

```bash
python otx_adbhoney_rolling.py --dry-run --config config.adb.json --window-hours 199
python otx_adbhoney_rolling.py --config config.adb.json --window-hours 199
```

---

## Scheduling with systemd

SSH publishers use templated units:

```bash
sudo systemctl enable --now otx-ssh@config.ssh.json.timer
```

Cisco ASA and T-Pot use classic timers:

```bash
sudo systemctl enable --now otx-ciscoasa.timer
sudo systemctl enable --now otx-publisher.timer
```

Verify:

```bash
systemctl list-timers | grep otx
```

---

## Indicator shaping (what goes to OTX)

• SSH
– IPv4
– Role: bruteforce

• Cisco ASA
– IPv4
– Role: scanning_host

• T-Pot
– IPv4 / IPv6 / URL / SHA256
– Role inferred via Suricata + heuristics

• ADBHoney
– IPv4 attacker IPs
– FileHash-SHA256 droppers

All publishers prioritise correctness over creativity.

---

## When something breaks

Checklist:

• Is the ES tunnel up?
• Does ES actually contain data in the time window?
• Are field names different on this sensor?
• Are thresholds too high?
• Is pulses.json corrupted?

Recovery is simple:

• Delete the state file → republish
• Delete the pulses.json entry → re-discover
• Delete the pulse in OTX → clean slate

Nothing here is irreversible.

---

## What this enables next

This repo is the **data spine** for:

• Monthly AI-generated threat reports
• STIX bundles per sensor/month
• Public dashboards
• nadsec.online browsing & visualisation

Those come next.

---

## License

MIT.

Use it. Fork it. Publish better intel.


