# T-POT → OTX PUBLISHER  
(T-Pot, Cisco ASA, ADBHoney, and SSH brute-force)

A small, loud, and opinionated off-box publisher that turns honeypot/firewall noodles into clean AlienVault OTX pulses.

It lives on a separate VM, talks to Elasticsearch over an SSH tunnel, dedupes the junk, tags the signal, and pushes tidy pulses on a schedule. It remembers what it sent so OTX doesn’t get spammed.

It’s meant for folks who like: **“copy/paste, run, see pulses.”**

---

## What’s inside

Publishers (run them independently, mix & match):

1. **T-Pot “big boi” (full honeypot)**  
   `publisher/otx_tpot_publisher.py`  
   Aggregates IPs, URLs, and SHA256s from T-Pot honeypots (Cowrie / Suricata / Dionaea / etc.).  
   Good for **daily / monthly “everything we saw”** pulses with lots of IOCs.

2. **Cisco ASA IP publisher**  
   `publisher/otx_ciscoasa_ips_only.py`  
   Pulls attacker IPv4s from ASA logs. Fast hourly watchlists.  
   Optionally folds `payload_printable` into indicator descriptions (snipped & cleaned).

3. **ADBHoney IP + hash publisher**  
   (Rolling ADB publisher — IPs plus SHA256 samples from `outfile` downloads.)  
   Uses ADBHoney logs to:
   - Track **attacker IPs** hitting TCP/5555 (and related fields)
   - Derive **FileHash-SHA256** from `outfile` like `dl/<sha256>.raw`
   - Enrich with basic context (src IPs, country codes, simple command previews)

4. **SSH brute-force IP publisher**  
   `publisher/otx_ssh_ips.py`  
   Tracks SSH attackers seen by Cowrie + Heralding.  
   Enriches with country/ASN/org/ports, top usernames/passwords (masked), and SSH client strings.  
   Uses the **`bruteforce`** role in OTX.

Plus a bit of **systemd glue** (oneshot services + timers per publisher) and an `autossh` unit for the persistent ES tunnel.

---

## Repo layout (read me like a map)

```text
publisher/
  otx_tpot_publisher.py           # 1) big boi full honeypot publisher (IPs, URLs, hashes)
  otx_ciscoasa_ips_only.py        # 2) Cisco ASA-only attacker IP watchlist publisher
  otx_ssh_ips.py                  # 4) SSH brute-force IP publisher (role=bruteforce)
  # (3) ADBHoney IP+hash publisher lives alongside these scripts on the box
  config.example.json             # T-Pot config template (sanitised)
  config.ciscoasa.example.json    # ASA config template (sanitised)
  config.ssh.example.json         # SSH config template (sanitised)
  requirements.txt                # pip deps

systemd/
  tpot-es-tunnel.service          # autossh tunnel to sensor-side ES
  otx-publisher.service           # T-Pot oneshot (big boi)
  otx-publisher.timer             # T-Pot schedule (daily by default)
  otx-ciscoasa.service            # Cisco ASA oneshot
  otx-ciscoasa.timer              # Cisco ASA schedule (hourly by default)
  otx-ssh@.service                # SSH oneshot (templated by config path)
  otx-ssh@.timer                  # SSH hourly timer (templated)
````

(ADBHoney publisher is designed to run in the same style — config JSON + simple python entrypoint — but can also be kicked off via cron, a custom systemd unit, or manually.)

---

## How it flows (10,000 ft)

```text
Attackers
  ↓
T-Pot honeypots / Cisco ASA
  ↓
Elasticsearch on the sensor
  ↓ (autossh tunnel)
Publisher VM
  ↓
AlienVault OTX Pulses
```

We **never expose your OTX key** to the T-Pot/ASA host.
The publisher pulls from Elasticsearch through the tunnel; the sensor never talks to OTX directly.

---

## Requirements

Tested on:

* Ubuntu 22.04 / 24.04 (Debian is fine too)
* `python3`, `python3-venv`
* `autossh`, `jq`, `git`, `ca-certificates`
* An SSH key the sensor accepts (for the tunnel)
* AlienVault OTX account + API key

Bootstrap on the publisher VM:

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

## Tunnel to Elasticsearch (autossh)

Expose the sensor’s ES as `127.0.0.1:64298` **on the publisher side** via SSH.

`systemd/tpot-es-tunnel.service`:

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

Install & enable:

```bash
sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service

curl -s http://127.0.0.1:64298/_cluster/health | jq .status
# should say "green" or "yellow"
```

---

## Configs (copy, fill, lock to 600)

Golden rules:

* Never commit real configs / keys.
* Treat `config*.json` as secrets.
* Same pattern for each publisher: OTX key, ES host/indices, pulse metadata, limits, log/state paths.

```bash
cd /opt/otx-publisher

cp publisher/config.example.json           config.json          # T-Pot big boi
cp publisher/config.ciscoasa.example.json  config.ciscoasa.json
cp publisher/config.ssh.example.json       config.ssh.json
# For ADBHoney, create your own config.adb.json based on the others.

chmod 600 config*.json
```

Shared fields across configs:

* `otx_api_key` — your OTX API key
* `elasticsearch.host` — typically `http://127.0.0.1:64298`
* `indices` — e.g. `["logstash-*"]`
* `pulse.*` — name prefix, time window, thresholds, TLP, location label
* `limits.max_indicators` — per run; `0` = unlimited (not recommended)
* `publish.min_interval_minutes` — cooldown between identical pulses
* `log_path` / `state_path` — where to write logs & dedupe state

### Example: SSH adapter (sanitised)

```json
{
  "otx_api_key": "REPLACE_ME",
  "elasticsearch": { "host": "http://127.0.0.1:64298", "timeout": 15 },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "SSH → Attacker IPs",
    "time_window_hours": 1,
    "min_event_count": 1,
    "exclude_private_ips": false,
    "tlp": "GREEN",
    "location_label": "Australia"
  },
  "limits": { "max_indicators": 2000 },
  "publish": { "min_interval_minutes": 60 },
  "log_path": "/opt/otx-publisher/ssh.run.log",
  "state_path": "/opt/otx-publisher/state.ssh.json"
}
```

### Example: Cisco ASA (sanitised)

```json
{
  "otx_api_key": "REPLACE_ME",
  "elasticsearch": { "host": "http://127.0.0.1:64298", "timeout": 15 },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "CiscoASA → Attacker IPs",
    "time_window_hours": 1,
    "min_event_count": 1,
    "exclude_private_ips": true,
    "tlp": "GREEN",
    "location_label": "Australia"
  },
  "log_path": "/opt/otx-publisher/ciscoasa.run.log",
  "state_path": "/opt/otx-publisher/state.ciscoasa.json"
}
```

### Example: T-Pot “big boi” (sanitised)

```json
{
  "otx_api_key": "REPLACE_ME",
  "elasticsearch": { "host": "http://127.0.0.1:64298", "timeout": 20 },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "Honeypot Data – T-Pot – Sydney, Australia",
    "time_window_hours": 24,
    "min_event_count": 1,
    "exclude_private_ips": true,
    "tlp": "GREEN",
    "location_label": "Australia"
  },
  "limits": { "max_indicators": 5000 },
  "publish": { "min_interval_minutes": 1440 },
  "log_path": "/opt/otx-publisher/tpot.run.log",
  "state_path": "/opt/otx-publisher/state.tpot.json"
}
```

For ADBHoney, you’ll use the same pattern but tailor `name_prefix` and window (often a wider window, e.g. 24–200h, for rolling hash/IP enrichment).

---

## Run it by hand (dry-run first)

Always run with `--dry-run` once to see what would be sent.

```bash
source /opt/otx-publisher/venv/bin/activate
cd /opt/otx-publisher
```

### SSH publisher

```bash
python publisher/otx_ssh_ips.py --dry-run --config config.ssh.json
python publisher/otx_ssh_ips.py --config config.ssh.json
```

### Cisco ASA publisher

```bash
python publisher/otx_ciscoasa_ips_only.py --dry-run --config config.ciscoasa.json
python publisher/otx_ciscoasa_ips_only.py --config config.ciscoasa.json
```

### T-Pot “big boi” publisher

```bash
python publisher/otx_tpot_publisher.py --dry-run --config config.json
python publisher/otx_tpot_publisher.py --config config.json
```

### ADBHoney IP + hash publisher

If you have the ADBHoney rolling script deployed:

```bash
python otx_adbhoney_rolling.py --dry-run --config config.adb.json --window-hours 199
python otx_adbhoney_rolling.py --config config.adb.json --window-hours 199
```

---

## Systemd — schedule it and forget it

### SSH adapter (templated units)

`systemd/otx-ssh@.service`:

```ini
[Unit]
Description=OTX SSH publisher (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/otx-publisher
Environment=PYTHONUNBUFFERED=1
ExecStart=/usr/bin/env python3 /opt/otx-publisher/publisher/otx_ssh_ips.py --config /opt/otx-publisher/%i
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
```

`systemd/otx-ssh@.timer`:

```ini
[Unit]
Description=Run OTX SSH publisher hourly (%i)

[Timer]
OnBootSec=5min
OnUnitActiveSec=1h
RandomizedDelaySec=2m
Persistent=true
Unit=otx-ssh@%i.service

[Install]
WantedBy=timers.target
```

Enable with your config filename as the instance:

```bash
sudo cp systemd/otx-ssh@.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-ssh@config.ssh.json.timer

journalctl -u otx-ssh@config.ssh.json.service -n 50 --no-pager
```

### Cisco ASA + T-Pot (classic units)

```bash
sudo cp systemd/otx-ciscoasa.* /etc/systemd/system/
sudo cp systemd/otx-publisher.* /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now otx-ciscoasa.timer
sudo systemctl enable --now otx-publisher.timer

systemctl list-timers --all | grep -i otx
```

For ADBHoney, you can either:

* Add a small `otx-adbhoney.service` + `.timer`, or
* Trigger it via cron, or
* Run manually when you want to append to the monthly pulse.

---

## Indicator shaping (what actually goes to OTX)

Each publisher produces indicators with consistent titles/tags and reasonable roles.

* **SSH publisher**

  * Type: `IPv4`
  * Role: `bruteforce`
  * Title: `Attacker IP • SSH`
  * Description includes:

    * Event count
    * Ports
    * Country / ASN / org
    * Top usernames/passwords (masked)
    * SSH client strings

* **Cisco ASA publisher**

  * Type: `IPv4`
  * Role: generic / scanning (kept simple)
  * Description includes:

    * Event count
    * Ports
    * Country / ASN / org (if present)
    * Snipped `payload_printable` when available (cleaned up and truncated)

* **T-Pot “big boi” publisher**

  * Types: `IPv4`, `IPv6`, `URL`, `FileHash-SHA256`
  * Uses heuristics and Suricata categories to tag roles:

    * `scanning_host`, `malware_hosting`, `malware_distribution`, `command_and_control`, etc.
  * Good for high-volume “everything this box saw” pulses.

* **ADBHoney IP + hash publisher**

  * Types:

    * `IPv4` attacker IPs seen in ADB attacks
    * `FileHash-SHA256` hashes parsed from `outfile` (e.g. `dl/<sha>.raw`)
  * IP descriptions include:

    * Count, ports, country, ASN/org, Suricata cats, snippet of last ADB command
  * Hash descriptions include:

    * `outfile`, associated `src_ip` / country codes, last seen timestamp
    * Short command preview if available (e.g. `cd /data/local/tmp; wget http://x.x.x.x/...`)
  * Roles stay conservative (scanner vs malware_hosting) unless the evidence is clear.

All publishers support:

* Time window filters (e.g. last 1h / last 24h / last 199h)
* Deduplication across runs via simple state files (no duplicate indicators per pulse)
* Max-indicator limits so you don’t by accident firehose OTX

---

## Troubleshooting quickies

* Tunnel:

  ```bash
  systemctl status tpot-es-tunnel
  curl -s http://127.0.0.1:64298/_cluster/health | jq .
  ```

* SSH adapter:

  ```bash
  journalctl -u otx-ssh@config.ssh.json.service -n 200 --no-pager
  ```

* Cisco ASA / T-Pot:

  ```bash
  journalctl -u otx-ciscoasa.service -n 200 --no-pager
  journalctl -u otx-publisher.service -n 200 --no-pager
  ```

* Dry-run everything first: add `--dry-run`.

* Force a republish: delete the relevant `state.*.json` and run again.

* Validate counts vs ES for sanity:

  ```bash
  ES=http://127.0.0.1:64298
  IDX=logstash-*
  IPF=src_ip.keyword

  curl -s -H 'Content-Type: application/json' -X POST "$ES/$IDX/_search" -d '{
    "size":0,
    "aggs":{"uniq":{"cardinality":{"field":"'"$IPF"'"}}},
    "query":{
      "bool":{
        "filter":[{"range":{"@timestamp":{"gte":"now-1h","lte":"now"}}},{"exists":{"field":"'"$IPF"'"}}],
        "should":[
          {"term":{"type.keyword":"cowrie"}},{"term":{"type.keyword":"Cowrie"}},
          {"term":{"type.keyword":"heralding"}},{"term":{"type.keyword":"Heralding"}},
          {"term":{"protocol.keyword":"ssh"}},
          {"term":{"event.dataset.keyword":"cowrie"}},
          {"term":{"event.dataset.keyword":"heralding"}}
        ],
        "minimum_should_match":1
      }
    }
  }' | jq .
  ```

---

## License

MIT. Use it, fork it, break it, fix it. PRs welcome.

```
