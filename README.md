# T‑POT → OTX PUBLISHER (T‑Pot, Cisco ASA, and SSH brute‑force)

A small, loud, and opinionated off‑box publisher that turns honeypot/firewall noodles into clean AlienVault OTX pulses. It lives on a separate VM, talks to Elasticsearch over an SSH tunnel, dedupes the junk, tags the signal, and pushes tidy pulses on a schedule. It remembers what it sent so OTX doesn’t get spammed.

It’s meant for folks who like: “copy/paste, run, see pulses.”

---

## What’s inside

**Adapters (pick what you want, run them independently):**

* **T‑Pot (full)** – IPs, URLs, SHA256s from Cowrie / Suricata / Dionaea / etc. Good for daily/forensic pulses.
* **Cisco ASA (lean)** – attacker IPs only. Fast hourly watchlists. Optionally snips `payload_printable` into indicator descriptions.
* **SSH brute‑force (new)** – IPs hammering SSH (Cowrie + Heralding). Enriches with country/ASN/org/ports, top usernames/passwords (masked), and SSH client strings. Uses the `bruteforce` role.

**Systemd glue:** oneshot services + timers per adapter. **autossh** unit for a persistent Elasticsearch tunnel.

---

## Repo layout (read me like a map)

```
publisher/
  otx_tpot_publisher.py           # full honeypot publisher (IPs, URLs, hashes)
  otx_ciscoasa_ips_only.py        # ASA-only IP watchlist publisher
  otx_ssh_ips.py                  # SSH brute-force IP publisher (bruteforce role)
  config.example.json             # T‑Pot config template (sanitised)
  config.ciscoasa.example.json    # ASA config template (sanitised)
  config.ssh.example.json         # SSH config template (sanitised)
  requirements.txt                # pip deps

systemd/
  tpot-es-tunnel.service          # autossh tunnel to sensor-side ES
  otx-publisher.service           # T‑Pot oneshot
  otx-publisher.timer             # T‑Pot schedule (daily by default)
  otx-ciscoasa.service            # ASA oneshot
  otx-ciscoasa.timer              # ASA schedule (hourly by default)
  otx-ssh@.service                # SSH oneshot (templated by config path)
  otx-ssh@.timer                  # SSH hourly timer (templated)
```

---

## How it flows (10,000 ft)

Attackers → T‑Pot / ASA → **Elasticsearch (sensor)** → (autossh tunnel) → **Publisher VM** → OTX Pulse

We never expose your OTX key to the sensor box. The publisher pulls data *through* the tunnel, not the other way around.

---

## Before you touch anything (requirements)

* Ubuntu 22.04/24.04 (Debian works too)
* `python3`, `python3-venv`, `autossh`, `jq`, `git`, `ca-certificates`
* An SSH key that the sensor accepts (for the tunnel)

**Bootstrap**

```bash
sudo apt update
sudo apt install -y python3 python3-venv autossh jq ca-certificates git
sudo mkdir -p /opt/otx-publisher && cd /opt/otx-publisher
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r publisher/requirements.txt
```

---

## Tunnel to Elasticsearch (autossh)

Expose the sensor’s ES as `127.0.0.1:64298` on the publisher side. Adjust host/user/key/port to your world.

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

Enable it:

```bash
sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service
curl -s http://127.0.0.1:64298/_cluster/health | jq .status  # should be green/yellow
```

---

## Configs (copy, fill, lock to 600)

**Golden rules**: never commit real configs/keys. Copy the examples and keep perms tight.

```bash
cd /opt/otx-publisher
cp publisher/config.example.json           config.json
cp publisher/config.ciscoasa.example.json  config.ciscoasa.json
cp publisher/config.ssh.example.json       config.ssh.json
chmod 600 config*.json
```

Key fields you’ll edit (all adapters):

* `otx_api_key` — your OTX API key
* `elasticsearch.host` — usually `http://127.0.0.1:64298`
* `indices` — e.g. `["logstash-*"]`
* `pulse.name_prefix`, `pulse.time_window_hours`, `pulse.min_event_count`, `pulse.exclude_private_ips`, `pulse.tlp`
* `limits.max_indicators` (0 = unlimited, but OTX will complain if you go wild)
* `publish.min_interval_minutes` — cooldown between identical pulses
* `log_path`, `state_path` — where to write logs & the dedupe state

### Example: SSH adapter (sanitised)

```json
{
  "otx_api_key": "REPLACE_ME",
  "elasticsearch": { "host": "http://127.0.0.1:64298", "timeout": 15 },
  "indices": ["logstash-*"] ,
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
  "indices": ["logstash-*"] ,
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

(There’s also a T‑Pot example; same idea, larger windows.)

---

## Run it by hand (dry‑run first)

```bash
source /opt/otx-publisher/venv/bin/activate

# SSH (brute‑force role)
python publisher/otx_ssh_ips.py --dry-run --config config.ssh.json
python publisher/otx_ssh_ips.py --config config.ssh.json

# Cisco ASA
python publisher/otx_ciscoasa_ips_only.py --dry-run --config config.ciscoasa.json
python publisher/otx_ciscoasa_ips_only.py --config config.ciscoasa.json

# T‑Pot (full)
python publisher/otx_tpot_publisher.py --dry-run --config config.json
python publisher/otx_tpot_publisher.py --config config.json
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

### Cisco ASA + T‑Pot (classic units)

```bash
sudo cp systemd/otx-ciscoasa.* /etc/systemd/system/
sudo cp systemd/otx-publisher.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-ciscoasa.timer
sudo systemctl enable --now otx-publisher.timer
```

See all timers:

```bash
systemctl list-timers --all | grep -i otx
```

---

## Indicator shaping (what goes to OTX)

* **SSH adapter** → indicator **IPv4**, role **`bruteforce`**, title `Attacker IP • SSH`.

  * Description includes: event count, sensors (Cowrie/Heralding), ports, country, ASN/org, top usernames/passwords (masked), and SSH client strings.
  * Private IPs are **included/excluded** by config (`exclude_private_ips`). Your call.
* **Cisco ASA** → indicator **IPv4**. If the doc has `payload_printable.keyword`, it’s folded into the indicator description (snipped and de‑quoted). Role intentionally left generic.
* **T‑Pot full** → IPv4/IPv6/URLs/SHA256 with consistent tags and heuristic roles.

All adapters apply:

* Time window filter (e.g., last 1h/24h)
* Deduplication across runs via a lightweight state file
* A max‑indicator limit so you don’t blast OTX by accident

---

## Troubleshooting quickies

* Tunnel: `systemctl status tpot-es-tunnel` and `curl http://127.0.0.1:64298/_cluster/health | jq .`
* SSH adapter: `journalctl -u otx-ssh@config.ssh.json.service -n 200 --no-pager`
* Dry‑run everything first: add `--dry-run`
* Force a republish: remove the adapter’s state file and run again
* Validate counts vs ES: run a cardinality agg on `src_ip.keyword` with the same time/should filter

Cardinality one‑liner (last hour, same filter SSH uses):

```bash
ES=http://127.0.0.1:64298 IDX=logstash-* IPF=src_ip.keyword \
curl -s -H 'Content-Type: application/json' -X POST "$ES/$IDX/_search" -d '{
  "size":0,
  "query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-1h","lte":"now"}}},{"exists":{"field":"'"$IPF"'"}}],
  "should":[{"term":{"type.keyword":"cowrie"}},{"term":{"type.keyword":"Cowrie"}},
  {"term":{"type.keyword":"heralding"}},{"term":{"type.keyword":"Heralding"}},
  {"term":{"protocol.keyword":"ssh"}},{"term":{"event.dataset.keyword":"cowrie"}},
  {"term":{"event.dataset.keyword":"heralding"}}],
  "minimum_should_match":1}},
  "aggs":{"uniq":{"cardinality":{"field":"'"$IPF"'","precision_threshold":40000}}}}' | jq '.aggregations.uniq.value'
```

---

## Safety, hygiene, and other adulting

* **Never** commit `config*.json`, `state*.json`, or your SSH keys. `.gitignore` is your friend.
* Lock configs to `chmod 600`.
* Choose TLP intentionally. `GREEN` means public.
* Masked credentials only; do not publish full user/pass pairs.
* Private IPs off by default for ASA/T‑Pot. For SSH you decide.

---

## Roadmap (a.k.a. the “not just two scripts” bit)

* More adapters: FortiGate / Palo Alto / Check Point, VPN concentrators, more honeypots
* Pluggable sinks: keep OTX first‑class, add MISP / Slack / internal watchlists
* Test fixtures + CI to stop regressions when new fields appear

---

## FAQ (fast answers)

**Why a tunnel to ES?**
Keeps creds off the sensor, keeps attack surface small, and lets one publisher aggregate many sensors.

**OTX is rejecting a huge pulse. Now what?**
Lower `limits.max_indicators`, split by adapter, or shorten the window. The logs will show the HTTP error.

**How do roles work?**
They’re set per adapter to keep the OTX UI consistent. SSH uses `bruteforce`. ASA is neutral. The full T‑Pot adapter uses heuristics per indicator type.

**Can I run all three at once?**
Yes. Each has its own config/state/logs. Enable all timers.

---

## License & contributions

MIT‑ish vibes unless your org needs something else. PRs welcome — especially new adapters and docs tweaks that make this easier for the next human.
