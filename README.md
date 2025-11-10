# T-POT → OTX PUBLISHER  
_Honeypots & logs in, clean OTX pulses out._

This lives on a separate VM, talks to your Elasticsearch over an SSH tunnel, dedupes the junk, adds context, and pushes tidy AlienVault OTX pulses on a schedule. It remembers what it has already sent so you don’t spam OTX or re-publish the same junk every hour.

Goal: make it dead simple for people running T-Pot and friends to push high-signal IOCs into OTX – and for everyone else to just subscribe to those pulses and use them straight away.

---

## What it does right now

Adapters (each one is independent):

- **T-Pot full honeypot publisher**
  - Pulls IPs, URLs, SHA256 hashes etc from `logstash-*` (Cowrie, Suricata, Dionaea, etc).
  - Good for daily or “last 24h” style pulses.
- **Cisco ASA IPs-only**
  - Builds a watchlist of attacker IPs from ASA logs.
  - Optionally includes a snip of `payload_printable` in the description so you can see what they tried.
- **SSH bruteforce (Cowrie + Heralding)**
  - Publishes IPs hammering SSH.
  - Enriches with country, ASN, org, ports, top usernames and passwords (masked), and SSH client strings.
  - Uses the `bruteforce` role in OTX.
- **ADB / ADBHoney (in progress)**
  - Config template is here as `config.adb.example.json`.
  - This will drive per-sensor ADBHoney pulses and monthly reports once the ADB adapter and reporting sidecar are finished.

Every adapter:

- Talks to ES through a local tunnel (no OTX key or creds on the sensor box).
- Applies a time window (eg last 1h or 24h).
- Dedupes across runs using a small state file.
- Enforces a `max_indicators` limit so you don’t accidentally ship 50k IOCs in one go.

---

## Repo layout

```text
publisher/
  otx_tpot_publisher.py        # full honeypot publisher (IPs, URLs, hashes)
  otx_ciscoasa_ips_only.py     # Cisco ASA attacker IP publisher
  otx_ssh_ips.py               # SSH bruteforce attacker IP publisher
  requirements.txt             # pip deps for all adapters

systemd/
  tpot-es-tunnel.service       # autossh tunnel to sensor-side Elasticsearch
  otx-publisher.service        # T-Pot oneshot
  otx-publisher.timer          # T-Pot schedule (daily by default)
  otx-ciscoasa.service         # Cisco ASA oneshot
  otx-ciscoasa.timer           # Cisco ASA schedule (hourly by default)
  otx-ssh@.service             # SSH oneshot (templated by config path)
  otx-ssh@.timer               # SSH hourly timer (templated)

config.example.json            # T-Pot config template
config.ciscoasa.example.json   # Cisco ASA config template
config.ssh.example.json        # SSH config template
config.adb.example.json        # ADB / ADBHoney config template (future adapter)

---

## How the flow works

```text
Attackers → T-Pot / ASA / ADBHoney → Elasticsearch (sensor) 
         → autossh tunnel → Publisher VM → OTX pulses
```

* The **sensor** never sees your OTX API key.
* The **publisher VM** pulls from ES via SSH port-forward and pushes to OTX.
* Each adapter has its own config, log and state file, so you can run any mix of them.

---

## Requirements

On the publisher VM:

* Ubuntu 22.04 or 24.04 (Debian works too).
* `python3`, `python3-venv`
* `autossh`, `jq`, `git`, `ca-certificates`
* SSH key that the sensor will accept.

Bootstrap example:

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

## Step 1 – Tunnel Elasticsearch with autossh

Expose the sensor’s Elasticsearch as `127.0.0.1:64298` on the publisher side.

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
  -o "ServerAliveInterval=30" -o "ServerAliveCountMax=3" \
  -i /root/.ssh/tpot_publisher_id \
  -L 64298:127.0.0.1:9200 tpotuser@your-sensor.example
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Install and test:

```bash
sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service

curl -s http://127.0.0.1:64298/_cluster/health | jq .status
# should be green or yellow
```

---

## Step 2 – Configs (copy and lock down)

Golden rule: never commit real configs or keys. Copy the examples and keep perms tight.

From `/opt/otx-publisher`:

```bash
cp publisher/config.example.json           config.json
cp publisher/config.ciscoasa.example.json  config.ciscoasa.json
cp publisher/config.ssh.example.json       config.ssh.json
cp config.adb.example.json                 config.adb.json   # optional / future ADB adapter

chmod 600 config*.json
```

Key fields you will edit (same ideas across adapters):

* `otx_api_key` – your OTX API key.
* `elasticsearch.host` – normally `http://127.0.0.1:64298`.
* `indices` – which indices to query, usually `["logstash-*"]`.
* `pulse.name_prefix` – base name for the pulse.
* `pulse.time_window_hours` – how far back to look.
* `pulse.min_event_count` – minimum events before an indicator is kept.
* `pulse.exclude_private_ips` – toggle whether private ranges are filtered.
* `pulse.tlp` – TLP for the pulse (green if you want it public).
* `limits.max_indicators` – sanity cap (0 means unlimited, not recommended).
* `publish.min_interval_minutes` – cooldown between identical pulses.
* `log_path`, `state_path` – where to put logs and the dedupe state file.

There is also a dedicated ADB config example (`config.adb.example.json`) which will be used by the ADB/ADBHoney adapter once that code is wired in.

---

## Step 3 – Run it by hand

Activate the venv:

```bash
source /opt/otx-publisher/venv/bin/activate
```

SSH brute-force:

```bash
python publisher/otx_ssh_ips.py --dry-run --config config.ssh.json
python publisher/otx_ssh_ips.py --config config.ssh.json
```

Cisco ASA:

```bash
python publisher/otx_ciscoasa_ips_only.py --dry-run --config config.ciscoasa.json
python publisher/otx_ciscoasa_ips_only.py --config config.ciscoasa.json
```

T-Pot full:

```bash
python publisher/otx_tpot_publisher.py --dry-run --config config.json
python publisher/otx_tpot_publisher.py --config config.json
```

Dry-run prints what would be sent to OTX without actually publishing.

---

## Step 4 – Systemd timers (fire and forget)

### SSH adapter (templated services)

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

### Cisco ASA and T-Pot

```bash
sudo cp systemd/otx-ciscoasa.* /etc/systemd/system/
sudo cp systemd/otx-publisher.* /etc/systemd/system/
sudo systemctl daemon-reload

sudo systemctl enable --now otx-ciscoasa.timer
sudo systemctl enable --now otx-publisher.timer

systemctl list-timers --all | grep -i otx
```

---

## Indicator shaping

Rough sketch of what goes into OTX:

* **SSH adapter**

  * Indicator type: IPv4.
  * Role: `bruteforce`.
  * Title: `Attacker IP • SSH`.
  * Description: event count, sensors (Cowrie, Heralding), ports, country, ASN / org, top usernames and passwords (masked), and the SSH client strings that turned up.

* **Cisco ASA**

  * Indicator type: IPv4.
  * If `payload_printable.keyword` is present, a snippet is included in the description, de-quoted and trimmed so it is readable.

* **T-Pot full**

  * Mix of IPs, URLs and SHA256s from the usual honeypot stack, tagged in a consistent way with reasonable default roles.

All of them:

* Filter by time window.
* Deduplicate across runs using a state file.
* Respect `max_indicators` so you don’t light OTX on fire.

---

## Troubleshooting

Some quick checks:

* Tunnel healthy:

  ```bash
  systemctl status tpot-es-tunnel
  curl -s http://127.0.0.1:64298/_cluster/health | jq .
  ```

* SSH adapter noisy?

  ```bash
  journalctl -u otx-ssh@config.ssh.json.service -n 200 --no-pager
  ```

* Dry-run first: add `--dry-run` to any adapter.

* Want to force a republish of something?

  * Stop the timer.
  * Delete the relevant `state.*.json`.
  * Run the adapter once manually.

* Sanity-check counts with ES directly (cardinality on `src_ip.keyword` with the same filters) if numbers look odd.

---

## Where this is heading

Short term:

* Wire in the **ADB / ADBHoney** adapter using `config.adb.json` as the template.
* Ship **per-sensor monthly and daily pulses** with a clean, repeatable naming scheme.
* Make the pulses from the public sensors easy to find and subscribe to on OTX.

Medium term:

* More adapters: FortiGate, Palo Alto, Check Point, VPN concentrators, and other honeypots.
* Optional sinks besides OTX:

  * MISP, internal watchlists, Slack or Teams notifications, etc.
* A small “Robert” sidecar that:

  * Reads pulse output and raw events.
  * Spits out human-readable monthly reports per sensor (Markdown that you can throw on a website or blog).

The philosophy stays the same: low friction, high signal, and pulses that other people can just ingest without babysitting every indicator by hand.

---

## Safety and hygiene

* Do not commit `config*.json`, `state*.json` or any SSH keys.
* Lock configs with `chmod 600`.
* Pick TLP on purpose. Green means public. If it should not leak, do not make it green.
* Only masked credentials ever go into pulses.

---

## License and contributions

MIT vibes. PRs welcome, especially:

* New adapters.
* Tweaks that make installation smoother.
* Docs improvements and examples from your own sensors.

If you build cool stuff on top of this or start pushing your own pulses from T-Pot or ASA, feel free to open an issue and link them.


