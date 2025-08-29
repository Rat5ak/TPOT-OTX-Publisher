# T-Pot → OTX Publisher

Publishes indicators of compromise (IPs, URLs, file hashes) from a T-Pot honeypot into AlienVault OTX as Pulses.

✅ Deduplicated & cooldown logic (no OTX spam) · ✅ Runs on a separate “publisher” VM (not on the honeypot) · ✅ Connects to T-Pot’s Elasticsearch over a persistent SSH tunnel · ✅ Lightweight systemd units for tunnel + publisher

---

## 📂 Repository Layout

```
TPOT-OTX-PUBLISHER/
├── publisher/
│   ├── otx_tpot_publisher.py     # Main Python publisher script
│   ├── requirements.txt          # Python dependencies
│   └── README.md                 # (optional: local usage notes)
│
├── systemd/
│   ├── tpot-es-tunnel.service    # Keeps SSH tunnel open
│   ├── otx-publisher.service     # Runs publisher once
│   └── otx-publisher.timer       # Schedules publisher (daily or every Xh)
│
├── config.example.json           # Safe template (copy to config.json on VM)
└── .gitignore
```

---

## 🔗 Topology

```
Attackers → T-Pot honeypot
   → Elasticsearch (local on T-Pot)
   → [persistent SSH tunnel] → Publisher VM
   → OTX Pulse
```

---

## 1) Publisher VM Setup

Ubuntu 22.04/24.04 tested.

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

## 2) Configuration

Copy the example and add your real OTX API key:

```bash
cp config.example.json config.json
chmod 600 config.json
```

**`config.example.json`:**

```json
{
  "otx_api_key": "PUT-YOUR-REAL-OTX-API-KEY-HERE",
  "elasticsearch": {
    "host": "http://127.0.0.1:64298",
    "timeout": 10
  },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "Honeypot Data – Cowrie/T-Pot",
    "time_window_hours": 24,
    "min_event_count": 3,
    "exclude_private_ips": true,
    "tlp": "green"
  },
  "limits": {
    "max_indicators": 2000
  },
  "publish": {
    "min_interval_minutes": 1440
  },
  "log_path": "/opt/otx-publisher/run.log",
  "state_path": "/opt/otx-publisher/state.json"
}
```

---

## 3) Persistent SSH Tunnel

**`systemd/tpot-es-tunnel.service`:**

```ini
[Unit]
Description=Persistent SSH tunnel to T-Pot Elasticsearch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/lib/autossh/autossh -M 0 -N \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -p <TPOT_SSH_PORT> <TPOT_SSH_USER>@<TPOT_PUBLIC_IP> \
  -L 127.0.0.1:64298:127.0.0.1:64298
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable + check:

```bash
sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service
curl -s http://127.0.0.1:64298/_cluster/health | jq .status
```

---

## 4) First Run

```bash
source /opt/otx-publisher/venv/bin/activate
python publisher/otx_tpot_publisher.py --dry-run --config config.json   # test only
python publisher/otx_tpot_publisher.py --config config.json            # publish
```

Check:

```bash
jq . state.json
tail -n 50 run.log
```

---

## 5) Automate with systemd

**`systemd/otx-publisher.service`:**

```ini
[Unit]
Description=Publish T-Pot IOCs to OTX
After=network-online.target tpot-es-tunnel.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/otx-publisher
ExecStart=/usr/bin/flock -n /opt/otx-publisher/.lock \
  /opt/otx-publisher/venv/bin/python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json
StandardOutput=append:/opt/otx-publisher/run.log
StandardError=append:/opt/otx-publisher/run.log
```

**`systemd/otx-publisher.timer` (daily at 03:17 UTC):**

```ini
[Unit]
Description=Run OTX publisher daily

[Timer]
OnCalendar=*-*-* 03:17:00
AccuracySec=1s
RandomizedDelaySec=0
Persistent=true
Unit=otx-publisher.service

[Install]
WantedBy=timers.target
```

Install + enable:

```bash
sudo cp systemd/otx-publisher.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-publisher.timer
systemctl list-timers | grep otx
```

---

## 6) Troubleshooting

**Tunnel down?**

```bash
systemctl status tpot-es-tunnel
```

**OTX auth?**

```bash
python publisher/otx_tpot_publisher.py --dry-run --config config.json
```

**Force republish?**

```bash
rm -f state.json
python publisher/otx_tpot_publisher.py --config config.json
```

**Logs:**

```bash
tail -n 100 run.log
journalctl -u otx-publisher.service --since "12h"
```

---

## 7) Security Notes

* Don’t commit `config.json` or `state.json` (they’re gitignored).
* Only IOCs are shared (IPs, URLs, hashes) — no raw session data.
* Choose `tlp: "green"` for public pulses, `amber`/`red` for private/internal.

---

## Example Output

```
INFO - Collected IOCs total=153 (IPs=153, URLs=0, Hashes=0)
INFO - Published pulse: Honeypot Data – Cowrie/T-Pot – last 24h (id=68ab5751f8fb3a0c7f3352d9)
```

If unchanged:

```
INFO - Indicators unchanged since last publish (fingerprint match) — skipping.
```

---

## `.gitignore`

```
# Local config / secrets / state
config.json
state.json
run.log

# Python build stuff
__pycache__/
*.py[cod]
.venv/
venv/
.env

# Editors / OS
.DS_Store
.idea/
.vscode/
```

---

## ⚙️ Advanced (what this build actually does)

### Composite aggs = pull *everything*

We use **composite aggregations** to walk all unique values (no 10k doc wobble):

* IPs from `src_ip` / `source_ip` / `client_ip`
* URLs from `url` / `http.url` / `request.url`
* Hashes from `sha256` / `fileinfo.sha256` / `files.sha256` / `shasum`

Each bucket is tagged using the event’s **`type.keyword`** (e.g., cowrie, suricata, dionaea, …) so you see far fewer “unknown” tags.

#### Indicator roles (what shows in OTX)

* `URL` → **malware\_hosting**
* `IPv4/IPv6` with `cowrie` or `honeytrap` sensor tags → **scanning\_host**
* other `IPv4/IPv6` → **unknown**
* **File hashes** → *no role set*

### Self-URL filter (safe)

We **drop only URLs that point to the honeypot itself**:

* Hosts exactly equal to your **local/public IP(s)** (auto-detected from **top destination IPs**)
* Or `localhost` / `127.0.0.1` / `::1`

We **do NOT** drop dashed hostnames like `194-195-253-210.ip.linodeusercontent.com`.

### Cool-off & determinism

* Skips re-publishing if run within `publish.min_interval_minutes` (default **1440** = 24h).
* systemd timer uses:

  ```ini
  AccuracySec=1s
  RandomizedDelaySec=0
  ```

  for predictable, to-the-second scheduling.

---

## 🎛 Tuning

### “Go big” mode (all the things)

Set these in `config.json`:

```json
"pulse":  { "min_event_count": 1 },
"limits": { "max_indicators": 0 }
```

* `min_event_count` = minimum doc count to include an IP (1 = include everything)
* `max_indicators` = overall cap (0 = unlimited; if you later cap, we trim IPs by activity but **never truncate URLs/Hashes**)

### Noise control

* Raise `pulse.min_event_count` (e.g., `3` or `5`) to keep only IPs seen multiple times.
* Keep `pulse.exclude_private_ips: true` to ignore RFC1918 chatter.

---

## 🏷 Sensor tags recognized

We auto-tag indicators from `type.keyword`. Known values/aliases include:

`adbhoney, beelzebub, ciscoasa, citrixhoneypot, conpot, cowrie, ddospot, dicompot, dionaea, docker, elasticpot, elasticsearch, elasticvue, endlessh, ewsposter, fatt, galah, glutton, gopot, h0neytr4p, hellpot, heralding, honeyaml, honeypots, honeytrap, ipphoney, kibana, logstash, log4pot, mailoney, maltrail, medpot, miniprint, p0f, redishoneypot, sentrypeer, spiderfoot, snare, tanner, suricata, wordpot, tpot`

(If you see other `type` values in ES, add them to the map in the script to tag even more precisely.)

---

## ⏱ Quick ops cheats

**Force one publish now (ignoring cooldown):**

```bash
rm -f /opt/otx-publisher/state.json
source /opt/otx-publisher/venv/bin/activate
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json
tail -n 80 /opt/otx-publisher/run.log
```

**Check next run time (UTC):**

```bash
systemctl list-timers --all | grep -i otx
```

**Verify ES via tunnel:**

```bash
curl -s http://127.0.0.1:64298/_cluster/health | jq .
```

---

## 🚨 If OTX ever chokes on huge pulses

Open an issue and we’ll switch to optional **chunked posting** (split into multiple pulses by size or indicator type). The current defaults are fine for most setups.
