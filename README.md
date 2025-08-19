T-Pot → OTX Publisher (separate VM + persistent SSH tunnel)

This pushes actionable indicators (IPs / URLs / hashes) from a T-Pot honeypot into AlienVault OTX as a Pulse.

Runs on a separate “publisher” VM

Reaches T-Pot’s Elasticsearch through a persistent SSH tunnel (non-standard SSH port supported)

Dedupe + cooldown so you don’t spam OTX with identical pulses

📂 Repository Layout
TPOT-OTX-PUBLISHER/
├── publisher/
│   ├── otx_tpot_publisher.py     # Main Python publisher script
│   ├── requirements.txt          # Python dependencies
│   └── README.md                 # (this file – optional to keep here too)
│
├── systemd/
│   ├── tpot-es-tunnel.service    # SSH tunnel into T-Pot ES (template)
│   ├── otx-publisher.service     # Runs publisher once
│   └── otx-publisher.timer       # Triggers publisher every 6h
│
├── .gitignore
└── config.example.json           # Safe template – copy to config.json on VM

Topology
Attackers → T-Pot honeypot
   → Elasticsearch (local on T-Pot)
   → [persistent SSH tunnel] → Publisher VM
   → OTX Pulse (with dedupe/cooldown)


Why a separate VM?

Keeps the honeypot clean and safer.

Easier upgrades (Python venv), logging, and scheduling.

Tight network controls (only SSH to T-Pot + HTTPS to OTX).

1) Prereqs (Publisher VM)

Ubuntu 24.04+ assumed.

sudo apt update
sudo apt install -y python3 python3-venv autossh jq moreutils ca-certificates git
sudo mkdir -p /opt/otx-publisher
sudo chown -R $USER:$USER /opt/otx-publisher


Create venv + deps:

cd /opt/otx-publisher
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r publisher/requirements.txt

2) Config (with placeholders)

Create /opt/otx-publisher/config.json from the example below.
(This file is ignored by Git; keep your real key here.)

config.example.json (commit this)

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
    "skip_if_same": true,
    "min_delta_indicators": 0,
    "republish_same_after_hours": 24,
    "min_interval_minutes": 1440
  },
  "log_path": "/opt/otx-publisher/run.log"
}


Then on the VM:

cp config.example.json config.json
# edit the key & any settings you need
chmod 600 /opt/otx-publisher/config.json

3) SSH Tunnel (Publisher VM → T-Pot)

This keeps a local ES port (64298) permanently forwarded to T-Pot’s ES (also 64298), over SSH port you choose.

systemd/tpot-es-tunnel.service

[Unit]
Description=Persistent SSH tunnel to T-Pot Elasticsearch
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
# EDIT THESE: user, host, ssh port
ExecStart=/usr/lib/autossh/autossh -M 0 -N \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -p <TPOT_SSH_PORT> <TPOT_SSH_USER>@<TPOT_PUBLIC_IP> \
  -L 127.0.0.1:64298:127.0.0.1:64298
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target


Install + enable:

sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service


Verify:

ss -ltnp | grep 64298
curl -s http://127.0.0.1:64298/_cluster/health | jq .status   # expect "green" or "yellow"

4) First Run (manual)
source /opt/otx-publisher/venv/bin/activate

# Dry run (collect only)
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --dry-run --config /opt/otx-publisher/config.json

# Real run (publishes + writes /opt/otx-publisher/state.json)
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json

# Second run should SKIP if nothing changed
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json


Check state / logs:

jq . /opt/otx-publisher/state.json
tail -n 100 /opt/otx-publisher/run.log


How dedupe works: all indicators (IPs/URLs/hashes) are sorted then hashed (SHA256).
If the fingerprint matches the last run, it skips (with optional cooldown/cadence from publish section).

5) Automate with systemd

systemd/otx-publisher.service

[Unit]
Description=Publish T-Pot IOCs to OTX
After=network-online.target tpot-es-tunnel.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/otx-publisher
# Use flock to avoid overlapping runs
ExecStart=/usr/bin/flock -n /opt/otx-publisher/.lock \
  /opt/otx-publisher/venv/bin/python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json
StandardOutput=append:/opt/otx-publisher/run.log
StandardError=append:/opt/otx-publisher/run.log


systemd/otx-publisher.timer

[Unit]
Description=Run OTX publisher every 6 hours

[Timer]
OnCalendar=*-*-* 00/6:17:00
RandomizedDelaySec=120
Persistent=true

[Install]
WantedBy=timers.target


Install + start:

sudo cp systemd/otx-publisher.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-publisher.timer
systemctl list-timers | grep otx-publisher


Manual trigger:

sudo systemctl start otx-publisher.service

6) Troubleshooting

Tunnel down

systemctl status tpot-es-tunnel --no-pager
curl -s http://127.0.0.1:64298/_cluster/health | jq .status


OTX auth

Wrong API key → fix config.json

Outbound egress blocked? allow HTTPS to otx.alienvault.com

No data

curl -s http://127.0.0.1:64298/_cat/indices?h=index | sort
# adjust indices or lower "min_event_count"


Force publish (ignore dedupe)

rm -f /opt/otx-publisher/state.json
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json


Logs

tail -n 100 /opt/otx-publisher/run.log
journalctl -u otx-publisher --since "12h" --no-pager

7) Security / Privacy

Keep real config.json on the VM only (git-ignored).

Only IOCs (IPs/URLs/hashes) are exported; no session data or PII.

Consider using tlp: "green" for public sharing; otherwise make pulses private.

8) What You Should See

New IOCs:

INFO - Published pulse: Honeypot Data – Cowrie/T-Pot – last 24h (id=...)


Unchanged:

INFO - Indicators unchanged since last publish (fingerprint match) — skipping.

.gitignore (commit this)
# Local config / secrets / state
config.json
state.json
run.log

# Python build stuff
__pycache__/
*.pyc
*.pyo
*.pyd
.venv/
venv/
.env

# Editors / OS
.DS_Store
.idea/
.vscode/

publisher/requirements.txt
requests
OTXv2


(If your Python warns about system package management, venv avoids that.)

Notes

The pulse title avoids embedding hostnames (stays consistent).

Dedupe uses a content fingerprint plus a cooldown (min_interval_minutes) and a fallback republish window (republish_same_after_hours) so if attackers keep hammering with the same 157 IPs all day, you don’t publish 4 identical pulses in a row.

You can relax/tighten noise with min_event_count and time_window_hours.