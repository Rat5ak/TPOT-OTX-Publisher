T-Pot → OTX Publisher

Publishes indicators of compromise (IPs, URLs, file hashes) from a T-Pot honeypot
 into AlienVault OTX
 as Pulses.

✅ Deduplicated & cooldown logic (no OTX spam)
✅ Runs on a separate “publisher” VM (not on the honeypot)
✅ Connects to T-Pot’s Elasticsearch over a persistent SSH tunnel
✅ Lightweight systemd units for tunnel + publisher

📂 Repository Layout
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

🔗 Topology
Attackers → T-Pot honeypot
   → Elasticsearch (local on T-Pot)
   → [persistent SSH tunnel] → Publisher VM
   → OTX Pulse

1. Publisher VM Setup

Ubuntu 22.04/24.04 tested.

sudo apt update
sudo apt install -y python3 python3-venv autossh jq ca-certificates git
sudo mkdir -p /opt/otx-publisher && cd /opt/otx-publisher
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r publisher/requirements.txt

2. Configuration

Copy the example and add your real OTX API key:

cp config.example.json config.json
chmod 600 config.json


config.example.json:

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

3. Persistent SSH Tunnel

systemd/tpot-es-tunnel.service:

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


Enable + check:

sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service
curl -s http://127.0.0.1:64298/_cluster/health | jq .status

4. First Run
source /opt/otx-publisher/venv/bin/activate
python publisher/otx_tpot_publisher.py --dry-run --config config.json   # test only
python publisher/otx_tpot_publisher.py --config config.json            # publish


Check:

jq . state.json
tail -n 50 run.log

5. Automate with systemd

systemd/otx-publisher.service:

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


systemd/otx-publisher.timer (daily at 03:17 UTC):

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


Install + enable:

sudo cp systemd/otx-publisher.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-publisher.timer
systemctl list-timers | grep otx

6. Troubleshooting

Tunnel down?

systemctl status tpot-es-tunnel


OTX auth?

python publisher/otx_tpot_publisher.py --dry-run --config config.json


Force republish?

rm -f state.json
python publisher/otx_tpot_publisher.py --config config.json


Logs:

tail -n 100 run.log
journalctl -u otx-publisher.service --since "12h"

7. Security Notes

Don’t commit config.json or state.json (they’re gitignored).

Only IOCs are shared (IPs, URLs, hashes) — no raw session data.

Choose tlp: green for public pulses, amber/red for private/internal.

Example Output
INFO - Collected IOCs total=153 (IPs=153, URLs=0, Hashes=0)
INFO - Published pulse: Honeypot Data – Cowrie/T-Pot – last 24h (id=68ab5751f8fb3a0c7f3352d9)


If unchanged:

INFO - Indicators unchanged since last publish (fingerprint match) — skipping.

.gitignore
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