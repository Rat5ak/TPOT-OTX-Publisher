# T-Pot → OTX Publisher (separate VM + persistent SSH tunnel)

This pushes **actionable indicators** (IPs / URLs / hashes) from a T-Pot honeypot into **AlienVault OTX** as a Pulse.  
It runs on a **separate “publisher” VM** and reaches T-Pot’s Elasticsearch via a **persistent SSH tunnel** on a **non-standard SSH port**.

---

## 📂 Repository Layout

```
TPOT-OTX-PUBLISHER/
├── publisher/
│   ├── otx_tpot_publisher.py     # Main Python publisher script
│   ├── requirements.txt          # Python dependencies
│   └── README.md                 # This documentation
│
├── systemd/
│   ├── tpot-es-tunnel.service    # SSH tunnel into T-Pot ES
│   ├── otx-publisher.service     # Runs publisher once
│   └── otx-publisher.timer       # Triggers publisher every 6h
│
└── .gitignore
```

---

## Topology

```
Attackers → T-Pot honeypot
   → Elasticsearch (local on T-Pot)
   → [SSH tunnel over weird port] → Publisher VM
   → OTX Pulse (with dedupe, no duplicates)
```

---

## Why separate VM?

- Keeps honeypot clean, reduces risk of accidental changes on T-Pot.
- Easier patching, Python/venv, systemd timer, logging.
- Tunnel can be tightly controlled (no broad network access).

---

## 1) Prereqs (Publisher VM)

Ubuntu 24.04+ assumed.

```bash
sudo apt update
sudo apt install -y python3 python3-venv autossh jq moreutils ca-certificates
sudo mkdir -p /opt/otx-publisher
sudo chown -R $USER:$USER /opt/otx-publisher
```

Create venv + deps:

```bash
cd /opt/otx-publisher
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 2) Files to place

- `/opt/otx-publisher/publisher/otx_tpot_publisher.py` (main script)
- `/opt/otx-publisher/publisher/requirements.txt`
- `/opt/otx-publisher/publisher/README.md`
- `/etc/systemd/system/tpot-es-tunnel.service` (edit IP/port)
- `/etc/systemd/system/otx-publisher.service`
- `/etc/systemd/system/otx-publisher.timer`

Lock down secrets:

```bash
chmod 600 /opt/otx-publisher/config.json
```

---

## 3) SSH tunnel (Publisher VM → T-Pot)

Edit `systemd/tpot-es-tunnel.service`:

- Replace `IP` with your T-Pot public IP
- Replace `-p 64298` with your T-Pot SSH port (T-Pot defaults to a non-22 port)
- Ensure T-Pot allows SSH key auth for the chosen user

Enable tunnel:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service
```

Check:

```bash
ss -ltnp | grep 64298
curl -s http://127.0.0.1:64298/_cluster/health | jq .status   # expect "green" or "yellow"
```

---

## 4) Configure the publisher

Edit `/opt/otx-publisher/config.json`:

```json
{
  "otx_api_key": "YOUR-OTX-API-KEY",
  "elasticsearch": { "host": "http://127.0.0.1:64298" },
  "indices": ["logstash-*"],
  "time_window_hours": 24,
  "min_event_count": 3,
  "tlp": "green"
}
```

---

## 5) First run (manual)

```bash
source /opt/otx-publisher/venv/bin/activate

# Dry run (collect only)
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --dry-run --config /opt/otx-publisher/config.json

# Real run (publishes + writes state.json)
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json

# Second run should SKIP if nothing changed
python /opt/otx-publisher/publisher/otx_tpot_publisher.py --config /opt/otx-publisher/config.json
```

State file:

```bash
jq . /opt/otx-publisher/state.json
```

Dedup works by fingerprinting all indicators (sorted), so identical sets don’t re-publish.

---

## 6) Automate with systemd timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now otx-publisher.timer
systemctl list-timers | grep otx-publisher
```

Runs every 6h (`OnCalendar=*-*-* 00/6:17:00`) with a small randomized delay.  
The service uses `flock` so runs don’t overlap.

Manual triggers:

```bash
sudo systemctl start otx-publisher.service
```

Logs:

```bash
tail -n 100 /opt/otx-publisher/run.log
journalctl -u otx-publisher --since "2h" --no-pager
```

---

## 7) Troubleshooting

- **Tunnel down:**
  ```bash
  systemctl status tpot-es-tunnel --no-pager
  curl -s http://127.0.0.1:64298/_cluster/health | jq .status
  ```

- **OTX auth:**
  - Wrong API key → check `config.json`
  - Outbound blocked → allow HTTPS to `otx.alienvault.com`

- **No data:**
  - Indices mismatch → run:
    ```bash
    curl -s http://127.0.0.1:64298/_cat/indices?h=index | sort
    ```
  - Adjust `min_event_count` lower if too strict.

- **Force publish despite dedupe:**
  ```bash
  python otx_tpot_publisher.py --config config.json --force
  ```

- **Reset dedupe (will re-publish same set):**
  ```bash
  rm -f /opt/otx-publisher/state.json
  ```

---

## 8) Safety notes

- Publisher VM is separate from T-Pot (good opsec).
- Outbound on publisher can be tighter (only OTX + SSH to T-Pot).
- No PII: we only export IOCs (IPs/URLs/hashes), not raw commands or creds.
- Use `tlp: green` for public; otherwise set `"public": false`.

---

## 9) What you should see

When new IOCs exist:

```
INFO - Published pulse: Honeypot Data – Cowrie/T-Pot (<host>) – last 24h (id=...)
```

When unchanged:

```
INFO - Indicators unchanged since last publish (fingerprint match) — skipping.
```

That’s it. Clean, repeatable, and no OTX duplicates.
