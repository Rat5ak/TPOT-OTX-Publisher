## T-Pot → OTX Publisher

**Clean threat intel from real honeypots**

A small, opinionated off-box publisher that turns **T-Pot honeypot data** and **Cisco ASA logs** into **clean, structured AlienVault OTX pulses**.

Runs on a separate VM, pulls from Elasticsearch over an SSH tunnel, dedupes what it’s already sent, enriches the rest, and publishes **rolling monthly pulses** that don’t spam OTX.

Built for people who want:

• copy / paste deploys
• real attacker data (not scraped feeds)
• pulses that actually make sense
• intel you can explain to humans

---

## What this is (and isn’t)

**This is:**
• a threat-intel publishing pipeline
• multiple focused pulse streams
• designed for automation + reporting

**This is not:**
• a SIEM
• a dashboard
• a single “everything” feed

Each attack surface gets its **own pulse on purpose**.

---

## Pulse streams (all of them)

Each publisher maintains **one rolling monthly pulse**.
Same pulse ID all month. New indicators appended safely.

### 1) T-Pot aggregate (everything)

**Honeypot Data – T-Pot – Location – Month**

• IPs, URLs, SHA256
• All enabled T-Pot sensors combined
• Wide “what did this box see?” view

---

### 2) SSH & Telnet brute-force

**SSH & Telnet → Attacker IPs – Location – Month**

• IPv4 attacker IPs
• Top usernames & passwords (masked)
• SSH client strings
• Role: `bruteforce`

Clean credential-attack intel.

---

### 3) Cisco ASA attacker IPs

**CiscoASA → Attacker IPs – Location – Month**

• IPv4 attacker IPs
• Optional cleaned payload snippets
• Conservative, fast, watchlist-friendly

---

### 4) Dionaea attacker IPs

**Dionaea → Attacker IPs – Location – Month**

• IPv4 attacker IPs
• Exploit & worm-centric traffic
• Kept separate from SSH / web noise

---

### 5) Suricata alert source IPs

**Suricata → Attacker IPs – Location – Month**

• IPv4 source IPs tied to IDS alerts
• Higher-confidence signal
• Great for correlation & tuning

---

### 6) ADBHoney (Android attacks)

**ADBHoney → Attacker IPs – Location – Month**

• IPv4 attacker IPs
• FileHash-SHA256 Android droppers
• Command previews (wget / curl / pm install)

Live botnet and loader infrastructure, deduped properly.

---

## Why multiple pulses

Because consumers are different.

Separating pulses by **sensor + intent** gives you:

• cleaner subscriptions
• better automation
• less noise
• easier reporting
• better AI summaries later

This is architecture, not over-engineering.

---

## How it flows

```
Attackers
  ↓
T-Pot / Cisco ASA
  ↓
Elasticsearch (sensor side)
  ↓  autossh tunnel
Publisher VM
  ↓
AlienVault OTX
```

• OTX keys never touch the sensor
• Elasticsearch is never exposed publicly

---

## State & dedupe

Pulse IDs are tracked in `pulses.json` using keys like:

```
ssh_telnet_2025-12
suricata_2025-12
adbhoney_2025-12
```

This allows safe restarts, clean month boundaries, and zero duplicate pulses.

---

## Running it

Always dry-run first:

```
source /opt/otx-publisher/venv/bin/activate

python otx_ssh_rolling.py --dry-run --config config.ssh.json
python otx_ciscoasa_rolling.py --dry-run --config config.ciscoasa.json
python otx_adbhoney_rolling.py --dry-run --config config.adb.json --window-hours 199
```

Remove `--dry-run` when happy.

---

## Scheduling

Designed for **systemd oneshot + timers**.

Typical cadence:

• SSH / ASA / Suricata / Dionaea → hourly
• ADBHoney → daily or multi-day rolling
• T-Pot aggregate → daily or monthly

Set it and forget it.

---

## Why this exists

• Real honeypot data
• No indicator spam
• Sensor-specific context
• Rolling monthly history
• Human-readable descriptions
• AI-ready outputs

This isn’t a feed generator.
It’s a **curated threat-intel publisher**.