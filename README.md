# T-POT → OTX PUBLISHER (and Cisco ASA mode)

Written in my voice — concise, filthy-honest ops doc with everything you need. No fluff. Drop this straight into `README.md` in the repo.

## Summary — what this is

This is a lightweight, off-box IOC publisher that turns honeypot and firewall log noise into tidy AlienVault OTX Pulses. It sits on a small “publisher” VM, talks to Elasticsearch running on the sensor side over a persistent SSH tunnel (autossh), scrubs and deduplicates indicators, classifies and tags them, and publishes clean pulses on a schedule. It remembers what it sent and won’t spam OTX.

Two modes:

* T-Pot mode — full honeypot publisher: IPs, URLs, SHA256 hashes from Cowrie / Suricata / Dionaea / etc. Good for forensic/telemetry pulses.
* Cisco ASA mode — lean IPs-only publisher: attacker IPs from ASA logs. Fast, short windows (hourly by default) for watchlists.

## Repo layout

```
publisher/
  otx_tpot_publisher.py           # full honeypot publisher (IPs, URLs, hashes)
  otx_ciscoasa_ips_only.py        # ASA IPs-only publisher (short windows)
  config.example.json             # T-Pot config template (sanitised)
  config.ciscoasa.example.json    # ASA config template (sanitised)
  requirements.txt                # pip deps

systemd/
  tpot-es-tunnel.service          # autossh persistent ES tunnel unit
  otx-publisher.service           # oneshot T-Pot run unit
  otx-publisher.timer             # schedule for T-Pot
  otx-ciscoasa.service            # oneshot ASA run unit
  otx-ciscoasa.timer              # schedule for ASA
```

## Topline architecture

Attackers → T-Pot/ASA → Elasticsearch (on sensor) → [persistent SSH tunnel] → Publisher VM → OTX Pulse

## Quick prerequisites (publisher VM)

* Ubuntu 22.04 or 24.04 (or equivalent Debian-based)
* python3 + venv, autossh, jq, git, ca-certificates
* least-privilege service user if you care about hygiene

Bootstrap commands (copy/paste)

```bash
sudo apt update
sudo apt install -y python3 python3-venv autossh jq ca-certificates git
sudo mkdir -p /opt/otx-publisher && cd /opt/otx-publisher
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r publisher/requirements.txt
```

## Config — copy and lock

Do this before anything else:

```bash
cp publisher/config.example.json config.json
chmod 600 config.json
cp publisher/config.ciscoasa.example.json config.ciscoasa.json
chmod 600 config.ciscoasa.json
```

Add `config.json`, `config.ciscoasa.json`, and `state.json` to `.gitignore`. Don’t be an idiot and commit keys.

## Key config options you will touch

* `otx_api_key`: your OTX API key (required)
* `elasticsearch.host`: `http://127.0.0.1:64298` (the tunnel endpoint)
* `indices`: e.g. `["logstash-*"]`
* `pulse.name_prefix`: human prefix for pulses
* `pulse.time_window_hours`: default 24 (T-Pot), 1 (ASA)
* `pulse.min_event_count`: suppress noise (default 3 for T-Pot, 1 for ASA)
* `pulse.exclude_private_ips`: true by default
* `publish.min_interval_minutes`: cooldown between identical pulses
* `limits.max_indicators`: cap pulse size to avoid OTX rejections
* `log_path`, `state_path`: filesystem locations for logs and state

Example (sanitised) config snippet — T-Pot

```json
{
  "otx_api_key": "REPLACE_ME",
  "elasticsearch": { "host": "http://127.0.0.1:64298" },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "Honeypot Data – Cowrie/T-Pot",
    "time_window_hours": 24,
    "min_event_count": 3,
    "exclude_private_ips": true,
    "tlp": "green"
  },
  "limits": { "max_indicators": 2000 },
  "publish": { "min_interval_minutes": 1440 },
  "log_path": "/opt/otx-publisher/run.log",
  "state_path": "/opt/otx-publisher/state.json"
}
```

Example (sanitised) config — Cisco ASA

```json
{
  "otx_api_key": "REPLACE_ME",
  "elasticsearch": { "host": "http://127.0.0.1:64298" },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "CiscoASA → Attacker IPs",
    "time_window_hours": 1,
    "min_event_count": 1,
    "exclude_private_ips": true,
    "tlp": "GREEN",
    "location_label": "Australia",
    "payload_snip": null
  },
  "log_path": "/opt/otx-publisher/ciscoasa.run.log"
}
```

## Tunnel setup (T-Pot ES → Publisher)

This repo includes an example systemd unit for a persistent autossh tunnel. The tunnel exposes the remote ES at `127.0.0.1:64298` on the publisher VM, which the scripts call.

Example `tpot-es-tunnel.service` (adjust for your environment):

```ini
[Unit]
Description=autossh tunnel to T-Pot Elasticsearch
After=network-online.target
Wants=network-online.target

[Service]
User=root
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M 0 -N -o "ServerAliveInterval 30" -o "ServerAliveCountMax 3" -i /root/.ssh/tpot_publisher_id -L 64298:127.0.0.1:9200 tpotuser@tpot.example.com
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Install and enable the tunnel:

```bash
sudo cp systemd/tpot-es-tunnel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tpot-es-tunnel.service
# sanity check
curl -s http://127.0.0.1:64298/_cluster/health | jq .status
```

## Run manually — dry-run first

Always test with `--dry-run` so you can see what would be published without hitting OTX.

T-Pot:

```bash
source /opt/otx-publisher/venv/bin/activate
python publisher/otx_tpot_publisher.py --dry-run --config config.json
python publisher/otx_tpot_publisher.py --config config.json
```

Cisco ASA:

```bash
source /opt/otx-publisher/venv/bin/activate
python publisher/otx_ciscoasa_ips_only.py --dry-run --config config.ciscoasa.json
python publisher/otx_ciscoasa_ips_only.py --config config.ciscoasa.json
```

## Systemd automation

Copy the units and enable the timers. Defaults are conservative: daily T-Pot and hourly ASA (adjust as you like).

T-Pot schedule:

```bash
sudo cp systemd/otx-publisher.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-publisher.timer
```

ASA schedule:

```bash
sudo cp systemd/otx-ciscoasa.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now otx-ciscoasa.timer
```

View next timers:

```bash
systemctl list-timers --all | grep -i otx
```

## What gets sent — behavior

T-Pot mode:

* Indicators: IPv4, IPv6, URLs, SHA256 file hashes.
* Tags: sensor/type from `type.keyword` (cowrie, suricata, dionaea, ciscoasa, etc.).
* Roles for OTX UI sanity:

  * URLs → `malware_hosting`
  * IPs with cowrie/honeypot tags → `scanning_host`
  * other IPs → `unknown`
  * file hashes → no role (OTX already handles hashes)
* Self-URL safety: URLs pointing to localhost / your detected IPs are dropped.

Cisco ASA mode:

* Indicators: IPs only (no URLs, no hashes).
* Short windows (default 1 hour) to produce watchlist-friendly pulses.
* Multiple field matching (`type`, `event.dataset`, `program`, `service.name`) to catch different ASA ingestion pipelines.

## Safety, dedupe, cooldown

* `publish.min_interval_minutes` + pulse fingerprinting avoids duplicate / repeated pulses.
* `min_event_count` avoids pushing singletons — set higher for noisy sensors.
* `exclude_private_ips: true` prevents leaking RFC1918 ranges.
* `limits.max_indicators` protects you from OTX size limits.

## Logs, state & where to poke when it sulks

* Publisher logs:

  * `/opt/otx-publisher/run.log`
  * `/opt/otx-publisher/ciscoasa.run.log`
* State:

  * `/opt/otx-publisher/state.json`
* Journal:

  * `journalctl -u otx-publisher.service --since "12h"`
  * `journalctl -u otx-ciscoasa.service --since "12h"`
* Tunnel:

  * `systemctl status tpot-es-tunnel`
  * `curl http://127.0.0.1:64298/_cluster/health`

## Common fixes

* Tunnel failed: inspect systemd unit, SSH key, and route/port mapping.
* ES unreachable: confirm tunnel endpoint, `curl` the ES health.
* OTX auth errors: `--dry-run` will show auth failures; rotate key if needed.
* Pulses too big: lower `limits.max_indicators` or chunk by indicator type.
* Force republish: `rm -f /opt/otx-publisher/state.json` then re-run.

## Tuning advice (practical)

* Want everything? `pulse.min_event_count = 1` and `limits.max_indicators = 0`. You will feast on noise and likely hit OTX limits.
* Want signal: `pulse.min_event_count = 3–5` and reasonable `limits.max_indicators` (e.g., 500–2000).
* Chunk: run IP-only hourly and URLs/hashes daily.
* If OTX rejects pulses, throttle / paginate / split.

## Operational hygiene

* Never commit `config.json`, keys, or `state.json`. Use `.gitignore`.
* Use a dedicated service account for the publisher processes if you care about least privilege.
* Choose TLP intentionally — green means public distribution; amber/red is internal only.
* Scrub `payload_snip` fields: do not include PII, credentials, full command output, or anything that might identify a private network asset.

## Extending to more devices / honeypots / appliances (future roadmap)

We’re expanding this into a framework, not a one-off hack. Goals:

* One publisher per major sensor family: cowrie, suricata, dionaea, ciscoasa, fortigate, paloalto, checkpoint, commercial firewall logs, VPN concentrators, IDS signatures, ICS honeypots, etc.
* One adapter module per log shape. The publisher core will:

  * Normalize events to a canonical shape (timestamp, src_ip, dst_ip, url, hash, sensor, raw_snip).
  * Apply role/tag heuristics per sensor type.
  * Enforce global filters (exclude private, exclude known-probably-benign ranges, noise suppression).
  * Fingerprint & dedupe pulses across adapters.
* Per-device tuning: each adapter will have defaults for `time_window_hours`, `min_event_count`, and tagging that match how that sensor behaves.
* Multi-target outputs: OTX is first-class, but we’ll add optional sinks: MISP, SIEM, Slack/Teams alerts, and internal watchlists.
* Versioned adapters so we can safely add new sensors without touching core logic.

## Naming conventions & organization

* Repos: `otx-publisher` remains core. Adapters live under `publisher/adapters/<sensor>`.
* Configs: `config.<adapter>.example.json` and per-deploy `config.<adapter>.json` (chmod 600).
* Systemd: `otx-<adapter>.service` & `otx-<adapter>.timer` for per-adapter scheduling.
* State: `state.<adapter>.json` so multiple adapters don’t stomp each other.

## Testing approach — how to validate

* Unit tests for normalization & fingerprinting (python `pytest`).
* Integration tests:

  * Synthetic ES index with sample docs for each adapter.
  * `--dry-run` and compare expected indicators to produced output.
* Acceptance: run with `--dry-run`, spin up a disposable OTX test account, verify pulses appear as expected.
* CI: GitHub Actions that lint, run unit tests, and smoke `--dry-run` against sample ES fixtures.

## Operational checklist — staging → production

1. Provision publisher VM.
2. Generate SSH keypair for tunnel; install public key on sensor host.
3. Copy examples to `config.*.json`, fill values, `chmod 600`.
4. Create venv, install deps.
5. Deploy and enable autossh tunnel.
6. `curl http://127.0.0.1:64298/_cluster/health` and confirm `green`/`yellow`/`greenish`.
7. Run `--dry-run` for each adapter. Inspect logs.
8. Run real job for a single adapter and confirm pulse content in OTX.
9. Enable timers. Observe logs & OTX pulses for 48–72 hours.
10. Tune `min_event_count`, `limits.max_indicators`, and `publish.min_interval_minutes`.

## Pulse design guidance (how to write useful pulses)

* Keep pulse names consistent: `SensorName – Type – Region – Window` (e.g. `Cowrie – Scanners – AU – 24h`).
* Payload must be short: indicators, short context snippet, sensor & window timestamp.
* Tag sensors and roles consistently. Analysts will thank you.
* Include `location_label` sparingly; only when it adds useful context.

## OTX considerations & quotas

* OTX will throttle or reject very large pulses. Respect `limits.max_indicators`.
* Keep `publish.min_interval_minutes` sane to avoid resending identical content.
* If you plan to publish lots of indicators, consider an internal MISP/SIEM sink and only publish high-signal pulses to OTX.

## Security notes

* Lock down `config*.json` to mode 600.
* Tunnel keys: protect them, rotate if leaked.
* Run publisher as a restricted service account where sensible (not root).
* Sanitize `payload_snip` — never include creds or system-identifying info.

## FAQ

Q: Why separate ASA mode?
A: ASA logs are noisy and usually only contain source IPs of interest. Shipping only IP watchlists on a short cadence reduces noise and creates useful watchlists for firewall blocking/monitoring.

Q: Why a tunnel to ES vs pushing from the sensor?
A: Keeps the publisher off the sensor, prevents exposing cloud/API keys to sensor hosts, centralizes OTX credentials, and allows cross-sensor dedupe/fetching.

Q: How do we avoid publishing internal IPs?
A: `pulse.exclude_private_ips = true` by default and the publisher filters private ranges and known local endpoints.

Q: What happens if OTX rejects my pulse?
A: The publisher logs the error. Tune `limits.max_indicators` or split payloads into multiple pulses by indicator type or time window.

## Appendices

A. Example systemd unit (tpot-es-tunnel.service) — see the `systemd/` directory for copies. Adjust user, key path, remote endpoint, and local port.

B. Example configs — `publisher/config.example.json` and `publisher/config.ciscoasa.example.json`. Copy, fill, chmod 600.

C. Troubleshooting commands

* Check tunnel: `systemctl status tpot-es-tunnel`
* ES health: `curl http://127.0.0.1:64298/_cluster/health | jq .`
* Dry-run logs: `tail -n 200 /opt/otx-publisher/run.log`
* Force republish: `rm -f /opt/otx-publisher/state.json && python publisher/otx_tpot_publisher.py --config config.json`
* Check timers: `systemctl list-timers --all | grep -i otx`

D. Glossary

* Publisher: off-box service that ingests ES data and publishes to OTX.
* Adapter: sensor-specific normalization/extraction module.
* Pulse: an OTX object containing indicators & metadata.
* Fingerprint: deterministic hash of pulse content to avoid duplicates.

## Final notes — practical, no-bullshit

This is a framework. Right now it's two adapters: T-Pot (general honeypot) and Cisco ASA (IP watchlists). We’re expanding that to support any sensor or appliance you care about. For every new honeypot, appliance, cloud service, or enterprise firewall, we make a small adapter that learns how that data looks, normalises into the publisher shape, and publishes with sensible defaults for windowing and noise suppression.

If you want, I will:

* produce cleaned `config.json` and `config.ciscoasa.json` examples (sanitised);
* paste the systemd units and timer files for publisher services (ready to copy);
* produce adapter scaffolding for a new sensor (FortiGate / Palo Alto / MISP export) with example queries and a test ES fixture;
* or tighten the Python docstrings + argparse defaults and add a basic `pytest` harness for the normalization logic.

Tell me which of those next steps you want and I’ll dump them ready to copy-paste. — Robert
