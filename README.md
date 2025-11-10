# TPOT-OTX-Publisher

Pushes indicators from a **T-Pot honeypot stack** into **AlienVault OTX** as rolling “intelligence” pulses.

The idea is:

- T-Pot writes everything into **Elasticsearch**.
- These scripts query ES for interesting attacker activity.
- New **IPv4** and **file hash** indicators are de-duplicated and pushed into **monthly OTX pulses**.

Currently supports:

- **ADBHoney** (Android ADB honeypot)
- **SSH honeypot** (e.g. Cowrie / Heralding via T-Pot)
- **Cisco ASA** logs (via T-Pot / Logstash)

> ⚠️ The repository is actively evolving and a lot of the newer logic (role classification, hash enrichment, etc.) is AI-assisted. Expect some rough edges.

---

## 1. Features

### 1.1 General

- Pulls data directly from your **T-Pot Elasticsearch**.
- Builds / updates **monthly OTX pulses**, e.g.:

  - `ADBHoney → Attacker IPs – Australia – November 2025`
  - `SSH → Attacker IPs – Australia – November 2025`
  - `CiscoASA → Attacker IPs – Australia – November 2025`

- **De-duplicates** indicators so the monthly pulse just grows as new stuff appears.
- Supports **hourly (or custom) lookback windows**, controlled via config.
- Skips your own **self IPs**, so you don’t dox your own box.

### 1.2 ADBHoney (otx_adbhoney_rolling.py)

The ADB script is currently the fanciest:

- Detects attacker **IPv4s** via ADBHoney events (with fallback runtime field tricks if ES field mapping is annoying).
- Pulls **Suricata alert categories** for each IP (if you run Suricata in T-Pot).
- Inspects **ADB commands** used by the attacker to:
  - Count hits (`adb_cmd_hits`)
  - Grab a **sample command preview** for the OTX description.
- Builds **roles** for each IP:
  - `scanning_host`
  - `malware_hosting`
  - `malware_distribution`
  - `command_and_control`
  - (and aliases like `c2` → `command_and_control`)
- Extracts **file hashes** (SHA-256) from `outfile` fields like:  
  `dl/<sha256>.raw`
- Enriches hashes with:
  - `outfile`
  - top source IPs and country codes
  - last seen timestamp
  - short command preview (`cmds=[...]`)
- Uses a single **rolling monthly pulse** to publish:
  - IPv4 indicators (`type="IPv4"`)
  - File hash indicators (`type="FileHash-SHA256"`)

---

## 2. Files / Scripts (high-level)

> File names here are intentionally high-level so the README stays valid even if you re-organise a bit.

- **otx_adbhoney_rolling.py**  
  Main ADBHoney → OTX publisher. Handles:
  - ES queries
  - attacker IP aggregation
  - hash extraction via `outfile`
  - role classification
  - OTX pulse creation / updates

- **SSH publisher script (TBD name)**  
  Similar idea but for SSH honeypot logs (Cowrie / Heralding).  
  Typically creates / updates a monthly pulse like:
  `SSH → Attacker IPs – <location> – <month year>`.

- **CiscoASA publisher script (TBD name)**  
  Same pattern for Cisco ASA logs.

- **Helper scripts**  
  Some extra helpers live in the repo for debugging and one-off checks, for example:
  - `otx_adb_hash_docdump.py`
  - `otx_adb_hash_lookup.py`
  - `otx_adb_update_test.py`

These helpers are **optional** and mostly there so you can poke at ES / OTX behaviour without touching the main monthly publisher.

---

## 3. Requirements

- **Python 3.x** (3.9+ recommended)
- T-Pot environment (or at least an ES instance populated with:
  - ADBHoney logs
  - SSH honeypot logs
  - Cisco ASA logs
- An **OTX API key** from your AlienVault OTX account.

If you haven’t already, create a venv and install dependencies:

```bash
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt   # if present
# or at minimum:
pip install requests
````

---

## 4. Configuration

Each publisher script expects a JSON config file. The ADBHoney script uses something like:

`/opt/otx-publisher/config.adb.json`

Example:

```json
{
  "otx_api_key": "YOUR_OTX_API_KEY_HERE",
  "elasticsearch": {
    "host": "http://127.0.0.1:64298",
    "timeout": 15
  },
  "indices": ["logstash-*"],
  "self_ips": [
    "172.105.186.117",
    "194.195.124.195"
  ],
  "pulse": {
    "time_window_hours": 199,
    "min_event_count": 1,
    "exclude_private_ips": true,
    "tlp": "green",
    "name_prefix": "ADBHoney → Attacker IPs",
    "location_label": "Australia",
    "tags": ["tpot","honeypot","adb","android","botnet","scanner","dropper"]
  },
  "log_path": "/var/log/otx_adbhoney_rolling.log"
}
```

Key bits:

* `otx_api_key` – your API key for OTX.
* `elasticsearch.host` – your T-Pot ES endpoint.
* `indices` – typically `"logstash-*"` for T-Pot.
* `self_ips` – IPs you never want to publish (your own honeypot / infra).
* `pulse.time_window_hours` – how far back each run looks in ES.
* `pulse.name_prefix` + `location_label` – used to build the monthly pulse name.

Other publisher scripts follow the **same pattern** but may use different default `name_prefix` (e.g. `SSH → Attacker IPs`, `CiscoASA → Attacker IPs`, etc.).

---

## 5. Running the ADBHoney publisher

Basic dry-run (does **not** actually create or patch pulses, only logs what it *would* do):

```bash
cd /opt/otx-publisher
source venv/bin/activate

python3 otx_adbhoney_rolling.py \
  --config /opt/otx-publisher/config.adb.json \
  --dry-run
```

Real run:

```bash
python3 otx_adbhoney_rolling.py \
  --config /opt/otx-publisher/config.adb.json
```

You can override the lookback window on the CLI:

```bash
python3 otx_adbhoney_rolling.py \
  --config /opt/otx-publisher/config.adb.json \
  --window-hours 24
```

### Cron example (hourly)

```bash
0 * * * * cd /opt/otx-publisher && /usr/bin/python3 otx_adbhoney_rolling.py --config /opt/otx-publisher/config.adb.json >> /var/log/otx_adbhoney_rolling.cron.log 2>&1
```

Similar cron entries can be created for your SSH / CiscoASA publisher scripts once you’re happy with them.

---

## 6. How the monthly pulses work

Each run:

1. Looks back `time_window_hours` in Elasticsearch.
2. Collects:

   * ADB attacker IPs (with some Suricata + ADB command enrichment)
   * File hashes from `outfile` (e.g. `dl/<sha256>.raw`)
3. Builds indicator objects:

   * IPv4s:

     * `indicator = "<ip>"`
     * `type = "IPv4"`
     * `description` includes ports, country, alert categories, adb command preview, etc.
     * `role` is auto-classified (`scanning_host`, `malware_hosting`, etc.).
   * Hashes:

     * `indicator = "<sha256>"`
     * `type = "FileHash-SHA256"`
     * `description` includes `outfile`, `src_ips`, `cc`, `last_seen`, minimal command preview.
4. Computes a **monthly pulse name**, e.g.:
   `ADBHoney → Attacker IPs – Australia – November 2025`
5. If that monthly pulse doesn’t exist yet:

   * It’s **created** with all indicators seen in this window.
6. If the pulse already exists:

   * The script **GETs** the pulse,
   * De-dupes indicators by `(indicator, type)`,
   * **PATCHes** with only the new ones.

---

## 7. AI-assisted pieces

A lot of the newer logic in this repo was designed in conversation with an LLM (ChatGPT / GPT-5):

* Role classification (`scanning_host` vs `malware_hosting` vs `command_and_control`).
* The `collect_hash_indicators` function:

  * Outfile → SHA-256 extraction
  * Hash enrichment (`src_ips`, `cc`, `cmds=[…]`)
* Runtime Elasticsearch tricks (like `runtime_mappings` to recover IPs when field mappings are messy).
* Various ES queries to avoid losing any indicators while still being safe.

If you see weird heuristics like:

* `adb_cmd_hits`
* text-based role classification based on Suricata alert categories
* string-slicing of previews

…that’s all part of the AI-assisted tuning. Feel free to fork and harden any of this for your own environment.

---

## 8. Housekeeping / TODOs

Things you may want to do to keep the repo clean and consistent:

* [ ] Add / update **requirements.txt** to reflect current Python dependencies.
* [ ] Add example configs:

  * `config.adb.example.json`
  * `config.ssh.example.json`
  * `config.ciscoasa.example.json`
* [ ] Add a LICENSE file if you want others to use / modify this.
* [ ] Ensure script naming is consistent:

  * e.g. `otx_adbhoney_rolling.py`, `otx_ssh_rolling.py`, `otx_ciscoasa_rolling.py`.
* [ ] Document any **known limitations**, e.g.:

  * “Hash src_url is currently not available from our T-Pot ES mapping; only `outfile` is used.”

---

## 9. Disclaimer

This project is provided **as-is**. It’s meant for research / threat-intel enrichment from honeypots, not as a production-grade SIEM product.

You are responsible for:

* Ensuring you’re only sharing data you’re legally / contractually allowed to share.
* Not accidentally publishing your own infra / customer IPs (use `self_ips`!).
* Understanding what you push into OTX.

PRs, forks, and tweaks are very welcome.

```
