here’s a clean commit message + tiny README tweaks (mainly the config example + a short “Indicator roles” note). everything else in your README looks mint.

## Commit message

```
feat(publisher): valid OTX roles + self-IP override; keep hashes; docs

- Add `_role_for()` so every indicator has a valid OTX role:
  * URL  -> malware_hosting
  * IPv4/IPv6 with {cowrie,honeytrap} tags -> scanning_host
  * other IPs -> unknown
- Do NOT set a role on file hashes (avoids OTX rejection).
- Keep URL/Hash indicators even when trimming by max_indicators.
- Add optional `pulse.local_ips` override and improve self-URL filtering.
- Update example config + README.
```

---

## README tweaks

### Replace the **Configuration** example with this

```json
{
  "otx_api_key": "PUT-YOUR-REAL-OTX-API-KEY-HERE",
  "elasticsearch": {
    "host": "http://127.0.0.1:64298",
    "timeout": 10
  },
  "indices": ["logstash-*"],
  "pulse": {
    "name_prefix": "Honeypot Data – T-Pot",
    "time_window_hours": 24,
    "min_event_count": 1,
    "exclude_private_ips": true,
    "tlp": "green",
    "include_sensor_in_title": true,
    "location_label": "LOCATION-HERE",
    "local_ips": ["YOUR-HONEYPOT-IP-HERE"]   // optional override; improves self-URL filter
  },
  "limits": { "max_indicators": 0 },          // 0 = no cap; if you add a cap, only IPs are trimmed
  "publish": { "min_interval_minutes": 1440 },
  "log_path": "/opt/otx-publisher/run.log",
  "state_path": "/opt/otx-publisher/state.json"
}
```

### Add this short subsection after “Advanced” (or wherever you like)

#### Indicator roles (what shows in OTX)

* `URL` → **malware\_hosting**
* `IPv4/IPv6` with `cowrie` or `honeytrap` sensor tags → **scanning\_host**
* other `IPv4/IPv6` → **unknown**
* **File hashes** → *no role set* (OTX accepts them best this way)

This keeps OTX happy and ensures all indicators (including hashes) get published.
