# Wireless workflow

The WirelessOperator agent's loop. Loaded verbatim into every wireless
iteration before per-technique skills.

## Hardware mode (read FIRST)

```
plan/roe.json:machine_enforcement.wireless.mode
   │
   ├── "in_sandbox"  →  USB passthrough in compose,
   │                     monitor mode inside the Kali sandbox
   │
   ├── "dropbox"     →  remote box reachable over SSH,
   │                     ssh <dropbox> -- '<command>' for every Wi-Fi op
   │
   └── "none"        →  refuse the objective, return outcome=blocked
```

Confirm the mode on every iteration. The sandbox does NOT ship
monitor-mode capable adapters by default; treat any objective that
arrives in `mode=none` as a misrouting from the orchestrator.

## Phase progression

```
HARDWARE_CHECK    (verify mode + adapter + regulatory domain)
   ↓
RECON             (passive airodump-ng / kismet; build airspace map)
   ↓
TARGET_SELECT     (pick BSSID matching OPPLAN objective's scope)
   ↓
TECHNIQUE         (skill-specific: handshake capture, evil-twin,
                   deauth, WPS, BLE GATT enum, Zigbee Touchlink, ...)
   ↓
CRACK / CAPTURE   (hashcat / credential capture)
   ↓
HANDOFF           (JSON to orchestrator with evidence path)
```

## Scope rules — never violate

- NEVER target a BSSID not in `plan/roe.json:in_scope`. The RoE
  evaluator extracts BSSIDs from your bash commands; out-of-scope
  hits land in the audit log as REFUSED.
- NEVER use deauth attacks unless the RoE explicitly permits them
  (`permitted_actions: deauth_for_handshake_capture`). On `stealth`,
  prefer PMKID (no deauth needed).
- NEVER transmit on a regulatory band you're not authorized to use.
  Check `iw reg get` and `plan/roe.json:machine_enforcement.wireless.regulatory`
  before activating any TX-capable mode (hostapd, eaphammer, etc.).
- NEVER bring up an evil-twin AP on public airspace without explicit
  operator approval recorded as a `permitted_actions` entry.

## Knowledge graph nodes

WirelessOperator writes:

- `Network` — discovered SSID + BSSID + crypto.
- `Host` — connected client MAC.
- `Credential` — captured handshake / cracked PSK / EAP credential.
- `Finding` — WPS Pixie-Dust susceptibility, PMF disabled, etc.

## OPSEC posture mapping

| posture   | recon         | active                          | crack location          |
|-----------|---------------|---------------------------------|-------------------------|
| stealth   | passive only  | PMKID (no deauth)               | offline only            |
| standard  | active scans  | targeted deauth, PMKID          | offline                 |
| loud      | full scan     | broadcast deauth, evil-twin     | offline + online attempts |
