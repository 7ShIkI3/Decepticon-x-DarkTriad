# Phisher workflow

The Phisher agent's loop, scope rules, and OPSEC posture. Loaded
verbatim into every Phisher iteration before the per-technique skills.

## Phase progression

```
PRETEXT          (skills/standard/phisher/pretext-engineering/)
   ↓ (validated pretext, target list confirmed)
DECONFLICTION    (skills/standard/phisher/lure-deconfliction/)  ← MANDATORY
   ↓ (blue-team ack received)
INFRASTRUCTURE   (skills/standard/phisher/lookalike-domain/)
   ↓ (domain + DNS + TLS ready)
CAMPAIGN BUILD   (skills/standard/phisher/gophish-campaign/  OR
                  skills/standard/phisher/evilginx2-proxy/)
   ↓ (campaign object created in gophish / phishlet loaded in evilginx2)
SMOKE TEST       (one test user from operator's own account)
   ↓ (capture confirmed)
LIVE SEND        (real target population, throttled per OPSEC level)
   ↓ (first capture event)
HANDOFF          (return JSON to orchestrator)
```

## RoE entries the Phisher consults

Every iteration reads `plan/roe.json`:

- `in_scope` / `out_of_scope` for the target population. A target
  email belonging to an out-of-scope user is RoE-refused before send.
- `permitted_actions: phishing_internal_employees` for pretexting as
  internal IT / HR / finance.
- `permitted_actions: oauth_device_code_phishing` for M365/Workspace
  OAuth device-code attacks.
- `escalation_contacts.blue_team_contact` — REQUIRED for the
  lure-deconfliction handshake. If the field is missing or the
  contact is unreachable, the Phisher pauses the objective and
  asks the operator via `ask_user_question`.

## Knowledge graph nodes

Phisher writes the following node types:

- `Campaign` — gophish campaign id + metadata.
- `Template` — pretext template (subject, body hash).
- `LandingPage` — captured-credential landing-page URL.
- `Domain` — lookalike domain + TLS cert info.
- `User` — every target user; sourced from the customer's user list.
- `Credential` — captured credential, linked to User via OBTAINED_VIA.

## OPSEC posture mapping

| posture   | send rate            | jitter            | lure type                  |
|-----------|----------------------|-------------------|----------------------------|
| stealth   | ≤2 emails / hour     | 5-30 min          | low-urgency, single user   |
| standard  | ≤20 emails / hour    | 30-90 sec         | typical phish patterns     |
| loud      | full send            | none              | aggressive (legal-review)  |
