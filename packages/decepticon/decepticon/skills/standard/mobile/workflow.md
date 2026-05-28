# MobileOperator workflow

The Android / iOS app-attack agent's loop. Loaded verbatim into every
mobile iteration before per-platform skills.

## Phase progression

```
APP_ACQUISITION   (APK from APKPure / Play, IPA from TestFlight / IPA file)
   ↓
STATIC_TRIAGE     (apktool/jadx for Android; class-dump for iOS)
   ↓
DECIDE_DYNAMIC    (sufficient finding from static? -> skip to handoff)
   ↓
DYNAMIC_SETUP     (emulator boot / real-device attach; frida-server push)
   ↓
RUNTIME_HOOK      (SSL pin bypass, root/jailbreak detect bypass,
                   custom hooks for the objective)
   ↓
API_VALIDATION    (extracted secrets / endpoints validated against
                   the real backend if RoE permits)
   ↓
HANDOFF
```

## Scope rules

- NEVER target a real user's device. Only the engagement's emulator,
  the test device the customer provided, or your dedicated burner.
- NEVER push payloads to a device you don't have write authorization
  for (typically the customer's test device or your own emulator).
- NEVER extract live user data via the mobile API; abide by
  `plan/roe.json:data_handling.credential_retention_policy`.
- NEVER deploy a frida hook that drains telemetry to anywhere other
  than the engagement workspace.

## Platform skill tree

- `mobile/android/` — apktool / jadx / frida-android / SSL pin bypass /
  root detection bypass / exported component abuse / WebView attacks /
  Android Manifest audit
- `mobile/ios/` — class-dump / frida-ios / Keychain ACL bypass / URL
  scheme abuse

## Knowledge graph nodes

- `SourceFile` — APK / IPA path + format + signing info.
- `Credential` — hardcoded secrets / API keys extracted from the
  bundle.
- `URL` + `Entrypoint` — every backend URL the app contacts.
- `Finding` — exported component, SSL pin bypass, WebView JS bridge.

## OPSEC

Mobile testing is OPSEC-cheap because nothing leaves the test
device + your sandbox. The OPSEC-expensive moment is the
API_VALIDATION step that talks to the customer's production backend
— this hits the customer's WAF / SIEM. Respect the engagement's
`opsec_level` posture for that step:

- `stealth`: API validation throttled, 1 request / minute, from the
  device's normal user-agent.
- `standard`: typical mobile-API patterns.
- `loud`: full integration test, multiple concurrent sessions.
