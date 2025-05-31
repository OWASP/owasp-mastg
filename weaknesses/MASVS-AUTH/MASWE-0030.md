---
title: Re-Authenticates Not Triggered On Contextual State Changes
id: MASWE-0030
alias: reauth-state-changes
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-AUTH-3]
  cwe: [285, 287]

refs:
- https://developers.google.com/identity/sign-in/android/disconnect
draft:
  description: Re-authentication means forcing a new login after e.g. timeout, changing
    state from running in the background to running in the foreground, remarkable
    changes in a user's location, profile, etc.
  topics:
  - timeout
  - changing state from running in the background to running in the foreground
  - (IEEE) remarkable changes in a user's location
  - ASVS V3.3 Session Logout and Timeout Requirements
  - NIST 800-63
  - etc.
status: placeholder

---

