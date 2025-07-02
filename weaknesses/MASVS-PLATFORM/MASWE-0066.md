---
title: Insecure Intents
id: MASWE-0066
alias: insecure-intents
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-PLATFORM-1, MASVS-STORAGE-2]

refs:
- https://support.google.com/faqs/answer/9267555?hl=en
- https://developer.android.com/privacy-and-security/security-tips#intents
- https://developer.android.com/topic/security/risks/intent-redirection
- https://developer.android.com/topic/security/risks/implicit-intent-hijacking
- https://developer.android.com/topic/security/risks/pending-intent
draft:
  description: e.g. calling startActivity, startService, sendBroadcast, or setResult
    on untrusted Intents without validating or sanitizing these Intents. Using an
    implicit intent to start a service is a security hazard, because you can't be
    certain what service will respond to the intent and the user can't see which service
    starts. e.g. mutable pending intents (not using FLAG_IMMUTABLE), replaying pending
    intents (not using FLAG_ONE_SHOT)
  topics:
  - Insecure Intent Redirection
  - Insecure Implicit Intents
  - Insecure Pending Intents (Mutable, Replaying)
status: placeholder

---

