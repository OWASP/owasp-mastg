---
title: Tapjacking Attacks
id: MASWE-0056
alias: tapjacking-attacks
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-PLATFORM-9]
  masvs-v2: [MASVS-PLATFORM-3, MASVS-CODE-1]
  cwe: [1021]

refs:
- https://developer.android.com/topic/security/risks/tapjacking
draft:
  description: not using View.setFilterTouchesWhenObscured(true) or android:filterTouchesWhenObscured="true"
    in the AndroidManifest.xml or not ignoring touch events that have FLAG_WINDOW_IS_PARTIALLY_OBSCURED
    flag
  topics:
  - Full occlusion
  - Partial occlusion
status: placeholder

---

