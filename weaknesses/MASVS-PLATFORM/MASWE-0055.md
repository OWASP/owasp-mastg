---
title: Sensitive Data Leaked via Screenshots
id: MASWE-0055
alias: data-leak-screenshots
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-9]
  masvs-v2: [MASVS-PLATFORM-3, MASVS-STORAGE-2]
  cwe: [200, 359]

refs:
- https://developer.android.com/about/versions/14/features/screenshot-detection
draft:
  description: no method is used to prevent specific content from being captured (e.g.
    via FLAG_SECURE on Android and Secure Text Entry on iOS)
  topics:
  - Screenshots Not Prevented (e.g. via DETECT_SCREEN_CAPTURE on Android)
  - Screenshots not deleted when backgrounding
  - Auto-Generated Screenshots
status: placeholder

---

