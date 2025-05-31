---
title: App Integrity Not Verified
id: MASWE-0104
alias: app-integrity
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-CODE-1]
  masvs-v2: [MASVS-RESILIENCE-2]

refs:
- https://developer.apple.com/documentation/xcode/using-the-latest-code-signature-format
draft:
  description: Potentially relevant for apps in alternative app stores (not Google
    PlayStore or Apple AppStore). Also, e.g. Android V1 signing scheme only or iOS
    CodeDirectory v less than 20400. Also, e.g. App Signature or Binaries, native
    libraries including e.g. AppAttest
  topics:
  - App Signature or Binaries check on runtime
  - native libraries including e.g. AppAttest
  - Invalid App Signing Certificate
  - Latest Available Signing Scheme Not Used - Android V1 signing scheme only
  - Latest Available Signing Scheme Not Used - iOS CodeDirectory v less than 20400
  - detection in place
  - Effectiveness Assessment (e.g. bypassing the detection)
  note: consider Static Code Modification? / Repackaging Detection Not Implemented
status: placeholder

---

