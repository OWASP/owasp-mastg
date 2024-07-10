---
title: Debuggable Flag Not Disabled
id: MASWE-0067
alias: debuggable-flag
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-2]
  masvs-v2: [MASVS-PLATFORM-1, MASVS-RESILIENCE-4]

refs:
- https://developer.android.com/topic/security/risks/android-debuggable
- https://developer.android.com/guide/topics/manifest/application-element
draft:
  description: not setting android:debuggable="false" on Android or get-task-allow="true"
    in the entitlements file on iOS
  topics: null
status: draft

---

