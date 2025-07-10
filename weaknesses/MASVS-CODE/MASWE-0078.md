---
title: Latest Platform Version Not Targeted
id: MASWE-0078
alias: target-latest-platform-version
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CODE-1]
  cwe: [693, 1357]

draft:
  description: The app does not target the latest platform version (e.g., via targetSdkVersion on Android or by using an older Xcode/toolchain), and as a result, misses out on the most recent platform-enforced security protections (e.g., scoped storage, permission auto-reset, modern TLS handling) (CWE-693 and CWE-1357).
  topics:
  - targetSDK on Android
  - XCode version on iOS
status: placeholder

---

