---
title: Running on a recent Platform Version Not Ensured
id: MASWE-0077
alias: run-on-recent-platform-version
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CODE-1]
  cwe: [693, 1357]

draft:
  description: e.g. via minSdkVersion on Android and MinimumOSVersion on iOS. with
    this we Ensure services/components availability (MASVS-STORAGE-1), also the NSC/ATS
    availability - Android > 7.0 / iOS > 9.0 (MASVS-NETWORK-1) and WebView secure
    config (MASVS-PLATFORM-2).
  topics:
  - The app sets a low minimum OS version to support older devices, but still relies, implicitly or explicitly, on security features (e.g., runtime permissions, hardware-backed keystore, network security policies) that may not exist on those versions (CWE-693 and CWE-1357).
status: placeholder

---

