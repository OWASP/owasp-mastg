---
title: WebViews Allows Access to Local Resources
id: MASWE-0069
alias: webviews-local-resources
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-PLATFORM-6]
  masvs-v2: [MASVS-PLATFORM-2, MASVS-STORAGE-2]

draft:
  description: use of setAllowFileAccessFromFileURLs. Mitigations include setAllowFileAccess(false),
    setAllowContentAccess(false)
  topics:
  - universal file access
  - restrict content access
  - handlers e.g. file:// vs content://
status: draft

---

