---
title: Insecure Use of UIActivity
id: MASWE-0060
alias: insecure-uiactivity
platform: [ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-PLATFORM-1, MASVS-STORAGE-2]
  cwe: [200, 285, 358]

draft:
  description: e.g. data (items) being shared, custom activities, excluded activity
    types. More examples include CWE-285 and CWE-200 for exposing UIActivity information to untrusted apps or actors. CWE-358 for possible bad activityViewController implemented in the UIActivity.
  topics:
  - data (items) being shared
  - custom activities
  - excluded activity types
status: draft

---

