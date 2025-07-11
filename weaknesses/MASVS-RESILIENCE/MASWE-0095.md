---
title: Code That Disables Security Controls Not Removed
id: MASWE-0095
alias: code-disables-security
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-CODE-4]
  masvs-v2: [MASVS-RESILIENCE-3]
  cwe: [489, 912]

draft:
  description: The app contains leftover debugging logic or test code (CWE-489) that was not removed before release, which can disable critical protections like TLS certificate validation. It may also include hidden settings or functions that allow bypassing security controls (CWE-912), making the app vulnerable to manipulation.
  topics:
  - backdoors
  - hidden settings to e.g. disable TLS verification
status: draft

---

