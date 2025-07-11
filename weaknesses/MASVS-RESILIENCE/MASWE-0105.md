---
title: Integrity of App Resources Not Verified
id: MASWE-0105
alias: app-resources-integrity
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-3]
  masvs-v2: [MASVS-RESILIENCE-2, MASVS-CODE-4]
  cwe: [693]

draft:
  description: The app's code doesn’t implement effective techniques to verify the integrity of its own resources (CWE-693).
  topics:
  - Sandbox Integrity
  - Integrity of downloaded resources
  - Integrity of dynamically loaded resources (e.g. via backup restore)
status: draft

---

