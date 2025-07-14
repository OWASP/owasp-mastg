---
title: Debugging Symbols Not Removed
id: MASWE-0093
alias: debugging-symbols
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-CODE-3]
  masvs-v2: [MASVS-RESILIENCE-3]
  cwe: [497, 540]

draft:
  description: The app contains debugging symbols, which can be exploited by attackers to understand the app's behavior (CWE-497). The app's debugging symbols are considered sensitive information (CWE-540) and should not be present in production builds.
  topics:
  - debugging symbols not removed
status: placeholder

---

