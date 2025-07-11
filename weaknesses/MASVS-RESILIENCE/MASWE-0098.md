---
title: App Virtualization Environment Detection Not Implemented
id: MASWE-0098
alias: app-virtualization-detection
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v2: [MASVS-RESILIENCE-1]
  cwe: [693]

draft:
  description: The app's code doesn’t implement effective techniques to detect if it is running in a virtualized environment (CWE-693), e.g. checking for known virtualization software or anomalies in the environment.
  topics:
  - detection in place for "cloned" apps or virtualized environments
  - Effectiveness Assessment (e.g. bypassing the detection)
status: placeholder

---

