---
title: Unsafe Handling of Data from IPC
id: MASWE-0084
alias: unsafe-ipc-data
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-PLATFORM-2]
  masvs-v2: [MASVS-CODE-4, MASVS-PLATFORM-1]
  cwe: [20, 345, 349]

draft:
  description: e.g. received intents, broadcast receivers, URL validation, URL schemes,
    etc.
  topics:
  - The app does not validate or sanitize input received through inter-process communication channels (e.g., intents, content URIs, broadcast receivers), which may lead to injection or logic vulnerabilities when the data is used in sensitive operations (CWE-20).
  - The app assumes that data received from other apps via IPC is trustworthy, without verifying its authenticity or origin (CWE-345).
  - The app combines untrusted IPC data with trusted inputs or internal state, which may allow attackers to influence app behavior or corrupt logic flows (CWE-349).
status: placeholder

---

