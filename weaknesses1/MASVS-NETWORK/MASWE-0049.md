---
title: Proved Networking APIs Not used
id: MASWE-0049
alias: no-proved-net-apis
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-NETWORK-6]
  masvs-v2: [MASVS-NETWORK-1, MASVS-CODE-3]

draft:
  description: AKA don't roll your own network security. For example, platform-provided
    authentication APIs or openssl are designed and implemented by experts who have
    deep knowledge of the platform's security features and considerations. These APIs
    often incorporate security best practices and are regularly updated to address
    new threats and vulnerabilities.
  topics:
  - Platform-provided Networking APIs Not used
  note: maybe merge with the next one or find a better separation
status: draft

---

