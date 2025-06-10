---
title: Data Sent Unencrypted Over Encrypted Connections
id: MASWE-0096
alias: data-unencrypted
platform: [android, ios]
profiles: [R]
mappings:
  masvs-v1: [MSTG-RESILIENCE-13]
  masvs-v2: [MASVS-RESILIENCE-3, MASVS-NETWORK-1]

draft:
  description: Use payload/End-2-End Encryption. Even if the connection is encrypted
    (e.g. HTTPS), performing a MITM attack should not reveal any sensitive information
    (e.g. about the inner workings of the app and its operations. This is not necessarily
    related to privacy).
  topics: null
status: placeholder

---

