---
title: Deprecated Android KeyStore Implementations
id: MASWE-0015
alias: deprecated-keystore
platform: [android]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-2, MASVS-CODE-3]
  cwe: [327, 477, 522]

refs:
- https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication
- https://developer.android.com/reference/java/security/KeyStore
- https://developer.android.com/about/versions/12/behavior-changes-all#bouncy-castle
draft:
  description: Avoid deprecated implementations such as BKS
  topics:
  - Bouncy Castle (BKS)
status: placeholder

---

