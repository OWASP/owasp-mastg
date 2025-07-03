---
title: Predictable Initialization Vectors (IVs)
id: MASWE-0022
alias: predictable-ivs
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [329]

refs:
- https://developer.android.com/privacy-and-security/cryptography#pbe-without-iv
draft:
  description: The use of predictable IVs (hardcoded, null, reused) in a security
    sensitive context can weaken data encryption strength and potentially compromise
    confidentiality.
  topics:
  - not use the IvParameterSpec.class anymore for GCM, use the GCMParameterSpec.class
    instead (Android)
  - Hardcoded IVs
  - Null IVs
  - Reused IVs
status: placeholder

---

