---
title: Insecure or Wrong Usage of Cryptographic Key
id: MASWE-0012
alias: insecure-key-usage
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-5]
  masvs-v2: [MASVS-CRYPTO-2]
  cwe: [323]

refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
draft:
  description: According to NIST.SP.800-57pt1r5, in general, a single key shall be
    used for only one purpose (e.g., encryption, integrity, authentication, key wrapping,
    random bit generation, or digital signatures)
  topics:
  - key used together with an authorized algorithm
  - key reuse for different purposes or operations (encrypt, decrypt, sign,...)
status: placeholder

---

