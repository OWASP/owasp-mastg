---
title: Weak Hashing
id: MASWE-0021
alias: weak-hashing
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [328]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
draft:
  description: Utilizing weak hashing algorithms such as MD5 and SHA1 in a security
    sensitive context may compromise data integrity and authenticity.
  topics:
  - Weak hashing algorithms (e.g. MD5, SHA1, etc.)
status: placeholder

---

