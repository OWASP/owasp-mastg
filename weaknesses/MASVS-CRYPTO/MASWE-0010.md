---
title: Weak Cryptographic Key Derivation
id: MASWE-0010
alias: weak-crypto-key-derivation
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-2]
  cwe: [326, 327]

refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
draft:
  description: e.g. PBKDF2 with insufficient iterations, lack of salt, etc.
  topics:
  - weak sources
  - lack of salt encryption when doing PBKDF2
status: placeholder

---

