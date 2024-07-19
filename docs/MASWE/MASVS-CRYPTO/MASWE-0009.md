---
title: Weak Cryptographic Key Generation
id: MASWE-0009
alias: weak-crypto-key-generation
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-2]

refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
draft:
  description: e.g. 1024-bit RSA keys, 128-bit AES keys, 160-bit ECDSA keys, 80-bit
    symmetric keys
  topics:
  - insufficient Key Length
status: draft

---

