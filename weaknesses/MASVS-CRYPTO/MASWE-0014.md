---
title: Cryptographic Keys Not Properly Protected at Rest
id: MASWE-0014
alias: crypto-keys-not-protected-at-rest
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-1]
  masvs-v2: [MASVS-CRYPTO-2, MASVS-STORAGE-1]

refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
draft:
  description: e.g. storing keys in SharedPreferences, storing keys in files, hardcoded
    keys, etc.
  topics:
  - platform keystore (Android KeyStore / iOS KeyChain)
  - TEE/SE
  - Cryptographic Keys Not Encrypted with key from platform keystore. envelope encryption
    (DEK+KEK) (considered "equivalent protection")
  - Key Wrapping (NIST.SP.800-175Br1 5.3.5)
status: draft

---

