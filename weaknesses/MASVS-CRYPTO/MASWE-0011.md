---
title: Cryptographic Key Rotation Not Implemented
id: MASWE-0011
alias: no-key-rotation
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CRYPTO-2]
  cwe: [262, 324]

refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- https://developers.google.com/tink/managing-key-rotation
draft:
  description: Key rotation is a best practice to limit the impact of a key compromise.
    It is especially important for long-lived keys such as asymmetric keys.
  topics:
  - long-lived keys (cryptoperiods as per NIST.SP.800-57pt1r5)
status: placeholder

---

