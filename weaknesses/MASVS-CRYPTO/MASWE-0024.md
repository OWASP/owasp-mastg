---
title: Weak Message Authentication Codes (MAC)
id: MASWE-0024
alias: weak-mac
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [327, 807, 915]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
draft:
  description: The use of weak MAC such as HmacMD5, etc. in a security sensitive context
    may expose cryptographic vulnerabilities, affecting data integrity.
  topics: null
status: placeholder

---

