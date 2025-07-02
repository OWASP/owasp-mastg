---
title: Weak Signature
id: MASWE-0025
alias: weak-signatures
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]
  cwe: [327]

refs:
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
- https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
draft:
  description: The use of weak signature such as SHA1withRSA, etc. in a security sensitive
    context should be avoided to ensure the integrity and authenticity of the data.
  topics: null
status: placeholder

---

