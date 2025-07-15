---
title: Improper Generation of Cryptographic Signatures
id: MASWE-0025
alias: improper-signature-generation
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
- https://csrc.nist.gov/pubs/ir/8547/ipd
draft:
  description: The use of algorithms with insufficient strength for signatures such as SHA1withRSA, etc. in a security-sensitive context should be avoided to ensure the integrity and authenticity of the data.
  topics: null
status: placeholder

---

