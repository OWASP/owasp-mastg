---
title: Weak Encryption
id: MASWE-0020
alias: weak-encryption
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-4]
  masvs-v2: [MASVS-CRYPTO-1]

refs:
- https://support.google.com/faqs/answer/10046138?hl=en
- https://support.google.com/faqs/answer/9450925?hl=en
- https://support.google.com/faqs/answer/9450925?hl=en
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar2.pdf
draft:
  description: The use of outdated encryption methods like DES and 3DES may compromise
    data confidentiality and integrity.
  topics:
  - Weak encryption algorithms (e.g. DES, 3DES, etc.)
  - Weak encryption modes (e.g. ECB, etc.)
  - Cipher.getInstance("AES") defaults to ECB (Android)
status: draft

---

