---
title: Potentially Weak Cryptography Implementations
id: MASWE-0019
alias: potentially-weak-crypto-impl
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-CRYPTO-2]
  masvs-v2: [MASVS-CRYPTO-1, MASVS-CODE-3]

refs:
- https://cwe.mitre.org/data/definitions/1240.html
- https://cwe.mitre.org/data/definitions/327.html
- https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)
- https://developer.android.com/privacy-and-security/security-gms-provider
- https://developer.android.com/privacy-and-security/cryptography#bc-algorithms
- https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library
- https://developer.android.com/privacy-and-security/cryptography#crypto_provider
- https://developer.android.com/privacy-and-security/cryptography#deprecated-functionality
- https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile
draft:
  description: Don't use outdated or known weak implementations and don't build your
    own cryptography. Using custom cryptography instead of relying on established,
    expert-designed APIs or certified modules exposes apps to vulnerabilities due
    to potential implementation flaws and lack of rigorous security review.
  topics:
  - platform-provided cryptographic APIs (e.g. conscrypt/CryptoKit)
  - custom-made cryptographic APIs (e.g. via xor, bit flipping, etc. or cryptographic
    constants or values such as sbox, etc.)
  - custom algorithms, primitives, protocols
  - specify Cipher.getInstance provider (Android)
  - Android Security Provider (Android)
  - Jetpack Security Crypto Library (Android)
  - BoucyCastle algorithms (Android)
status: draft

---

