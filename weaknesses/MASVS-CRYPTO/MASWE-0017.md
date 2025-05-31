---
title: Cryptographic Keys Not Properly Protected on Export
id: MASWE-0017
alias: crypto-keys-not-protected-export
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CRYPTO-2, MASVS-STORAGE-1, MASVS-NETWORK-1]
  cwe: [522]

refs:
- https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
- https://developer.android.com/reference/kotlin/android/security/keystore/KeyProtection
- https://developer.apple.com/documentation/cryptokit/aes/keywrap
- https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_as_data#2933723
draft:
  description: Before exporting, keys should be "wrapped" or encrypted with another
    key. This process ensures that the cryptographic key is protected during and after
    export. This is true even if the key is sent over a secure channel.
  topics:
  - key wrapping (NIST.SP.800-175Br1 5.3.5)
status: placeholder

---

