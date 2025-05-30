---
title: Unsafe Handling of Imported Cryptographic Keys
id: MASWE-0016
alias: unsafe-imported-key-handling
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v2: [MASVS-CRYPTO-2, MASVS-CODE-4]
  cwe: [322]

refs:
- https://mas.owasp.org/MASTG/0x05d-Testing-Data-Storage/#secure-key-import-into-keystore
- https://developer.android.com/privacy-and-security/keystore#ImportingEncryptedKeys
- https://developer.android.com/reference/kotlin/android/security/keystore/KeyProtection
- https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_as_data#2933724
draft:
  description: Importing keys without validating their origin or integrity, or using
    insecure custom key exchange protocols, can inadvertently introduce malicious
    or compromised keys into the app environment.
  topics:
  - key import from untrusted sources
  - key import from untrusted storage
status: placeholder

---

