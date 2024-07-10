---
title: Sensitive Data Stored Unencrypted in Private Storage Locations
id: MASWE-0006
alias: data-unencrypted-private-storage
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-1, MASVS-CRYPTO-2]

draft:
  description: Sensitive data may be stored in internal locations without encryption
    and may be accessible to other apps under certain conditions.
  topics:
  - envelope encryption (DEK+KEK) or equivalent (Android)
  - Android Security Lib usage (EncryptedFile/EncryptedSharedPreferences) (Android)
  - Don't roll your own storage encryption, use platform provided APIs EncryptedFile/EncryptedSharedPreferences.
    (Android)
  - iOS KeyChain DataProtection classes (iOS)
  - envelope encryption (DEK+KEK) or equivalent (iOS)
  - sensitive data must not encoded (e.g. base64, simple bit operations such as XOR
    or bit flipping) instead of encrypted
status: draft

---

