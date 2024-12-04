---
title: Use Secure Encryption Modes
alias: use-secure-encryption-modes
id: MASTG-BEST-0005
platform: android
---

Replace insecure encryption modes with secure block cipher modes such as [AES-GCM or AES-CCM](https://csrc.nist.gov/pubs/sp/800/38/d/final) which are authenticated encryption modes that provide confidentiality, integrity, and authenticity.

We recommend avoiding CBC, which while being more secure than ECB, improper implementation, especially incorrect padding, can lead to vulnerabilities such as padding oracle attacks.

For comprehensive guidance on implementing secure encryption modes in Android, refer to the official Android Developers documentation on [Cryptography](https://developer.android.com/privacy-and-security/cryptography).
