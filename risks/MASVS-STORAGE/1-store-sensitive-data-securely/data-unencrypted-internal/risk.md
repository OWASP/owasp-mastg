---
title: Sensitive Data Stored Unencrypted in Internal Locations
alias: data-unencrypted-internal
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-1, MASVS-CRYPTO-2]
  mastg-v1: [MASTG-TEST-0052, MASTG-TEST-0001]

---

## Overview

Mobile apps may need to store sensitive data locally within the application sandbox and this data is at risk of exposure via, for example, incorrect file permissions, an app vulnerability, device vulnerability or data backup mechanisms.

[sensitive data](MASTG-THEORY-0023.md "Sensitive Data") may include personally identifiable information (PII), passwords, cryptographic keys or session tokens.

Sensitive data stored locally on the device should be encrypted, and any keys used for encryption methods should be protected by the device's hardware-backed keystore, where available.

## Impact

- **Loss of Confidentiality**: Under the right conditions an attacker could extract sensitive data stored internally within the application sandbox leading to loss of confidentiality and enable further attacks such as identity theft or account takeover.

## Modes of Introduction

- **Data Stored Unencrypted**: Sensitive data is written to the app's private data directory (sandbox) unencrypted.
- **Hardcoded Encryption Key**: Sensitive data is encrypted but the key is hardcoded inside the application.
- **Encryption Key Stored on Filesystem**: Sensitive data is encrypted but the key is stored alongside it or in another easily accessible location.
- **Encryption Used is Insufficient**: Sensitive data is encrypted but the encryption is not considered to be strong.

## Mitigations

- Avoid storing sensitive data locally at all.
- Use the platform's hardware-backed keystore solution to store the key used for encryption.
- Use platform features such as [androidx.security.crypto](https://developer.android.com/jetpack/androidx/releases/security) to safely store files and sharedpreferences.