---
title: Sensitive Data Stored Unencrypted in Private Storage Locations
id: MASWE-0006
alias: data-unencrypted-private-storage
platform: [android, ios]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-1, MASVS-CRYPTO-2]
  mastg-v1: [MASTG-TEST-0052, MASTG-TEST-0001]
  cwe: [312, 313, 922]
refs:
  - https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files
status: new
---

## Overview

Mobile apps may need to store sensitive data locally within private storage locations such as the application sandbox. This data is at risk of exposure via, for example, incorrect file permissions (on very old Android versions), an app vulnerability (such as an incorrectly exposed content provider), device vulnerability, or data backup mechanisms.

> **Note:** On Android, incorrect file permissions (e.g., world-readable or world-writable files) are only a risk for apps targeting `minSdkVersion` < 17. Since API 17, `Context.MODE_PRIVATE` is obligatory and files are private by default. Modern apps are not at risk from file permission misconfiguration, but are still at risk if sensitive data is stored unencrypted.

[Sensitive data](../../Document/0x04b-Mobile-App-Security-Testing.md#identifying-sensitive-data "Sensitive Data") may include:

- Personally identifiable information (PII), passwords, cryptographic keys, or session tokens (user sensitive data)
- Proprietary or business assets (e.g., intellectual property, business logic, confidential algorithms)

## Impact

- **Loss of Confidentiality**: Under the right conditions an attacker could extract sensitive data stored internally within the application sandbox leading to loss of confidentiality and enable further attacks such as identity theft or account takeover.

## Modes of Introduction

- **Data Stored Unencrypted**: Sensitive data is written to the app's private data directory (sandbox) unencrypted.
- **Hardcoded Encryption Key**: Sensitive data is encrypted but the key is hardcoded inside the application.
- **Encryption Key Stored on Filesystem**: Sensitive data is encrypted but the key is stored alongside it or in another easily accessible location.
- **Encryption Used is Insufficient**: Sensitive data is encrypted but the encryption is not considered to be strong.
- **App Vulnerability**: Sensitive data is exposed due to an app vulnerability, such as an incorrectly exposed content provider or insecure IPC mechanism.

## Mitigations

- Avoid storing sensitive data locally if not required for application functionality to reduce the likelihood and impact of this weakness. For example, keep PII server-side, render it at time of use, and remove any cached data on logout.
- Store cryptographic keys exclusively using the platform's hardware-backed keystore solution, such as the Android Keystore or the iOS Keychain.
- For storing other files and preferences, use platform-provided features for encrypting data at rest or other techniques implementing envelope encryption with Data Encryption Keys (DEK) and Key Encryption Keys (KEK) or equivalent methods. For example, on Android, use [EncryptedFile](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile) or [EncryptedSharedPreferences](https://developer.android.com/reference/androidx/security/crypto/EncryptedSharedPreferences); on iOS, use [iOS Data Protection](https://developer.apple.com/documentation/uikit/protecting_the_user_s_privacy/encrypting_your_app_s_files).
- Exclude sensitive files from backups where possible, and always encrypt user sensitive data to protect from other apps and from others obtaining the backup. Encrypt proprietary/business assets to protect from other apps on the device.
