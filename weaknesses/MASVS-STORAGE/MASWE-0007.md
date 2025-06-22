---
title: Sensitive Data Stored Unencrypted in Shared Storage Requiring No User Interaction
id: MASWE-0007
alias: data-unencrypted-shared-storage-no-user-interaction
platform: [android]
profiles: [L1, L2]
mappings:
  masvs-v1: [MSTG-STORAGE-2]
  masvs-v2: [MASVS-STORAGE-1]
  mastg-v1: [MASTG-TEST-0052, MASTG-TEST-0001]
  cwe: [312, 313, 921, 922]
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/sensitive-data-external-storage
status: new
---

## Overview

Apps frequently opt to store data in the external storage due to its larger capacity. However, this convenience comes with a potential security drawback. Once a malicious app is granted the relevant permissions, it can access this data without user consent or interaction at any time. Additionally, external storage like SD cards can be physically removed and read by a malicious actor. Even if the external storage is emulated by the system, the risk arises from improper file permissions or the misuse of APIs for saving files. In such cases, the files become vulnerable to unauthorized access, modifications and deletions, posing a security threat to the application.

Developers may consider switching to Private Storage or Shared Storage Requiring User Interaction if they need more privacy and security. However, if the external storage is the most suitable for the app, it's a good practise to encrypt data stored in the external storage. Below you can find potential security impacts and mitigations linked to the use of the external storage.

## Impact

- **Loss of confidentiality**: An attacker can extract sensitive data stored externally, such as personal information and media like photos, documents, and audio files.

- **Loss of secure material**: An attacker can extract passwords, cryptographic keys, and session tokens to facilitate additional attacks, such as identity theft or account takeover.

- **Modification of app's behaviour**: An attacker can tamper with data used by the app, altering the app's logic. For example, they could modify a database describing the state of premium features or inject a malicious payload to enable further attacks such as SQL injection and Path Traversal.

- **Modification of downloaded code**: An app can download new functionality from the Internet and store the executable code in external storage before loading it into the process. An attacker can modify this code before it is used by the app.

## Modes of Introduction

This threat is primarily a concern for Android devices since they permit the use of external storage. Even if a device lacks physical external storage, Android emulates it to provide access to the external storage API.

- **Data Stored Unencrypted**: Sensitive data is stored in the external storage unencrypted.
- **Hardcoded Encryption Key**: Sensitive data is encrypted and stored in the external storage but the key is hardcoded inside the application.
- **Encryption Key Stored on Filesystem**: Sensitive data is encrypted and stored in the external storage but the key is stored alongside it or in another easily accessible location.
- **Encryption Used is Insufficient**: Sensitive data is encrypted but the encryption is not considered to be strong.
- **Reuse of encryption key**: The encryption key is shared between two devices owned by a single user, enabling the process of data cloning between these devices in the external storage.

On iOS, apps cannot directly write to or read from the arbitrary locations, as compared to desktop operating system or Android. iOS maintains strict sandboxing rules, meaning apps can only access their own sandboxed file directories.

## Mitigations

Sensitive data stored in the external storage should be encrypted, and any keys used for data encryption should be protected by the device's hardware-backed keystore, where available. It is highly discouraged to include cryptographic keys hardcoded inside the application. You can also consider storing your files in the [private app sandbox or internal storage](https://developer.android.com/training/data-storage/app-specific#internal) and using [Android's EncryptedFile API wrapper for file encryption](https://developer.android.com/reference/androidx/security/crypto/EncryptedFile).

!!! Warning

    The **Jetpack security crypto library**, including the `EncryptedFile` and  `EncryptedSharedPreferences` classes, has been [deprecated](https://developer.android.com/privacy-and-security/cryptography#jetpack_security_crypto_library). However, since an official replacement has not yet been released, we recommend using these classes until one is available.
