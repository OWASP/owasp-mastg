---
title: Sensitive Data Not Excluded From Backup
id: MASWE-0004
alias: data-not-excluded-backup
platform: [android, ios]
profiles: [L1, L2, P]
mappings:
  masvs-v1: [MSTG-STORAGE-8]
  masvs-v2: [MASVS-STORAGE-2, MASVS-PRIVACY-1]

refs:
- https://developer.android.com/guide/topics/data/autobackup#include-exclude-android-11
- https://developer.android.com/guide/topics/data/autobackup#include-exclude-android-12
draft:
  description: sensitive data can be excluded to prevent it from being backed up.
  topics:
  - '`android:fullBackupContent` (Android 11-) or `android:dataExtractionRules` (Android
    12+)'
  - iOS `isExcludedFromBackup` (iOS)
status: draft

---

## Overview

iOS and Android automatically back up app data to cloud services, and users can also create local backups on physical machines, or backups are automatically created during data transfers when switching between phones. When developers fail to properly configure how their app handles backups and neglect to exclude sensitive files, the backups may contain sensitive user and app data. Under certain conditions, the backups may not be adequately secured by the cloud provider, or a malicious actor could tamper with the backed up files, potentially altering the app's behavior or extracting confidential information.

## Impact

- **Modification of app's behavior**: An attacker can tamper with data inside the backup, altering the app's logic. For example, they could modify a database that tracks the state of premium features and then restore the modified backup to the device. Another common scenario is backing up the device before redeeming a one-time coupon and restoring the backup afterward. This would allow the malicious actor to reuse the same coupon multiple times.

- **Loss of confidentiality**: Sensitive data stored in backups (e.g., personal information, photos, documents, audio files) may be extracted by attackers, leading to privacy breaches.

- **Leakage of authentication material**: An attacker can extract passwords, cryptographic keys, and session tokens to facilitate additional attacks, such as identity theft, account takeover, or unauthorized access.

## Modes of Introduction

- **Automatic System Backups**: By default, iOS and Android back up app data to the cloud once the user consents during the initial setup.

- **Local Backups**: Users can back up their devices to local systems (e.g., laptops). If local backups are stored unencrypted or not securely handled, attackers could tamper with this data.

- **Device-To-Device Transfer**: Transferring data between devices (e.g., via iCloud or Google’s device-to-device migration tools) enables an attacker to perform similar attacks.

## Mitigations

The app should instruct the system on which files to exclude from the backup.
