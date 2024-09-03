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

iOS and Android automatically back up app's to the cloud. These files often include sensitive user and app data. Under certain conditions, the backup may not be adequately secured by the cloud provider, or a malicious actor may tamper with the backed-up files. It's a good practice to review how your app instructs the system to perform backups and exclude sensitive files. This page also covers local backups made to your laptop and device-to-device transfers.

## Impact

- **Modification of app's behavior**: An attacker can tamper with data inside the backup, altering the app's logic. For example, they could modify a database that tracks the state of premium features and then restore the modified backup to the device. Another common scenario is backing up the device before redeeming a one-time coupon and restoring the backup afterward. This would allow the malicious actor to reuse the same coupon multiple times.

- **Loss of confidentiality**: An attacker can extract sensitive data stored in the backup, such as personal information, photos, documents, and audio files.

- **Loss of secure material**: An attacker can extract passwords, cryptographic keys, and session tokens to facilitate additional attacks, such as identity theft or account takeover.

## Modes of Introduction

- **System backs up app's data by default**: Backing up the device to the cloud is enabled by default for all apps once the user gives consent during setting up the phone for the first time.
- **Users can back up app's data locally to a laptop**: Under certain conditions, an attacker can tamper the backup locally.

- **Usage of Device-To-Device transfer**: Transferring data to another device enables an attacker to perform similar attacks.

## Mitigations

The app should instruct the system on which files to exclude from the backup.
