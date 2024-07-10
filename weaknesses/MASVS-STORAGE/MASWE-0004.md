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

