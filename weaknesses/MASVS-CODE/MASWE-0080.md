---
title: Unsafe Handling of Data from Backups
id: MASWE-0080
alias: unsafe-backup-data
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-CODE-4]

refs:
- https://developer.android.com/guide/topics/data/keyvaluebackup#RestoreVersion
draft:
  description: e.g. on Android via android:fullBackupContent (Android 11-) or android:dataExtractionRules
    (Android 12+). On iOS seek for isExcludedFromBackup and check for file operations
    that reset backup exclusion.
  topics:
  - backups
status: placeholder

---

