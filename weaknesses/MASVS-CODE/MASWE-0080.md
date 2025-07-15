---
title: Unsafe Handling of Data from Backups
id: MASWE-0080
alias: unsafe-backup-data
platform: [android, ios]
profiles: [L1, L2]
mappings:
  masvs-v2: [MASVS-CODE-4]
  cwe: [349]

refs:
- https://developer.android.com/guide/topics/data/keyvaluebackup#RestoreVersion
draft:
  description: The app does not validate restored backup data, potentially accepting untrusted modifications alongside trusted data (CWE-349).
  topics:
  - backup data validation
  - backup data integrity
status: placeholder

---

