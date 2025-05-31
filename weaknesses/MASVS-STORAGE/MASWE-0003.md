---
title: Backup Unencrypted
id: MASWE-0003
alias: backup-unencrypted
platform: [android]
profiles: [L2]
mappings:
  masvs-v1: [MSTG-STORAGE-8]
  masvs-v2: [MASVS-STORAGE-2, MASVS-PRIVACY-1]
  cwe: [313]
  android-risks:
  - https://developer.android.com/privacy-and-security/risks/backup-best-practices

refs:
- https://developer.android.com/guide/topics/data/autobackup#define-device-conditions
draft:
  description: The app may not encrypt sensitive data in backups, which may compromise
    data confidentiality.
  topics:
  - Backup Device Conditions clientSideEncryption and deviceToDeviceTransfer Not Checked
    (Android)
status: placeholder

---

