---
title: Backup Unencrypted
alias: backup-unencrypted
platform: ["android"]
profiles: ["L1", "L2"]
mappings:
- masvs-v1: [MSTG-STORAGE-8]
- masvs-v2: [MASVS-STORAGE-2]
- cwe: [311, 312]
refs:
    - https://developer.android.com/guide/topics/data/autobackup#define-device-conditions
---

## Overview

Android allows apps to automatically backup their data to Google Drive. This is a convenient feature for users, but it can also be a security risk if the data is not encrypted. The backup data is stored in the user's Google Drive account, which is protected by the user's Google account password. However, if the user's Google account password is compromised, the attacker can access the user's backup data.

## Impact

Loss of confidentiality: The backup data is stored in the user's Google Drive account, which is protected by the user's Google account password. However, if the user's Google account password is compromised, the attacker can access the user's backup data.

## Mitigations

- [Encrypted Backup](mitigations/MAS-MITIGATION-0006): Ensure the backup data is encrypted.
- [Exclude sensitive data from Backup](mitigations/MAS-MITIGATION-0007): Exclude sensitive data from the backup.
