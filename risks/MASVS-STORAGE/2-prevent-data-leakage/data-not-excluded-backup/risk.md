---
title: Sensitive Data Not Excluded From Backup
platform: [android, ios]
profiles: ["L1", "L2", "P"]
mappings:
  - android: https://developer.android.com/privacy-and-security/risks/backup-leaks
refs:
    - https://developer.android.com/guide/topics/data/autobackup#include-exclude-android-11
    - https://developer.android.com/guide/topics/data/autobackup#include-exclude-android-12
---

## Overview

Apps striving to protect user privacy should not backup sensitive data to the cloud. Android and iOS provide mechanisms to exclude sensitive data from backups. However, if the app does not exclude sensitive data from backups, the data may be backed up to the cloud, where it can be accessed by attackers or unauthorized users.

## Impact

Loss of confidentiality: The backup data is stored in the user's Google Drive account, which is protected by the user's Google account password. However, if the user's Google account password is compromised, the attacker can access the user's backup data.

## Mitigations

- [Exclude sensitive data from Backup](mitigations/MAS-MITIGATION-0007): Exclude sensitive data from the backup.
- [Encrypted Backup](mitigations/MAS-MITIGATION-0006): Ensure the backup data is encrypted.
