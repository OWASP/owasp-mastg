---
title: Exclude Sensitive Data from Backups
alias: exclude-sensitive-data-from-backups
id: MASTG-BEST-0004
platform: android
---

For the sensitive files found, instruct the system to exclude them from the backup:

- If you are using Auto Backup, mark them with the `exclude` tag in `backup_rules.xml` (for Android 11 or lower using `android:fullBackupContent`) or `data_extraction_rules.xml` (for Android 12 and higher using `android:dataExtractionRules`), depending on the target API. Make sure to use both the `cloud-backup` and `device-transfer` parameters.
- If you are using the key-value approach, set up your [BackupAgent](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) accordingly.

Refer to ["Security recommendations for backups - Mitigations"](https://developer.android.com/privacy-and-security/risks/backup-best-practices#security-recommendations-for-backups-mitigations) for more information.
