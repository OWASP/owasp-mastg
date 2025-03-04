---
platform: android
title: Sensitive Data Not Excluded From Backup
id: MASTG-TEST-0216
type: [dynamic, filesystem]
weakness: MASWE-0004
best-practices: [MASTG-BEST-0004]
---

## Overview

This test verifies whether your app correctly instructs the system to exclude sensitive files from backups.

["Android Backups"](../../../0x05d-Testing-Data-Storage.md/#backups) can be implemented via [Auto Backup](https://developer.android.com/identity/data/autobackup) (Android 6.0 (API level 23) and higher) and [Key-value backup](https://developer.android.com/identity/data/keyvaluebackup) (Android 2.2 (API level 8) and higher). Auto Backup is the recommended approach by Android as it is enabled by default and requires no work to implement.

To exclude specific files when using Auto Backup, developers must explicitly define exclusion rules in the `exclude` tag in `backup_rules.xml` (for Android 11 or lower using `android:fullBackupContent`) or `data_extraction_rules.xml` (for Android 12 and higher using `android:dataExtractionRules`), depending on the target API. The `cloud-backup` and `device-transfer` parameters can be used to exclude files from cloud backups and device-to-device transfers, respectively. The key-value backup approach requires developers to set up a [`BackupAgent`](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) or [`BackupAgentHelper`](https://developer.android.com/identity/data/keyvaluebackup#BackupAgentHelper) and specify what data should be backed up.

Regardless of which approach the app used, Android provides a way to start the backup daemon to back up and restore app files. You can use this daemon for testing purposes and initiate the backup process and restore the app's data, allowing you to verify which files were restored from the backup.

## Steps

1. Start the device.
2. Install an app on your device.
3. Launch and use the app going through the various workflows while inputting sensitive data wherever you can.
4. Run the backup daemon.
5. Uninstall and reinstall the app but don't open it anymore.
6. Restore the data from the backup and get the list of restored files.

## Observation

The output should contain a list of files that are restored from the backup.

## Evaluation

The test fails if any of the files are considered sensitive.
