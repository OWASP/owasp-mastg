---
platform: android
title: Sensitive Data Not Excluded From Backup
id: MASTG-TEST-0216
type: [dynamic, filesystem]
weakness: MASWE-0004
---

## Overview

This test verifies whether your app correctly instructs the system to exclude sensitive files from backups.

Android provides two distinct approaches for instructing the system to exclude files:

1. [Auto Backup](https://developer.android.com/identity/data/autobackup)
2. [Key-value backup](https://developer.android.com/identity/data/keyvaluebackup)

Regardless of which approach the app used, Android provides a way to start the backup daemon to back up and restore your app's files. You can use this daemon to initiate the backup process and restore the app's data, allowing you to verify which files have been restored from the backup.

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

For the sensitive files found, instruct the system to exclude them from the backup. 
- If you are using Auto Backup, mark them with the `exclude` tag in `backup_rules.xml` or `data_extraction_riles.xml` depending on your target API. Make sure you use both `cloud-backup` and `device-transfer` parameters.
- If you are using the key-value approach, set up your [BackupAgent](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) accordingly.
