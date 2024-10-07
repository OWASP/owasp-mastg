---
platform: android
title: Sensitive Data Not Excluded From Backup
id: MASTG-TEST-0211
type: [dynamic, filesystem]
weakness: MASWE-0004
---

## Overview

This test verifies whether your app correctly instructs the system to exclude sensitive files from backups. There are two distinct APIs for instructing the system to exclude files:

1. [Auto Backup](https://developer.android.com/identity/data/autobackup)
2. [Key-value backup](https://developer.android.com/identity/data/autobackup)

Regardless of which API you use, Android provides a way to start the backup daemon to back up and restore your app's files. You can use this daemon to initiate the backup process and restore the app's data, allowing you to verify which files have been restored from the backup.

## Steps

1. Start the device.

2. Install an app on your device.

3. Launch and use the app going through the various workflows while inputting sensitive data wherever you can.

4. Run the backup daemon.

5. Uninstall the app and install it again. Don't open the app anymore.

6. Restore the data from the backup.

7. Verify that restored files don't contain sensitive data. Test both private and shared storage locations.

## Observation

After installing the app for the second time and restoring data from the backup, inspect the files inside the Private and Shared storages and note down files with sensitive content.

## Evaluation

Once you complete the list of restored files containing sensitive data, instruct the system to exclude them from the backup. If you use Auto Backup, mark them with `exclude` tag inside `backup_rules.xml` or `data_extraction_riles.xml` depending on your target API. Make sure you use fill out both `cloud-backup` and `device-transfer` parameters. If you use Key-value approach, set up your [BackupAgent](https://developer.android.com/identity/data/keyvaluebackup#BackupAgent) accordingly.
