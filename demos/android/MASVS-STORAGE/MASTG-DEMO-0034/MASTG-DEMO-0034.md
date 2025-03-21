---
platform: android
title: Backup and Restore App Data with semgrep
id: MASTG-DEMO-0034
code: [kotlin]
test: MASTG-TEST-0216
status: new
---

### Sample

This demo uses the sample from @MASTG-DEMO-0020.

{{ ../MASTG-DEMO-0020/MastgTest.kt # ../MASTG-DEMO-0020/AndroidManifest.xml # ../MASTG-DEMO-0020/backup_rules.xml }}

### Steps

1. Read the AndroidManifest.xml and backup_rules.xml files.
2. Run the semgrep script.

{{ run.sh # ../../../../rules/mastg-android-backup-manifest.yml }}

### Observation

The output contains all backup-related attributes from the AndroidManifest.xml file.

{{ output.txt }}

### Evaluation

The test fails because the app allows sensitive data to be backed up as indicated by `android:allowBackup="true"`

{{ evaluation.txt }}

The app also has `android:fullBackupContent="@xml/backup_rules"` which we could also retrieve:

{{ ../MASTG-DEMO-0020/backup_rules.xml }}

The backup includes all files in the app's data directory except for `backup_excluded_secret.txt`. This explains why the file `secret.txt` ends up in the backup.
