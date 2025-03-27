---
platform: android
title: Backup and Restore App Data with semgrep
id: MASTG-DEMO-0034
code: [kotlin]
test: MASTG-TEST-0262
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

The test fails because the sensitive file `secret.txt` ends up in the backup. This is due to:

- The `android:allowBackup="true"` attribute in the AndroidManifest.xml file.
- The `android:fullBackupContent="@xml/backup_rules"` attribute is present in the AndroidManifest.xml file.
- The `backup_rules.xml` file is present in the APK and does not exclude **all** sensitive files.

{{ ../MASTG-DEMO-0020/backup_rules.xml }}

The backup includes all files in the app's data directory except for `backup_excluded_secret.txt`.
