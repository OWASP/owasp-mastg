---
platform: android
title: Data Exclusion using backup_rules.xml with adb backup
id: MASTG-DEMO-0035
code: [kotlin]
test: MASTG-TEST-0216
---

### Sample

This demo uses the sample from @MASTG-DEMO-0020.

{{ ../MASTG-DEMO-0020/MastgTest.kt # ../MASTG-DEMO-0020/AndroidManifest.xml # ../MASTG-DEMO-0020/backup_rules.xml }}

### Steps

1. Install the target app on your device.
2. Open the app and exercise it to trigger file creations.
3. Execute `run.sh`.

{{ run.sh # ../../../../utils/mastg-android-backup-adb.sh }}

For simplicity, in `run.sh` we restrict the files to the `filesDir` directory in the backup structure (`apps/org.owasp.mastestapp/f`).

### Observation

The output contains:

- `output.txt`: the list of files from the backup.
- `apps/org.owasp.mastestapp/f/`: the directory containing a copy of the backup files.

{{ output.txt }}

### Evaluation

The test fails because `secret.txt` is part of the backup and it contains sensitive data.

{{ apps/org.owasp.mastestapp/f/secret.txt }}

Note that `backup_excluded_secret.txt` file is not part of the backup, which is expected as it was marked as `exclude` in the `backup_rules.xml` file.
