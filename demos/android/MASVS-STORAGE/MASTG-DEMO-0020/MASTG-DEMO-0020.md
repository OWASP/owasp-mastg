---
platform: android
title: Data Exclusion using backup_rules.xml with Backup Manager
id: MASTG-DEMO-0020
code: [kotlin]
test: MASTG-TEST-0216
---

### Sample

The following samples contain:

- the Kotlin code that creates two files inside [`filesDir`](https://developer.android.com/reference/android/content/Context#getFilesDir()).
- the AndroidManifest.xml with the `android:fullBackupContent` attribute (for Android 11 and lower).
- the `backup_rules.xml` file including a rule to exclude one of the files using an `<exclude>` element.

{{ MastgTest.kt # AndroidManifest.xml # backup_rules.xml }}

### Steps

1. Install the target app on your device.
2. Open the app and exercise it to trigger file creations.
3. Execute `run.sh`.

{{ run.sh # ../../../../utils/mastg-android-backup-bmgr.sh }}

For simplicity, in `run.sh` we restrict the files to the `filesDir` directory (`/data/user/0/org.owasp.mastestapp/files/` which is equivalent to `/data/data/org.owasp.mastestapp/files/`).

The `run.sh` script does the following:

1. Takes a snapshot of the app data before the backup.
2. Runs the backup script, which:
    - backs up the app data.
    - uninstalls the app.
    - restores the app data.
3. Takes a snapshot of the app data after the restore.
4. Retrieves the list of restored files from the device.

### Observation

The output contains:

- `output.txt`: the output of the `run.sh` script.
- `output_before.txt`: the list of files before the backup.
- `output_after.txt`: the list of files after the restore.
- `restored_files/`: the directory containing the restored files.

{{ output.txt # output_before.txt # output_after.txt }}

### Evaluation

The test fails because `secret.txt` is restored from the backup and it contains sensitive data.

{{ restored_files/secret.txt }}

Note that `output_after.txt` does not contain the `backup_excluded_secret.txt` file, which is expected as it was marked as `exclude` in the `backup_rules.xml` file.
