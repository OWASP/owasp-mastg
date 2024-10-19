---
platform: android
title: Uses of AutoBackup backup_rules.xml to Exclude Data From Backups
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
2. Execute `run_before.sh` which runs @MASTG-TOOL-0004.
3. Open the app and exercise it to trigger file creations.
4. Execute `run_after.sh`.
5. Close the app once you finish testing.

{{ run.sh }}

### Observation

The output contains the list of all restored files which were written to the `./restored_files/` directory:

{{ output.txt }}

The app wrote two files: `backup_excluded_secret.txt` which is not restored because it is marked as `exclude` in the `backup_rules.xml` file, and `secret.txt`, which contains a password:

{{ restored_files/secret.txt }}

Note that `/data/user/0/org.owasp.mastestapp/files/` is equivalent to `/data/data/org.owasp.mastestapp/files/`.

### Evaluation

The test fails because `secret.txt` is restored from the backup and it contains sensitive data.
