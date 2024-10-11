---
platform: android
title: Sensitive Data Not Excluded From Backup
id: MASTG-DEMO-0020
code: [kotlin]
test: MASTG-TEST-0216
---

### Sample

The snippet below shows sample code that creates two files inside [`filesDir`](https://developer.android.com/reference/android/content/Context#getFilesDir()). One of the files is also marked as `exclude` inside `backup_rules.xml`.

{{ MastgTest.kt # backup_rules.xml }}

### Steps

1. Install the target app on your device.
2. Execute `run_before.sh` which runs @MASTG-TOOL-0004.
3. Open the app and exercise it to trigger file creations.
4. Execute `run_after.sh`.
5. Close the app once you finish testing.

{{ run.sh }}

### Observation

The output contains a list of all restored files.

{{ output.txt }}

Their content is inside the `./restored_files/` directory and contains:

A password:

{{ restored_files/secret.txt }}

The file was created in `/data/user/0/org.owasp.mastestapp/files/` which is equivalent to `/data/data/org.owasp.mastestapp/files/`.

Note that the sample app wrote two files: `secret.txt` and `backup_excluded_secret.txt`. The latter is not restored because it is marked as `exclude` in the `backup_rules.xml` file.

### Evaluation

The test fails because `secret.txt` is restored from the backup and it contains sensitive data.
