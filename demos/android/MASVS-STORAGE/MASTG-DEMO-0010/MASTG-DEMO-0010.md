---
platform: android
title: File System Snapshots from Internal Storage
id: MASTG-DEMO-0010
tools: [adb]
code: [kotlin]
test: MASTG-TEST-0207
---

### Sample

The snippet below shows sample code that creates a file on the **internal storage** using using the [`filesDir`](https://developer.android.com/reference/android/content/Context#getFilesDir()) property of the context object.

{{ MastgTest.kt }}

### Steps

1. Install an app on your device.
2. Execute `run_before.sh`.
3. Open an app and exercise it to trigger file creations.
4. Execute `run_after.sh`.
5. Close the app once you finish testing.

{{ run_before.sh # run_after.sh }}

### Observation

There is a list of all created files inside `output.txt`.

{{ output.txt }}

Their content is inside the `./new_files/` directory and contains:

A password:

{{ new_files/secret.txt }}

The file was created in `/data/user/0/org.owasp.mastestapp/files/` which is equivalent to `/data/data/org.owasp.mastestapp/files/`.

### Evaluation

This test fails because the file is not encrypted and contains sensitive data (a password). You can further confirm this by reverse engineering the app and inspecting the code.
