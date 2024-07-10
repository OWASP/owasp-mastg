---
platform: android
title: File System Snapshots from Internal Storage
id: MASTG-DEMO-0010
tools: [adb]
code: [kotlin]
---

### Sample

The snippet below shows sample code that creates a file on the internal storage using the `getFilesDir` method.

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

### Evaluation

This test fails because the file is not encrypted and contains sensitive data (a password). You can further confirm this by reverse engineering the app and inspecting the code.
