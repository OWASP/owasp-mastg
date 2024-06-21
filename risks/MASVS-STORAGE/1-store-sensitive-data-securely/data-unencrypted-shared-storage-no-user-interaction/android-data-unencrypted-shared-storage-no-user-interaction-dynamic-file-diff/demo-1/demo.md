---
platform: android
title: File System Snapshots from External Storage 
tools: [adb]
code: [kotlin]
---

### Sample

The snippet below shows sample code that creates two files in the external storage using the `getExternalFilesDir` method and the `MediaStore` API.

{{ MastgTest.kt }}

### Steps

1. Install an app on your device.
2. Execute `run_before.sh`.
3. Open an app and exercise it to trigger file creations.
4. Execute `run_after.sh`.
5. Close the app once you finish testing.

{{ run.sh }}

### Observation

There is a list of all created files inside `output.txt`.

{{ output.txt }}

Their content is inside the `./new_files/` directory and contains:

A password:

{{ secret.txt }}

And an API key:

{{ secretFile75.txt }}

### Evaluation

This test fails because the files are not encrypted and contain sensitive data (a password and an API key). You can further confirm this by reverse engineering the app and inspecting the code.
